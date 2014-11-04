#!/usr/bin/python

__author__ = 'Fabrice Bacchella'

import sys

import optparse
import docker as dockerlib
import yaml
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
import inspect
import tempfile
import os
import stat
import string
import collections
from pwd import getpwnam
import re

# a template that allows . in variables name
class DotTemplate(string.Template):
    delimiter = '$'
    idpattern = r'[_a-z][_a-z0-9\.]*'


class DockerOption(optparse.Option):
    ACTIONS = optparse.Option.ACTIONS + ("store_first", "store_variable", )
    STORE_ACTIONS = optparse.Option.STORE_ACTIONS + ("store_first", "store_variable", )
    TYPED_ACTIONS = optparse.Option.TYPED_ACTIONS + ("store_first", "store_variable", )
    ALWAYS_TYPED_ACTIONS = optparse.Option.ALWAYS_TYPED_ACTIONS + ("store_first", "store_variable", )

    def __init__(self, *args, **kwargs):
        if kwargs['action'] == "store_variable":
            kwargs['nargs'] = 2
            if not 'default' in kwargs:
                kwargs['default'] = {}
        elif kwargs['action'] == "store_first":
            self.seen = set([])
        optparse.Option.__init__(self, *args, **kwargs)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "store_first" and dest in self.seen:
            pass
        elif action == "store_variable":
            (v_key, v_value) = value
            values.variables[v_key] = v_value
        else:
            if action == "store_first":
                self.seen.add(dest)
                action = "store"
            optparse.Option.take_action(self, action, dest, opt, value, values, parser)


def run(docker, path, yamls, variables):
    allowed_paths = []
    if path is not None:
        for element in path.split(os.pathsep):
            allowed_paths.append( os.path.normcase(os.path.abspath(element)) )

    for docker_file_name in yamls:

        # Check if the docker yaml file is in an allowed path
        if len(allowed_paths) > 0:
            # no path given, look in allowed path and use it as the file name
            # path is checked any way, to resolve symbolic links
            if os.path.basename(docker_file_name) == docker_file_name:
                for element in allowed_paths:
                    if os.path.exists(element + os.sep + docker_file_name):
                        # use that as the new file name
                        docker_file_name = element + os.sep + docker_file_name
                        break
            # Resolve to a absolute real path
            # symbolic links are resolve too
            real_file_name = os.path.normcase(os.path.realpath(docker_file_name))
            valid = False
            for element in allowed_paths:
                if os.path.commonprefix([element, real_file_name]) == element:
                    valid = True
            if not valid:
                print "invalid yaml container: %s" % docker_file_name
                return 1

        #loads the file
        with open(docker_file_name, 'r') as docker_file:
            content = docker_file.read()
            content = re.sub(r'^#.*\n', '\n', content)
            template = DotTemplate(content)
            try:
                content = template.substitute(variables)
            except KeyError as e:
                print e
            docker_kwargs = yaml.load(content)

        effective_create_kwargs = {}
        effective_start_kwargs = {}

        # Converted the binding, must be given as an array of single-element hash
        # transformed to OrderedDict, docker-py expect a dict
        if 'binds' in docker_kwargs:
            binds = docker_kwargs['binds']
            if not isinstance(binds, list):
                print "binding must be an array"
                return 1
            new_binds = collections.OrderedDict()
            for bind in binds:
                (key, value) = bind.items()[0]
                new_binds[key] = value
            docker_kwargs['binds'] = new_binds

        # if a script is given, save it as a temporary file
        if 'script' in docker_kwargs:
            script = docker_kwargs.pop('script')
            with tempfile.NamedTemporaryFile(delete=False) as script_file:
                script_file.write(script)
                script_file.flush()
                os.chmod(script_file.name,
                         (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO) & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
                docker_kwargs['command'] = [script_file.name]
            if 'binds' not in docker_kwargs:
                docker_kwargs['binds'] = collections.OrderedDict()
            docker_kwargs['binds'][script_file.name] = {'bind': script_file.name, 'ro': True}

        if 'detach' in docker_kwargs and not docker_kwargs['detach']:
            attach = True
        else:
            attach = False

        # some exceptions, given in create_container, should be used in start:
        if 'volumes_from' in docker_kwargs:
            effective_start_kwargs['volumes_from'] = docker_kwargs.pop('volumes_from')
        if 'dns' in docker_kwargs:
            effective_start_kwargs['dns'] = docker_kwargs.pop('dns')

        #start with 1, 0 is 'self'
        for arg_name in inspect.getargspec(dockerlib.Client.create_container).args[1:]:
            if arg_name in docker_kwargs:
                effective_create_kwargs[arg_name] = docker_kwargs.pop(arg_name)
        #start with 1, 0 is 'self'
        for arg_name in inspect.getargspec(dockerlib.Client.start).args[1:]:
            if arg_name in docker_kwargs:
                effective_start_kwargs[arg_name] = docker_kwargs.pop(arg_name)

        # is a numeric id given for the user, or is it needed to resolve it ?
        if 'user' in effective_create_kwargs and not isinstance( effective_create_kwargs['user'], ( int, long ) ):
            user = effective_create_kwargs['user']
            try:
                effective_create_kwargs['user'] = getpwnam(user).pw_uid
            except KeyError:
                print "user '%s' not found" % user
                return 1

        if len(docker_kwargs) > 0:
            print "invalid arguments: %s" % docker_kwargs
            return 1
        container = docker.create_container(**effective_create_kwargs)
        if container['Warnings'] is not None:
            print "warning: %s" % container.Warnings
        docker.start(container, **effective_start_kwargs)

        if attach:
            os.execlp("docker", "docker", "attach", container['Id'])

def list_contenair(docker):
    real_user = os.environ['SUDO_UID']
    for container in docker.containers(all=True):
        info = docker.inspect_container(container)
        docker_user = info['Config']['User']
        if docker_user == real_user:
            print "%s %s" % (info['Config']['Hostname'], container['Status'])

def rm_contenair(docker, container, force=True):
    info = docker.inspect_container(container)
    docker_user = info['Config']['User']
    real_user = os.environ['SUDO_UID']
    if not docker_user == real_user:
        print "not you're own container"

    docker.remove_container(container, force=force)

def attach(docker, container):
    info = docker.inspect_container(container)
    docker_user = info['Config']['User']
    real_user = os.environ['SUDO_UID']
    if docker_user == real_user:
        os.execlp("docker", "docker", "attach", container)
    else:
        print "not you're own container"

def main():
    parser = optparse.OptionParser(option_class=DockerOption)
    parser.add_option("-p", "--p", dest="path", help="allowed path for yaml files", default=None, action="store_first")
    parser.add_option("-u", "--url", dest="url", help="base URL for docker connection", default=None, action="store")
    parser.add_option("-s", "--socket", dest="socket", help="docker socket", default=None, action="store")
    parser.add_option("-a", "--api", dest="api_version", help="docker api version", default='1.13', action="store_first")
    parser.add_option("-t", "--timeout", dest="timeout", help="docker timeout", default=20, action="store", type="int")
    parser.add_option("-v", "--variable", dest="variables", action="store_variable", type="string")

    (options, args) = parser.parse_args()

    # Override -p with content of DOCKERRUN_YAMLPATH
    # it's used in sudoers
    if 'SUDO_COMMAND' in os.environ:
        if 'DOCKERRUN_YAMLPATH' in os.environ:
            options.path = os.environ['DOCKERRUN_YAMLPATH']
        else:
            print "run in sudo but not DOCKERRUN_YAMLPATH defined"
            return 1
    docker = dockerlib.Client(base_url=options.url,
                              version=options.api_version,
                              timeout=options.timeout)

    # add some values in the variables
    options.variables['system.uid'] = os.geteuid()
    for (name, value) in os.environ.items():
        options.variables['environment.%s' % name] = value

    if args[0] == "run":
        run(docker, options.path, args[1:], options.variables)
        return 0
    elif args[0] == "info":
        print docker.info()
        return 0
    elif args[0] == "list":
        list_contenair(docker)
        return 0
    elif args[0] == "rm":
        rm_contenair(docker, args[1])
        return 0
    elif args[0] == "attach":
        attach(docker, args[1])
        return 0
    else:
        print "no action given"
        return 1

# no global name space pollution
if __name__ == '__main__':
    sys.exit(main())
