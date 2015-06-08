#!/usr/bin/python

__author__ = 'Fabrice Bacchella'

import sys

import optparse
import docker as dockerlib
import dockerpty
import yaml
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
import inspect
import tempfile
import os
import sys
import stat
import string
import collections
from pwd import getpwnam
import re
import socket

class Verb(object):
    verbs = {}

    def __init__(self, name, numargs=0):
        self.name = name
        self.numargs = numargs

    def __call__(self, f):
        Verb.verbs[self.name] = (f, self.numargs)
        return f


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


@Verb('run', 1)
def run(docker, path, variables, yamls):
    """run a new container, using a predefined yaml"""
    allowed_paths = []
    if path is not None:
        for element in path.split(os.pathsep):
            allowed_paths.append(os.path.normcase(os.path.abspath(element)))

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
                print >> sys.stderr, "invalid yaml container: %s" % docker_file_name
                return 1

        # First load of the yaml file to check allowed variables values
        with open(docker_file_name, 'r') as docker_file:
            content = docker_file.read()
            content = re.sub(r'^#.*\n', '\n', content)
            docker_conf = yaml.load(content)
            if 'variables' in docker_conf:
                for (key, value) in docker_conf['variables'].items():
                    if key not in variables:
                        print >> sys.stderr,  "undefined variable '%s'" % key
                        return 1
                    #The variable check is a string, the filter is a regex
                    if type(value) == str or type(value) == unicode:
                        if re.match("^" + value + "$", variables[key]) is None:
                            print >> sys.stderr,  "variable %s not a valid value: '%s'" % (key, variables[key])
                            return 1
                    # it's a list, search in allowed values
                    elif type(value) == list:
                        if not variables[key] in value:
                            print >> sys.stderr,  "variable %s not an allowed value" % key
                            return 1

        # now again but with variable substitution
        template = DotTemplate(content)
        try:
            content = template.substitute(variables)
        except KeyError as e:
            print >> sys.stderr, "unresolved variable %s" % e
            return 1

        docker_kwargs = yaml.load(content)
        effective_create_kwargs = {}
        effective_start_kwargs = {}

        # Converted the binding, must be given as an array of single-element hash
        # transformed to OrderedDict, docker-py expect a dict
        if 'binds' in docker_kwargs:
            binds = docker_kwargs['binds']
            if not isinstance(binds, list):
                print >> sys.stderr,  "binding must be an array"
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

        do_attach = not docker_kwargs.pop('detach', False)
        do_rm = docker_kwargs.pop('rm', False)

        # list of capability to drop or add
        if 'cap_drop' in docker_kwargs and isinstance(docker_kwargs['cap_drop'], list):
            effective_start_kwargs['cap_drop'] = docker_kwargs.pop('cap_drop')
        if 'cap_add' in docker_kwargs and isinstance(docker_kwargs['cap_drop'], list):
            effective_start_kwargs['cap_add'] = docker_kwargs.pop('cap_add')

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
        if 'user' in effective_create_kwargs and not isinstance(effective_create_kwargs['user'], (int, long)):
            user = effective_create_kwargs['user']
            try:
                effective_create_kwargs['user'] = getpwnam(user).pw_uid
            except KeyError:
                print >> sys.stderr, "user '%s' not found" % user
                return 1

        if len(docker_kwargs) > 0:
            print >> sys.stderr, "invalid argument: %s" % docker_kwargs
            return 1
        container = docker.create_container(**effective_create_kwargs)
        if container['Warnings'] is not None:
            print >> sys.stderr, "warning: %s" % container.Warnings

        if do_attach:
            try:
                dockerpty.start(docker, container, **effective_start_kwargs)
                if do_rm:
                    docker.remove_container(container, v=True)
            except socket.error:
                print >> sys.stderr, "container detached"
        else:
            docker.start(container, **effective_start_kwargs)

    return 0


@Verb('list')
def list_contenair(docker):
    """return the list of active contenaire"""
    real_user = os.environ['SUDO_UID']
    for container in docker.containers(all=True):
        info = docker.inspect_container(container)
        docker_user = info['Config']['User']
        if docker_user == real_user:
            print "%s %s" % (info['Config']['Hostname'], container['Status'])
    return 0


@Verb('rm', numargs=2)
def rm_contenair(docker, container, force=True):
    """remove a container, given is id or name"""
    info = docker.inspect_container(container)
    docker_user = info['Config']['User']
    real_user = os.environ['SUDO_UID']
    if not docker_user == real_user:
        print >> sys.stderr, "not you're own container"

    docker.remove_container(container, force=force)
    return 0


@Verb('attach', numargs=1)
def attach(docker, container):
    """attach to a running container"""
    info = docker.inspect_container(container)
    docker_user = info['Config']['User']
    real_user = os.environ['SUDO_UID']
    if docker_user == real_user:
        os.execlp("docker", "docker", "attach", container)
    else:
        print >> sys.stderr, "not you're own container"
    return 0


def main():
    help_header = "[args]* 'verb' [verb_args]*\n"
    for (verb, (function, numargs)) in Verb.verbs.items():
        if function.__doc__ is None:
            doc = ""
        else:
            doc = ": %s" % function.__doc__
        help_header += "%s%s\n" % (verb, doc)

    parser = optparse.OptionParser(option_class=DockerOption, usage=help_header)
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
        # Check that SUDO_COMMAND was ourself
        # bash -s|-i also set SUDO_COMMAND
        run_command = os.path.basename(os.path.abspath(sys.argv[0]))
        sudo_command = os.path.basename(os.path.abspath(os.environ['SUDO_COMMAND'].split(' ')[0]))
        # argv is not the current file, not launched with sudo .../dockerrun
        # it's not our duty to check any more
        if run_command != sudo_command:
            pass
        elif 'DOCKERRUN_YAMLPATH' in os.environ:
            options.path = os.environ['DOCKERRUN_YAMLPATH']
        else:
            print >> sys.stderr, "run in sudo but not DOCKERRUN_YAMLPATH defined"
            return 1
    docker = dockerlib.Client(base_url=options.url,
                              version=options.api_version,
                              timeout=options.timeout)

    # add some values in the variables
    options.variables['system.uid'] = os.geteuid()
    for (name, value) in os.environ.items():
        options.variables['environment.%s' % name] = value

    if len(args) == 0:
        parser.print_help()
        return 1
    elif args[0] not in Verb.verbs:
        print >> sys.stderr, "unknow verb %s, allowed verbs are %s" % (args[0], Verb.verbs.keys())
    else:
        verb = args[0]
        if verb in Verb.verbs:
            (f, numargs) = Verb.verbs[verb]
            if len(args) < numargs:
                print >> sys.stderr, "not enough argument for %s" % verb
                if f.__doc__ is not None:
                    print f.__doc__
                return 1
            if verb == 'run':
                return f(docker, options.path, options.variables, *[args[1:]])
            else:
                return f(docker, *args[1:])

# no global name space pollution
if __name__ == '__main__':
    sys.exit(main())
