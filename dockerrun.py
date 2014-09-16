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

create_kwargs = ('image', 'command', 'hostname', 'user',
                   'detach', 'stdin_open', 'tty', 'mem_limit',
                   'ports', 'environment', 'dns', 'volumes',
                   'volumes_from', 'network_disabled', 'name',
                   'entrypoint', 'cpu_shares', 'working_dir',
                   'memswap_limit')

start_kwargs = ('container', 'binds', 'port_bindings', 'lxc_conf',
        'publish_all_ports', 'links=', 'privileged',
        'dns', 'dns_search', 'volumes_from', 'network_mode',
        'restart_policy', 'cap_add', 'cap_drop')


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

def main():
    parser = optparse.OptionParser(option_class=DockerOption)
    parser.add_option("-p", "--p", dest="path", help="allowed path for yaml files", default="", action="store_first")
    parser.add_option("-u", "--url", dest="url", help="base URL for docker connection", default=None, action="store")
    parser.add_option("-s", "--socket", dest="socket", help="docker socket", default=None, action="store")
    parser.add_option("-a", "--api", dest="api_version", help="docker api version", default='1.13', action="store_first")
    parser.add_option("-t", "--timeout", dest="timeout", help="docker timeout", default=5, action="store", type="int")
    parser.add_option("-v", "--variable", dest="variables", action="store_variable", type="string")

    (options, args) = parser.parse_args()

    allowed_paths = []
    for element in options.path.split(os.pathsep):
        allowed_paths.append( os.path.normcase(os.path.abspath(element)) )

    docker = dockerlib.Client(base_url=options.url,
                                  version=options.api_version,
                                  timeout=options.timeout)

    for docker_file_name in args:

        # Check if the docker yaml file is in an allowed path
        if len(allowed_paths) > 0:
            real_file_name = os.path.normcase(os.path.abspath(docker_file_name))
            valid = False
            for element in allowed_paths:
                if os.path.commonprefix([element, real_file_name ]) == element:
                    valid = True
            if not valid:
                print "invalid yaml container: %s" % docker_file_name
                return 1

        #loads the file
        docker_file = open(docker_file_name, 'r')
        docker_kwargs = yaml.load(docker_file)

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
            if len(options.variables) > 0:
                template = string.Template(docker_kwargs.pop('script'))
                script = template.substitute(options.variables)
            else:
                script = docker_kwargs.pop('script')
            with tempfile.NamedTemporaryFile(delete=False) as script_file:
                script_file.write(script)
                script_file.flush()
                os.chmod(script_file.name, (stat.S_IRWXU|stat.S_IRWXG|stat.S_IRWXO) & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
                docker_kwargs['command'] = [ script_file.name ]
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
                value = docker_kwargs.pop(arg_name)
                if isinstance(value, str) or isinstance(value, unicode):
                    template = string.Template(value)
                    value = template.substitute(options.variables)
                effective_create_kwargs[arg_name] = value
        #start with 1, 0 is 'self'
        for arg_name in inspect.getargspec(dockerlib.Client.start).args[1:]:
            if arg_name in docker_kwargs:
                value = docker_kwargs.pop(arg_name)
                if isinstance(value, str) or isinstance(value, unicode):
                    template = string.Template(value)
                    value = template.substitute(options.variables)
                effective_start_kwargs[arg_name] = value

        if len(docker_kwargs) > 0:
            print "invalid arguments: %s" % docker_kwargs
            return 1
        container = docker.create_container(**effective_create_kwargs)
        if container['Warnings'] is not None:
            print "warning: %s" % container.Warnings
        docker.start(container, **effective_start_kwargs)

        if attach:
            os.execlp("docker", "docker", "attach", container['Id'])

# no global name space pollution
if __name__ == '__main__':
    sys.exit(main())
