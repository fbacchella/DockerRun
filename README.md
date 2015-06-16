This tools is used to launch some docker container.

It parses some yaml files and construct container as described.

It's made to be used through sudo, as it can take a path of allowed directory for yaml description files.

Common usage
-------------

dockerrun is intended to run from within sudo. Common usage is

    Usage: [args]* 'verb' [verb_args]*
    
Current verbs are:

 - run: run a new container, using a predefined yaml
 - logs: show the stdout and stderr logs from a container
 - start: start a container
 - list: return the list of active contenaire
 - attach: attach to a running container
 - tail: follow stdout and stdin from a container, without attaching
 - rm: remove a container, given is id or name

Common args are :

    -h, --help            show this help message and exit
    -p PATH, --p=PATH     allowed path for yaml files
    -u URL, --url=URL     base URL for docker connection
    -s SOCKET, --socket=SOCKET
                        docker socket
    -a API_VERSION, --api=API_VERSION
                        docker api version
    -t TIMEOUT, --timeout=TIMEOUT
                        docker timeout
    -v VARIABLES, --variable=VARIABLES


Sudo settings
-------------
To use it, one should add in /etc/sudoers.d/docker:

    Cmnd_Alias DOCKER_COMMANDS = /usr/bin/dockerrun *
    User_Alias DOCKER_USERS = ...
    Defaults!DOCKER_COMMANDS env_file = /etc/dockerrun/environment

    DOCKER_USERS ALL = (root) DOCKER_COMMANDS

The content of /etc/dockerrun/environment should then be :
    DOCKERRUN_YAMLPATH=/etc/dockerrun

It also allow to attach to a container if the `user value` is equal to the user who launched the command, read
from `SUDO_UID`

Variables
---------

The yaml files can contains variable that will be resolved at container creation time. A variable is set
with a `-v name value` argument. The environment variable are available as `environment.*name*`

Variable content can be check with a `check` section in the yaml file. For each given variable, 3 different check can
be done:

 * empty value, check the variable is given
 * a regex, the whole variable will need to match it
 * a list, the variable must be one of the given values

For example:

    ...
    check:
        v1:
        v2: "[a-zA-Z]+"
        v3:
            - one
            - two
            - three

It the template contains a `variables` section, it can define new variables. In this case, each element is a 
new variable and a python expression that will resolve it, using the already defined variables.

For example, if dockerrun is launched with `-v key 1` and the template containes:

    variables:
       v1: int(key) * 2
       v2: {'1': 'a'}[key]

it will add a variable `v1` with value `2` and `v2` with value `'a'`. All variable are strings and so must
be converted before use a int or other types

Common settings
---------------

A lot of attributes have the same meaning that in docker create/ docker run, they are :

* image
* hostname
* name
* command
* binds
* rm
* user

Attach a tty
------------
The default setting is to create a tty and attach an interactive console to the command.
To create a detached container, just set `detach` to `True`.

Network bindings
----------------
Binding can be added using the parameter port_bindings

It can take 3 value:

 * None, it generate a direct badding
 * a integer, it generate a tcp port redirection, listening on any IP
 * a dictionnary, it takes the following arguments:
 
    * port: the outside listenning port
    * protocol: the listening protocol, tcp or udp (tcp if missing)
    * range: a port range, that can be written as start-stop or start,count
    
Example:

    port_bindings:
       80:
       22: 2222
       10000: 
          range: ${port_base}, 100
          proto: tcp
          host: 127.0.0.1

Mount bindings
--------------
A list of mount can be given using the parameter binds

It's a array of mapping
For each internal mount point, a set of attributes is given:

* bind: what is the source of the mount point
* ro: is mount read-only ?

If the attribute bind is not given, if default to name of the mapping

Example:

    binds:
        - /data:
            bind: "/data/playground/${environment.SUDO_USER}/${name}"
        - /etc/nsswitch.conf:
            bind: /etc/nsswitch.conf
            ro: true
    

