This tools is used to launch some docker container.

It parses some yaml files and construct container as described.

It's made to be used through sudo, as it can take a path of allowed directory for yaml description files.

To use it, one should add in /etc/sudoers.d/docker:

    Cmnd_Alias DOCKER_COMMANDS = /usr/bin/dockerrun *
    User_Alias DOCKER_USERS = ...
    Defaults!DOCKER_COMMANDS env_file = /etc/dockerrun/environment

    DOCKER_USERS ALL = (root) DOCKER_COMMANDS

The content of /etc/dockerrun/environment should then be :
    DOCKERRUN_YAMLPATH=/etc/dockerrun

The yaml files can contains variable that will be resolved at container creation time. A variable is set
with a `-v name value` argument. The environment variable are available as `environment.*name*`

It also allow to attach to a container if the `user value` is equal to the user who launched the command, read
from `SUDO_UID`
