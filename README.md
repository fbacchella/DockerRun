This tools is used to launch some docker container.

It parses some yaml files and construct container as described.

It's made to be used through sudo, as it can can a path of allowed directory for yaml description files.

To use it, one should add in /etc/sudoers.d/docker:

    Cmnd_Alias DOCKER_COMMANDS = /user/bin/dockerrun -p /etc/dockercommand *
    User_Alias DOCKER_USERS = %docker

    DOCKER_USERS ALL = (root) DOCKER_COMMANDS
