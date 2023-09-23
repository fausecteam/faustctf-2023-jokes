# CI Example for a service using docker-compose

The .gitlab-ci.yml in this repo builds and pushes all possible images (docker-compose.yml is parsed and used to call kaniko).

In the vulnbox build process, the compose file is used to pull all images and include them in the vm.
