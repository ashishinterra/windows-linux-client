#!/bin/bash

#
# Build worker docker images used to test KeyTalk on
#

set -e
set -u

# Dockerfile disallows files outside the build context, so copy them here first
cp ../../../../Import/docker-systemctl-replacement/files/docker/systemctl.py ./

# Build images to build KeyTalk client
docker build --no-cache --file=worker_dockerfiles/debian-8_keytalk_build_test --tag=debian-8-keytalk-build-test .
docker build --no-cache --file=worker_dockerfiles/debian-9_keytalk_build_test --tag=debian-9-keytalk-build-test .
docker build --no-cache --file=worker_dockerfiles/ubuntu-16.04_keytalk_build_test --tag=ubuntu-16.04-keytalk-build-test .
docker build --no-cache --file=worker_dockerfiles/ubuntu-18.04_keytalk_build_test --tag=ubuntu-18.04-keytalk-build-test .
docker build --no-cache --file=worker_dockerfiles/centos-6_keytalk_build_test --tag=centos-6-keytalk-build-test .
docker build --no-cache --file=worker_dockerfiles/centos-7_keytalk_build_test --tag=centos-7-keytalk-build-test .

# Build images to test KeyTalk client built with the images above
docker build --no-cache --file=worker_dockerfiles/debian-8_keytalk_install_test --tag=debian-8-keytalk-install-test .
docker build --no-cache --file=worker_dockerfiles/debian-9_keytalk_install_test --tag=debian-9-keytalk-install-test .
docker build --no-cache --file=worker_dockerfiles/ubuntu-16.04_keytalk_install_test --tag=ubuntu-16.04-keytalk-install-test .
docker build --no-cache --file=worker_dockerfiles/ubuntu-18.04_keytalk_install_test --tag=ubuntu-18.04-keytalk-install-test .
docker build --no-cache --file=worker_dockerfiles/centos-6_keytalk_install_test --tag=centos-6-keytalk-install-test .
docker build --no-cache --file=worker_dockerfiles/centos-7_keytalk_install_test --tag=centos-7-keytalk-install-test .
