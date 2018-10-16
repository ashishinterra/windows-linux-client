#!/bin/bash

# The script runs on a worker build server
# Dependency: KeyTalk Linux client build server output

set -e
set -u
# set -x

INITIAL_PWD=`pwd`
REPO_DIR=${INITIAL_PWD}/src
INSTALLER_DIR=${INITIAL_PWD}/installer
LOG_DIR=${INITIAL_PWD}/log

function start_test()
{
    echo "Starting tests"

    pushd ${REPO_DIR}/Software/Client/TestProjects/testReseptInstaller/linux > /dev/null

    # make sure 'tee' does not mask failed tests
    set -o pipefail

    ./test_install_bin.sh ${INSTALLER_DIR} ${LOG_DIR} 2>&1 | tee -a ${LOG_DIR}/test.log

    popd > /dev/null
}

#
# Here we go!
#

echo "Starting installation tests..."

# NOTICE
# to debug this docker container by pausing it:
# 1. uncomment the line below the comment
# 2. start the container (docker run) with '-it' argument (e.g. from supervisor_start_test.sh)
# 3. in a separate shell: docker exec -it ${container_name} /bin/bash
# read -p "The test script is paused, let's debug it!"

start_test
