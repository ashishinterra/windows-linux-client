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

start_test
