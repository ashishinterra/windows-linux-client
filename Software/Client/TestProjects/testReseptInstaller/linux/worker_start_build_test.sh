#!/bin/bash

# The script runs on a worker build server
# The script builds KeyTalk client and executes low-level unit tests
# The script produces KeyTalk client installer package and logs to be used by the host

set -e
set -u

INITIAL_PWD=`pwd`
REPO_DIR=${INITIAL_PWD}/src
# Built installer packages will be stored in this directory
RESULT_DIR=${INITIAL_PWD}/result
LOG_DIR=${INITIAL_PWD}/log

OS_SPEC=$(lsb_release --id --short | tr "[:upper:]" "[:lower:]")$(lsb_release --release --short | egrep -o [0-9]+ | sed -n '1p')-x64

function cleanup()
{
    pushd ${REPO_DIR} > /dev/null
    echo "Cleaning repository under ${REPO_DIR}"
    git clean -x -f ./
    popd > /dev/null
}

function setup_test()
{
    echo "Setting up tests"
    pushd ${REPO_DIR}/Software/ContinuousIntegration/cc.py/rlinuxclient.worker/ > /dev/null
    cp ccpy.conf ccpyd.conf /etc/
    popd > /dev/null
}

function run_test()
{
    echo "Starting tests"

    # don't immediately exit on failed test but collect the test output first
    /ccpy/ccpy.sh --fg || true

    echo "Collecting test results"

    if [ -f /etc/ccpy.state ]; then

        local ccpy_state=$(cat /etc/ccpy.state |  egrep -o 'state="[A-Z]+"' |  sed -e 's/^state="//' -e 's/"$//')
        echo "Test finished with status ${ccpy_state}"

        # NOTICE: do not use tilde '~' for home dir but use $HOME since bash does not expand the former
        local test_log_files=\
" $HOME/.keytalk/ktclient.log"\
" $HOME/tmp/ktapachecertrenewal.log"\
" $HOME/tmp/ktconfig.log"\
" $HOME/tmp/ktconfigtool.log"\
" $HOME/tmp/ktconfupdater.log"\
" $HOME/tmp/ktprgenerator.log"\
" $HOME/tmp/ktcaupdater.log"\
" /tmp/ktcaupdater.log"\
" ${REPO_DIR}/Software/Client/TestProjects/Export/testReseptConsoleClient.log"\
" ${REPO_DIR}/Software/Client/TestProjects/Export/testlibrclientappcommon.log"\
" ${REPO_DIR}/Software/Client/TestProjects/Export/testlibrclientcore.log"\
" ${REPO_DIR}/Software/Client/TestProjects/Export/testlibtaclientcommon.log"\
" /var/log/ccpyd.log"

        for log_file in ${test_log_files} ; do
            if [ -f "${log_file}" ] ; then
                echo "Collecting log file ${log_file}"
                cp "${log_file}" "${LOG_DIR}/"
            fi
        done

        if [[ "${ccpy_state}" == "OK" ]]; then
            local client_version=$(cut -d '=' -f 2 ${REPO_DIR}/Software/Client/version)
            local app_package=KeyTalkClient-${client_version}-${OS_SPEC}.tgz
            local python_demo_package=KeyTalkClient-${client_version}.python.demo.tgz
            local apache_remote_deployment_package=KeyTalkClient-${client_version}.linux.apache-remote-deployment.tgz
            local tomcat_remote_deployment_package=KeyTalkClient-${client_version}.linux.tomcat-remote-deployment.tgz

            for package in ${app_package} ${python_demo_package} ${apache_remote_deployment_package} ${tomcat_remote_deployment_package} ; do
                echo "Collecting installer package ${package}"
                local installer_package_path="${REPO_DIR}/Software/Client/Projects/Export/${package}"
                if [ -f "${installer_package_path}" ]; then
                    cp "${installer_package_path}" "${RESULT_DIR}/"
                else
                    echo "ERROR: No installer package found under ${installer_package_path}" >&2
                    return 1
                fi
            done

            return 0
        else
            echo "ERROR: Test failed" >&2
            return 1
        fi
    else
        echo "ERROR: Test status not found!" >&2
        return 2
    fi
}

#
# Here we go!
#

echo "Starting build tests..."

# NOTICE
# to debug this docker container by pausing it:
# 1. uncomment the line below the comment
# 2. start the container (docker run) with '-it' argument (e.g. from supervisor_start_test.sh)
# 3. in a separate shell: docker exec -it ${container_name} /bin/bash
# read -p 'The test script is paused, use "docker exec -it ${container_name} /bin/bash" to debug it'

cleanup
setup_test
run_test
