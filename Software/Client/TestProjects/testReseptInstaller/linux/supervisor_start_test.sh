#!/bin/bash

# The script runs on the  KeyTalk Linux client build server supervisor
# The scripts manages worker docker images, specifically:
# 1. start images to build KeyTalk client providing the KeyTalk repo key
# 2. wait for the images to finish
# 3. collect client installer packages produced by the above
# 4. start KeyTalk client installer test images, feeding them with the installer packages received on the previous step
# 5. wait for the images to finish
# 6. collect the results and reports on them by email

set -e
set -u

# set to true if you already have a pre-built installation package built and you merely want to run installation test against it
FAKE_BUILD_TEST=false

# dict( build image name -> installation image name )
TEST_IMAGES=\
" debian-8-keytalk-build-test:debian-8-keytalk-install-test"\
" debian-9-keytalk-build-test:debian-9-keytalk-install-test"\
" ubuntu-16.04-keytalk-build-test:ubuntu-16.04-keytalk-install-test"\
" ubuntu-18.04-keytalk-build-test:ubuntu-18.04-keytalk-install-test"

# Repository root, the supervisor shares it with the workers.
# The primary reason to share the repository is to save time for the workers cloning it.
# E.g. even a shallow git clone (without history) takes almost 5 minutes which all adds up to quite a number with the amount of workers we have.
SHARED_REPO_DIR="$(pwd)/../../../../../"

#
# Directories the supervisor makes available to the workers (as docker volumes) in order to collect test results produced by them
# NOTICE: these directories must reside outside $SHARED_REPO_DIR because the workers will likely choose to clean it before use
# thus removing unversioned files together with the test results
#

# Here the worker images write logs
SHARED_TEST_LOG_DIR=/var/log/keytalk
# Here the worker build images store the installers they create later to be used by worker installation images
SHARED_BUILT_INSTALLATION_PACKAGES_DIR=/var/lib/keytalk/installers

function fmt_time()
{
    local total_seconds="$1"
    ((hours=${total_seconds}/3600))
    ((minutes=(${total_seconds}%3600)/60))
    ((seconds=${total_seconds}%60))
    printf "%02d:%02d:%02d\n" $hours $minutes $seconds
}

function cleanup()
{
    # Cleanup to reclaim some disk space

    local stopped_containers=$(docker ps -a -q -f status=exited)
    if [ "${stopped_containers}" ]; then
        echo "  recycling stopped container(s) ${stopped_containers}"
        docker rm ${stopped_containers}
    fi

    local untagged_images=$(docker images | grep "^<none>" | awk '{print $3}')
    if [ "${untagged_images}" ]; then
        echo "  removing untagged image(s) ${untagged_images}"
        docker rmi ${untagged_images}
    fi
}

function elapsed_time()
{
    local start_time="$1"
    local elapsed_seconds=$(expr `date +%s` - $start_time)
    fmt_time ${elapsed_seconds}
}

function test_build()
{
    local image_name="$1"

    if ${FAKE_BUILD_TEST}; then
        echo "Faking successful build test on ${image_name}"
        return 0
    fi

    local start_time=`date +%s`
    local worker_testdir='/test'
    local container_name="${image_name}-container"
    echo "Start build test on ${image_name} (container ${container_name})"

    # Adding either 'privileged=true' or '--cap-add SYS_PTRACE' is necessary to avoid false positives starting tomcat (see https://github.com/moby/moby/issues/6800)
    if docker run \
      --privileged=true \
       --volume ${SHARED_REPO_DIR}:${worker_testdir}/src:rw \
       --volume ${SHARED_TEST_LOG_DIR}/${image_name}/:${worker_testdir}/log:rw \
       --volume ${SHARED_BUILT_INSTALLATION_PACKAGES_DIR}/:${worker_testdir}/result:rw \
       --workdir=${worker_testdir} \
       --hostname ktclient-dev \
       --add-host=demo.keytalkdemo.com:192.168.33.111 \
       --add-host=keytalkadmin.keytalkdemo.com:192.168.33.111 \
       --name ${container_name} \
        --net=host \
       ${image_name}
       then
           echo "TEST ${image_name} SUCCEEDED ($(elapsed_time "${start_time}"))"
           return 0
       else
           echo "TEST ${image_name} FAILED ($(elapsed_time "${start_time}"))"
           return 1
       fi

    # echo "To track progress 'docker logs ${container_name} | tail'"
    # echo "To login into 'docker exec -it ${container_name} /bin/bash'"
}

function test_installation()
{
    local image_name="$1"
    local start_time=`date +%s`
    local worker_testdir='/test'
    local container_name="${image_name}-container"
    echo "Start installation test on ${image_name} (container ${container_name})"

    # Adding either 'privileged=true' or '--cap-add SYS_PTRACE' is necessary to avoid false positives starting tomcat (see https://github.com/moby/moby/issues/6800)
    if docker run \
      --privileged=true \
       --volume ${SHARED_REPO_DIR}:${worker_testdir}/src:rw \
       --volume ${SHARED_TEST_LOG_DIR}/${image_name}/:${worker_testdir}/log:rw \
       --volume ${SHARED_BUILT_INSTALLATION_PACKAGES_DIR}/:${worker_testdir}/installer:rw \
       --workdir=${worker_testdir} \
       --add-host=demo.keytalkdemo.com:192.168.33.111 \
       --add-host=keytalkadmin.keytalkdemo.com:192.168.33.111 \
       --name ${container_name} \
        --net=host \
       ${image_name}
    then
        echo "TEST ${image_name} SUCCEEDED ($(elapsed_time "${start_time}"))"
        return 0
    else
        echo "TEST ${image_name} FAILED ($(elapsed_time "${start_time}"))"
        return 1
    fi

    # echo "To track progress 'docker logs ${container_name} | tail'"
    # echo "To login into 'docker exec -it ${container_name} /bin/bash'"
}

function start_tests()
{
    local start_time=`date +%s`
    local succeeded_build_tests=0
    local failed_build_tests=0
    local succeeded_installation_tests=0
    local failed_installation_tests=0

    rm -rf ${SHARED_TEST_LOG_DIR}
    mkdir -p ${SHARED_TEST_LOG_DIR}
    if ! ${FAKE_BUILD_TEST}; then
        rm -rf ${SHARED_BUILT_INSTALLATION_PACKAGES_DIR}
        mkdir -p ${SHARED_BUILT_INSTALLATION_PACKAGES_DIR}
    fi

    cleanup

    for imgs in ${TEST_IMAGES}
    do
        local image_name=$(echo ${imgs} | cut -d ':' -f 1)
        if test_build ${image_name}
        then
            succeeded_build_tests=$((succeeded_build_tests+1))

            image_name=$(echo ${imgs} | cut -d ':' -f 2)
            if test_installation ${image_name} ; then
                succeeded_installation_tests=$((succeeded_installation_tests+1))
            else
                failed_installation_tests=$((failed_installation_tests+1))
            fi
        else
            failed_build_tests=$((failed_build_tests+1))
        fi
    done

    cleanup

    local total_test_time=$(elapsed_time "${start_time}")
    local total_tests_run=$((succeeded_build_tests+failed_build_tests))

    echo "TOTAL: tested ${total_tests_run} images (${total_test_time})"
    echo "${succeeded_build_tests} build tests and ${succeeded_installation_tests} installation tests succeeded, ${failed_build_tests} build tests and ${failed_installation_tests} installation tests failed, ${failed_build_tests} installation tests skipped"
    echo "Logs can be found under ${SHARED_TEST_LOG_DIR}"

    if (( failed_build_tests == 0 && failed_installation_tests == 0 )); then
        exit 0
    else
        exit 1
    fi
}

#
# Here we go
#
start_tests
