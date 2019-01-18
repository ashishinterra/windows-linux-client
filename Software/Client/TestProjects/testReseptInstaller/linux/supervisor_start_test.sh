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
" ubuntu-16.04-keytalk-build-test:ubuntu-16.04-keytalk-install-test"\
" ubuntu-18.04-keytalk-build-test:ubuntu-18.04-keytalk-install-test"\
" debian-8-keytalk-build-test:debian-8-keytalk-install-test"\
" debian-9-keytalk-build-test:debian-9-keytalk-install-test"\
" centos-6-keytalk-build-test:centos-6-keytalk-install-test"\
" centos-7-keytalk-build-test:centos-7-keytalk-install-test"

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
# A location to save the latest successfully created installer. Comes to handy when a failed build proves to be a false-negative yet it already removed "good" installers
LAST_INSTALLATION_PACKAGES_DIR=/var/lib/keytalk/last-good-installers

KEYTALK_SERVER_IP='192.168.33.111'

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

    if [[ "${image_name}" =~ ^centos\-7 ]]; then
      # CentOS 7 docker images do not support systemd and need special treatment

      # Basically we start these images detached with 'docker run' and then fire up "inject" build script from a separate 'docker exec"

      # Adding either 'privileged=true' or '--cap-add SYS_PTRACE' is necessary to avoid false positives starting tomcat (see https://github.com/moby/moby/issues/6800)
      docker run \
        --detach \
        --privileged=true \
         --volume ${SHARED_REPO_DIR}:${worker_testdir}/src:rw \
         --volume ${SHARED_TEST_LOG_DIR}/${image_name}/:${worker_testdir}/log:rw \
         --volume ${SHARED_BUILT_INSTALLATION_PACKAGES_DIR}/:${worker_testdir}/result:rw \
         --workdir=${worker_testdir} \
         --add-host=demo.keytalkdemo.com:${KEYTALK_SERVER_IP} \
         --add-host=keytalkadmin.keytalkdemo.com:${KEYTALK_SERVER_IP} \
         --name ${container_name} \
         --net=host \
         --hostname ktclient-dev \
         ${image_name}

         # uncomment this for debugging only
         # docker exec -it ${container_name} bash

         # Start the build
         if docker exec -i ${container_name} ./src/Software/Client/TestProjects/testReseptInstaller/linux/worker_start_build_test.sh
         then
             echo "TEST ${image_name} SUCCEEDED ($(elapsed_time "${start_time}"))"
             docker rm -f ${container_name} || true
             return 0
         else
             echo "TEST ${image_name} FAILED ($(elapsed_time "${start_time}"))"
             docker rm -f ${container_name} || true
             return 1
         fi

    else

      # Adding either 'privileged=true' or '--cap-add SYS_PTRACE' is necessary to avoid false positives starting tomcat (see https://github.com/moby/moby/issues/6800)
      if docker run \
        --privileged=true \
         --volume ${SHARED_REPO_DIR}:${worker_testdir}/src:rw \
         --volume ${SHARED_TEST_LOG_DIR}/${image_name}/:${worker_testdir}/log:rw \
         --volume ${SHARED_BUILT_INSTALLATION_PACKAGES_DIR}/:${worker_testdir}/result:rw \
         --workdir=${worker_testdir} \
         --add-host=demo.keytalkdemo.com:${KEYTALK_SERVER_IP} \
         --add-host=keytalkadmin.keytalkdemo.com:${KEYTALK_SERVER_IP} \
         --name ${container_name} \
         --net=host \
         --hostname ktclient-dev \
         ${image_name}
         then
             echo "TEST ${image_name} SUCCEEDED ($(elapsed_time "${start_time}"))"
             return 0
         else
             echo "TEST ${image_name} FAILED ($(elapsed_time "${start_time}"))"
             return 1
         fi

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

    if [[ "${image_name}" =~ ^centos\-7 ]]; then
      # CentOS 7 docker images do not support systemd and need special treatment

      # Adding either 'privileged=true' or '--cap-add SYS_PTRACE' is necessary to avoid false positives starting tomcat (see https://github.com/moby/moby/issues/6800)
      docker run \
        --detach \
        --privileged=true \
         --volume ${SHARED_REPO_DIR}:${worker_testdir}/src:rw \
         --volume ${SHARED_TEST_LOG_DIR}/${image_name}/:${worker_testdir}/log:rw \
         --volume ${SHARED_BUILT_INSTALLATION_PACKAGES_DIR}/:${worker_testdir}/installer:rw \
         --workdir=${worker_testdir} \
         --add-host=demo.keytalkdemo.com:${KEYTALK_SERVER_IP} \
         --add-host=keytalkadmin.keytalkdemo.com:${KEYTALK_SERVER_IP} \
         --name ${container_name} \
          --net=host \
         ${image_name}

      # uncomment this for debugging only
      # docker exec -it ${container_name} bash

      # Start the build
      if docker exec -i ${container_name} ./src/Software/Client/TestProjects/testReseptInstaller/linux/worker_start_installation_test.sh
      then
          echo "TEST ${image_name} SUCCEEDED ($(elapsed_time "${start_time}"))"
          docker rm -f ${container_name} || true
          return 0
      else
          echo "TEST ${image_name} FAILED ($(elapsed_time "${start_time}"))"
          docker rm -f ${container_name} || true
          return 1
      fi

    else

        # Adding either 'privileged=true' or '--cap-add SYS_PTRACE' is necessary to avoid false positives starting tomcat (see https://github.com/moby/moby/issues/6800)
        if docker run \
          --privileged=true \
           --volume ${SHARED_REPO_DIR}:${worker_testdir}/src:rw \
           --volume ${SHARED_TEST_LOG_DIR}/${image_name}/:${worker_testdir}/log:rw \
           --volume ${SHARED_BUILT_INSTALLATION_PACKAGES_DIR}/:${worker_testdir}/installer:rw \
           --workdir=${worker_testdir} \
           --add-host=demo.keytalkdemo.com:${KEYTALK_SERVER_IP} \
           --add-host=keytalkadmin.keytalkdemo.com:${KEYTALK_SERVER_IP} \
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

    fi

    # echo "To track progress 'docker logs ${container_name} | tail'"
    # echo "To login into 'docker exec -it ${container_name} /bin/bash'"
}

function create_fat_installer()
{
    local client_version=$(cut -d '=' -f 2 ${SHARED_REPO_DIR}/Software/Client/version)
    pushd ${SHARED_BUILT_INSTALLATION_PACKAGES_DIR} > /dev/null

    # check
    for os in centos6 centos7 debian8 debian9 ubuntu16 ubuntu18 ; do
        if [ ! -f KeyTalkClient-${client_version}-${os}-x64.tgz ]; then
            echo "Cannot create fat installer. KeyTalkClient-${client_version}-${os}-x64.tgz is missing"
            popd > /dev/null
            return 1
        fi
    done

    # CentOS is binary compatible with RHEL, let's make use of that
    ln -s KeyTalkClient-${client_version}-centos6-x64.tgz KeyTalkClient-${client_version}-rhel6-x64.tgz
    ln -s KeyTalkClient-${client_version}-centos7-x64.tgz KeyTalkClient-${client_version}-rhel7-x64.tgz

    # Create master installation script
    printf '
#!/bin/bash

OS_SPEC=$(lsb_release --id --short | tr "[:upper:]" "[:lower:]")$(lsb_release --release --short | egrep -o [0-9]+ | sed -n '1p')-x64
KTCLIENT_VERSION="%s"
INSTALLER_FILENAME=KeyTalkClient-${KTCLIENT_VERSION}-${OS_SPEC}.tgz
if [ ! -f ${INSTALLER_FILENAME} ]; then
    echo "${INSTALLER_FILENAME} not found!" >&2
    exit 1
fi

rm -rf ./keytalkclient-${KTCLIENT_VERSION}
tar -xzf ${INSTALLER_FILENAME}

cd keytalkclient-${KTCLIENT_VERSION}
./install.sh
' ${client_version} > install.sh
    chmod +x install.sh

    tar -cf KeyTalkClient-${client_version}-linux.tar *.tgz install.sh

    # save the installer to a non-volatile location to it doesn't disappear after the next failed build
    cp -f KeyTalkClient-${client_version}-linux.tar ${LAST_INSTALLATION_PACKAGES_DIR}/

    popd > /dev/null
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
    mkdir -p ${LAST_INSTALLATION_PACKAGES_DIR}
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

    # produce a fat installer regardless the build success
    # because we don't want to suffer from possible fault negatives
    local fat_installer_created
    if create_fat_installer ; then
        fat_installer_created=1
        echo "Fat installer successfully created"
    else
        fat_installer_created=0
        echo "Failed to create fat installer"
    fi

    if (( failed_build_tests == 0 && failed_installation_tests == 0 && fat_installer_created == 1 )); then
        exit 0
    else
        exit 1
    fi
}

#
# Here we go
#
start_tests
