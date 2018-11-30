#!/bin/bash

# check python scripts

FAILCOUNT=0
MSG_TEMPLATE='{abspath}:{line:3d},{column}: {obj}: [{msg_id}] {msg}'
# disable Convention, Refactoring and Warning messages
MESSAGE_CONTROL_OPIONS="--disable=C,R,W"

function check_python_scripts()
{
    local filelist="$1"
    local message_control_options=${MESSAGE_CONTROL_OPIONS}
    if [ $# -eq 2 ]; then
        message_control_options+=",$2"
    fi
    pylint --reports=no --msg-template="${MSG_TEMPLATE}" ${message_control_options} ${filelist}
    if [ $? -ne 0 ]; then
        let "FAILCOUNT=FAILCOUNT+1"
    fi
}

function check_python3_scripts()
{
    local filelist="$1"
    local message_control_options=${MESSAGE_CONTROL_OPIONS}
    if [ $# -eq 2 ]; then
        message_control_options+=",$2"
    fi
    pylint3 --reports=no --msg-template="${MSG_TEMPLATE}" ${message_control_options} ${filelist}
    if [ $? -ne 0 ]; then
        let "FAILCOUNT=FAILCOUNT+1"
    fi
}

# We check directories one-by-one (as separate projects) otherwise pylint gets confused by the same module names (e.g. common.py) and will not import them again
if [ -f /resept_server_dev ]; then
    check_python3_scripts "Server/Projects/fw/*.py"
    check_python3_scripts "Server/Projects/settings/*.py"
    check_python3_scripts "Server/Projects/config/*.py"
    check_python3_scripts "Server/Projects/pykeytalk/*.py"
    check_python3_scripts "Server/TestProjects/testpykeytalk/*.py"
    # workaround pylint's false-positive "[E1101] Module 'ssl' has no 'PROTOCOL_TLSv1_2' member" erroneously reported in python-3.5.2
    check_python3_scripts "Client/Projects/ReseptPythonClient/*.py" "E1101"

    check_python_scripts "WebUI.Server/TestProjects/webuitests/*.py"
fi
if [ -f /resept_linux_client_dev ]; then
    # workaround pylint's false-positive "[E1101] Module 'ssl' has no 'PROTOCOL_TLSv1' member"
    check_python_scripts "Client/Projects/ReseptConsoleClient/*.py" "E1101"
    check_python_scripts "Client/TestProjects/testReseptInstaller/linux/apache/*.py" "E1101"
    check_python_scripts "Client/TestProjects/testReseptInstaller/linux/tomcat/*.py" "E1101"
fi

exit $FAILCOUNT
