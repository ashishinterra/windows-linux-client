#!/bin/bash

set -o nounset

#
# The purpose of this script is to effectuate added or removed KeyTalk CAs in the System Certificate Trust store
# The script is ought to be run with sufficient privileges (normally root e.g. from the service or from the cron job) to be able to refresh the System Store.
# The demand for elevated rights is the main reason for having this script iso having the same function in end-user code of KeyTalk client.
#

function monitor_and_apply_keytalk_cas()
{
    echo "Start monitoring the System Certificate Trust Store for KeyTak CA changes"

    # Debian/Ubuntu
    if [ -f /etc/debian_version ]; then
        inotifywait -q -m -e modify,delete,move /usr/local/share/ca-certificates/ | while read dirname event filename
        do
            if [[ "$filename" =~ ^keytalk_.*\.crt$ ]]; then
                echo "$(date) [DEBUG] $event event for $dirname$filename"
                if [[ "$event" == "MODIFY" || "$event" == "MOVED_TO" ]]; then
                    echo "$(date) [DEBUG] Refreshing added/changed trust CAs in the system cert store"
                    update-ca-certificates 2> >(sed "s/^/$(date) [ERROR] /g">&2) 1> >(sed -n -e '1,5p' | sed "s/^/$(date) [DEBUG] /")
                else
                    echo "$(date) [DEBUG] Refreshing deleted trust CAs in the system cert store"
                    update-ca-certificates --fresh 2> >(sed "s/^/$(date) [ERROR] /g">&2) 1> >(sed -n -e '1,5p' | sed "s/^/$(date) [DEBUG] /")
                fi

                if [ $? -eq 0 ]; then
                    echo "$(date) [DEBUG] Updating system trust CAs finished successfully"
                else
                    echo "$(date) [ERROR] Updating system trust CAs failed"
                fi
            fi
        done

    # RHEL, CentOS
    elif  [ -f /etc/redhat-release ]; then
        inotifywait -q -m -e  modify,delete,move /etc/pki/ca-trust/source/anchors/ | while read dirname event filename
        do
            if [[ "$filename" =~ ^keytalk_.*\.crt$ ]]; then
                echo "$(date) [DEBUG] $event event for $dirname$filename"
                if [[ "$event" == "MODIFY" || "$event" == "MOVED_TO" ]]; then
                    echo "$(date) [DEBUG] Refreshing added/changed trust CAs in the system cert store"
                    update-ca-trust
                else
                    echo "$(date) [DEBUG] Refreshing deleted trust CAs in the system cert store"
                    update-ca-trust extract
                fi

                if [ $? -eq 0 ]; then
                    echo "$(date) [DEBUG] Updating system trust CAs finished successfully"
                else
                    echo "$(date) [ERROR] Updating system trust CAs failed"
                fi
            fi
        done

    else
        echo "$(date) [ERROR] Unsupported platform"
        exit 1
    fi
}

#
# Boilerplate for daemon processes
#
# save file descriptors so they can be restored to whatever they were before redirection or used themselves to output to whatever they were before the following redirect.
exec 3>&1 4>&2
# Restore file descriptors for particular signals. Not generally necessary since they should be restored when the sub-shell exits.
trap 'exec 2>&4 1>&3' EXIT HUP INT QUIT TERM

LOG_DIR="${HOME-}"
mkdir -p $LOG_DIR/tmp/
exec >> $LOG_DIR/tmp/ktcaupdater.log 2>&1

monitor_and_apply_keytalk_cas
