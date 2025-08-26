#!/bin/sh
#######################################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
#  Copyright 2025 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#######################################################################################
RFC_SYNC_DONE="/tmp/.rfcSyncDone"
LOCKFILE="/tmp/rfcSelfhealLock"
MAX_RETRIES=3
RETRY_COUNT=0

# Define 'echo_t'
if [ -f /etc/log_timestamp.sh ]; then
    source /etc/log_timestamp.sh
fi
if ! type echo_t >/dev/null 2>&1; then
    echo_t() { echo "$@"; }
fi

# Always remove lockfile on exit
cleanup() {
    rm -f "$LOCKFILE"
}
trap cleanup EXIT

# Create lock file to prevent multiple instances of this script
touch "$LOCKFILE"

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if [ -f "$RFC_SYNC_DONE" ]; then
        echo_t "[RFC_SELFHEAL] : File $RFC_SYNC_DONE exists. Exiting."
        exit 0
    else
        if [ -f /lib/rdk/rfc.service ]; then
            echo_t "[RFC_SELFHEAL] : File $RFC_SYNC_DONE not found. Restarting RFC service"
            systemctl restart rfc.service
            # sleep for 3 minutes
            sleep 180
        else
            echo_t "[RFC_SELFHEAL] : rfc.service not found. Unable to Restart it."
            exit 0
        fi
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
done
echo_t "[RFC_SELFHEAL] : Max retries ($MAX_RETRIES) reached. Exiting."