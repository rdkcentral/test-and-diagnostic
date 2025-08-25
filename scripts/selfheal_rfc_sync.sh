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
TAD_PATH="/usr/ccsp/tad"
RFC_SYNC_DONE="/tmp/.rfcSyncDone"
LOCKFILE="/tmp/rfcselfhealLock"
MAX_RETRIES=3
RETRY_COUNT=0

#Create lock file to prevent multiple instances of this script
touch "$LOCKFILE"
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if [ -f "$RFC_SYNC_DONE" ]; then
        echo_t "File $FILE exists. Exiting script."
		rm -f "$LOCKFILE"
        exit 0
    else
        echo_t "File $FILE not found. Restarting RFC service ..."
        systemctl stop rfc.service
        systemctl start rfc.service
        sleep 180
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
done

rm -f "$LOCKFILE"