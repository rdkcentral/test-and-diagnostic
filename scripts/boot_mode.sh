#!/bin/sh
#######################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:

#  Copyright 2018 RDK Management

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#######################################################################################

MODE_FILE="/tmp/boot_check_cron.mode"

# INTERNAL BOOT-CHECK: 
# If the .mode file doesn't exist, this is the FIRST run since reboot.
if [ ! -f "$MODE_FILE" ]; then
    CRON_ENABLED=$(syscfg get SelfHealCronEnable)
    if [ "$CRON_ENABLED" = "true" ]; then
        echo "CRON" > "$MODE_FILE"
    else
        echo "PROCESS" > "$MODE_FILE"
    fi
fi
SAVED_MODE=$(cat "$MODE_FILE")
