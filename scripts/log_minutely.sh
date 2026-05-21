#! /bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2019 RDK Management
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
##########################################################################

POLL_INTERVAL=$(syscfg get CPUMEMLog_PollInterval)

if [ -z "$POLL_INTERVAL" ]; then
    POLL_INTERVAL=60
fi

# Validate range: 1 min to 1440 min
if [ "$POLL_INTERVAL" -lt 1 ] || [ "$POLL_INTERVAL" -gt 1440 ]; then
    POLL_INTERVAL=60
fi

CURRENT_HOUR=$(date +%H)
CURRENT_MIN=$(date +%M)

CURRENT_HOUR=$((10#$CURRENT_HOUR))
CURRENT_MIN=$((10#$CURRENT_MIN))

TOTAL_MINUTES=$((CURRENT_HOUR * 60 + CURRENT_MIN))

REMAINDER=$((TOTAL_MINUTES % POLL_INTERVAL))

if [ "$REMAINDER" -eq 0 ]; then
    echo "$(date) : Triggering log_mem_cpu_info.sh with PollInterval=$POLL_INTERVAL minutes" >> /rdklogs/logs/minutely_check.log

    sh /usr/ccsp/tad/log_mem_cpu_info.sh
fi
