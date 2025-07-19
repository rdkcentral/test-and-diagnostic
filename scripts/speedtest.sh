#!/bin/sh
#######################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
#  Copyright 2018 RDK Management
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

#This script is used to enable / start the speedtest tool
LOG_FILE=/rdklogs/logs/speedtest-init.log

log_message() {
    echo "$(date +"[%Y-%m-%d %H:%M:%S]") $1" >> $LOG_FILE
}

execute_speedtest() {
    log_message "$1"
    $2
}

log_message "Enabling / Starting speedtest..."
. /etc/device.properties

# If Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.ClientType exists, then:
# Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.ClientType = 1 implies the C client should run.
ST_CLIENT_TYPE=`dmcli eRT retv Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.ClientType`

if [ "x$ST_CLIENT_TYPE" = 'x1' ]; then
    if [ -f /usr/bin/speedtest-client ]; then
        execute_speedtest "Executing speedtest-client-c for $BOX_TYPE" "nice -n 19 /usr/bin/speedtest-client"
    else
        log_message "Unsupported device model"
    fi
else
    log_message "Unsupported client"
fi
