#!/bin/sh
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
if [ -f /lib/rdk/utils.sh ];then
     . /lib/rdk/utils.sh
fi
UPTIME=$(cut -d. -f1 /proc/uptime)

if [ "$UPTIME" -lt 900 ]
then
    exit 0
fi

removeCron "/usr/ccsp/tad/start_gw_heath.sh"

sh /usr/ccsp/tad/check_gw_health.sh bootup-check


