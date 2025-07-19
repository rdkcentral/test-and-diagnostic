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

UPTIME=$(cut -d. -f1 /proc/uptime)

if [ "$UPTIME" -lt 86400 ]
then
    exit 0
fi

UTOPIA_PATH="/etc/utopia/service.d"

source $UTOPIA_PATH/log_env_var.sh

exec 3>&1 4>&2 >>$SELFHEALFILE 2>&1

getDateTime()
{
	dandtwithns_now=`date +'%Y-%m-%d:%H:%M:%S:%6N'`
	echo "$dandtwithns_now"
}

if [ -f /tmp/CPUUsageReachedMAXThreshold ]; then
	rm -rf /tmp/CPUUsageReachedMAXThreshold
	echo "[`getDateTime`] RDKB_SELFHEAL : Removed /tmp/CPUUsageReachedMAXThreshold file after 24hrs uptime"
fi

if [ -f /tmp/CPU5MinsUsageReachedMAXThreshold ]; then
	rm -rf /tmp/CPU5MinsUsageReachedMAXThreshold
	echo "[`getDateTime`] RDKB_SELFHEAL : Removed /tmp/CPU5MinsUsageReachedMAXThreshold file after 24hrs uptime"
fi
