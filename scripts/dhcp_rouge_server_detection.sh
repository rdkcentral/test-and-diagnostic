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

bridge_mode=`sysevent get bridge_mode`
if [ "0" = "$bridge_mode" ]; then
UPTIME=$(cut -d. -f1 /proc/uptime)

if [ "$UPTIME" -lt 3600 ]
then
    exit 0
fi

source /etc/utopia/service.d/log_capture_path.sh

#Gateway sends out DHCP discover message on the MoCA interface every 60 minutes.
echo_t "Gateway started to send DHCP discover message on the MoCA interface"
/usr/bin/dhcpsrv_detect
echo_t "Gateway sends out DHCP discover message on the MoCA interface"
fi

