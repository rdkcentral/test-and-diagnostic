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

source /etc/utopia/service.d/log_capture_path.sh
source /etc/device.properties

MAPT_CONFIG=`sysevent get mapt_config_flag`
dt=`date "+%m-%d-%y-%I-%M%p"`
ps -l | grep '^Z' > /tmp/zombies.txt
count=`wc -l < /tmp/zombies.txt`
echo "************ ZOMBIE_COUNT $count at $dt ************"

if [ $count -ne 0 ];then
    echo "*************** List of Zombies ***************"
    cat /tmp/zombies.txt
    echo "***********************************************"
fi
rm /tmp/zombies.txt

if [ "xstarted" == "x`sysevent get wan-status`" ];then
    if [ "$MAPT_CONFIG" != "set" ]; then
        if [  "x`ip -4 route show table erouter | grep "default via" | grep erouter0 | cut -f3 -d' ' `" == "x" ]; then
            echo "ipv4 default gateway is missing" >> /rdklogs/logs/Consolelog.txt.0
        fi
    elif [  "x`ip -4 route show table erouter | grep "default via" | grep map0 | cut -f3 -d' ' `" == "x" ]; then
        echo "ipv4 map0 default gateway is missing" >> /rdklogs/logs/Consolelog.txt.0
    fi


    if [ "x`ip -6 route show | grep "default via" | grep erouter0 | grep -i "dead:beef"`"  != "x" ];then
        echo "Device is connected to virtual cmts, default ipv6 erouter entry not needed in erouter table"  >> /rdklogs/logs/Consolelog.txt.0
    elif [  "x`ip -6 route show table erouter | grep "default via" | grep erouter0 | cut -f3 -d' ' `" == "x" ]; then
        echo "ipv6 default gateway is missing" >> /rdklogs/logs/Consolelog.txt.0
    fi
fi

# Mesh diagnostics logs for XLE and XB7
WFO_ARG=
# Skip first iteration since device would be still initializing.
UPTIME=$(cut -d. -f1 /proc/uptime)

# Device reporting cpu issue, hence skipping for now : RDKB-49082 
skip_blackbox=true
if [ "$MODEL_NUM" == "WNXL11BWL" ]; then
    skip_blackbox=false
fi

if $skip_blackbox; then
    echo  " Skipped periodic Xmesh checks: Unsupported Mode" >> /rdklogs/logs/MeshBlackbox.log
else 
    if [ "$UPTIME" -gt 600 ]; then
        /usr/ccsp/tad/log_xmesh_diagnostics.sh
    fi
fi
