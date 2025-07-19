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
if [ -f /lib/rdk/utils.sh ];then
     . /lib/rdk/utils.sh
fi
source /etc/utopia/service.d/log_capture_path.sh


DhcpServDetectEnableStatus=`syscfg get DhcpServDetectEnable`

#DhcpServDetectEnableStatus is true then place the file in /etc/cron/cron.hourly directory for hourly basis execution
#DhcpServDetectEnableStatus is false then remove the file dhcp_rouge_server_detection.sh from /etc/cron/cron.hourly directory

if [ "$DhcpServDetectEnableStatus" = "true" ]
then
	#Gateway sends out DHCP discover message on the MoCA interface every 60 minutes.
        addCron "48 * * * *  /usr/ccsp/tad/dhcp_rouge_server_detection.sh"
else
        removeCron "/usr/ccsp/tad/dhcp_rouge_server_detection.sh"
fi
