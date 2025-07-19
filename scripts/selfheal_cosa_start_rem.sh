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

if [ "$UPTIME" -lt 600 ]
then
    exit 0
fi

source /etc/utopia/service.d/log_capture_path.sh

if [ -f /tmp/cosa_start_rem_triggered ]; then
	echo "Already cosa_start_rem script triggered so no need to trigger again from selfheal"
        removeCron "/usr/ccsp/tad/selfheal_cosa_start_rem.sh"
else
	echo "cosa_start_rem script not triggered even after 10 minutes from boot-up so start from selfheal"
	# some platforms like AXB3 need to run the following script,
	# but some platforms like TCXB6 use systemd and does not need it,
	# only start the script if it exists
	if [ -f /usr/ccsp/cosa_start_rem.sh ]; then
		sh /usr/ccsp/cosa_start_rem.sh &	
	fi
        removeCron "/usr/ccsp/tad/selfheal_cosa_start_rem.sh"
fi
