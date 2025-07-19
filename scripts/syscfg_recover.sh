#! /bin/sh
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

source /etc/device.properties

TAD_PATH="/usr/ccsp/tad"
UTOPIA_PATH="/etc/utopia/service.d"
SYSCFG_SHM_FILE="/tmp/syscfg.shmid"
SYSCFG_TMP_LOCATION=/tmp
SYSCFG_FILE=$SYSCFG_TMP_LOCATION/syscfg.db

source $UTOPIA_PATH/log_env_var.sh
source /etc/log_timestamp.sh
source /lib/rdk/t2Shared_api.sh

exec 3>&1 4>&2 >>$SELFHEALFILE 2>&1
# skipping the run if uptime is lessthan 15 mins to avoid the race condtion 
UPTIME=$(cut -d. -f1 /proc/uptime)
if [ "$UPTIME" -lt 900 ]
then
    echo_t "RDKB_SELFHEAL : Uptime is lessthan 15 mins, so exiting the run at $UPTIME"
    exit 0
fi

#check whether syscfg is proper or not
syscfg get redirection_flag > /dev/null
if [ $? == 0 ]; then
	exit
fi

#check whether syscfg is proper or not once again
syscfg get selfheal_enable > /dev/null
if [ $? != 0 ]; then
	echo_t "RDKB_SELFHEAL : syscfg queries are failing"
	echo_t "RDKB_SELFHEAL : Memory Dump"
	echo_t "==========================="
	free -m
	df -h
	du -h $SYSCFG_MOUNT
	echo_t "==========================="

	echo_t "RDKB_SELFHEAL : Recreating syscfg DB again..."

	if [ -f $SYSCFG_SHM_FILE ]; then 
		rm -rf $SYSCFG_SHM_FILE		
	fi

	#Re-create syscfg create again
	syscfg_create -f $SYSCFG_FILE
	syscfg_oldDB=$?
	if [ $syscfg_oldDB -eq 0 ]; then
	   echo_t "RDKB_SELFHEAL : syscfg DB functional now"

		SELFHEAL_ENABLE=`syscfg get selfheal_enable`
		if [ "$SELFHEAL_ENABLE" == "true" ]; then
			SelfHealScript_PID=$(busybox pidof self_heal_connectivity_test.sh)
			if [ "$SelfHealScript_PID" == "" ]; then
				echo_t "Restarting selfheal connectivity script"
				$TAD_PATH/self_heal_connectivity_test.sh &
			fi

			SelfHealScript_PID=$(busybox pidof resource_monitor.sh)
			if [ "$SelfHealScript_PID" == "" ]; then
				echo_t "Restarting resource monitor script"
				t2CountNotify "SYS_SH_ResourceMonitor_restart"
				$TAD_PATH/resource_monitor.sh & 
			fi
		fi
	else
	   echo_t "RDKB_SELFHEAL : syscfg DB creation failed"		
	fi
fi
