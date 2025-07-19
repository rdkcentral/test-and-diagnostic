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
source /etc/device.properties
source /etc/utopia/service.d/log_capture_path.sh
source /lib/rdk/t2Shared_api.sh

CRONTAB_DIR="/var/spool/cron/crontabs/"
CRON_FILE_BK="/tmp/crontab$$.txt"
SCRIPT_NAME="syscfg_cleanup"

if [ -f "/nvram/syscfg_clean" ]; then
    echo "Syscfg cleanup already done" 
    echo "Remove /nvram/syscfg_clean file to cleanup again"
    exit 1
fi

UPTIME=$(cut -d. -f1 /proc/uptime)
if [ "$UPTIME" -lt 1800 ]; then
    echo "Uptime is less than 30 mins, exiting the syscfg_cleanup"
    exit 0
fi

if [ "$BOX_TYPE" = "XB3" ]; then
SYSCFG_DB_FILE="/nvram/syscfg.db"
else
SYSCFG_DB_FILE="/opt/secure/data/syscfg.db"
fi

#Removing erouter0 "_inst_num" dynamic enteries from database
erouter_inst_num=`grep tr_erouter0 $SYSCFG_DB_FILE | grep "_inst_num" | cut -d "=" -f1`
for entry in $erouter_inst_num
do
        echo "$entry"
        syscfg unset $entry
done

#Removing erouter0 "_alias" dynamic enteries from database
erouter_alias=`grep tr_erouter0 $SYSCFG_DB_FILE | grep "_alias" | cut -d "=" -f1`

for entry in $erouter_alias
do
        echo "$entry"
        syscfg unset $entry
done

#Removing brlan0 "_inst_num" dynamic enteries from database
brlan_inst_num=`grep tr_brlan0 $SYSCFG_DB_FILE | grep "_inst_num" | cut -d "=" -f1`

for entry in $brlan_inst_num
do
        echo "$entry"
        syscfg unset $entry
done

#Removing brlan0 "_alias" dynamic enteries from database
brlan_alias=`grep tr_brlan0 $SYSCFG_DB_FILE | grep "_alias" | cut -d "=" -f1`

for entry in $brlan_alias
do
        echo "$entry"
        syscfg unset $entry
done

syscfg commit

check_cleanup_erouter_inst_num=`grep tr_erouter0 $SYSCFG_DB_FILE | grep "_inst_num" `
check_cleanup_erouter_alias=`grep tr_erouter0 $SYSCFG_DB_FILE | grep "_alias" `
check_cleanup_brlan_inst_num=`grep tr_brlan0 $SYSCFG_DB_FILE | grep "_inst_num" `
check_cleanup_brlan_alias=`grep tr_brlan0 $SYSCFG_DB_FILE | grep "_alias" `

#Check that cleanup is successful or not
if [ "$check_cleanup_erouter_inst_num" = "" ] && [ "$check_cleanup_erouter_alias" = "" ] && [ "$check_cleanup_brlan_inst_num" = "" ] && [ "$check_cleanup_brlan_alias" = "" ] ;then
	echo "Database clean up success"
	t2CountNotify "SYS_INFO_DBCleanup"
        touch /nvram/syscfg_clean
else
	echo "Database clean up failed"
fi

#Clean the job from crontab
crontab -l -c $CRONTAB_DIR > $CRON_FILE_BK
sed -i "/$SCRIPT_NAME/d" $CRON_FILE_BK
crontab $CRON_FILE_BK -c $CRONTAB_DIR
rm -rf $CRON_FILE_BK

echo "Running apply system defaults"
apply_system_defaults

if [ "$BOX_TYPE" = "XB3" ];then
	echo "XB3 device, restaring PandM"
	cd /usr/ccsp/pam/
	kill -9 $(busybox pidof CcspPandMSsp)
	/usr/bin/CcspPandMSsp -subsys eRT.

	isPeriodicFWCheckEnable=`syscfg get PeriodicFWCheck_Enable`
	PID_XCONF=$(busybox pidof xb3_firmwareDwnld.sh)
	if [ "$isPeriodicFWCheckEnable" == "false" ] && [ "$PID_XCONF" == "" ] ;then
	        echo "XCONF SCRIPT : Calling XCONF Client"
	        /etc/xb3_firmwareDwnld.sh &
	fi
elif [ "$BOX_TYPE" = "XB6" ];then
		echo "XB6 device, restaring PandM"

	systemctl restart CcspPandMSsp.service

elif [ "$BOX_TYPE" = "VNTXER5" ];then
	echo "XER5 device, restarting PandM"
	systemctl restart CcspPandMSsp.service
fi
