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
if [ -f /lib/rdk/utils.sh ];then
     . /lib/rdk/utils.sh
fi

if [ -f /etc/device.properties ]; then
    source /etc/device.properties
fi


UPTIME=$(cut -d. -f1 /proc/uptime)

if [ "$UPTIME" -lt 600 ]
then
    exit 0
fi

# RDKB-57087 , BCOMB-2484
if [ "$WAN0_IS_DUMMY" = "true" ]; then
    CM_INTERFACE="privbr"
else
    CM_INTERFACE="wan0"
fi

WAN_INTERFACE="erouter0"
Check_CM_Ip=0
Check_WAN_Ip=0

isIPv4=""
isIPv6=""

RDKLOGGER_PATH="/rdklogger"
TAD_PATH="/usr/ccsp/tad"
UTOPIA_PATH="/etc/utopia/service.d"
PING_PATH="/usr/sbin"
ping_failed=0
ping_success=0
needSelfhealReboot="/nvram/self_healreboot"
crash_count=0
MF_WiFi_Index="5 6 9 10"
PSM_CONFIG="/tmp/bbhm_cur_cfg.xml"
WiFi_INIT_FILE="/tmp/wifi_initialized"
PROCESS_RESTART_LOG=/rdklogs/logs/systemd_processRestart.log
xle_device_mode=0
if [ "$BOX_TYPE" = "WNXL11BWL" ]; then
    xle_device_mode=`syscfg get Device_Mode`
fi


source $UTOPIA_PATH/log_env_var.sh
source /etc/log_timestamp.sh

T2_MSG_CLIENT=/usr/bin/telemetry2_0_client
if [ -f /etc/onewifi_enabled ] || [ -d /sys/module/openvswitch ] ||
                                  [ -f /etc/WFO_enabled ]; then
    ovs_enable="true"
else
    ovs_enable=`syscfg get mesh_ovs_enable`
fi

t2CountNotify() {
    if [ -f $T2_MSG_CLIENT ]; then
        marker=$1
        $T2_MSG_CLIENT  "$marker" "1"
    fi
}

t2ValNotify() {
    if [ -f $T2_MSG_CLIENT ]; then
        marker=$1
        shift
        $T2_MSG_CLIENT "$marker" "$*"
    fi
}

if [ -f /etc/device.properties ]
then
	source /etc/device.properties
fi

CCSP_ERR_TIMEOUT=191
CCSP_ERR_NOT_EXIST=192

#log_nvram2=`syscfg get logbackup_enable`


if [ ! -d "$LOG_SYNC_PATH" ] 
then
	mkdir -p $LOG_SYNC_PATH
fi

if [ "$backupenable" == "true" ]
then
	exec 3>&1 4>&2 >>$SELFHEALFILE_BOOTUP 2>&1
fi

#Remove script from cron execution
removeCron "selfheal_bootup.sh"

# This function will check if captive portal needs to be enabled or not.
checkCaptivePortal()
{

# Get all flags from DBs
isWiFiConfigured=`syscfg get redirection_flag`
psmNotificationCP=`psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges`

PandM_wait_timeout=600
PandM_wait_count=0
#Read the http response value
networkResponse=`cat /var/tmp/networkresponse.txt`

iter=0
max_iter=2
while [ "$psmNotificationCP" = "" ] && [ "$iter" -le $max_iter ]
do
	iter=$((iter+1))
	echo "$iter"
	psmNotificationCP=`psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges`
done

echo_t "RDKB_SELFHEAL : NotifyWiFiChanges is $psmNotificationCP"
echo_t "RDKB_SELFHEAL : redirection_flag val is $isWiFiConfigured"

if [ "$isWiFiConfigured" = "true" ]
then
	if [ "$networkResponse" = "204" ] && [ "$psmNotificationCP" = "true" ]
	then
		# Check if P&M is up and able to find the captive portal parameter
		while : ; do
			echo_t "RDKB_SELFHEAL : Waiting for PandM to initalize completely to set ConfigureWiFi flag"
			CHECK_PAM_INITIALIZED=`find /tmp/ -name "pam_initialized"`
			echo_t "RDKB_SELFHEAL : CHECK_PAM_INITIALIZED is $CHECK_PAM_INITIALIZED"
			if [ "$CHECK_PAM_INITIALIZED" != "" ]
			then
				echo_t "RDKB_SELFHEAL : WiFi is not configured, setting ConfigureWiFi to true"
				output=`dmcli eRT setvalues Device.DeviceInfo.X_RDKCENTRAL-COM_ConfigureWiFi bool TRUE`
				check_success=`echo $output | grep  "Execution succeed."`
				if [ "$check_success" != "" ]
				then
					echo_t "RDKB_SELFHEAL : Setting ConfigureWiFi to true is success"
				else
					echo "$output"
				fi
				break
			fi
			PandM_wait_count=$(($PandM_wait_count+2))
			if [ "$PandM_wait_count" -gt "$PandM_wait_timeout" ]	
			then
				echo_t "RDKB_SELFHEAL_BOOTUP : PandM_wait_count reached timeout value, exiting from checkCaptivePortal function"
				break
			fi
			sleep 2
		done
	else
		echo_t "RDKB_SELFHEAL : We have not received a 204 response or PSM valus is not in sync"
	fi
else
	echo_t "RDKB_SELFHEAL : Syscfg DB value is : $isWiFiConfigured"
fi	

}
getDateTime()
{
	dandtwithns_now=`date +'%Y-%m-%d:%H:%M:%S:%6N'`
	echo "$dandtwithns_now"
}
 

resetNeeded()
{
	ProcessName=$1
	BINPATH="/usr/bin"
	export LD_LIBRARY_PATH=$PWD:.:$PWD/../../lib:$PWD/../../.:/lib:/usr/lib:$LD_LIBRARY_PATH
	export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/var/run/dbus/system_bus_socket

	if [ -f /tmp/cp_subsys_ert ]; then
        	Subsys="eRT."
	elif [ -e ./cp_subsys_emg ]; then
        	Subsys="eMG."
	else
        	Subsys=""
	fi

	echo_t "RDKB_SELFHEAL_BOOTUP : Resetting process $ProcessName"
	cd /usr/ccsp/pam/
	$BINPATH/CcspPandMSsp -subsys $Subsys
	cd -
	# We need to check whether to enable captive portal flag
	checkCaptivePortal

}


setRebootreason()
{
        echo_t "Setting rebootReason to $1 and rebootCounter to $2"
        
	if [ -e "/usr/bin/onboarding_log" ]; then
	    /usr/bin/onboarding_log "Device reboot due to reason $1"
	fi
        syscfg set X_RDKCENTRAL-COM_LastRebootReason $1
        result=`echo $?`
        if [ "$result" != "0" ]
        then
            echo_t "SET for Reboot Reason failed"
        fi
        syscfg commit
        result=`echo $?`
        if [ "$result" != "0" ]
        then
            echo_t "Commit for Reboot Reason failed"
        fi

        syscfg set X_RDKCENTRAL-COM_LastRebootCounter $2
        result=`echo $?`
        if [ "$result" != "0" ]
        then
            echo_t "SET for Reboot Counter failed"
        fi
        syscfg commit
        result=`echo $?`
        if [ "$result" != "0" ]
        then
            echo_t "Commit for Reboot Counter failed"
        fi
}


db_clean_up_required()
{

	if [ "$BOX_TYPE" = "XB3" ]
	then
		GET_PID_FROM_PEER=`rpcclient $ATOM_ARPING_IP "busybox pidof CcspWifiSsp"`
		WiFi_PID=`echo "$GET_PID_FROM_PEER" | awk 'END{print}' | grep -v "RPC CONNECTED"`
		if [ ! -z "$WiFi_PID" ]; then
			echo_t "RDKB_SELFHEAL_BOOTUP : Stopping CcspWifiSsp before cleaning the database"
			rpcclient $ATOM_ARPING_IP "kill -9 $WiFi_PID"
		fi
	else
		WiFi_PID=$(busybox pidof CcspWifiSsp)
		if [ ! -z "$WiFi_PID" ]; then
			echo_t "RDKB_SELFHEAL_BOOTUP : Stopping CcspWifiSsp before cleaning the database"
			kill -9 $WiFi_PID
		fi
	fi

	entries_needs_to_delete=""
	for index in $MF_WiFi_Index
	do
		MF_Table=`grep "eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.$index.MacFilter." $PSM_CONFIG | grep -v MacFilterMode | grep -v MacFilterList | awk -F '"' '{print $2}'`
		for entry in $MF_Table
		do
			entries_needs_to_delete="$entries_needs_to_delete $entry"
		done

		if [ ! -z "$entries_needs_to_delete" ]; then
			echo_t "Deleting psm entries from macfilter table"
			psmcli del $entries_needs_to_delete
		fi
		psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.$index.MacFilterList "0:"
		sleep 2
	done
}



if [ "$backupenable" == "true" ]
then   

#Vantiva XER5 is a Ethernet Router , hence excluding CM_INTERFACE check.
if [ "$WAN_TYPE" != "EPON" ] && [ "$MODEL_NUM" != "VTER11QEL" ]; then
# Check for CM IP Address
	ifConInfo=`ifconfig $CM_INTERFACE 2> /dev/null`
	if [ -n "$ifConInfo" ]; then
		isIPv4=`echo "$ifConInfo" | grep inet | grep -v inet6`
		if [ "$isIPv4" == "" ]
		then
			isIPv6=`echo "$ifConInfo" | grep inet6 | grep "Scope:Global"`
			if [ "$isIPv6" != "" ]
			then
				Check_CM_Ip=1
			else
			   	Check_CM_Ip=0
				echo_t "RDKB_SELFHEAL_BOOTUP : CM interface doesn't have IP"
			fi
		else
			Check_CM_Ip=1
		fi
	else
		Check_CM_Ip=0
		echo_t "RDKB_SELFHEAL_BOOTUP : CM interface doesn't have IP"
	fi

#Check whether system time is in 1970's
		
	         if [ "$Check_CM_Ip" -eq 1 ]
		 then
			year_is=`date +"%Y"`
			if [ "$year_is" == "1970" ]
			then
				echo_t "RDKB_SELFHEAL_BOOTUP : System time is in 1970's"
			fi
		 fi
fi

#LTE-1639 log-assoclist.service should not be in failed state.
if [ "$BOX_TYPE" = "WNXL11BWL" ];then
	log_assoclist_service_status=`systemctl status log-assoclist.service | grep -i "Active:" | awk -F"Active:|since" '{print $2}'`
	if [ "$(echo "$log_assoclist_service_status" | grep -i "active (exited)")" = "" ]; then	
		echo_t "log-assoclist.service is not in active (exited) state it is in $log_assoclist_service_status state.Hence restarting the service" >> $PROCESS_RESTART_LOG
		systemctl restart log-assoclist.service
	fi
        
	#LTE-1648 extenderModeWait.sh process is not running after bootup.
	xle_device_mode=`syscfg get Device_Mode`
	if [ "$xle_device_mode" -eq "1" ]; then
		EXTENDERMODEWAIT_PID=$(busybox pidof extenderModeWait.sh)
		ccsplmlite_service_status=`systemctl status CcspLMLite.service | grep -i "Active:" | awk -F"Active:|since" '{print $2}'`
		if [ "$EXTENDERMODEWAIT_PID" == "" ]; then
			echo_t "extenderModeWait.sh is not runnning in the extender mode & CcspLMLite.service is in $ccsplmlite_service_status state. so starting the CcspLMLite.service" >> $PROCESS_RESTART_LOG
			systemctl start CcspLMLite.service
		fi
	fi
fi


isIPv4=""
isIPv6=""
# Check for WAN IP Address 
	if [ -f /etc/waninfo.sh ]; then
		WAN_INTERFACE=$(getWanInterfaceName)
	fi

	ifConInfo=`ifconfig $WAN_INTERFACE 2> /dev/null`
	if [ -n "$ifConInfo" ]; then
		isIPv4=`ifconfig "$ifConInfo" | grep inet | grep -v inet6`
		if [ "$isIPv4" == "" ]
		then
			isIPv6=`ifconfig "$ifConInfo" | grep inet6 | grep "Scope:Global"`
			if [ "$isIPv6" != "" ]
			then
				Check_WAN_Ip=1
			else
				Check_WAN_Ip=0
				echo_t "RDKB_SELFHEAL_BOOTUP : WAN interface doesn't have IP"
			fi
		else
			Check_WAN_Ip=1
		fi
	else
		Check_WAN_Ip=0
		echo_t "RDKB_SELFHEAL_BOOTUP : WAN interface doesn't have IP"
	fi

if [ "$BOX_TYPE" = "XB3" ]
then

	#RDKB-21681 Need RDKlogging for All SQUASHFS errors
	dmesg | grep SQUASHFS >> /rdklogs/logs/Consolelog.txt.0

	## Check Peer ip is accessible
	if [ -f $PING_PATH/ping_peer ]
	then
	loop=1
		while [ "$loop" -le 3 ]
		do
	
		PING_RES=`ping_peer`
		CHECK_PING_RES=`echo $PING_RES | grep "packet loss" | cut -d"," -f3 | cut -d"%" -f1`

		if [ "$CHECK_PING_RES" != "" ]
		then
			if [ "$CHECK_PING_RES" -ne 100 ] 
			then
				ping_success=1
				echo_t "RDKB_SELFHEAL_BOOTUP : Ping to Peer IP is success"
				break
			else
				ping_failed=1
			fi
		else
				ping_failed=1
		fi
	
		if [ "$ping_failed" -eq 1 ]
		then
		     echo_t "RDKB_SELFHEAL_BOOTUP : Ping to peer failed check whether ATOM is really down thru RPC"
		     # This test is done only for XB3 cases 
	       	     if [ -f /usr/bin/rpcclient ] && [ "$ATOM_ARPING_IP" != "" ];then 
				RPC_RES=`rpcclient $ATOM_ARPING_IP pwd`
				RPC_OK=`echo $RPC_RES | grep "RPC CONNECTED"`
				if [ "$RPC_OK" != "" ]
			 	then
		    			echo_t "RDKB_SELFHEAL_BOOTUP : RPC Communication with ATOM is OK"
				else
				   	echo_t "RDKB_SELFHEAL_BOOTUP : RPC Communication with ATOM is NOK"    
				fi
		     else
				echo_t "Non-XB3 case / ATOM_ARPING_IP is NULL not checking communication using rpcclient"
		     fi
	      	 fi

		 if [ "$ping_failed" -eq 1 ] && [ "$loop" -lt 3 ]
		 then
			echo_t "RDKB_SELFHEAL_BOOTUP : Ping to Peer IP failed in iteration $loop"
			t2CountNotify "SYS_SH_pingPeerIP_Failed"
			echo_t "RDKB_SELFHEAL : Ping command output is $PING_RES"
		 else
			echo_t "RDKB_SELFHEAL_BOOTUP : Ping to Peer IP failed after iteration $loop also ,rebooting the device"
			t2CountNotify "SYS_SH_pingPeerIP_Failed"
			echo_t "RDKB_SELFHEAL : Ping command output is $PING_RES"
			if [ ! -f "$needSelfhealReboot" ]
			then
				touch $needSelfhealReboot
				crash_count=1
				echo_t "RDKB_REBOOT : Peer is not up ,Rebooting device "
				echo_t "RDKB_REBOOT : Setting Last reboot reason as Peer_down"
		       	        reason="Peer_down"
			        rebootCount=1
	      		        setRebootreason $reason $rebootCount
				$RDKLOGGER_PATH/backupLogs.sh "true" ""
			fi

			fi
			loop=$((loop+1))
			sleep 5
		done
	else
	   echo_t "RDKB_SELFHEAL_BOOTUP : ping_peer command not found"
	fi
fi
##################
        # Check whether CR process is running
        crTestop=`dmcli eRT getv com.cisco.spvtg.ccsp.CR.Name`
        isCRAlive=`echo $crTestop | grep "Execution succeed"`
        if [ "$isCRAlive" == "" ]; then
        		
				if [ "$WAN_TYPE" != "EPON" ]; then
					# Test CR Alive or not using rpcclient
				    RPC_RES=`rpcclient $ATOM_ARPING_IP "dmcli eRT getv com.cisco.spvtg.ccsp.CR.Name"`
				    isRpcOk=`echo $RPC_RES | grep "RPC CONNECTED"`
				    isCRAlive=`echo $RPC_RES | grep "Execution succeed"`
				    if [ "$isRpcOk" != "" ]
				    then
				        echo_t "RDKB_SELFHEAL_BOOTUP : RPC Communication between ARM and ATOM is OK"
				    else
				        echo_t "RDKB_SELFHEAL_BOOTUP : RPC Communication between ARM and ATOM is NOK"
				    fi  

					if [ "$isCRAlive" != "" ]
				    then
						echo_t "RDKB_SELFHEAL_BOOTUP : CR process is alive thru RPC"
					else
					  	echo_t "RDKB_SELFHEAL_BOOTUP : CR process is not alive thru RPC as well"
					fi
				fi

                # Retest by querying some other parameter
                isCRAlive=`dmcli eRT retv Device.X_CISCO_COM_DeviceControl.DeviceMode`
                  if [ "$isCRAlive" = "" ]; then
                        echo_t "RDKB_PROCESS_CRASHED : CR_process is not running, need to reboot the unit"
                        echo_t "RDKB_SELFHEAL_BOOTUP : CR_process is not running, need reboot"
                        touch $HAVECRASH
						
                        if [ ! -f "$needSelfhealReboot" ]
                        then
                                touch $needSelfhealReboot
				crash_count=1
				if [ "$ping_failed" == "1" ]
				then
					echo_t "RDKB_PROCESS_CRASHED : Ping peer failed and CR_process not running"
                                	reason="Peer_down"
					backupreason=""
				else
					reason="CR_crash"
					backupreason="CR"
				fi
                                rebootCount=1
                                setRebootreason $reason $rebootCount
                                $RDKLOGGER_PATH/backupLogs.sh "true" $backupreason
			fi
                 fi
        fi

# Check whether PSM process is running
	# Checking PSM's PID
	PSM_PID=$(busybox pidof PsmSsp)
	if [ "$PSM_PID" == "" ]; then

		echo_t "RDKB_PROCESS_CRASHED : PSM_process is not running, need to reboot the unit"
		echo_t "Setting Last reboot reason"
		dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason string Psm_crash
		t2CountNotify "SYS_ERROR_PSMCrash_reboot"
		echo_t "SET succeeded"
		touch $HAVECRASH	
		echo_t "RDKB_PROCESS_CRASHED : PSM_process is not running, need reboot"
		echo_t "RDKB_SELFHEAL_BOOTUP : PSM_process is not running, need reboot"

			if [ ! -f "$needSelfhealReboot" ]
			then
				touch $needSelfhealReboot
				crash_count=1
				$RDKLOGGER_PATH/backupLogs.sh "true" "PSM"
			fi
	else
		psm_name=`dmcli eRT getv com.cisco.spvtg.ccsp.psm.Name`
		psm_name_timeout=`echo $psm_name | grep "$CCSP_ERR_TIMEOUT"`
		psm_name_notexist=`echo $psm_name | grep "$CCSP_ERR_NOT_EXIST"`
		if [ "$psm_name_timeout" != "" ] || [ "$psm_name_notexist" != "" ]; then
			psm_health=`dmcli eRT getv com.cisco.spvtg.ccsp.psm.Health`
			psm_health_timeout=`echo $psm_health | grep "$CCSP_ERR_TIMEOUT"`
			psm_health_notexist=`echo $psm_health | grep "$CCSP_ERR_NOT_EXIST"`
			if [ "$psm_health_timeout" != "" ] || [ "$psm_health_notexist" != "" ]; then
				if [ ! -f "$needSelfhealReboot" ]
				then
					touch $needSelfhealReboot
                                 	crash_count=1
					echo_t "RDKB_SELFHEAL_BOOTUP : PSM_process is not responding, need reboot"
					dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason string Psm_hang
					$RDKLOGGER_PATH/backupLogs.sh "true" "PSM"
				fi
			fi
		fi
	fi

# Check whether PAM process is running
	PAM_PID=$(busybox pidof CcspPandMSsp)
	if [ "$PAM_PID" == "" ]; then
		# Remove the P&M initialized flag
		rm -rf /tmp/pam_initialized
		echo_t "RDKB_PROCESS_CRASHED : PAM_process is not running, need restart"
		t2CountNotify "SYS_SH_PAM_CRASH_RESTART"
		echo_t "RDKB_SELFHEAL_BOOTUP : PAM_process is not running, need restart"
		resetNeeded CcspPandMSsp
	fi

if [ "$WAN_TYPE" != "EPON" ]; then
    if [ "$xle_device_mode" -eq "0" ]; then
# Checking whether brlan0 and l2sd0.100 are created properly

        device_mode=`dmcli eRT retv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode`

        if [ "$device_mode" != "" ]
        then
            if [ "$device_mode" = "router" ]
            then
               	    check_if_brlan0_created=`ifconfig | grep brlan0`
		    check_if_brlan0_up=`ifconfig brlan0 | grep UP`
	   	    check_if_brlan0_hasip=`ifconfig brlan0 | grep "inet addr"`

                    # l2sd0.100 is an interface specific to intel platform. Not applicable for other soc vendors.
                    if [ "$BOX_TYPE" = "XB6" ] || [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$BOX_TYPE" = "WNXL11BWL" ] || [ "$BOX_TYPE" = "VNTXER5" ] || [ "$BOX_TYPE" = "SCER11BEL" ] || [ "$BOX_TYPE" = "SCXF11BFL" ]
                    then
                        check_if_l2sd0_100_created="NotApplicable"
                        check_if_l2sd0_100_up="NotApplicable"
                    else
		        check_if_l2sd0_100_created=`ifconfig | grep l2sd0.100`
		        check_if_l2sd0_100_up=`ifconfig l2sd0.100 | grep UP `
                    fi
			  
		   if [ "$check_if_brlan0_created" = "" ] || [ "$check_if_brlan0_up" = "" ] || [ "$check_if_brlan0_hasip" = "" ] || [ "$check_if_l2sd0_100_created" = "" ] || [ "$check_if_l2sd0_100_up" = "" ]
		   then
			   echo_t "[RDKB_SELFHEAL_BOOTUP] : brlan0 and l2sd0.100 o/p "
			   ifconfig brlan0;ifconfig l2sd0.100;

                   	   if [ "x$ovs_enable" = "xtrue" ];then
                        	ovs-vsctl list-ifaces brlan0
                   	   else
                        	brctl show
                           fi
			   echo_t "[RDKB_SELFHEAL_BOOTUP] : Either brlan0 or l2sd0.100 is not completely up, setting event to recreate vlan and brlan0 interface"

			   ipv4_status=`sysevent get ipv4_4-status`
			   lan_status=`sysevent get lan-status`

			   if [ "$lan_status" != "started" ]
			   then
					if [ "$ipv4_status" = "" ] || [ "$ipv4_status" = "down" ]
					then
						echo_t "[RDKB_SELFHEAL_BOOTUP] : ipv4_4-status is not set or lan is not started, setting lan-start event"
						sysevent set lan-start
						sleep 60
					else
						sysevent set multinet-down 1
						sleep 5
						sysevent set multinet-up 1
						sleep 30
					fi
			   else
				sysevent set multinet-down 1
				sleep 5
				sysevent set multinet-up 1
				sleep 30
			   fi
		   fi


# Check for iptable corruption 
		   if [ "$check_if_brlan0_hasip" != "" ]
		   then
       		          echo_t "brlan0 has IPV4 Address in router mode"
                	  Check_Iptable_Rules=`iptables-save -t nat | grep "A PREROUTING -i"`
		          if [ "$Check_Iptable_Rules" == "" ]; then
        	    	      	 echo_t "[RDKB_SELFHEAL_BOOTUP] : iptable corrupted."
        	    	      	 t2CountNotify "SYS_ERROR_iptable_corruption"
		          	 #sysevent set firewall-restart
		          fi	
		   fi
            fi
        else
            echo_t "[RDKB_SELFHEAL_BOOTUP] : Something went wrong while fetching Bridge mode "
            echo "$check_device_mode"
        fi

# Checking whether brlan1 and l2sd0.101 interface are created properly
		if [ "$IS_BCI" != "yes" ]; then
			check_if_brlan1_created=`ifconfig | grep brlan1`
			check_if_brlan1_up=`ifconfig brlan1 | grep UP`
				check_if_brlan1_hasip=`ifconfig brlan1 | grep "inet addr"`
			
				# l2sd0.101 is an intel specific interface. Not applicable for other soc vendors.
				if [ "$BOX_TYPE" = "XB6" ] || [ "$BOX_TYPE" = "VNTXER5" ] || [ "$BOX_TYPE" = "SCER11BEL" ]
				then
					check_if_l2sd0_101_created="NotApplicable"
					check_if_l2sd0_101_up="NotApplicable"
				else
					check_if_l2sd0_101_created=`ifconfig | grep l2sd0.101`
					check_if_l2sd0_101_up=`ifconfig l2sd0.101 | grep UP`
				fi
			
			if [ "$check_if_brlan1_created" = "" ] || [ "$check_if_brlan1_up" = "" ] || [ "$check_if_brlan1_hasip" = "" ] || [ "$check_if_l2sd0_101_created" = "" ] || [ "$check_if_l2sd0_101_up" = "" ]
				then
				echo_t "[RDKB_SELFHEAL_BOOTUP] : brlan1 and l2sd0.101 o/p "
				ifconfig brlan1;ifconfig l2sd0.101;
						if [ "x$ovs_enable" = "xtrue" ];then
							ovs-vsctl list-ifaces brlan1
						else
							brctl show
						fi
					echo_t "[RDKB_SELFHEAL_BOOTUP] : Either brlan1 or l2sd0.101 is not completely up, setting event to recreate vlan and brlan1 interface"
				
				ipv5_status=`sysevent get ipv4_5-status`
					lan_l3net=`sysevent get homesecurity_lan_l3net`
				
				if [ "$lan_l3net" != "" ]
				then
					if [ "$ipv5_status" = "" ] || [ "$ipv5_status" = "down" ]
					then
						echo_t "[RDKB_SELFHEAL_BOOTUP] : ipv5_4-status is not set , setting event to create homesecurity lan"
						sysevent set ipv4-up $lan_l3net
						sleep 60
					else
						sysevent set multinet-down 2
						sleep 5
						sysevent set multinet-up 2
						sleep 10
					fi
				else
					sysevent set multinet-down 2
					sleep 5
					sysevent set multinet-up 2
					sleep 10
				fi
			fi
		fi
	fi
fi

	SYSEVENT_PID=$(busybox pidof syseventd)
	if [ "$SYSEVENT_PID" == "" ]
	then
        if [ ! -f "$needSelfhealReboot" ]
        then
            #Needs to avoid false alarm
            rebootCounter=`syscfg get X_RDKCENTRAL-COM_LastRebootCounter`
            echo_t "[syseventd] Previous rebootCounter:$rebootCounter"

            if [ "$rebootCounter" != "1" ] ; then
      			echo_t "[RDKB_SELFHEAL_BOOTUP] : syseventd is crashed, need to reboot the unit." 
			    echo_t "Setting Last reboot reason"
			    dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason string Syseventd_crash
			    dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootCounter int 1
			    touch $needSelfhealReboot
			    crash_count=1
			    $RDKLOGGER_PATH/backupLogs.sh "true" "syseventd"
            fi
		fi
    fi


if [ "$WAN_TYPE" != "EPON" ]; then	
	if [ "$xle_device_mode" -eq "0" ]; then
		#Check whether dnsmasq is running or not
		DNS_PID=$(busybox pidof dnsmasq)
		if [ "$DNS_PID" == "" ]
		then
			BR_MODE=0
			bridgeMode=`dmcli eRT retv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode`
			if [ "$bridgeMode" != "" ]
			then
				if [ "$bridgeMode" != "router" ]
				then
					BR_MODE=1
				fi
			fi

				InterfaceInConf=`grep "interface=" /var/dnsmasq.conf`
				if [ "x$InterfaceInConf" = "x" ] && [ $BR_MODE -eq 1 ] ; then
						if [ ! -f /tmp/dnsmaq_noiface ]; then
							echo_t "[ RDKB_SELFHEAL_BOOTUP ] : Unit in bridge mode,interface info not available in dnsmasq.conf"
							touch /tmp/dnsmaq_noiface
						fi
				else
						echo_t "[ RDKB_SELFHEAL_BOOTUP ] : dnsmasq is not running."
						t2CountNotify "SYS_SH_dnsmasq_restart"
				fi

				if [ $BR_MODE -eq 1 ]
				then
					echo_t "[ RDKB_SELFHEAL_BOOTUP ] : Device is in bridge mode"

					if [ "" == "`sysevent get lan_status-dhcp`" ] ; then
						echo_t "[ RDKB_SELFHEAL_BOOTUP ] : Setting lan_status-dhcp event to started"
						sysevent set lan_status-dhcp started
									echo_t "[ RDKB_SELFHEAL_BOOTUP ] : Setting an event to restart dnsmasq"
						sysevent set dhcp_server-restart
					fi
				fi
		else
		brlan1up=`grep brlan1 /var/dnsmasq.conf`
			brlan0up=`grep brlan0 /var/dnsmasq.conf`
			infup="NA"
			if [ "$(syscfg get lost_and_found_enable)" = "true" ]; then
				lnf_ifname=$(syscfg get iot_ifname)
				if [ $lnf_ifname == "l2sd0.106" ]; then
					lnf_ifname=$(syscfg get iot_brname)
				fi
				if [ -n "$lnf_ifname" ]
				then
					echo_t "[RDKB_SELFHEAL_BOOTUP] : LnF interface is: $lnf_ifname"
					infup=$(grep $lnf_ifname /var/dnsmasq.conf)
				else
					echo_t "[RDKB_SELFHEAL_BOOTUP] : LnF interface not available in DB"
				fi
			fi

		if [ -f /tmp/dnsmaq_noiface ]; then
			rm -rf /tmp/dnsmasq_noiface
		fi

		IsAnyOneInfFailtoUp=0	
		BR_MODE=0
		bridgeMode=`dmcli eRT retv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode`
		if [ "$bridgeMode" != "" ]
		then
			if [ "$bridgeMode" != "router" ]
			then
				BR_MODE=1
			fi
		fi

		if [ $BR_MODE -eq 0 ]
		then
				if [ "$brlan0up" == "" ]
				then
					echo_t "[RDKB_SELFHEAL_BOOTUP] : brlan0 info is not availble in dnsmasq.conf"
					IsAnyOneInfFailtoUp=1
				fi
		fi

		if [ "$IS_BCI" != "yes" ] && [ "$brlan1up" == "" ] && [ "$BOX_TYPE" != "HUB4" ] &&  [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$BOX_TYPE" != "WNXL11BWL" ]
		then
				echo_t "[RDKB_SELFHEAL_BOOTUP] : brlan1 info is not availble in dnsmasq.conf"
				IsAnyOneInfFailtoUp=1
		fi

			if [ "$infup" == "" ]
			then
					echo_t "[RDKB_SELFHEAL_BOOTUP] : $lnf_ifname info is not availble in dnsmasq.conf"
				IsAnyOneInfFailtoUp=1
			fi
		if [ $IsAnyOneInfFailtoUp -eq 1 ]
		then
			echo_t "[RDKB_SELFHEAL_BOOTUP] : dnsmasq.conf is." 
			echo "`cat /var/dnsmasq.conf`"

			echo_t "[RDKB_SELFHEAL_BOOTUP] : Setting an event to restart dnsmasq"
			sysevent set dhcp_server-restart
			fi
		fi
	fi
fi
	if [ "$BOX_TYPE" = "XB3" ]
	then
		GET_PID_FROM_PEER=`rpcclient $ATOM_ARPING_IP "busybox pidof CcspWifiSsp"`
		WiFi_PID=`echo "$GET_PID_FROM_PEER" | awk 'END{print}' | grep -v "RPC CONNECTED"`
		RPC_WiF_FILE_EXISTS=`rpcclient $ATOM_ARPING_IP "ls $WiFi_INIT_FILE"`
		WIFI_INIT_FILE_EXISTS=`echo "$RPC_WiF_FILE_EXISTS" | awk 'END{print}' | grep -v "RPC CONNECTED"`
	else
		WiFi_PID=$(busybox pidof CcspWifiSsp)
		WIFI_INIT_FILE_EXISTS=`ls /tmp/wifi_initialized`
	fi

		if ([ -z "$WiFi_PID" ] || [ "$WIFI_INIT_FILE_EXISTS" != "$WiFi_INIT_FILE" ])  && [ "$MODEL_NUM" != "CVA601ZCOM" ]; then
		echo_t "RDKB_SELFHEAL : WiFi Agent is not running or not initialized completely, checking if MacFilter entries are corrupted"
		for index in $MF_WiFi_Index
		do
			#MF_List_5="41:,56,67,68,69,70,71,72"
			#db_clean_up_required="no"
			MF_List=`psmcli get eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.$index.MacFilterList`
			echo_t "MF_List = $MF_List for index $index"
			#MF_List_$index=`psmcli get eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.5.MacFilterList`
			#echo "MF_List_$index = $MF_List_$index"

			if [ ! -z "$MF_List"  ] &&  [ "$MF_List" != "0:" ] ;then
				MF_No_Of_Entries=`echo $MF_List | cut -d":" -f1`
				echo_t "MF_No_Of_Entries = $MF_No_Of_Entries"

				MF_Entries=`echo $MF_List | cut -d":" -f2`
				echo_t "MF_Entries = $MF_Total_Entries"


				#check if the first field is empty
				check_if_first_field_empty=`echo "$MF_Entries" | awk -F "," '{print $1}'`

				#Get the total entries based of "," delimiter
				MF_Total_Count_Delim=`echo "$MF_Entries" | awk -F "," "{ print NF }"`

				if [ "$check_if_first_field_empty" = "" ] || [ "$MF_No_Of_Entries" != "$MF_Total_Count_Delim" ] 
				then
					#db_clean_up_required="yes"
					echo_t "RDKB_SELFHEAL : PSM database is corrupted for MacFilter entries, cleaning up MacFilter entries from database"
					db_clean_up_required
					break;
				fi

			fi
			MF_List=""
			MF_No_Of_Entries=""
			MF_Entries=""
			check_if_first_field_empty=""
			MF_Total_Count_Delim=""
		done

	fi
else
	echo_t "RDKB_SELFHEAL_BOOTUP : nvram2 logging is disabled , not logging data"
fi

#Temporary selfheal. Needs to be removed after ARRISXB6-11395 is fixed.
if [ "$MODEL_NUM" = "TG3482G" ];then
	Host_Count=0
	Host_Count=`dmcli eRT retv Device.Hosts.HostNumberOfEntries`
	echo_t "Host_Count:$Host_Count"

	if [ $Host_Count -gt 0 ];then
		host_active_success=`dmcli eRT retv Device.Hosts.Host.1.Active`
		if [ "$host_active_success" = "" ];then
			echo_t "RDKB_SELFHEAL_BOOTUP : Restart LMLite"
			systemctl restart CcspLMLite.service
		fi
	fi

fi

# XLE specific. Temporary selfheal for deleting extra APN profiles created for verizon network.
if [ "$BOX_TYPE" = "WNXL11BWL" ]; then
    qmi_home_network=`qmicli -p -d /dev/cdc-wdm0 --nas-get-home-network | grep -i Verizon`
    if [ "$qmi_home_network" != "" ];then
		qmi_vzw_count=`qmicli -p -d /dev/cdc-wdm0 --device-open-proxy --wds-get-profile-list=3gpp | grep -i vzwinternet | wc -l`
		echo_t "vzwinternet profile count : $qmi_vzw_count"
		if [ "$qmi_vzw_count" != "1" ];then
			qmicli -p -d /dev/cdc-wdm0 --wds-set-default-profile-number=3gpp,3
			qmicli -p -d /dev/cdc-wdm0 --wds-set-lte-attach-pdn-list=1,3
			loop=1
			while [ $loop -lt $qmi_vzw_count ]
			do
				profile_num=$((loop+6))
				echo_t "Deleting profile : $profile_num"
				qmicli --device=/dev/cdc-wdm0 --device-open-proxy --wds-delete-profile=3gpp,$profile_num
				loop=$((loop+1))
			done
			echo_t "Restarting CellularManager on bootup"
			systemctl restart RdkCellularManager.service
		fi
	fi
fi

BBHM_CUR_PREV="/nvram/bbhm_cur_cfg.xml.prev"
BBHM_BAK_PREV="/nvram/bbhm_bak_cfg.xml.prev"

if [ -f $BBHM_CUR_PREV ] || [ -f $BBHM_BAK_PREV ]
then
	rm -rf $BBHM_CUR_PREV $BBHM_BAK_PREV
	echo_t "RDKB_SELFHEAL_BOOTUP : files removed $BBHM_CUR_PREV $BBHM_BAK_PREV"
fi

if [ -f "$needSelfhealReboot" ] && [ $crash_count -eq 0 ]
then
	rm -rf $needSelfhealReboot
fi


checkIfWanHasIp()
{
    wan_ipv4_addr=$(ip -4 addr show dev $WAN_INTERFACE | grep -i "scope global" | awk '{print $2}' | cut -f1 -d"/")
    wan_ipv6_addr=$(ip -6 addr show dev $WAN_INTERFACE | grep -i "scope global" | awk '{print $2}' | cut -f1 -d"/")

    echo "wan_ipv4_addr is $wan_ipv4_addr"
    echo "wan_ipv6_addr is $wan_ipv6_addr"

    if [ -z "$wan_ipv4_addr" ] && [ -z "$wan_ipv6_addr" ];then
        return 1
    fi
    return 0
}

dumpLogs()
{
    cp /var/log/dibbler/dibbler-client.log /rdklogs/logs/dbg_wan_ip_missing.txt
    ps ww >> /rdklogs/logs/dbg_wan_ip_missing.txt
    ip route show >> /rdklogs/logs/dbg_wan_ip_missing.txt
    ip -6 route show >> /rdklogs/logs/dbg_wan_ip_missing.txt
    sysevent show /rdklogs/logs/sysevent_list.txt 
    ifconfig -a  >> /rdklogs/logs/dbg_wan_ip_missing.txt
}

UseLANIFIPV6=`sysevent get LANIPv6GUASupport`
eth_wan_enabled=$(syscfg get eth_wan_enabled)
if [ "$eth_wan_enabled" = "true" ] && [ "$UseLANIFIPV6" != "true" ];then
    
    LinkStatus=$(dmcli eRT getv Device.X_RDKCENTRAL-COM_EthernetWAN.LinkStatus  | grep "value" | cut -f3 -d":" | cut -f2 -d" ")

    WAN_INTERFACE=$(sysevent get wan_ifname)
    CURRENT_WAN_IFNAME=$(sysevent get current_wan_ifname)
    if [ "$CURRENT_WAN_IFNAME" = "" ] || [ "$CURRENT_WAN_IFNAME" = "$WAN_INTERFACE" ];then
        if [ "$LinkStatus" = "true" ];then
             checkIfWanHasIp
             wan_ip_ret=$?
             if [ "$wan_ip_ret" = "1" ];then
                echo "Wan doesn't have IP, monitor after 3 mins"
                sleep 180
                checkIfWanHasIp
                wan_ip_ret=$?
                if [ "$wan_ip_ret" = "1" ];then
                    checkPrevRebootReason=$(syscfg get X_RDKCENTRAL-COM_LastRebootReason)
                    if [ "$checkPrevRebootReason" != "missing_wan_ip" ];then
                        echo "Wan doesn't have IP , need to reboot device to recover"
                        syscfg set X_RDKCENTRAL-COM_LastRebootReason "missing_wan_ip"
                        syscfg set X_RDKCENTRAL-COM_LastRebootCounter 1
                        syscfg commit
                        dumpLogs
                        $RDKLOGGER_PATH/backupLogs.sh "true" "missing_wan_ip"

                    else
                        echo "Device was previously rebooted because of missing_wan_ip , not rebooting again"
                    fi

                 fi
             fi

        fi
    fi
fi
if [ "$MODEL_NUM" = "TG4482A" ]
then
   radio_enum_count=`lspci -mk | grep mtlk | wc -l`
   echo_t "pci_enumeration_count:$radio_enum_count" >> $SELFHEALFILE
   t2ValNotify "PciEnumeration_split" "$radio_enum_count"
fi
touch /tmp/selfheal_bootup_completed
