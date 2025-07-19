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

if [ "$WAN0_IS_DUMMY" = "true" ]; then
    CM_INTERFACE="privbr"
else
    CM_INTERFACE="wan0"
fi

WAN_INTERFACE=$(getWanInterfaceName)
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


source $UTOPIA_PATH/log_env_var.sh
source /etc/log_timestamp.sh

T2_MSG_CLIENT=/usr/bin/telemetry2_0_client

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
removeCron "/usr/ccsp/tad/selfheal_bootup.sh"

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
        echo_t " Setting rebootReason to $1 and rebootCounter to $2"
	if [ -e "/usr/bin/onboarding_log" ]; then
            /usr/bin/onboarding_log "Device reboot due to reason $1"
	fi
        syscfg set X_RDKCENTRAL-COM_LastRebootReason $1
        result=`echo $?`
        if [ "$result" != "0" ]
        then
            echo_t " SET for Reboot Reason failed"
        fi
        syscfg commit
        result=`echo $?`
        if [ "$result" != "0" ]
        then
            echo_t " Commit for Reboot Reason failed"
        fi

        syscfg set X_RDKCENTRAL-COM_LastRebootCounter $2
        result=`echo $?`
        if [ "$result" != "0" ]
        then
            echo_t " SET for Reboot Counter failed"
        fi
        syscfg commit
        result=`echo $?`
        if [ "$result" != "0" ]
        then
            echo_t " Commit for Reboot Counter failed"
        fi
}

#Check if /data/wifi_config_nvram and /data/wifi_config_nvram_bak ar present in TCCBR. If yes, remove these files
if [ -f /data/wifi_config_nvram ] || [ -f /data/wifi_config_nvram_bak ]; then
        echo_t "Removing wifi_config_nvram and wifi_config_nvram_bak, not required for TCCBR"
        rm -rf /data/wifi_config_nvram /data/wifi_config_nvram_bak
fi

if [ "$backupenable" == "true" ]
then    
# Check for CM IP Address 
 	isIPv4=`ifconfig $CM_INTERFACE | grep inet | grep -v inet6`
	 if [ "$isIPv4" == "" ]
	 then
        	 isIPv6=`ifconfig $CM_INTERFACE | grep inet6 | grep "Scope:Global"`
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

#Check whether system time is in 1970's
	
         if [ "$Check_CM_Ip" -eq 1 ]
	 then
		year_is=`date +"%Y"`
		if [ "$year_is" == "1970" ]
		then
			echo_t "RDKB_SELFHEAL_BOOTUP : System time is in 1970's"
		fi
	 fi


isIPv4=""
isIPv6=""
# Check for WAN IP Address 

	 isIPv4=`ifconfig $WAN_INTERFACE | grep inet | grep -v inet6`
	 if [ "$isIPv4" == "" ]
	 then
        	 isIPv6=`ifconfig $WAN_INTERFACE | grep inet6 | grep "Scope:Global"`
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
		if [ ! -f "/nvram/self_healreboot" ]
		then
			touch /nvram/self_healreboot
			echo_t "RDKB_REBOOT : Peer is not up ,Rebooting device "
			echo_t "RDKB_REBOOT : Setting Last reboot reason as Peer_down"
	       	        reason="Peer_down"
        	        rebootCount=1
      		        setRebootreason $reason $rebootCount
			$RDKLOGGER_PATH/backupLogs.sh "true" ""
		else
			rm -rf /nvram/self_healreboot
		fi

	 fi
		loop=$((loop+1))
		sleep 5
	done
else
   echo_t "RDKB_SELFHEAL_BOOTUP : ping_peer command not found"
fi
##################
        # Check whether CR process is running
        crTestop=`dmcli eRT getv com.cisco.spvtg.ccsp.CR.Name`
        isCRAlive=`echo $crTestop | grep "Execution succeed"`
        if [ "$isCRAlive" == "" ]; then
				# Test CR Alive or not using rpcclient
		# This test is done only for XB3 cases 
		if [ -f /usr/bin/rpcclient ] && [ "$ATOM_ARPING_IP" != "" ]; then 
			RPC_RES=`rpcclient $ATOM_ARPING_IP "dmcli eRT getv com.cisco.spvtg.ccsp.CR.Name"`
			isRpcOk=`echo $RPC_RES | grep "RPC CONNECTED"`
			isCRAlive=`echo $RPC_RES | grep "Execution succeed"`
			if [ "$isRpcOk" != "" ]; then
				echo_t "RDKB_SELFHEAL_BOOTUP : RPC Communication between ARM and ATOM is OK"
			else
				echo_t "RDKB_SELFHEAL_BOOTUP : RPC Communication between ARM and ATOM is NOK"
			fi

			if [ "$isCRAlive" != "" ]; then
				echo_t "RDKB_SELFHEAL_BOOTUP : CR process is alive thru RPC"
			else
				echo_t "RDKB_SELFHEAL_BOOTUP : CR process is not alive thru RPC as well"
			fi
		else
			echo_t "Non-XB3 case / ATOM_ARPING_IP is NULL not checking CR process using rpcclient"
		fi

                # Retest by querying some other parameter
                crReTestop=`dmcli eRT getv Device.X_CISCO_COM_DeviceControl.DeviceMode`
                isCRAlive=`echo $crReTestop | grep "Execution succeed"`
                  if [ "$isCRAlive" == "" ]; then
                        echo_t "RDKB_PROCESS_CRASHED : CR_process is not running, need to reboot the unit"
                        echo_t "RDKB_SELFHEAL_BOOTUP : CR_process is not running, need reboot"
                        touch $HAVECRASH
						
                        if [ ! -f "$needSelfhealReboot" ]
                        then
                                touch $needSelfhealReboot
                                reason="CR_crash"
                                rebootCount=1
                                setRebootreason $reason $rebootCount

                                $RDKLOGGER_PATH/backupLogs.sh "true" "CR"
                        else
                                rm -rf $needSelfhealReboot
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
				$RDKLOGGER_PATH/backupLogs.sh "true" "PSM"
			else
				rm -rf $needSelfhealReboot
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

# Checking whether brlan0 created properly

        check_device_mode=`dmcli eRT getv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode`

        check_param_get_succeed=`echo $check_device_mode | grep "Execution succeed"`

        if [ "$check_param_get_succeed" != "" ]
        then
            check_device_in_router_mode=`echo $check_param_get_succeed | grep router`
            if [ "$check_device_in_router_mode" != "" ]
            then
               	    check_if_brlan0_created=`ifconfig | grep brlan0`
		    check_if_brlan0_up=`ifconfig brlan0 | grep UP`
	   	    check_if_brlan0_hasip=`ifconfig brlan0 | grep "inet addr"`
			  
		   if [ "$check_if_brlan0_created" = "" ] || [ "$check_if_brlan0_up" = "" ] || [ "$check_if_brlan0_hasip" = "" ]
		   then
			   echo_t "[RDKB_SELFHEAL_BOOTUP] : brlan0 is not completely up, setting event to recreate vlan and brlan0 interface"
			   t2CountNotify "SYS_ERROR_brlan0_not_created"
			   ipv4_status=`sysevent get ipv4_4-status`
			   lan_status=`sysevent get lan-status`

			   if [ "$ipv4_status" = "" ] && [ "$lan_status" != "started" ]
			   then
			   	echo_t "[RDKB_SELFHEAL_BOOTUP] : ipv4_4-status is not set or lan is not started, setting lan-start event"
				sysevent set lan-start
				sleep 5
			   fi
			   sysevent set multinet-down 1
			   sleep 5
			   sysevent set multinet-up 1
			   sleep 30
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
        fi

	SYSEVENT_PID=$(busybox pidof syseventd)
	if [ "$SYSEVENT_PID" == "" ]
	then
                if [ ! -f "$needSelfhealReboot" ]
                then
			echo_t "[RDKB_SELFHEAL_BOOTUP] : syseventd is crashed, need to reboot the unit." 
			echo_t "Setting Last reboot reason"
			dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason string Syseventd_crash
			touch $needSelfhealReboot
			$RDKLOGGER_PATH/backupLogs.sh "true" "syseventd"
		else
			rm -rf $needSelfhealReboot
		fi

	fi

    BR_MODE=0
    bridgeMode=`dmcli eRT getv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode`
    bridgeSucceed=`echo $bridgeMode | grep "Execution succeed"`
    if [ "$bridgeSucceed" != "" ]
    then
       isBridging=`echo $bridgeMode | grep router`
       if [ "$isBridging" = "" ]
       then
           BR_MODE=1
       fi
    fi

    #Check whether dnsmasq is running or not
    DNS_PID=$(busybox pidof dnsmasq)
    if [ "$DNS_PID" == "" ]
    then
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
    else
          brlan0up=`cat /var/dnsmasq.conf | grep brlan0`
      if [ -f /tmp/dnsmaq_noiface ]; then
          rm -rf /tmp/dnsmasq_noiface
      fi
	  IsAnyOneInfFailtoUp=0	
	
	  if [ $BR_MODE -eq 0 ]
	  then
			if [ "$brlan0up" == "" ]
			then
			    echo_t "[RDKB_SELFHEAL_BOOTUP] : brlan0 info is not availble in dnsmasq.conf"
			    IsAnyOneInfFailtoUp=1
			fi
	  fi

	  if [ $IsAnyOneInfFailtoUp -eq 1 ]
	  then
		 echo_t "[RDKB_SELFHEAL_BOOTUP] : dnsmasq.conf is."   
	 	 echo "`cat /var/dnsmasq.conf`"

		 echo_t "[RDKB_SELFHEAL_BOOTUP] : Setting an event to restart dnsmasq"
	         sysevent set dhcp_server-restart
        fi
    fi
    
else
	echo_t "RDKB_SELFHEAL_BOOTUP : nvram2 logging is disabled , not logging data"
fi
