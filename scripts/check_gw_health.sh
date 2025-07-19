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

source /etc/log_timestamp.sh
source /etc/utopia/service.d/log_env_var.sh
source /etc/waninfo.sh

WAN_INTERFACE=$(getWanInterfaceName)

#bit mask for corresponding functionality
CMStatus_mask=$((1<<0))
CMIPStatus_mask=$((1<<1))
WANIPStatus_mask=$((1<<2))
IPv4PingStatus_mask=$((1<<3))

bitmask=0
stored_gw_health=0
IsNeedtoRebootDevice=0
RebootReason=""

exec 3>&1 4>&2 >>$SELFHEALFILE 2>&1

##TELEMETRY 2.0 SUPPORT ##RDKB-26620
T2_MSG_CLIENT=/usr/bin/telemetry2_0_client

t2ValNotify() {
    if [ -f $T2_MSG_CLIENT ]; then
        marker=$1
        shift
        $T2_MSG_CLIENT "$marker" "$*"
    fi
}

CheckandSetCMStatus()
{
	cm_status=""
	cm_status=`dmcli eRT retv Device.X_CISCO_COM_CableModem.CMStatus`
	echo_t "cm_status=$cm_status"

	if [ "$cm_status" == "OPERATIONAL" ];then
		cm_status_bit=1
		bitmask=$((bitmask | CMStatus_mask))
	else
		cm_status_bit=0
	fi
	echo_t "cm_status=$cm_status_bit"
#	echo_t "bitmask=$bitmask"
}

CheckandSetCMIPStatus()
{
	cm_ipv4=""
	cm_ipv6=""
	cm_prov=""
	cm_prov=`dmcli eRT retv Device.X_CISCO_COM_CableModem.ProvIpType`

	echo_t "cm_prov=$cm_prov"
        
# checking also if cm prove type is APM(Alternate provision mode) in docsis 3.1 version of AXB6 and CMXB7
	if [ "x$cm_prov" == "xIPv4" ] || [ "x$cm_prov" == "xIPV4" ] || [ "x$cm_prov" == "xAPM" ];then

		cm_ipv4=`dmcli eRT retv Device.X_CISCO_COM_CableModem.IPAddress`
		echo_t "cm_ipv4=$cm_ipv4"

		if [ "$cm_ipv4" != "" ] && [ "$cm_ipv4" != "0.0.0.0" ];then
			cm_ipv4_bit=1
		else
			cm_ipv4_bit=0
		fi
	else
        	cm_ipv4_bit=0
	fi

	if [ "x$cm_prov" == "xIPv6" ] || [ "x$cm_prov" == "xIPV6" ] || [ "x$cm_prov" == "xAPM" ];then

		cm_ipv6=`dmcli eRT retv Device.X_CISCO_COM_CableModem.IPv6Address`
		echo_t "cm_ipv6=$cm_ipv6"

		if [ "$cm_ipv6" != "" ] && [ "$cm_ipv6" != "0000::0000" ];then
			cm_ipv6_bit=1
		else
			cm_ipv6_bit=0
		fi
	else
        	cm_ipv6_bit=0
	fi

#	echo_t "cm_ipv4_bit=$cm_ipv4_bit"
#	echo_t "cm_ipv6_bit=$cm_ipv6_bit"

	if [ "$cm_ipv4_bit" == "1" ] || [ "$cm_ipv6_bit" == "1" ];then
		cm_ip_bit=1
		bitmask=$((bitmask | CMIPStatus_mask))
	else
		cm_ip_bit=0
	fi

	echo_t "cm_ip_status=$cm_ip_bit"
#	echo_t "bitmask=$bitmask"
}

CheckandSetWANIPStatus()
{
	wan_ipv4=""
	wan_ipv6=""
	wan_ipv4=`dmcli eRT retv Device.DeviceInfo.X_COMCAST-COM_WAN_IP`

	if [ "$wan_ipv4" == "" ];then
		wan_ipv4=`ifconfig $WAN_INTERFACE | grep "inet addr" | awk '{print $(NF-2)}' | cut -f2 -d:`
	fi

	wan_ipv6=`dmcli eRT retv Device.DeviceInfo.X_COMCAST-COM_WAN_IPv6`

	if [ "$wan_ipv6" == "" ];then
		wan_ipv6=`ifconfig $WAN_INTERFACE | grep inet6 | grep Global | awk '{print $(NF-1)}' | cut -f1 -d\/`
	fi

	echo_t "wan_ipv4=$wan_ipv4"
	echo_t "wan_ipv6=$wan_ipv6"

	if [ "$wan_ipv4" != "" ] && [ "$wan_ipv4" != "0.0.0.0" ];then
		wan_ipv4_bit=1
	else
		wan_ipv4_bit=0
	fi
#	echo_t "wan_ipv4_bit=$wan_ipv4_bit"

	if [ "$wan_ipv6" != "" ] && [ "$wan_ipv6" != "0000::0000" ];then
		wan_ipv6_bit=1
	else
		wan_ipv6_bit=0
	fi
#	echo_t "wan_ipv6_bit=$wan_ipv6_bit"

	if [ "$wan_ipv4_bit" == "1" ] || [ "$wan_ipv6_bit" == "1" ];then
		wan_ip_bit=1
		bitmask=$((bitmask | WANIPStatus_mask))
	else
		wan_ip_bit=0
	fi

	echo_t "wan_ip_status=$wan_ip_bit"
#	echo_t "bitmask=$bitmask"
}

CheckandSetIPv4PingStatus()
{
	WAN_INTERFACE=$(getWanInterfaceName)
	PING_PACKET_SIZE=56
	PINGCOUNT=3
	RESWAITTIME=3

	IPv4_Gateway_addr=""
	IPv4_Gateway_addr=`sysevent get default_router`
	ping4_success=0
	if [ "$IPv4_Gateway_addr" != "" ]
	then
		PING_OUTPUT=`ping -I $WAN_INTERFACE -c $PINGCOUNT -w $RESWAITTIME -s $PING_PACKET_SIZE $IPv4_Gateway_addr`
		CHECK_PACKET_RECEIVED=`echo $PING_OUTPUT | grep "packet loss" | cut -d"%" -f1 | awk '{print $NF}'`

		if [ "$CHECK_PACKET_RECEIVED" != "" ]
		then
			if [ "$CHECK_PACKET_RECEIVED" -ne 100 ]
			then
				ping4_success=1
				bitmask=$((bitmask | IPv4PingStatus_mask))
			else
				ping4_success=0
			fi
		else
			ping4_success=0
		fi
	fi

	echo_t "ping4_status=$ping4_success"
#	echo_t "bitmask=$bitmask"
}

CompareStoredAndCurrGWHealthStatus()
{
	IsCMFailure=0
	IsCMIPFailure=0
	IsWANIPFailure=0
	IsIPv4Failure=0
	timestamp=`date +%Y-%m-%d_%H-%M-%S`

	#CM_Status
	stored_CMstatus=$((stored_gw_health & CMStatus_mask))
	current_CMstatus=$((bitmask & CMStatus_mask))

	#CM_IP_Status
	stored_CMIPstatus=$((stored_gw_health & CMIPStatus_mask))
	current_CMIPstatus=$((bitmask & CMIPStatus_mask))

	#WAN_IP_Status
	stored_WANIPstatus=$((stored_gw_health & WANIPStatus_mask))
	current_WANIPstatus=$((bitmask & WANIPStatus_mask))

	#IPv4_Ping_Status
	stored_IPv4Pingstatus=$((stored_gw_health & IPv4PingStatus_mask))
	current_IPv4Pingstatus=$((bitmask & IPv4PingStatus_mask))

	if [ $current_CMstatus -eq 0 ] && [ $current_CMstatus -ne $stored_CMstatus ]; then
	   IsCMFailure=1
	fi

	if [ $current_CMIPstatus -eq 0 ] && [ $current_CMIPstatus -ne $stored_CMIPstatus ]; then
	   IsCMIPFailure=1
	fi

	if [ $current_WANIPstatus -eq 0 ] && [ $current_WANIPstatus -ne $stored_WANIPstatus ]; then
	   IsWANIPFailure=1
	fi

	if [ $current_IPv4Pingstatus -eq 0 ] && [ $current_IPv4Pingstatus -ne $stored_IPv4Pingstatus ]; then
	   IsIPv4Failure=1
	fi

	#Check whether we need to reboot the device or not
	if [ $IsCMFailure -eq 1 ] || [ $IsCMIPFailure -eq 1 ] || [ $IsWANIPFailure -eq 1 ] || [ $IsIPv4Failure -eq 1 ]; then
	   IsNeedtoRebootDevice=1
	   RebootReason="wan_link_heal"
	   t2ValNotify "RDKB_SELFHEAL:WAN_Link_Heal" "$timestamp"
	   echo_t "RDKB_SELFHEAL:WAN_Link_Heal"
	fi
	echo_t "IsNeedtoRebootDevice = $IsNeedtoRebootDevice"
}

RfcRebootDebug()
{
	list1=`ls -l /var/`
	list2=`ls -l /var/run/`
	mount=`mount`
	echo_t "####### /var List #######"
	echo "$list1"
	echo_t "####### /var/run List #######"
	echo "$list2"
	echo_t "####### mount List #######"
	echo "$mount"
}
CheckandRebootBasedOnCurrentHealth()
{
#	echo_t "RDKB_SELFHEAL_BOOTUP : gw_health inside CheckandRebootBasedOnCurrentHealth"

	stored_gw_health=`syscfg get gw_health`
	echo_t "gw_health stored = $stored_gw_health"

	CheckandSetCMStatus
	CheckandSetCMIPStatus
if [ "x$MAPT_CONFIG" != "xset" ]; then
	CheckandSetIPv4PingStatus
fi
	CheckandSetWANIPStatus
	CompareStoredAndCurrGWHealthStatus

	echo_t "gw_health current = $bitmask"
	#Check and reboot the device
	if [ $IsNeedtoRebootDevice -eq 1 ]; then
	    echo_t "RDKB_SELFHEAL_BOOTUP : Device is going to reboot Reason[$RebootReason]"
	    if [ -e "/usr/bin/onboarding_log" ]; then
	        /usr/bin/onboarding_log "RDKB_SELFHEAL_BOOTUP : Device is going to reboot Reason[$RebootReason]"
	    fi
	    syscfg set X_RDKCENTRAL-COM_LastRebootReason "$RebootReason"
	    syscfg set X_RDKCENTRAL-COM_LastRebootCounter "1"
	    syscfg set gw_health "$bitmask"
	    syscfg commit
	    RfcRebootDebug
	    /rdklogger/backupLogs.sh true
	fi
}

CheckandStoreCurrentHealth()
{
#	echo_t "RDKB_SELFHEAL : gw_health inside CheckandStoreCurrentHealth"

	stored_gw_health=`syscfg get gw_health`
	echo_t "gw_health stored = $stored_gw_health"

	CheckandSetCMStatus
	CheckandSetCMIPStatus
if [ "x$MAPT_CONFIG" != "xset" ]; then
	CheckandSetIPv4PingStatus
fi
	CheckandSetWANIPStatus

	#Update current gw health status
	syscfg set gw_health "$bitmask" 
        syscfg commit

	echo_t "gw_health current = $bitmask"
}

echo_t "check_gw_health.sh called with $1"

MAPT_CONFIG=`sysevent get mapt_config_flag`

case "$1" in

   bootup-check)

	if [ -f "/nvram/reboot_due_to_sw_upgrade" ]; then
		echo_t "Device is waiting for reboot after CDL , Exiting Wan Link Heal bootup-check"
		exit 0
	fi

        gw_wan_status=$(IsGWinWFO)
        if [ "$gw_wan_status" == "1" ]; then
                echo_t "gw_wan_status : Exiting Wan Link Heal bootup-check due to WFO"
                exit 0
        fi 
	LastrebootReason=`syscfg get X_RDKCENTRAL-COM_LastRebootReason`
	echo_t "LastrebootReason = $LastrebootReason"
	if [ "Software_upgrade" == "$LastrebootReason" ] || [ "forced_software_upgrade" == "$LastrebootReason" ] || [ "PROVISIONING_Image_Upgrade" == "$LastrebootReason" ] || [ "rfc_reboot" == "$LastrebootReason" ]; then
		echo_t "Wan Link Heal for bootup-check invoked"
		CheckandRebootBasedOnCurrentHealth
	fi

   ;;

   store-health)

	echo_t "Wan Link Heal for store-health invoked"
	CheckandStoreCurrentHealth
   ;;

esac

