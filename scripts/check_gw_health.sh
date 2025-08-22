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
source /usr/ccsp/tad/corrective_action.sh

WAN_INTERFACE=$(getWanInterfaceName)

#bit mask for corresponding functionality
CMStatus_mask=$((1<<0))
CMIPStatus_mask=$((1<<1))
WANIPStatus_mask=$((1<<2))
ConnectivityStatus_mask=$((1<<3))

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

get_dmcli_value() {
    param=$1
    retries=3
    delay=5
    value=""
    attempt=1
    while [ $retries -gt 0 ]; do
        value=$(dmcli eRT retv "$param")
        if [ -n "$value" ]; then
            echo "$value"
            return 0
        fi
        echo_t "Warning: dmcli returned empty for parameter '$param'. Retrying attempt $attempt in $delay seconds..."
        sleep $delay
        retries=$((retries - 1))
        attempt=$((attempt + 1))
    done
    echo ""
    return 1
}

CheckandSetCMStatus()
{
	cm_status=""
	cm_status=$(get_dmcli_value "Device.X_CISCO_COM_CableModem.CMStatus")
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
	cm_prov=$(get_dmcli_value "Device.X_CISCO_COM_CableModem.ProvIpType")

	echo_t "cm_prov=$cm_prov"
        
# checking also if cm prove type is APM(Alternate provision mode) in docsis 3.1 version of AXB6 and CMXB7
	if [ "x$cm_prov" == "xIPv4" ] || [ "x$cm_prov" == "xIPV4" ] || [ "x$cm_prov" == "xAPM" ];then

		cm_ipv4=$(get_dmcli_value "Device.X_CISCO_COM_CableModem.IPAddress")
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

		cm_ipv6=$(get_dmcli_value "Device.X_CISCO_COM_CableModem.IPv6Address")
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
    routerMode=`syscfg get last_erouter_mode`
    if [ -z "$routerMode" ]; then
        echo_t "routerMode is not set. Defaulting to 3."
        routerMode=3
    fi

    wan_ipv4=""
    wan_ipv6=""

    wan_ipv4=`dmcli eRT retv Device.DeviceInfo.X_COMCAST-COM_WAN_IP`
    if [ "$wan_ipv4" == "" ]; then
        wan_ipv4=`ifconfig $WAN_INTERFACE | grep "inet addr" | awk '{print $(NF-2)}' | cut -f2 -d:`
    fi

    wan_ipv6=`dmcli eRT retv Device.DeviceInfo.X_COMCAST-COM_WAN_IPv6`
    if [ "$wan_ipv6" == "" ]; then
        wan_ipv6=`ifconfig $WAN_INTERFACE | grep inet6 | grep Global | awk '{print $(NF-1)}' | cut -f1 -d\/`
    fi

    echo_t "routerMode=$routerMode"
    echo_t "wan_ipv4=$wan_ipv4"
    echo_t "wan_ipv6=$wan_ipv6"

    if [ "$wan_ipv4" != "" ] && [ "$wan_ipv4" != "0.0.0.0" ]; then
        wan_ipv4_bit=1
    else
        wan_ipv4_bit=0
    fi

    if [ "$wan_ipv6" != "" ] && [ "$wan_ipv6" != "0000::0000" ]; then
        wan_ipv6_bit=1
    else
        wan_ipv6_bit=0
    fi

    case "$routerMode" in
        1)
            wan_ip_bit=$wan_ipv4_bit
            ;;
        2)
            wan_ip_bit=$wan_ipv6_bit
            ;;
        3)
            if [ "$wan_ipv4_bit" == "1" ] && [ "$wan_ipv6_bit" == "1" ]; then
                wan_ip_bit=1
            else
                wan_ip_bit=0
            fi
            ;;
        *)
            # Treat unknown or empty mode as dual stack
            if [ "$wan_ipv4_bit" == "1" ] && [ "$wan_ipv6_bit" == "1" ]; then
                wan_ip_bit=1
            else
                wan_ip_bit=0
            fi
            ;;
    esac

    if [ "$wan_ip_bit" == "1" ]; then
        bitmask=$((bitmask | WANIPStatus_mask))
    fi

    echo_t "wan_ip_status=$wan_ip_bit"
}



CheckandSetConnectivityStatus() {

    # Get DNS servers
    ipv4_dns_0=$(sysevent get ipv4_dns_0)
    ipv4_dns_1=$(sysevent get ipv4_dns_1)
    ipv6_dns_0=$(sysevent get ipv6_dns_0)
    ipv6_dns_1=$(sysevent get ipv6_dns_1)

    # Fallback to secondary DNS if primary is empty
    [ -z "$ipv4_dns_0" ] && ipv4_dns_0="$ipv4_dns_1"
    [ -z "$ipv6_dns_0" ] && ipv6_dns_0="$ipv6_dns_1"

    # Get WebPA and Xconf URLs
    webpa_url=`dmcli eRT retv Device.X_RDKCENTRAL-COM_Webpa.DNSText.URL`
    xconf_url=`dmcli eRT retv Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.XconfURL | sed -e 's~http[s]*://~~'`
    ntp_url=`dmcli eRT retv Device.Time.NTPServer1`

    # Log empty URL warnings
    [ -z "$webpa_url" ] && echo_t "Warning: WebPA URL is empty"
    [ -z "$xconf_url" ] && echo_t "Warning: Xconf URL is empty"
    [ -z "$ntp_url" ] && echo_t "Warning: NTP URL is empty"

    # Function to check DNS resolution
    check_dns() {
        nslookup "$1" "$2" > /dev/null 2>&1
        return $?
    }

    # Initialize status flags
    webpa_status=1
    xconf_status=1
    ntp_status=1

    # Perform lookups based on router mode
    case "$routerMode" in
        1)
            echo "Router Mode: IPv4 only"
            [ -n "$webpa_url" ] && check_dns "$webpa_url" "$ipv4_dns_0" && webpa_status=0
            [ -n "$xconf_url" ] && check_dns "$xconf_url" "$ipv4_dns_0" && xconf_status=0
            [ -n "$ntp_url" ] && check_dns "$ntp_url" "$ipv4_dns_0" && ntp_status=0
            ;;
        2)
            echo "Router Mode: IPv6 only"
            [ -n "$webpa_url" ] && check_dns "$webpa_url" "$ipv6_dns_0" && webpa_status=0
            [ -n "$xconf_url" ] && check_dns "$xconf_url" "$ipv6_dns_0" && xconf_status=0
            [ -n "$ntp_url" ] && check_dns "$ntp_url" "$ipv6_dns_0" && ntp_status=0
            ;;
        3)
            echo "Router Mode: Dual stack"
            if [ -n "$webpa_url" ]; then
                check_dns "$webpa_url" "$ipv4_dns_0"
                webpa_ipv4=$?
                check_dns "$webpa_url" "$ipv6_dns_0"
                webpa_ipv6=$?
                [ $webpa_ipv4 -eq 0 ] && [ $webpa_ipv6 -eq 0 ] && webpa_status=0 || webpa_status=1
            fi

            if [ -n "$xconf_url" ]; then
                check_dns "$xconf_url" "$ipv4_dns_0"
                xconf_ipv4=$?
                check_dns "$xconf_url" "$ipv6_dns_0"
                xconf_ipv6=$?
                [ $xconf_ipv4 -eq 0 ] && [ $xconf_ipv6 -eq 0 ] && xconf_status=0 || xconf_status=1
            fi

            if [ -n "$ntp_url" ]; then
                check_dns "$ntp_url" "$ipv4_dns_0"
                ntp_ipv4=$?
                check_dns "$ntp_url" "$ipv6_dns_0"
                ntp_ipv6=$?
                [ $ntp_ipv4 -eq 0 ] && [ $ntp_ipv6 -eq 0 ] && ntp_status=0 || ntp_status=1
            fi
            ;;
        *)
            echo "Unknown router mode: $routerMode. Defaulting to dual stack."
            if [ -n "$webpa_url" ]; then
                check_dns "$webpa_url" "$ipv4_dns_0"
                webpa_ipv4=$?
                check_dns "$webpa_url" "$ipv6_dns_0"
                webpa_ipv6=$?
                [ $webpa_ipv4 -eq 0 ] && [ $webpa_ipv6 -eq 0 ] && webpa_status=0 || webpa_status=1
            fi

            if [ -n "$xconf_url" ]; then
                check_dns "$xconf_url" "$ipv4_dns_0"
                xconf_ipv4=$?
                check_dns "$xconf_url" "$ipv6_dns_0"
                xconf_ipv6=$?
                [ $xconf_ipv4 -eq 0 ] && [ $xconf_ipv6 -eq 0 ] && xconf_status=0 || xconf_status=1
            fi

            if [ -n "$ntp_url" ]; then
                check_dns "$ntp_url" "$ipv4_dns_0"
                ntp_ipv4=$?
                check_dns "$ntp_url" "$ipv6_dns_0"
                ntp_ipv6=$?
                [ $ntp_ipv4 -eq 0 ] && [ $ntp_ipv6 -eq 0 ] && ntp_status=0 || ntp_status=1
            fi
            ;;
    esac

    # Log results
    echo "WebPA DNS status: $webpa_status"
    echo "Xconf DNS status: $xconf_status"
    echo "NTP DNS status: $ntp_status"

    # Set connectivity status bit based on DNS resolution results
    if [ $webpa_status -ne 0 ] && [ $xconf_status -ne 0 ] && [ $ntp_status -ne 0 ]; then
        connectivity_status_bit=0
    else
        echo "At least one DNS resolution succeeded."
        connectivity_status_bit=1
        bitmask=$((bitmask | ConnectivityStatus_mask))
    fi

    echo_t "Connectivity status bit: $connectivity_status_bit"
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

CheckAndRebootIfNeeded()
{
	echo_t "RDKB_SELFHEAL_BOOTUP : Checking if reboot is needed based on current health status"
	timestamp=$(date +%s)
	echo_t "RDKB_SELFHEAL_BOOTUP : Current timestamp = $timestamp"

	if [ -z "$1" ]; then
	    CheckandSetCMIPStatus
	    current_CMstatus=$((bitmask & CMStatus_mask))
	    current_CMIPstatus=$((bitmask & CMIPStatus_mask))
	fi

	CheckandSetWANIPStatus

	CheckandSetConnectivityStatus

	current_WANIPstatus=$((bitmask & WANIPStatus_mask))
	current_ConnectivityStatus=$((bitmask & ConnectivityStatus_mask))

	echo_t "Status Breakdown:"
	if [ -z "$1" ]; then
	    echo_t "  CMStatus = $current_CMstatus"
	    echo_t "  CMIPStatus = $current_CMIPstatus"
	    if [ $current_CMIPstatus -eq 0 ]; then
		echo_t "CM is Operational,but CMIPStatus is not healthy, checking WAN and Connectivity status..."
	    fi
	fi
	echo_t "  WANIPStatus = $current_WANIPstatus"
	echo_t "  ConnectivityStatus = $current_ConnectivityStatus"

	fail_status=""
	IsNeedtoRebootDevice=0

	echo_t "Checking WAN and Connectivity status..."
	if [ $current_WANIPstatus -eq 0 ] || [ $current_ConnectivityStatus -eq 0 ]; then
            [ $current_WANIPstatus -eq 0 ] && fail_status="${fail_status}WANIP "
            [ $current_ConnectivityStatus -eq 0 ] && fail_status="${fail_status}Connectivity "

	    if [ -z "$1" ]; then
		IsNeedtoRebootDevice=1
		echo_t "RDKB_SELFHEAL_BOOTUP : Device is not healthy, failure in: ${fail_status}"
	    else
		echo_t "WAN and Connectivity are not recovered, checking CM status again..."
		return
	    fi
	fi


	if [ $IsNeedtoRebootDevice -eq 1 ]; then
	    echo_t "RDKB_SELFHEAL_BOOTUP : Device is not healthy, failure in: ${fail_status}"
	    RebootReason="wan_link_heal"
	    echo_t "RDKB_SELFHEAL_BOOTUP : Device is going to reboot Reason[$RebootReason]"

	    if [ -e "/usr/bin/onboarding_log" ]; then
		/usr/bin/onboarding_log "RDKB_SELFHEAL_BOOTUP : Device is going to reboot Reason[$RebootReason]"
	    fi

	    t2ValNotify "RDKB_SELFHEAL:WAN_Link_Heal" "$timestamp"
	    echo_t "RDKB_SELFHEAL:WAN_Link_Heal"
	    echo_t "IsNeedtoRebootDevice = $IsNeedtoRebootDevice"

	    RfcRebootDebug
	    rebootNeeded RM "" $RebootReason "1"
	else
	    echo_t "RDKB_SELFHEAL_BOOTUP : Device is healthy. No reboot required."
            exit 0
	fi
}

CheckandRebootBasedOnCurrentHealth()
{
    CheckandSetCMStatus

    current_CMstatus=$((bitmask & CMStatus_mask))

    while [ "$current_CMstatus" -eq 0 ]; do
        echo "CM not operational. Retrying in 3 minutes..."
        sleep 180
	CheckandSetCMStatus

        current_CMstatus=$((bitmask & CMStatus_mask))

	if [ "$current_CMstatus" -eq 0 ]; then
	    echo "CM still not operational. Checking other status..."
            CheckAndRebootIfNeeded "skip_cm_ip_check"
        fi
    done

    echo "CM is operational. Waiting 10 minutes for WAN manager to lock WAN type..."
    sleep 600
    CheckAndRebootIfNeeded ""

}


echo_t "check_gw_health.sh called with $1"


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

	echo_t "Wan Link Heal for bootup-check invoked"
	CheckandRebootBasedOnCurrentHealth

   ;;

   store-health)

	echo_t "Wan Link Heal for store-health Deprecated"
        exit 0
   ;;

esac
