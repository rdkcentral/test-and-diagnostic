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
HELLO WORLD

source /etc/log_timestamp.sh
source /etc/utopia/service.d/log_env_var.sh
source /etc/waninfo.sh
source /usr/ccsp/tad/corrective_action.sh

WAN_INTERFACE=$(getWanInterfaceName)


# Define lock file
SCRIPT_LOCK="/tmp/check_gw_health.lock"

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

CheckandSetWANIPStatus() {
    echo_t "Starting WAN IP status check..."

    routerMode=`syscfg get last_erouter_mode`
    if [ -z "$routerMode" ]; then
        echo_t "routerMode is not set. Defaulting to 3 (Dual Stack)."
        routerMode=3
    fi

    wan_ipv4=`dmcli eRT retv Device.DeviceInfo.X_COMCAST-COM_WAN_IP`
    [ -z "$wan_ipv4" ] && wan_ipv4=`ifconfig $WAN_INTERFACE | grep "inet addr" | awk '{print $(NF-2)}' | cut -f2 -d:`

    wan_ipv6=`dmcli eRT retv Device.DeviceInfo.X_COMCAST-COM_WAN_IPv6`
    [ -z "$wan_ipv6" ] && wan_ipv6=`ifconfig $WAN_INTERFACE | grep inet6 | grep Global | awk '{print $(NF-1)}' | cut -f1 -d\/`

    echo_t "routerMode=$routerMode"
    echo_t "WAN IPv4=$wan_ipv4"
    echo_t "WAN IPv6=$wan_ipv6"

    wan_ipv4_bit=0
    wan_ipv6_bit=0

    if [ -n "$wan_ipv4" ] && [ "$wan_ipv4" != "0.0.0.0" ]; then
        wan_ipv4_bit=1
        echo_t "Valid WAN IPv4 detected."
    else
        echo_t "WAN IPv4 is invalid or not set."
    fi

    if [ -n "$wan_ipv6" ] && [ "$wan_ipv6" != "0000::0000" ]; then
        wan_ipv6_bit=1
        echo_t "Valid WAN IPv6 detected."
    else
        echo_t "WAN IPv6 is invalid or not set."
    fi

    # Set WAN IP status bit based on router mode
    case "$routerMode" in
        1)
            wan_ip_bit=$wan_ipv4_bit
            [ "$wan_ipv4_bit" -eq 0 ] && echo_t "IPv4-only mode: WAN IPv4 is invalid."
            ;;
        2)
            wan_ip_bit=$wan_ipv6_bit
            [ "$wan_ipv6_bit" -eq 0 ] && echo_t "IPv6-only mode: WAN IPv6 is invalid."
            ;;
        3|*)
            # Dual stack or unknown: set if either IPv4 or IPv6 is valid
            if [ "$wan_ipv4_bit" -eq 1 ] || [ "$wan_ipv6_bit" -eq 1 ]; then
                wan_ip_bit=1
                echo_t "Dual stack mode: At least one valid WAN IP detected."
                [ "$wan_ipv4_bit" -eq 0 ] && echo_t "Dual stack mode: WAN IPv4 is invalid."
                [ "$wan_ipv6_bit" -eq 0 ] && echo_t "Dual stack mode: WAN IPv6 is invalid."
            else
                wan_ip_bit=0
                echo_t "Dual stack mode: Both WAN IPv4 and IPv6 are invalid."
            fi
            ;;
    esac

    # Update bitmask if WAN IP is valid
    if [ "$wan_ip_bit" -eq 1 ]; then
        bitmask=$((bitmask | WANIPStatus_mask))
        echo_t "WAN IP status is valid. Bitmask updated."
    else
        echo_t "WAN IP status is invalid. Bitmask not updated."
    fi

    echo_t "WAN IP Status Bit: $wan_ip_bit"
}


CheckandSetConnectivityStatus() {
    # Extract fallback DNS entries from /etc/resolv.conf
    fallback_ipv4_dns=($(grep '^nameserver' /etc/resolv.conf | grep -E '^[^:]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}'))
    fallback_ipv6_dns=($(grep '^nameserver' /etc/resolv.conf | grep -E '([a-fA-F0-9:]+:+)+[a-fA-F0-9]+' | awk '{print $2}'))

    # Helper to get DNS from sysevent or fallback
    get_dns_server() {
        local dns_type="$1"
        local key1="$2"
        local key2="$3"
        local dns_val=$(sysevent get "$key1")

        if [ -z "$dns_val" ]; then
            echo_t "Primary DNS ($key1) is empty, checking secondary..." >&2
            dns_val=$(sysevent get "$key2")
            if [ -z "$dns_val" ]; then
                echo_t "Secondary DNS ($key2) is also empty, using resolv.conf DNS" >&2
                if [ "$dns_type" = "ipv4" ]; then
                    if [ ${#fallback_ipv4_dns[@]} -ge 1 ]; then
                        dns_val=${fallback_ipv4_dns[0]}
                        if [ -z "$dns_val" ] && [ ${#fallback_ipv4_dns[@]} -ge 2 ]; then
                            dns_val=${fallback_ipv4_dns[1]}
                        fi
                    else
                        echo_t "No IPv4 DNS servers found in resolv.conf" >&2
                    fi
                else
                    if [ ${#fallback_ipv6_dns[@]} -ge 1 ]; then
                        dns_val=${fallback_ipv6_dns[0]}
                        if [ -z "$dns_val" ] && [ ${#fallback_ipv6_dns[@]} -ge 2 ]; then
                            dns_val=${fallback_ipv6_dns[1]}
                        fi
                    else
                        echo_t "No IPv6 DNS servers found in resolv.conf" >&2
                    fi
                fi
            fi
        fi
        echo "$dns_val"
    }

    # Get DNS servers with fallback
    ipv4_dns_0=$(get_dns_server ipv4 ipv4_dns_0 ipv4_dns_1)
    ipv6_dns_0=$(get_dns_server ipv6 ipv6_dns_0 ipv6_dns_1)

    echo_t "Using IPv4 DNS: $ipv4_dns_0"
    echo_t "Using IPv6 DNS: $ipv6_dns_0"
    if [ -z "$ipv4_dns_0" ] && [ -z "$ipv6_dns_0" ]; then
        echo_t "No DNS servers available for connectivity check. Exiting."
        connectivity_status_bit=0
        return
    fi
    echo_t "Starting connectivity status check..."

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
        server_type="$1"
        echo_t "Checking $server_type connectivity with URL $2 using DNS server $3"
        # busybox nslookup does not support specifying ipv6 server directly
        # so using dig for ipv6 checks
        if [ "$server_type" == "ipv4" ]; then
            nslookup $2 $3
            result=$?
        else
            #check if dig is available
            if which dig > /dev/null; then
                output=$(dig @$3 $2)
                echo_t "$output"
                if [ -z "$output" ]; then
                    result=1
                else
                    result=0
                fi
            else
                echo_t "dig command not found, trying nslookup as fallback"
                nslookup $2
                result=$?
            fi
        fi
        return $result
    }

    # Initialize status flags
    webpa_status=1
    xconf_status=1
    ntp_status=1

    # Perform lookups based on router mode
    case "$routerMode" in
        1)
            echo "Router Mode: IPv4 only"
            [ -n "$webpa_url" ] && check_dns "ipv4" "$webpa_url" "$ipv4_dns_0" && webpa_status=0
            [ -n "$xconf_url" ] && check_dns "ipv4" "$xconf_url" "$ipv4_dns_0" && xconf_status=0
            [ -n "$ntp_url" ] && check_dns "ipv4" "$ntp_url" "$ipv4_dns_0" && ntp_status=0
            ;;
        2)
            echo "Router Mode: IPv6 only"
            [ -n "$webpa_url" ] && check_dns "ipv6" "$webpa_url" "$ipv6_dns_0" && webpa_status=0
            [ -n "$xconf_url" ] && check_dns "ipv6" "$xconf_url" "$ipv6_dns_0" && xconf_status=0
            [ -n "$ntp_url" ] && check_dns "ipv6" "$ntp_url" "$ipv6_dns_0" && ntp_status=0
            ;;
        3|*)
            echo "Router Mode: Dual stack or unknown"
            if [ -z "$ipv4_dns_0" ]; then
                echo_t "No IPv4 DNS server available for lookup"
            fi
            if [ -z "$ipv6_dns_0" ]; then
                echo_t "No IPv6 DNS server available for lookup"
            fi
            if [ -n "$webpa_url" ]; then
                webpa_ipv4=1
                webpa_ipv6=1
                [ -n "$ipv4_dns_0" ] && check_dns "ipv4" "$webpa_url" "$ipv4_dns_0" && webpa_ipv4=$?
                [ -n "$ipv6_dns_0" ] && check_dns "ipv6" "$webpa_url" "$ipv6_dns_0" && webpa_ipv6=$? 
                if [ $webpa_ipv4 -eq 0 ] || [ $webpa_ipv6 -eq 0 ]; then
                    webpa_status=0
                fi
                [ $webpa_ipv4 -ne 0 ] && echo_t "WARNING: WebPA IPv4 DNS resolution failed"
                [ $webpa_ipv6 -ne 0 ] && echo_t "WARNING: WebPA IPv6 DNS resolution failed"
            fi

            if [ -n "$xconf_url" ]; then
                xconf_ipv4=1
                xconf_ipv6=1
                [ -n "$ipv4_dns_0" ] && check_dns "ipv4" "$xconf_url" "$ipv4_dns_0" && xconf_ipv4=$?
                [ -n "$ipv6_dns_0" ] && check_dns "ipv6" "$xconf_url" "$ipv6_dns_0" && xconf_ipv6=$?
                if [ $xconf_ipv4 -eq 0 ] || [ $xconf_ipv6 -eq 0 ]; then
                    xconf_status=0
                fi
                [ $xconf_ipv4 -ne 0 ] && echo_t "WARNING: Xconf IPv4 DNS resolution failed"
                [ $xconf_ipv6 -ne 0 ] && echo_t "WARNING: Xconf IPv6 DNS resolution failed"
            fi

            if [ -n "$ntp_url" ]; then
                ntp_ipv4=1
                ntp_ipv6=1
                [ -n "$ipv4_dns_0" ] && check_dns "ipv4" "$ntp_url" "$ipv4_dns_0" && ntp_ipv4=$?
                [ -n "$ipv6_dns_0" ] && check_dns "ipv6" "$ntp_url" "$ipv6_dns_0" && ntp_ipv6=$?
                if [ $ntp_ipv4 -eq 0 ] || [ $ntp_ipv6 -eq 0 ]; then
                    ntp_status=0
                fi
                [ $ntp_ipv4 -ne 0 ] && echo_t "WARNING: NTP IPv4 DNS resolution failed"
                [ $ntp_ipv6 -ne 0 ] && echo_t "WARNING: NTP IPv6 DNS resolution failed"
            fi

            if [ $ntp_ipv4 -ne 0 ] && [ $webpa_ipv4 -ne 0 ] && [ $xconf_ipv4 -ne 0 ]; then
                echo_t "WARNING: All IPv4 DNS resolutions failed"
            fi
            if [ $ntp_ipv6 -ne 0 ] && [ $webpa_ipv6 -ne 0 ] && [ $xconf_ipv6 -ne 0 ]; then
                echo_t "WARNING: All IPv6 DNS resolutions failed"
            fi
            ;;
    esac

    # Log results
    echo_t "WebPA DNS resolution status: $webpa_status (0=success,1=failure)"
    echo_t "Xconf DNS resolution status: $xconf_status (0=success,1=failure)"
    echo_t "NTP DNS resolution status: $ntp_status (0=success,1=failure)"

    # Set connectivity status bit based on DNS resolution results
    if [ $webpa_status -ne 0 ] && [ $xconf_status -ne 0 ] && [ $ntp_status -ne 0 ]; then
        echo_t "Connectivity check failed: All DNS resolutions failed."
        connectivity_status_bit=0
    else
        echo_t "Connectivity check passed: At least one DNS resolution succeeded."
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

            # Cleanup lock
            rm -f $SCRIPT_LOCK

	    RfcRebootDebug
	    rebootNeeded RM "" $RebootReason "1"
	else
            # Cleanup lock
            rm -f $SCRIPT_LOCK
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

# Check if script is already running
if [ -e "$SCRIPT_LOCK" ] && kill -0 `cat $SCRIPT_LOCK` 2>/dev/null; then
    pid=`cat $SCRIPT_LOCK`
    if [ -d /proc/$pid ] && [ -f /proc/$pid/cmdline ]; then
        processName=`cat /proc/$pid/cmdline`
        if echo "$processName" | grep -q `basename $0`; then
            echo "Script is already running with PID $pid. Exiting."
            exit 0
        fi
    fi
fi

# Set trap to remove lock on exit
trap "rm -f $SCRIPT_LOCK; exit 0" INT TERM EXIT

# Create lock
echo $$ > $SCRIPT_LOCK


case "$1" in

   bootup-check)

	if [ -f "/nvram/reboot_due_to_sw_upgrade" ]; then
		echo_t "Device is waiting for reboot after CDL , Exiting Wan Link Heal bootup-check"
                # Cleanup lock
                rm -f $SCRIPT_LOCK
		exit 0
	fi

        gw_wan_status=$(IsGWinWFO)
        if [ "$gw_wan_status" == "1" ]; then
                echo_t "gw_wan_status : Exiting Wan Link Heal bootup-check due to WFO"
                # Cleanup lock
                rm -f $SCRIPT_LOCK
                exit 0
        fi 

	echo_t "Wan Link Heal for bootup-check invoked"
	CheckandRebootBasedOnCurrentHealth

   ;;

   store-health)

	echo_t "Wan Link Heal for store-health Deprecated"
        rm -f $SCRIPT_LOCK
        exit 0
   ;;

esac
