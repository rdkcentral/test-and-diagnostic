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

TAD_PATH="/usr/ccsp/tad/"

source $TAD_PATH/corrective_action.sh
source $TAD_PATH/boot_mode.sh
source /etc/waninfo.sh

exec 3>&1 4>&2 >>$SELFHEALFILE 2>&1

WAN_INTERFACE=$(getWanInterfaceName)
WAN_INTERFACE_IPV4=$(getWanInterfaceName)

UseLANIFIPV6=`sysevent get LANIPv6GUASupport`

calcRandom=1
ping4_server_num=0
ping6_server_num=0
ping4_success=0
ping6_success=0
ping4_failed=0
ping6_failed=0

SELFHEAL_CONN_TMP_DIR="/tmp/.selfheal_conn"
UPLOAD_SCHEDULE_FILE="$SELFHEAL_CONN_TMP_DIR/.selfheal_schedule.log"
DELAY_COUNTDOWN_FILE="$SELFHEAL_CONN_TMP_DIR/.selfheal_delay_countdown"
MODE_FILE="$SELFHEAL_CONN_TMP_DIR/.selfheal_mode"
LAST_EXECUTION_FILE="$SELFHEAL_CONN_TMP_DIR/.selfheal_last_exec"

if [ ! -d "$SELFHEAL_CONN_TMP_DIR" ]; then
    mkdir -p "$SELFHEAL_CONN_TMP_DIR"
fi

getCorrectiveActionState() {
    Corrective_Action=`syscfg get ConnTest_CorrectiveAction`
    echo "$Corrective_Action"
}

generate_random_sleep()
{
    rand_min=0
    rand_sec=0

    # Calculate random min
    rand_min=`awk -v min=10 -v max=59 -v seed="$(date +%N)" 'BEGIN{srand(seed);print int(min+rand()*(max-min+1))}'`

    # Calculate random second
    rand_sec=`awk -v min=0 -v max=59 -v seed="$(date +%N)" 'BEGIN{srand(seed);print int(min+rand()*(max-min+1))}'`

    sec_to_sleep=$(($rand_min*60 + $rand_sec))
    echo_t "self_heal_connectivity_test is going into sleep for $sec_to_sleep sec"
}

ready_to_ping_test()
{
    INTERVAL_MIN=`syscfg get ConnTest_PingInterval`
    [ -z "$INTERVAL_MIN" ] && INTERVAL_MIN=60

    # Validate INTERVAL_MIN is numeric (POSIX-safe)
    case "$INTERVAL_MIN" in
        ''|*[!0-9]*) INTERVAL_MIN=60 ;;
    esac

    INTERVAL_SEC=$((INTERVAL_MIN * 60))
    current_time=$(date +%s)

    if [ ! -f "$LAST_EXECUTION_FILE" ]; then
		return 0
    fi

    last_time=$(cat "$LAST_EXECUTION_FILE")
    # Validate last_time is numeric (POSIX-safe)
    case "$last_time" in
        ''|*[!0-9]*) return 0 ;;
    esac

    diff=$((current_time - last_time))
    remaining=$((INTERVAL_SEC - diff))

    if [ "$diff" -ge "$INTERVAL_SEC" ]; then
        echo_t "Interval met ($diff >= $INTERVAL_SEC)" 
        return 0
    elif [ "$remaining" -le 600 ]; then
        echo_t "Interval almost met, sleeping $remaining sec to align exact run" 
        sleep "$remaining"
        echo_t "Interval met after sleep, running ping now" 
        return 0
    else
        return 1
    fi
}

calcRandTimetoStartPing()
{
    if [ "$CRON_MODE" = "1" ]; then
        if [ ! -f "$DELAY_COUNTDOWN_FILE" ] && [ ! -f "$MODE_FILE" ]; then
            generate_random_sleep
            remaining=$((sec_to_sleep - 600))
            [ "$remaining" -lt 0 ] && remaining="$sec_to_sleep"
            echo "$remaining" > "$DELAY_COUNTDOWN_FILE"
            echo_t "RDKB_SELF_HEAL_CONN: Initial random delay stored: $sec_to_sleep seconds" 
            echo "DELAY" > "$MODE_FILE"
            echo_t "RDKB_SELF_HEAL_CONN: Remaining delay: $remaining sec"
            exit 0
        fi

        MODE=$(cat "$MODE_FILE" 2>/dev/null)

        if [ "$MODE" = "DELAY" ]; then
            remaining=$(cat "$DELAY_COUNTDOWN_FILE" 2>/dev/null)
            [ -z "$remaining" ] && remaining=0

            if [ "$remaining" -le 600 ]; then
                echo_t "Final delay sleep: $remaining sec" 
                [ "$remaining" -gt 0 ] && sleep "$remaining"

                rm -f "$DELAY_COUNTDOWN_FILE"
                echo "NORMAL" > "$MODE_FILE"

                echo_t "Delay complete -> NORMAL mode" 
            else
                remaining=$((remaining - 600))
                echo "$remaining" > "$DELAY_COUNTDOWN_FILE"

                exit 0
            fi
        fi
    else
        generate_random_sleep
        echo_t "RDKB_SELF_HEAL_CONN: Sleeping for $sec_to_sleep seconds" 
        sleep $sec_to_sleep;
    fi
}

# A generic function which can be used for any URL parsing
removehttp()
{
	urlToCheck=$1
	haveHttp=`echo $urlToCheck | grep //`
	if [ "$haveHttp" != "" ]
	then
		url=`echo $urlToCheck | cut -f2 -d":" | cut -f3 -d"/"`
		echo $url
	else
		haveSlashAlone=`echo $urlToCheck | grep /`
		if [ "$haveSlashAlone" != "" ]
		then
			url=`echo $urlToCheck | cut -f1 -d"/"`
			echo $url
		else	
			echo $urlToCheck
		fi
	fi
}

runDNSPingTest() 
{
	DNS_PING_TEST_STATUS=`syscfg get selfheal_dns_pingtest_enable`
	
	if [ "$DNS_PING_TEST_STATUS" = "true" ]
	then
		urlToVerify=`syscfg get selfheal_dns_pingtest_url`
		
		if [ -z "$urlToVerify" ]
		then
			echo_t "DNS Response: DNS PING Test URL is empty"
			return
		fi

		DNS_PING_TEST_URL=`removehttp $urlToVerify`

		if [ "$DNS_PING_TEST_URL" = "" ]
		then
			echo_t "DNS Response: DNS PING Test URL is empty"
			return
		fi

		nslookup $DNS_PING_TEST_URL > /dev/null 2>&1
		RESPONSE=$?

		# Validate RESPONSE is numeric (POSIX-safe)
		case "$RESPONSE" in
		    ''|*[!0-9]*) RESPONSE=1 ;;
		esac

		if [ "$RESPONSE" -eq 0 ]
		then
			echo_t "DNS Response: Got success response for this URL $DNS_PING_TEST_URL"
		else
			echo_t "DNS Response: fail to resolve this URL $DNS_PING_TEST_URL"

			if [ `getCorrectiveActionState` = "true" ]
			then
				echo_t "RDKB_SELFHEAL : Taking corrective action"
				resetNeeded "" PING
			fi
		fi
	fi
}

# Get ULA (Unique Local Address - fd00::) IPv6 gateway address
# ULA addresses are used in vCMTS environments where Link-Local (fe80::) pings
# are blocked by Source Address Verification (SAV)
# COMCAST-SPECIFIC: Only applicable to Comcast partner deployments
# Note: ULA-based checks only validate connectivity up to the upstream gateway,
# not end-to-end connectivity. ICMP echo must be permitted in the network.
# Returns the fd00:: gateway address
getULAIPv6GatewayAddr() {
    local wan_interface="$1"

    # Guard: return if interface parameter is empty
    if [ -z "$wan_interface" ]; then
        return
    fi

    # Restrict ULA ping to Comcast platforms only
    # Check PartnerId to determine if this is a Comcast deployment
    # Use robust dmcli parsing with awk to handle varying output formats
    local partnerId=`dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.PartnerId 2>/dev/null | awk '/value:/ {print $NF}' | tr -d ' '`

    if [ "$partnerId" != "comcast" ]; then
        return
    fi

    # Extract ULA gateway from routing table
    # Prefer actual gateway from 'default via fd00::...' route
    local ula_gateway=`ip -6 route list dev "$wan_interface" | awk '/^default via fd00/ {print $3; exit}'`
    
    # Fallback: if no default gateway, derive from fd00 prefix with ::1 heuristic
    if [ -z "$ula_gateway" ]; then
        local fd00_prefix=`ip -6 route list dev "$wan_interface" | awk '/^fd00/ {print $1}' | cut -f1 -d\/ | head -n1`
        if [ -n "$fd00_prefix" ]; then
            fd00_prefix=`echo "$fd00_prefix" | sed 's/:*$//'`
            ula_gateway="${fd00_prefix}::1"
        fi
    fi

    # Return the gateway if found
    if [ -n "$ula_gateway" ]; then
        echo "$ula_gateway"
    fi
}

# Helper function to perform IPv6 gateway ping test and parse results
# Reduces code duplication between ULA and Link-Local ping paths
# Parameters: $1 = gateway address to ping
# Returns: 0 on success, 1 on failure
# Sets globals: ping6_success, ping6_failed
performIPv6GatewayPing() {
    local gateway_addr="$1"
    local ping_output
    local packet_loss

    if [ -z "$gateway_addr" ]; then
        return 1
    fi

    ping_output=`ping6 -I "$WAN_INTERFACE" -c "$PINGCOUNT" -w "$RESWAITTIME" -s "$PING_PACKET_SIZE" "$gateway_addr" 2>/dev/null`
    packet_loss=`echo $ping_output | grep "packet loss" | cut -d"%" -f1 | awk '{print $NF}'`

    # Validate packet_loss is numeric (POSIX-safe)
    case "$packet_loss" in
        ''|*[!0-9]*) packet_loss=100 ;;
    esac

    if [ -n "$packet_loss" ] && [ "$packet_loss" -ne 100 ]; then
        ping6_success=1
        ping6_failed=0
        # Extract and log latency
        PING_LATENCY="PING_LATENCY_GWIPv6:"
        PING_LATENCY_VAL=`echo $ping_output | awk 'BEGIN {FS="ms"} { for(i=1;i<=NF;i++) print $i}' | grep "time=" | cut -d"=" -f4`
        PING_LATENCY_VAL=${PING_LATENCY_VAL%?};
        echo $PING_LATENCY$PING_LATENCY_VAL|sed 's/ /,/g'
        return 0
    else
        ping6_failed=1
        return 1
    fi
}

runPingTest()
{
	#BCOMB-1120 getWanInterfaceName returning NULL at the start of device.So calling here if value is NULL
	if [ -z "$WAN_INTERFACE" ]; then
		WAN_INTERFACE=$(getWanInterfaceName)
	fi

	# Initialize ula_gw to avoid stale values from previous iterations
	ula_gw=""

	PING_PACKET_SIZE=`syscfg get selfheal_ping_DataBlockSize`
	PINGCOUNT=`syscfg get ConnTest_NumPingsPerServer`

	if [ "$PINGCOUNT" = "" ] 
	then
		PINGCOUNT=3
	fi

#	MINPINGSERVER=`syscfg get ConnTest_MinNumPingServer`

#	if [ "$MINPINGSERVER" = "" ] 
#	then
#		MINPINGSERVER=1
#	fi	

	RESWAITTIME=`syscfg get ConnTest_PingRespWaitTime`

	if [ "$RESWAITTIME" = "" ] 
	then
		RESWAITTIME=1000
	fi

	# Validate RESWAITTIME is numeric before arithmetic operations (POSIX-safe)
	case "$RESWAITTIME" in
	    ''|*[!0-9]*) RESWAITTIME=1000 ;;
	esac
	RESWAITTIME=$(($RESWAITTIME/1000))

	# Validate PINGCOUNT is numeric before arithmetic operations (POSIX-safe)
	case "$PINGCOUNT" in
	    ''|*[!0-9]*) PINGCOUNT=3 ;;
	esac
	RESWAITTIME=$(($RESWAITTIME*$PINGCOUNT))


        IPv4_Gateway_addr=""
	#LTE-1335 ping to IPv4 address should be xb's br-403 IPV4 for xle.
	if [ "$BOX_TYPE" = "WNXL11BWL" ] 
	then
		IPv4_Gateway_addr=`ip route show default | grep "$WAN_INTERFACE" | awk '{print $3}'`
		echo_t "RDKB_SELFHEAL : $WAN_INTERFACE IPv4 address is $IPv4_Gateway_addr"		
	else
        	IPv4_Gateway_addr=`sysevent get default_router`
	fi

        IPv6_Gateway_addr=""
        #LTE-1335 ping Ipv6 not needed for XLE.
	if [ "$BOX_TYPE" != "WNXL11BWL" ]
        then
	erouterIP6=`ifconfig $WAN_INTERFACE | grep inet6 | grep Global | head -n1 | awk '{print $(NF-1)}' | cut -f1 -d:`

        if [ "$erouterIP6" != "" ]
        then
	   if [ "$BOX_TYPE" = "XF3" ] && [ -n "$IPv4_Gateway_addr" ]
           then
              #XF3-5270
              #Getting CMTS MAC from `ip -4 neigh show`(arp -an)
              CMTS_MAC=`ip -4 neigh show dev erouter0 | grep "$IPv4_Gateway_addr" | grep lladdr | cut -f3 -d' '`
              
              # Only proceed with CMTS_MAC-based lookup if MAC was found
              if [ -n "$CMTS_MAC" ]; then
                  IPv6_Gateway_addr=`ip -6 neigh show dev erouter0 | grep "$CMTS_MAC" | grep lladdr | grep "$erouterIP6" | cut -f1 -d' '`

                  if [ -z "$IPv6_Gateway_addr" ]
                  then
                     IPv6_Gateway_addr=`ip -6 neigh show dev erouter0 | grep "$CMTS_MAC" | grep lladdr | grep fe80 | cut -f1 -d' '`
                  fi
              fi
           fi
           
           # If XF3 CMTS_MAC lookup failed or not XF3, use standard neighbor table method
           if [ -z "$IPv6_Gateway_addr" ]
           then
              # firstly, use ipv6 neighbor table
              routeEntry=`ip -6 neigh show | grep "$WAN_INTERFACE" | grep "$erouterIP6"`
              IPv6_Gateway_addr=`echo "$routeEntry" | grep lladdr |cut -f1 -d ' '`

              # ARRISXB6-10567
              # If IPv6_Gateway_addr not found in neigbor table, use ipv6 default route,
              # ip -6 route list
              # default via fe80::201:5cff:fe85:c046 dev erouter0 proto ra metric 1024 expires 1799sec
              if [ -z "$IPv6_Gateway_addr" ]
              then
                  IPv6_Gateway_addr=`ip -6 route list | grep "default via" | grep "$WAN_INTERFACE" | grep fe80 | cut -f3 -d' '`
                  echo "IPv6 default route $IPv6_Gateway_addr"
              fi
           fi
	fi	

	#RDKB-21946
	#If GW IPv6 is missing in both route list and neighbour list checking for Link Local GW ipv6 in neighbour list and    	
	#Checking if route list returns Box_IPv6_addr as IPv6_Gateway_addr	

	Box_IPv6_addr=`ifconfig $WAN_INTERFACE | grep inet6 | grep Global | head -n1 | awk '{print $(NF-1)}' | cut -f1 -d\/`	
	
	if [ "$BOX_TYPE" != "XF3" ]
	then
           if [ -z "$IPv6_Gateway_addr" ] || [ "$IPv6_Gateway_addr" = "$Box_IPv6_addr" ]
	   then
	      erouterIP6=`ifconfig "$WAN_INTERFACE" | grep inet6 | grep Link | head -n1 | awk '{print $(NF-1)}' | cut -f1 -d:`
	      routeEntry=`ip -6 neigh show | grep "$WAN_INTERFACE" | grep "$erouterIP6"`
              IPv6_Gateway_addr=`echo "$routeEntry" | grep lladdr |cut -f1 -d ' '` 	
    	   fi
	fi	
	fi #LTE-133 ping to ipv6 not needed for xle.
    if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] ||  [ "$BOX_TYPE" = "SR213" ] || [ "$UseLANIFIPV6" = "true" ]
    then
        IPv6_Gateway_addr=`ip -6 neigh show | grep "$WAN_INTERFACE" | grep lladdr |cut -f1 -d ' '`
    fi

	if [ "$IPv4_Gateway_addr" != "" ] && [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$MAPT_CONFIG" != "set" ] && [ "$UseLANIFIPV6" != "true" ]
	then
		PING_OUTPUT=`ping -I "$WAN_INTERFACE" -c "$PINGCOUNT" -w "$RESWAITTIME" -s "$PING_PACKET_SIZE" "$IPv4_Gateway_addr"`
		CHECK_PACKET_RECEIVED=`echo $PING_OUTPUT | grep "packet loss" | cut -d"%" -f1 | awk '{print $NF}'`

		# Validate CHECK_PACKET_RECEIVED is numeric (POSIX-safe)
		case "$CHECK_PACKET_RECEIVED" in
		    ''|*[!0-9]*) CHECK_PACKET_RECEIVED=100 ;;
		esac

		if [ "$CHECK_PACKET_RECEIVED" != "" ]
		then
			if [ "$CHECK_PACKET_RECEIVED" -ne 100 ] 
			then
				ping4_success=1
				PING_LATENCY="PING_LATENCY_GWIPv4:"
				PING_LATENCY_VAL=`echo $PING_OUTPUT | awk 'BEGIN {FS="ms"} { for(i=1;i<=NF;i++) print $i}' | grep "time=" | cut -d"=" -f4`
				PING_LATENCY_VAL=${PING_LATENCY_VAL%?};
				echo $PING_LATENCY$PING_LATENCY_VAL|sed 's/ /,/g'
			else
				ping4_failed=1
			fi
		else
			ping4_failed=1
		fi
	fi

    # For HUB4/SR300/SE501/SR213, Using IPOE Health Check Status
    if [ "$IPv4_Gateway_addr" != "" ] && ([ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$UseLANIFIPV6" = "true" ])
    then
        IPOE_HEALTH_CHECK_STATUS_IPV4=`sysevent get ipoe_health_check_ipv4_status`
        if [ "$IPOE_HEALTH_CHECK_STATUS_IPV4" = "success" ]
        then
            ping4_success=1
        else
            ping4_failed=1
        fi
    fi

    	#LTE-1335 ping to ipv6 not needed for xle.
	if [ "$BOX_TYPE" != "WNXL11BWL" ]
	then
		# Decouple ULA test from IPv6_Gateway_addr check - ULA should work even if LL detection fails
		if [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$UseLANIFIPV6" != "true" ]
		then
			echo_t "RDKB_SELFHEAL : Testing IPv6 connectivity on $WAN_INTERFACE"

			# Check for ULA (fd00::) address first - used in vCMTS environments where LL pings are blocked by SAV
			# Currently available on TXB7 and TXB8 platforms
			ula_gw=`getULAIPv6GatewayAddr "$WAN_INTERFACE"`

			if [ -n "$ula_gw" ]; then
				# Platform HAS ULA - perform ULA ping test (preferred method)
				echo_t "RDKB_SELFHEAL : ULA (fd00::) detected. Testing with ULA gateway address: $ula_gw"

				if performIPv6GatewayPing "$ula_gw"; then
					echo_t "RDKB_SELFHEAL : IPv6 connectivity test successful using ULA address"
				else
					# ULA ping failed - this is a real failure
					echo_t "RDKB_SELFHEAL : ULA IPv6 ping failed"
				fi
			elif [ -n "$IPv6_Gateway_addr" ]; then
				# No ULA available - fallback to standard Link-Local gateway ping
				echo_t "RDKB_SELFHEAL : No ULA detected. Falling back to Link-Local gateway ping."
				for gw_addr in $IPv6_Gateway_addr
				do
					if performIPv6GatewayPing "$gw_addr"; then
						# Ping succeeded, exit loop
						break
					fi
				done

				# Removed IPv6_Gateway_addr_global ping - it was pinging device's own address
				# which caused false positives. Only Link-Local gateway ping is valid.
			else
				# No ULA and no Link-Local gateway detected
				echo_t "RDKB_SELFHEAL : No IPv6 gateway addresses detected (neither ULA nor Link-Local)"
				ping6_success=0
				ping6_failed=1
			fi
		fi

	fi #LTE-1335 Ping to ipv6 not needed for xle.
    # For HUB4/SR300/SE501/SR213, Using IPOE Health Check Status
    if [ "$IPv6_Gateway_addr" != "" ] && ([ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$UseLANIFIPV6" = "true" ])
    then
        IPOE_HEALTH_CHECK_STATUS_IPV6=`sysevent get ipoe_health_check_ipv6_status`
        if [ "$IPOE_HEALTH_CHECK_STATUS_IPV6" = "success" ]
        then
            ping6_success=1
        else
            ping6_failed=1
        fi
    fi

	if [ "$ping4_success" -ne 1 ] &&  [ "$ping6_success" -ne 1 ] && [ "$MAPT_CONFIG" != "set" ]
	then
		if [ -z "$IPv4_Gateway_addr" ]
		then
			echo_t "RDKB_SELFHEAL : No IPv4 Gateway Address detected"
		else
			echo_t "RDKB_SELFHEAL : Ping to IPv4 Gateway Address failed."
			t2CountNotify "RF_ERROR_IPV4PingFailed"
			echo_t "PING_FAILED:$IPv4_Gateway_addr"
		fi
		#LTE-1335 Ping to ipv6 not needed for xle.
		if [ "$BOX_TYPE" != "WNXL11BWL" ]
		then
	    	last_erouter_mode=$(sysevent get last_erouter_mode)
			if [ -z "$last_erouter_mode" ]
			then
				echo_t "RDKB_SELFHEAL : erouter mode is null, fetch from syscfg."
				last_erouter_mode=$(syscfg get last_erouter_mode)
			fi

			# Validate last_erouter_mode is numeric (POSIX-safe)
			case "$last_erouter_mode" in
			    ''|*[!0-9]*) last_erouter_mode=0 ;;
			esac

			# Only report IPv6 issues if device is in IPv6-capable mode (mode > 1)
			# This prevents misleading IPv6 telemetry in IPv4-only deployments
			if [ -n "$last_erouter_mode" ] && [ "$last_erouter_mode" -gt 1 ]
			then
				# Check both Link-Local and ULA - only report "no gateway" if BOTH are absent
				if [ -z "$IPv6_Gateway_addr" ] && [ -z "$ula_gw" ]
				then
					echo_t "RDKB_SELFHEAL : No IPv6 Gateway Address detected"
					t2CountNotify "SYS_INFO_NoIPv6_Address"
				else
					# At least one gateway exists - determine which one failed
					if [ -n "$ula_gw" ]; then
						# Platform has ULA and ping failed - real connectivity failure
						echo_t "RDKB_SELFHEAL : Ping to ULA IPv6 Gateway Address failed."
						t2CountNotify "RF_ERROR_IPV6PingFailed"
						echo_t "PING_FAILED:$ula_gw"
					elif [ -n "$IPv6_Gateway_addr" ]; then
						# Had Link-Local address but ping failed
						echo_t "RDKB_SELFHEAL : Ping to IPv6 Gateway Address failed."
						t2CountNotify "RF_ERROR_IPV6PingFailed"
						echo_t "PING_FAILED:$IPv6_Gateway_addr"
					fi
				fi
			fi
		fi #LTE-1335 Ping to ipv6 not needed for xle.
	 				
		# check if erouter0 is up
		echo_t "RDKB_SELFHEAL : checking $WAN_INTERFACE status"
		ifconfig "$WAN_INTERFACE"

		if [ `getCorrectiveActionState` = "true" ]
		then
			echo_t "RDKB_SELFHEAL : Taking corrective action"
			resetNeeded "" PING
		fi
	elif [ "$ping4_success" -ne 1 ] && [ "$MAPT_CONFIG" != "set" ]
	then
		if [ -n "$IPv4_Gateway_addr" ]
		then
			echo_t "RDKB_SELFHEAL : Ping to IPv4 Gateway Address failed."
			t2CountNotify "RF_ERROR_IPV4PingFailed"
		echo_t "PING_FAILED:$IPv4_Gateway_addr"
		else
			echo_t "RDKB_SELFHEAL : No IPv4 Gateway Address detected"
		fi

		if [ "$BOX_TYPE" = "XB3" ]
		then
				dhcpStatus=`dmcli eRT retv Device.DHCPv4.Client.1.DHCPStatus`
				wanIP=`ifconfig erouter0 | grep "inet addr" | head -n1 |cut -f2 -d: | cut -f1 -d" "`
				if [ "$dhcpStatus" = "Rebinding" ] && [ "$wanIP" != "" ]
				then
					echo_t "EROUTER_DHCP_STATUS:Rebinding"
		t2CountNotify "RF_ERROR_DHCP_Rebinding"
				fi
		fi

		if [ `getCorrectiveActionState` = "true" ]
		then
			echo_t "RDKB_SELFHEAL : Taking corrective action"
			resetNeeded "" PING
		fi
	#LTE-1335 ping to ipv6 not needed for xle.
	elif [ "$ping6_success" -ne 1 ] && [ "$BOX_TYPE" != "WNXL11BWL" ]
	then
		# Initialize last_erouter_mode for IPv6-only failure path
		last_erouter_mode=$(sysevent get last_erouter_mode)
		if [ -z "$last_erouter_mode" ]
		then
			echo_t "RDKB_SELFHEAL : erouter mode is null, fetch from syscfg."
			last_erouter_mode=$(syscfg get last_erouter_mode)
		fi

		# Validate last_erouter_mode is numeric (POSIX-safe)
		case "$last_erouter_mode" in
		    ''|*[!0-9]*) last_erouter_mode=0 ;;
		esac

		# Only report IPv6 issues if device is in IPv6-capable mode (mode > 1)
		# This prevents misleading IPv6 telemetry in IPv4-only deployments
		if [ -n "$last_erouter_mode" ] && [ "$last_erouter_mode" -gt 1 ]
		then
			# Handle different IPv6 failure scenarios
			# Check both ULA and Link-Local gateway addresses
			if [ -n "$IPv6_Gateway_addr" ] || [ -n "$ula_gw" ]; then
				# Had IPv6 gateway address (ULA or Link-Local) but ping failed
				echo_t "RDKB_SELFHEAL : Ping to IPv6 Gateway Address failed."
				t2CountNotify "RF_ERROR_IPV6PingFailed"
				# Log whichever gateway was tested
				if [ -n "$ula_gw" ]; then
					echo_t "PING_FAILED:$ula_gw"
				else
					echo_t "PING_FAILED:$IPv6_Gateway_addr"
				fi
				
				# Take corrective action only for actual ping failures (gateway existed but unreachable)
				if [ `getCorrectiveActionState` = "true" ]
				then
					echo_t "RDKB_SELFHEAL : Taking corrective action"
					resetNeeded "" PING
				fi
			else
				# No IPv6 gateway address detected at all (informational, no corrective action)
				echo_t "RDKB_SELFHEAL : No IPv6 Gateway Address detected"
				t2CountNotify "SYS_INFO_NoIPv6_Address"
			fi
		fi
	else
		echo_t "[RDKB_SELFHEAL] : GW IP Connectivity Test Successfull"
		echo_t "[RDKB_SELFHEAL] : IPv4 GW  Address is:$IPv4_Gateway_addr"
		#LTE-1335  Ping to ipv6 not needed for xle.
		if [ "$BOX_TYPE" != "WNXL11BWL" ]
		then
			# Log ULA if it was used (reuse ula_gw from earlier in this function)
			if [ -n "$ula_gw" ]; then
				echo_t "[RDKB_SELFHEAL] : IPv6 ULA GW Address is:$ula_gw"
			fi
			if [ -n "$IPv6_Gateway_addr" ]; then
				echo_t "[RDKB_SELFHEAL] : IPv6 GW Link-Local Address is:$IPv6_Gateway_addr"
			fi
		fi
	fi	

	ping4_success=0
	ping4_failed=0
	ping6_success=0
	ping6_failed=0


	IPV4_SERVER_COUNT=`syscfg get Ipv4PingServer_Count`
	IPV6_SERVER_COUNT=`syscfg get Ipv6PingServer_Count`
	
	# Ping test for IPv4 Server 
	while [ "$ping4_server_num" -le "$IPV4_SERVER_COUNT" ] && [ "$IPV4_SERVER_COUNT" -ne 0 ]
	do
		
		ping4_server_num=$((ping4_server_num+1))
		PING_SERVER_IS=`syscfg get Ipv4_PingServer_$ping4_server_num`
		if [ "$PING_SERVER_IS" != "" ] && [ "$PING_SERVER_IS" != "0.0.0.0" ]
		then
			PING_OUTPUT=`ping -I "$WAN_INTERFACE_IPV4" -c "$PINGCOUNT" -w "$RESWAITTIME" -s "$PING_PACKET_SIZE" "$PING_SERVER_IS"`
			CHECK_PACKET_RECEIVED=`echo $PING_OUTPUT | grep "packet loss" | cut -d"%" -f1 | awk '{print $NF}'`
			# Validate CHECK_PACKET_RECEIVED is numeric (POSIX-safe)
			case "$CHECK_PACKET_RECEIVED" in
			    ''|*[!0-9]*) CHECK_PACKET_RECEIVED=100 ;;
			esac
			if [ "$CHECK_PACKET_RECEIVED" != "" ]
			then
				if [ "$CHECK_PACKET_RECEIVED" -ne 100 ] 
				then
					ping4_success=1
					PING_LATENCY="PING_LATENCY_IPv4_SERVER:"
					PING_LATENCY_VAL=`echo $PING_OUTPUT | awk 'BEGIN {FS="ms"} { for(i=1;i<=NF;i++) print $i}' | grep "time=" | cut -d"=" -f4`
					PING_LATENCY_VAL=${PING_LATENCY_VAL%?};
					echo $PING_LATENCY$PING_LATENCY_VAL|sed 's/ /,/g'
				else
					ping4_failed=1
				fi
			else
				ping4_failed=1
			fi
			
			if [ "$ping4_failed" -eq 1 ];then
			   echo_t "PING_FAILED:$PING_SERVER_IS"
			   ping4_failed=0
			fi
		fi
	done

	# Ping test for IPv6 Server 
	while [ "$ping6_server_num" -le "$IPV6_SERVER_COUNT" ] && [ "$IPV6_SERVER_COUNT" -ne 0 ]
	do
		
		ping6_server_num=$((ping6_server_num+1))
		PING_SERVER_IS=`syscfg get Ipv6_PingServer_$ping6_server_num`
		if [ "$PING_SERVER_IS" != "" ] && [ "$PING_SERVER_IS" != "0000::0000" ]
		then
			PING_OUTPUT=`ping -I "$WAN_INTERFACE" -c "$PINGCOUNT" -w "$RESWAITTIME" -s "$PING_PACKET_SIZE" "$PING_SERVER_IS"`
			CHECK_PACKET_RECEIVED=`echo $PING_OUTPUT | grep "packet loss" | cut -d"%" -f1 | awk '{print $NF}'`
			# Validate CHECK_PACKET_RECEIVED is numeric (POSIX-safe)
			case "$CHECK_PACKET_RECEIVED" in
			    ''|*[!0-9]*) CHECK_PACKET_RECEIVED=100 ;;
			esac
			if [ "$CHECK_PACKET_RECEIVED" != "" ]
			then
				if [ "$CHECK_PACKET_RECEIVED" -ne 100 ] 
				then
					ping6_success=1
					PING_LATENCY="PING_LATENCY_IPv6_SERVER:"
					PING_LATENCY_VAL=`echo $PING_OUTPUT | awk 'BEGIN {FS="ms"} { for(i=1;i<=NF;i++) print $i}' | grep "time=" | cut -d"=" -f4`
					PING_LATENCY_VAL=${PING_LATENCY_VAL%?};
					echo $PING_LATENCY$PING_LATENCY_VAL|sed 's/ /,/g'
				else
					ping6_failed=1
				fi
			else
				ping6_failed=1
			fi

			if [ "$ping6_failed" -eq 1 ];then
			   echo_t "PING_FAILED:$PING_SERVER_IS"
			   ping6_failed=0
			fi

		fi
	done

	if [ "$IPV4_SERVER_COUNT" -eq 0 ] ||  [ "$IPV6_SERVER_COUNT" -eq 0 ]
	then

			if [ "$IPV4_SERVER_COUNT" -eq 0 ] && [ "$IPV6_SERVER_COUNT" -eq 0 ]
			then
				echo_t "RDKB_SELFHEAL : Ping server lists are empty , not taking any corrective actions"				

			elif [ "$ping4_success" -ne 1 ] && [ "$IPV4_SERVER_COUNT" -ne 0 ]
			then
				echo_t "RDKB_SELFHEAL : Ping to IPv4 servers are failed."
				if [ `getCorrectiveActionState` = "true" ]
				then
					echo_t "RDKB_SELFHEAL : Taking corrective action"
					resetNeeded "" PING
				fi
			elif [ "$ping6_success" -ne 1 ] && [ "$IPV6_SERVER_COUNT" -ne 0 ]
			then
				echo_t "RDKB_SELFHEAL : Ping to IPv6 servers are failed."
				if [ `getCorrectiveActionState` = "true" ]
				then
					echo_t "RDKB_SELFHEAL : Taking corrective action"
					resetNeeded "" PING
				fi
			else
				echo_t "RDKB_SELFHEAL : One of the ping server list is empty, ping to the other list is successfull"
				echo_t "RDKB_SELFHEAL : Connectivity Test is Successfull"
			fi	

	elif [ "$ping4_success" -ne 1 ] &&  [ "$ping6_success" -ne 1 ]
	then
		echo_t "RDKB_SELFHEAL : Ping to both IPv4 and IPv6 servers are failed."
		t2CountNotify "RF_ERROR_IPV4IPV6PingFailed"
				if [ `getCorrectiveActionState` = "true" ]
				then
					echo_t "RDKB_SELFHEAL : Taking corrective action"
					resetNeeded "" PING
				fi
	elif [ "$ping4_success" -ne 1 ]
	then
		echo_t "RDKB_SELFHEAL : Ping to IPv4 servers are failed."
				if [ `getCorrectiveActionState` = "true" ]
				then
					echo_t "RDKB_SELFHEAL : Taking corrective action"
					resetNeeded "" PING
				fi
	elif [ "$ping6_success" -ne 1 ]
	then
		echo_t "RDKB_SELFHEAL : Ping to IPv6 servers are failed."
				if [ `getCorrectiveActionState` = "true" ]
				then
					echo_t "RDKB_SELFHEAL : Taking corrective action"
					resetNeeded "" PING
				fi
	else
		echo_t "RDKB_SELFHEAL : Connectivity Test is Successfull"
	fi	

	ping4_success=0
	ping4_failed=0
	ping6_success=0
	ping6_failed=0
	ping4_server_num=0
	ping6_server_num=0

}

SELFHEAL_ENABLE=$(syscfg get selfheal_enable)
BOOTUP_TIME_SEC=$(cut -d. -f1 /proc/uptime)

run_connectivity_test() {
    WAN_INTERFACE=$(getWanInterfaceName)
    wan_status=$(sysevent get wan-status)

    if [ -z "$wan_status" ] || [ "$wan_status" = "stopped" ]; then
        echo_t "RDKB_SELFHEAL : WAN is not up, bypassing connectivity test"
        return
    fi

    MAPT_CONFIG=$(sysevent get mapt_config_flag)
    if [ "$MAPT_CONFIG" = "set" ]; then
        WAN_INTERFACE_IPV4="map0"
    fi

    #LTE-1335 runPingTest needs to be run only in extender mode for xle.
    if [ "$BOX_TYPE" = "WNXL11BWL" ]
    then
        xle_device_mode=`syscfg get Device_Mode`
        # Validate xle_device_mode is numeric (POSIX-safe)
        case "$xle_device_mode" in
            ''|*[!0-9]*) xle_device_mode=0 ;;
        esac
        if [ "$xle_device_mode" -eq "1" ]; then
            echo_t "RDKB_SELFHEAL : Device is in Extender mode, calling runPingTest."
            runPingTest
        else
            echo_t "RDKB_SELFHEAL : Device is in Gateway mode, runPingTest is not needed."
        fi
    else
        runPingTest
    fi
    runDNSPingTest
}

cron_mode()
{
    acquire_lock "self_heal_connectivity_test" "self_heal_connectivity_test.sh"
    echo_t "RDKB_CONN_SELFHEAL : Cron job is enabled"

    # Validate BOOTUP_TIME_SEC is numeric (POSIX-safe)
    case "$BOOTUP_TIME_SEC" in
        ''|*[!0-9]*) BOOTUP_TIME_SEC=0 ;;
    esac

    if [ "$BOOTUP_TIME_SEC" -le 900 ]; then
        echo_t "[RDKB_CONN_SELFHEAL] : Selfheal scripts will start after 15 mins of Device uptime, skipping the run at $BOOTUP_TIME_SEC seconds"
        exit 0
    fi

    if [ "$SELFHEAL_ENABLE" != "true" ]; then
        echo_t "[RDKB_CONN_SELFHEAL] : selfheal_enable != true, exiting"
        exit 0
    fi

    calcRandTimetoStartPing

    MODE=$(cat "$MODE_FILE" 2>/dev/null)
    if [ "$MODE" = "DELAY" ]; then
        exit 0
    fi

    if ready_to_ping_test; then
        echo_t "[RDKB_CONN_SELFHEAL] : Running connectivity test"

        run_connectivity_test
        date +%s > "$LAST_EXECUTION_FILE"
    fi
    exit 0
}

process_mode()
{
	echo_t "RDKB_CONN_SELFHEAL : Self Heal Cron is disabled "
	while [ $SELFHEAL_ENABLE = "true" ]
        do
            if [ "$calcRandom" -eq 1 ]
            then
                    calcRandTimetoStartPing
                    calcRandom=0
            else
                    INTERVAL=`syscfg get ConnTest_PingInterval`
		            [ -z "$INTERVAL" ] && INTERVAL=60
                    INTERVAL=$(($INTERVAL*60))
                    sleep $INTERVAL
            fi
            run_connectivity_test
	 done
}

if [ "$SELFHEAL_EXECUTION_MODE" = "CRON" ]; then
    CRON_MODE=1
    cron_mode
else
    CRON_MODE=0
    process_mode
fi
