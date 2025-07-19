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


getCorrectiveActionState() {
    Corrective_Action=`syscfg get ConnTest_CorrectiveAction`
    echo "$Corrective_Action"
}

calcRandTimetoStartPing()
{

    rand_min=0
    rand_sec=0

    # Calculate random min
    rand_min=`awk -v min=10 -v max=59 -v seed="$(date +%N)" 'BEGIN{srand(seed);print int(min+rand()*(max-min+1))}'`

    # Calculate random second
    rand_sec=`awk -v min=0 -v max=59 -v seed="$(date +%N)" 'BEGIN{srand(seed);print int(min+rand()*(max-min+1))}'`

    sec_to_sleep=$(($rand_min*60 + $rand_sec))
    echo_t "self_heal_connectivity_test is going into sleep for $sec_to_sleep sec"
    sleep $sec_to_sleep; 
        
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

		if [ $RESPONSE -eq 0 ]
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

runPingTest()
{
        #BCOMB-1120 getWanInterfaceName returning NULL at the start of device.So calling here if value is NULL
        if [[ "x$WAN_INTERFACE" = "x" ]];then
            WAN_INTERFACE=$(getWanInterfaceName)
        fi
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
	RESWAITTIME=$(($RESWAITTIME/1000))

	RESWAITTIME=$(($RESWAITTIME*$PINGCOUNT))


        IPv4_Gateway_addr=""
	#LTE-1335 ping to IPv4 address should be xb's br-403 IPV4 for xle.
	if [ "$BOX_TYPE" = "WNXL11BWL" ] 
	then
		IPv4_Gateway_addr=`ip route show default | grep $WAN_INTERFACE | awk '{print $3}'`
		echo_t "RDKB_SELFHEAL : $WAN_INTERFACE IPv4 address is $IPv4_Gateway_addr"		
	else
        	IPv4_Gateway_addr=`sysevent get default_router`
	fi

        IPv6_Gateway_addr=""
        #LTE-1335 ping Ipv6 not needed for XLE.
	IPv6_Gateway_addr_global=""
	if [ "$BOX_TYPE" != "WNXL11BWL" ]
        then
	erouterIP6=`ifconfig $WAN_INTERFACE | grep inet6 | grep Global | head -n1 | awk '{print $(NF-1)}' | cut -f1 -d:`

        if [ "$erouterIP6" != "" ]
        then
	   if [ "$BOX_TYPE" = "XF3" ]
           then
              #XF3-5270
              #Getting CMTS MAC from `ip -4 neigh show`(arp -an)
              CMTS_MAC=`ip -4 neigh show dev erouter0 | grep $IPv4_Gateway_addr | grep lladdr | cut -f3 -d' '`
              IPv6_Gateway_addr=`ip -6 neigh show dev erouter0 | grep $CMTS_MAC |grep  lladdr | grep $erouterIP6 | cut -f1 -d' '`

              if [ "$IPv6_Gateway_addr" = "" ]
              then
                 IPv6_Gateway_addr=`ip -6 neigh show dev erouter0 | grep $CMTS_MAC |grep  lladdr | grep fe80 | cut -f1 -d' '`
              fi
           else
              # firstly, use ipv6 neighbor table
              routeEntry=`ip -6 neigh show | grep $WAN_INTERFACE | grep $erouterIP6`
              IPv6_Gateway_addr=`echo "$routeEntry" | grep lladdr |cut -f1 -d ' '`

              # ARRISXB6-10567
              # If IPv6_Gateway_addr not found in neigbor table, use ipv6 default route,
              # ip -6 route list
              # default via fe80::201:5cff:fe85:c046 dev erouter0 proto ra metric 1024 expires 1799sec
              if [ "$IPv6_Gateway_addr" = "" ]
              then
                  IPv6_Gateway_addr=`ip -6 route list | grep "default via" | grep $WAN_INTERFACE | grep fe80 | cut -f3 -d' '`
                  echo "IPv6 default route $IPv6_Gateway_addr"

		  routeEntry_global=`ip -6 route list | grep $WAN_INTERFACE | grep $erouterIP6`
		  IPv6_Gateway_addr_global=`echo "$routeEntry_global" | cut -f1 -d\/`

		  # If we don't get the Network prefix we need this additional check to
		  # retrieve the IPv6 GW Addr , here route entry and IPv6_Gateway_addr_global(which is retrived from above execution)
		  # are same
		  if [ "$routeEntry_global" = "$IPv6_Gateway_addr_global" ] && [ "$routeEntry_global" != "" ]
		  then
		    IPv6_Gateway_addr_global=`echo $routeEntry_global | cut -f1 -d ' '`
		  fi
		  echo "IPv6 global route $IPv6_Gateway_addr_global"
              fi
           fi
	fi	

	#RDKB-21946
	#If GW IPv6 is missing in both route list and neighbour list checking for Link Local GW ipv6 in neighbour list and    	
	#Checking if route list returns Box_IPv6_addr as IPv6_Gateway_addr	

	Box_IPv6_addr=`ifconfig $WAN_INTERFACE | grep inet6 | grep Global | head -n1 | awk '{print $(NF-1)}' | cut -f1 -d\/`	
	
	if [ "$BOX_TYPE" != "XF3" ]
	then
           if [ "$IPv6_Gateway_addr" = "" ]  || [ "$IPv6_Gateway_addr" = "$Box_IPv6_addr" ]
	   then
	      erouterIP6=`ifconfig $WAN_INTERFACE | grep inet6 | grep Link | head -n1 | awk '{print $(NF-1)}' | cut -f1 -d:`
	      routeEntry=`ip -6 neigh show | grep $WAN_INTERFACE | grep $erouterIP6`
              IPv6_Gateway_addr=`echo "$routeEntry" | grep lladdr |cut -f1 -d ' '` 	
    	   fi
	fi	
	fi #LTE-133 ping to ipv6 not needed for xle.
    if [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] ||  [ "$BOX_TYPE" = "SR213" ] || [ "$UseLANIFIPV6" == "true" ]
    then
        IPv6_Gateway_addr=`ip -6 neigh show | grep $WAN_INTERFACE | grep lladdr |cut -f1 -d ' '`
    fi

	if [ "$IPv4_Gateway_addr" != "" ] && [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$MAPT_CONFIG" != "set" ] && [ "$UseLANIFIPV6" != "true" ]
	then
		PING_OUTPUT=`ping -I $WAN_INTERFACE -c $PINGCOUNT -w $RESWAITTIME -s $PING_PACKET_SIZE $IPv4_Gateway_addr`
		CHECK_PACKET_RECEIVED=`echo $PING_OUTPUT | grep "packet loss" | cut -d"%" -f1 | awk '{print $NF}'`

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
    if [ "$IPv4_Gateway_addr" != "" ] && ([ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$UseLANIFIPV6" == "true" ])
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
	if [ "$IPv6_Gateway_addr" != "" ] && [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$UseLANIFIPV6" != "true" ]
	then
		for IPv6_Gateway_addr in $IPv6_Gateway_addr
		do
			PING_OUTPUT=`ping6 -I $WAN_INTERFACE -c $PINGCOUNT -w $RESWAITTIME -s $PING_PACKET_SIZE $IPv6_Gateway_addr`
			CHECK_PACKET_RECEIVED=`echo $PING_OUTPUT | grep "packet loss" | cut -d"%" -f1 | awk '{print $NF}'`

			if [ "$CHECK_PACKET_RECEIVED" != "" ]
			then
				if [ "$CHECK_PACKET_RECEIVED" -ne 100 ] 
				then
					ping6_success=1
                                        ping6_failed=0
					PING_LATENCY="PING_LATENCY_GWIPv6:"
					PING_LATENCY_VAL=`echo $PING_OUTPUT | awk 'BEGIN {FS="ms"} { for(i=1;i<=NF;i++) print $i}' | grep "time=" | cut -d"=" -f4`
					PING_LATENCY_VAL=${PING_LATENCY_VAL%?};
					echo $PING_LATENCY$PING_LATENCY_VAL|sed 's/ /,/g'
					break
				else
					ping6_failed=1
				fi
			else
				ping6_failed=1
			fi
		done
	fi

	if [ "$ping6_failed" -eq 1 ] && [ "$IPv6_Gateway_addr_global" != "" ] && [ "$BOX_TYPE" != "HUB4" ] &&  [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$UseLANIFIPV6" != "true" ]
	then
		PING_OUTPUT=`ping6 -I $WAN_INTERFACE -c $PINGCOUNT -w $RESWAITTIME -s $PING_PACKET_SIZE $IPv6_Gateway_addr_global`
		CHECK_PACKET_RECEIVED=`echo $PING_OUTPUT | grep "packet loss" | cut -d"%" -f1 | awk '{print $NF}'`

		if [ "$CHECK_PACKET_RECEIVED" != "" ]
		then
			if [ "$CHECK_PACKET_RECEIVED" -ne 100 ]
			then
				ping6_success=1
				PING_LATENCY="PING_LATENCY_GWIPv6:"
				PING_LATENCY_VAL=`echo $PING_OUTPUT | awk 'BEGIN {FS="ms"} { for(i=1;i<=NF;i++) print $i}' | grep "time=" | cut -d"=" -f4`
				PING_LATENCY_VAL=${PING_LATENCY_VAL%?};
				echo $PING_LATENCY$PING_LATENCY_VAL|sed 's/ /,/g'
			else
				ping6_failed=1
			fi
		else
			ping6_failed=1
		fi
	fi
	fi #LTE-1335 Ping to ipv6 not needed for xle.
    # For HUB4/SR300/SE501/SR213, Using IPOE Health Check Status
    if [ "$IPv6_Gateway_addr" != "" ] && ([ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ] || [ "$BOX_TYPE" = "SE501" ] || [ "$BOX_TYPE" = "SR213" ] || [ "$UseLANIFIPV6" == "true" ])
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
			if [ "$IPv4_Gateway_addr" == "" ]
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
                if [ "$last_erouter_mode" == "" ]
		then
		    echo_t "RDKB_SELFHEAL : erouter mode is null, fetch from syscfg."
		    last_erouter_mode=$(syscfg get last_erouter_mode)
		fi
                if [ "$IPv6_Gateway_addr" == "" ] && [ "$IPv6_Gateway_addr_global" == "" ] && [ "$last_erouter_mode" -gt 1 ]

              	then
                  	 echo_t "RDKB_SELFHEAL : No IPv6 Gateway Address detected"
			 t2CountNotify "SYS_INFO_NoIPv6_Address"
               	else
                      echo_t "RDKB_SELFHEAL : Ping to IPv6 Gateway Address are failed."
                      t2CountNotify "RF_ERROR_IPV6PingFailed"
                      echo_t "PING_FAILED:$IPv6_Gateway_addr"
                fi
		fi #LTE-1335 Ping to ipv6 not needed for xle.
	 				
		# check if erouter0 is up
		echo_t "RDKB_SELFHEAL : checking $WAN_INTERFACE status"
		ifconfig $WAN_INTERFACE

		if [ `getCorrectiveActionState` = "true" ]
		then
			echo_t "RDKB_SELFHEAL : Taking corrective action"
			resetNeeded "" PING
		fi
	elif [ "$ping4_success" -ne 1 ] && [ "$MAPT_CONFIG" != "set" ]
	then
                if [ "$IPv4_Gateway_addr" != "" ]
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
                if [ "$IPv6_Gateway_addr" != "" ] || [ "$IPv6_Gateway_addr_global" != "" ]
                then
		            echo_t "RDKB_SELFHEAL : Ping to IPv6 Gateway Address are failed."
		            t2CountNotify "RF_ERROR_IPV6PingFailed"
		            echo_t "PING_FAILED:$IPv6_Gateway_addr"
                elif [[ $last_erouter_mode -gt 1 ]]
		then
                    echo_t "RDKB_SELFHEAL : No IPv6 Gateway Address detected"
		    t2CountNotify "SYS_INFO_NoIPv6_Address"
                fi
		
		if [ `getCorrectiveActionState` = "true" ]
		then
			echo_t "RDKB_SELFHEAL : Taking corrective action"
			resetNeeded "" PING
		fi
	else
		echo_t "[RDKB_SELFHEAL] : GW IP Connectivity Test Successfull"
		echo_t "[RDKB_SELFHEAL] : IPv4 GW  Address is:$IPv4_Gateway_addr"
		#LTE-1335  Ping to ipv6 not needed for xle.
		if [ "$BOX_TYPE" != "WNXL11BWL" ]
		then		
		echo_t "[RDKB_SELFHEAL] : IPv6 GW  Address is:$IPv6_Gateway_addr"
		echo_t "[RDKB_SELFHEAL] : IPv6 GW global Address is:$IPv6_Gateway_addr_global"
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
			PING_OUTPUT=`ping -I $WAN_INTERFACE_IPV4 -c $PINGCOUNT -w $RESWAITTIME -s $PING_PACKET_SIZE $PING_SERVER_IS`
			CHECK_PACKET_RECEIVED=`echo $PING_OUTPUT | grep "packet loss" | cut -d"%" -f1 | awk '{print $NF}'`
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
			PING_OUTPUT=`ping -I $WAN_INTERFACE -c $PINGCOUNT -w $RESWAITTIME -s $PING_PACKET_SIZE $PING_SERVER_IS`
			CHECK_PACKET_RECEIVED=`echo $PING_OUTPUT | grep "packet loss" | cut -d"%" -f1 | awk '{print $NF}'`
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

SELFHEAL_ENABLE=`syscfg get selfheal_enable`

while [ $SELFHEAL_ENABLE = "true" ]
do

	if [ "$calcRandom" -eq 1 ] 
	then

		calcRandTimetoStartPing
		calcRandom=0
	else
		INTERVAL=`syscfg get ConnTest_PingInterval`

		if [ "$INTERVAL" = "" ] 
		then
			INTERVAL=60
		fi
                INTERVAL=$(($INTERVAL*60))
		sleep $INTERVAL
	fi

	WAN_INTERFACE=$(getWanInterfaceName)
	wan_status=`sysevent get wan-status`
	if [ "$wan_status" = "" ] || [ "$wan_status" = "stopped" ]
	then
		echo_t "RDKB_SELFHEAL : WAN is not up, bypassing ping test"
	else
		MAPT_CONFIG=`sysevent get mapt_config_flag`
		if [ "$MAPT_CONFIG" == "set" ]
		then
			WAN_INTERFACE_IPV4="map0"
		fi
		
		#LTE-1335 runPingTest needs to be run only in extender mode for xle.
		if [ "$BOX_TYPE" = "WNXL11BWL" ]
		then
			xle_device_mode=`syscfg get Device_Mode`
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
	fi

	SELFHEAL_ENABLE=`syscfg get selfheal_enable`
	# ping -I $WAN_INTERFACE -c $PINGCOUNT 
		
done
