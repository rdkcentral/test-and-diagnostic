#!/bin/sh
#######################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
#  Copyright 2019 RDK Management
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
#######################################################################################

TAD_PATH="/usr/ccsp/tad"
source $TAD_PATH/corrective_action.sh
source /etc/waninfo.sh
source /etc/utopia/service.d/event_handler_functions.sh
DIBBLER_SERVER_CONF="/etc/dibbler/server.conf"

SelfHeal_Support=`sysevent get SelfhelpWANConnectionDiagSupport`
UseLANIFIPV6=`sysevent get LANIPv6GUASupport`

if [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "CGA4131COM" ] || [ "$MODEL_NUM" = "CGM4140COM" ] || [ "$MODEL_NUM" = "CGM4331COM" ] || [ "$MODEL_NUM" = "TG4482A" ] || [ "$MODEL_NUM" = "VTER11QEL" ]
then
    DHCPV6_HANDLER="/usr/bin/service_dhcpv6_client"
else
    DHCPV6_HANDLER="/etc/utopia/service.d/service_dhcpv6_client.sh"
fi

PRIVATE_LAN="brlan0"
CCSP_COMMON_FIFO="/tmp/ccsp_common_fifo"

ETHWAN_ENABLED=$(syscfg get eth_wan_enabled)
SYSCFG_SEL_WANMODE=$(syscfg get selected_wan_mode)
WAN_AUTO_SEL_MODE="0"
WAN_ETH_SEL_MODE="1"
WAN_DOCSIS_SEL_MODE="2"

#Legacy Non WAN Manager Ethernet WAN Interface Prefixes/Names
if [ "$MANUFACTURE" = "Technicolor" ] || [ "$MANUFACTURE" = "Sercomm" ]; then
ETHWAN_INTF_PREFIX1="eth"
ETHWAN_INTF_PREFIX2=""
elif [ "$MANUFACTURE" = "Arris" ]; then
ETHWAN_INTF_PREFIX1="nsgmii"
ETHWAN_INTF_PREFIX2="macsec"
fi

exec 5>&1 6>&2 >> /rdklogs/logs/SelfHealAggressive.txt 2>&1

Unit_Activated=$(syscfg get unit_activated)
#function to restart Dhcpv6_Client
Dhcpv6_Client_restart ()
{
	if [ "$1" = "" ];then
		echo_t "DHCPv6 Client not running.."
		return 
	fi

	if [ "$DHCPcMonitoring" == "false" ];then
		echo_t "DHCP Monitoring done by wanmanager"
		return 
	fi

	process_restart_need=0
	if [ "$2" = "restart_for_dibbler-server" ];then
        	PAM_UP="$(busybox pidof CcspPandMSsp)"
		if [ "$PAM_UP" != "" ];then
                	echo_t "PAM pid $PAM_UP & $1 pid $dibbler_client_type $ti_dhcpv6_type"
                        echo_t "RDKB_PROCESS_CRASHED : Restarting $1 to reconfigure server.conf"
			process_restart_need=1
		fi
	fi
	if [ "$process_restart_need" = "1" ] || [ "$2" = "Idle" ];then
		sysevent set dibbler_server_conf-status ""
		if [ "$1" = "dibbler-client" ];then
			dibbler-client stop
            sleep 2
            dibbler-client start
            sleep 8
		elif [ "$1" = "ti_dhcp6c" ];then
            if [ -f /tmp/dhcpmgr_initialized ]; then
                sysevent set dhcpv6_client-stop
            else
                $DHCPV6_HANDLER dhcpv6_client_service_disable
            fi
            sleep 2
            if [ -f /tmp/dhcpmgr_initialized ]; then
                sysevent set dhcpv6_client-start
            else
                $DHCPV6_HANDLER dhcpv6_client_service_enable
            fi
            sleep 8
		fi
		wait_till_state "dibbler_server_conf" "ready"
		touch /tmp/dhcpv6-client_restarted
	fi
	if [ ! -f "$DIBBLER_SERVER_CONF" ];then
		return 2
	elif [ ! -s  "$DIBBLER_SERVER_CONF" ];then
		return 1
        elif [ -z "$(busybox pidof dibbler-server)" ];then
        	dibbler-server stop
                sleep 2
                dibbler-server start
	fi
}

self_heal_process ()
{
  status_rpc_error=`systemctl status CcspCMAgentSsp.service | grep "Timed outRPC communication fail"`
  if [ "$status_rpc_error" != "" ]
  then
     echo_t "[RDKB_PLATFORM_ERROR] : CcspCMAgent service restart needed for RPC issue"
     systemctl restart CcspCMAgentSsp.service
  fi
}

if [ -f /etc/onewifi_enabled ] || [ -d /sys/module/openvswitch ] ||
                                  [ -f /etc/WFO_enabled ]; then
    ovs_enable="true"
else
    ovs_enable=`syscfg get mesh_ovs_enable`
fi
self_heal_peer_ping ()
{
    ping_failed=0
    ping_success=0
    PING_PATH="/usr/sbin"

    if [ "$MULTI_CORE" = "yes" ]; then
	if [ -f $PING_PATH/ping_peer ]
	then
	    WAN_STATUS=`sysevent get wan-status`
	    if [ "$WAN_STATUS" = "started" ]; then
		## Check Peer ip is accessible
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
			    echo_t "RDKB_AGG_SELFHEAL : Ping to Peer IP is success"
			    break
			else
			    echo_t "[RDKB_PLATFORM_ERROR] : ATOM interface is not reachable"
			    ping_failed=1
			fi
		    else
			if [ "$DEVICE_MODEL" = "TCHXB3" ]; then
			    check_if_l2sd0_500_up=`ifconfig l2sd0.500 | grep UP `
			    check_if_l2sd0_500_ip=`ifconfig l2sd0.500 | grep inet `
			    if [ "$check_if_l2sd0_500_up" = "" ] || [ "$check_if_l2sd0_500_ip" = "" ]
			    then
				echo_t "[RDKB_PLATFORM_ERROR] : l2sd0.500 is not up, setting to recreate interface"
				rpc_ifconfig l2sd0.500 >/dev/null 2>&1
				sleep 3
			    fi
			    PING_RES=`ping_peer`
			    CHECK_PING_RES=`echo $PING_RES | grep "packet loss" | cut -d"," -f3 | cut -d"%" -f1`
			    if [ "$CHECK_PING_RES" != "" ]
			    then
				if [ "$CHECK_PING_RES" -ne 100 ]
				then
				    echo_t "[RDKB_PLATFORM_ERROR] : l2sd0.500 is up,Ping to Peer IP is success"
				    break
				fi
			    fi
			fi
			ping_failed=1
		    fi
		    if [ "$ping_failed" -eq 1 ] && [ "$loop" -lt 3 ]
		    then
			echo_t "RDKB_AGG_SELFHEAL : Ping to Peer IP failed in iteration $loop"
			t2CountNotify "SYS_SH_pingPeerIP_Failed"
			echo_t "RDKB_AGG_SELFHEAL : Ping command output is $PING_RES"
		    else
			echo_t "RDKB_AGG_SELFHEAL : Ping to Peer IP failed after iteration $loop also ,rebooting the device"
			t2CountNotify "SYS_SH_pingPeerIP_Failed"
			echo_t "RDKB_AGG_SELFHEAL : Ping command output is $PING_RES"
			echo_t "RDKB_REBOOT : Peer is not up ,Rebooting device "
			#echo_t " RDKB_AGG_SELFHEAL : Setting Last reboot reason as Peer_down"
			reason="Peer_down"
			rebootCount=1
			#setRebootreason $reason $rebootCount
			rebootNeeded RM "" $reason $rebootCount
		    fi
		    loop=$((loop+1))
		    sleep 5
		done
	    else
		echo_t "RDKB_AGG_SELFHEAL : wan-status is $WAN_STATUS , Peer_down check bypassed"
	    fi
	else
            echo_t "RDKB_AGG_SELFHEAL : ping_peer command not found"
	fi
	if [ -f $PING_PATH/arping_peer ]
	then
            $PING_PATH/arping_peer
	else
            echo_t "RDKB_AGG_SELFHEAL : arping_peer command not found"
	fi
    else
	echo_t "RDKB_AGG_SELFHEAL : MULTI_CORE is not defined as yes. Define it as yes if it's a multi core device."
    fi    
}

self_heal_dnsmasq()
{
    DNSMASQ_UP="$(busybox pidof dnsmasq)"
    if [ "$DNSMASQ_UP" = "" ];then
        echo_t "RDKB_PROCESS_CRASHED : dnsmasq is not running, need restart"
        t2CountNotify "SYS_SH_dnsmasq_restart"
        sysevent set dhcp_server-restart
    fi
}

self_heal_dnsmasq_restart()
{
    kill -9 $(busybox pidof dnsmasq)
    if [ "$BOX_TYPE" != "XF3" ]; then
        sysevent set dhcp_server-restart
    else
        systemctl stop CcspXdnsSsp.service
        systemctl stop dnsmasq
        systemctl start dnsmasq
        systemctl start CcspXdnsSsp.service
    fi
}

self_heal_dnsmasq_zombie()
{
    checkIfDnsmasqIsZombie=`ps | grep dnsmasq | grep "Z" | awk '{ print $1 }'`
    if [ "$checkIfDnsmasqIsZombie" != "" ] ; then
        for zombiepid in $checkIfDnsmasqIsZombie
        do
            confirmZombie=`grep "State:" /proc/$zombiepid/status | grep -i "zombie"`
            if [ "$confirmZombie" != "" ] ; then
                echo_t "[RDKB_AGG_SELFHEAL] : Zombie instance of dnsmasq is present, restarting dnsmasq"
                t2CountNotify "SYS_ERROR_Zombie_dnsmasq"
                self_heal_dnsmasq_restart
                break
            fi
        done
    fi   
}

#Selfheal for brlan0, brlan1 and erouter0
self_heal_interfaces()
{
    case $SELFHEAL_TYPE in
        "BASE")
            # Checking whether brlan0 and l2sd0.100 are created properly , if not recreate it
	    if [ "$MODEL_NAME" = "RPI" ] || [ "$MODEL_NAME" = "BPI" ]; then
                 device_mode=$(dmcli eRT retv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode)
                if [ ! -f /tmp/.router_reboot ]; then
                    if [ "$device_mode" != "" ]; then
                        if [ "$device_mode" = "router" ]; then
                            check_if_brlan0_created=$(ifconfig | grep "brlan0")
                            check_if_brlan0_up=$(ifconfig brlan0 | grep "UP")
                            check_if_brlan0_hasip=$(ifconfig brlan0 | grep "inet addr")
                            if [ "$check_if_brlan0_created" = "" ] || [ "$check_if_brlan0_up" = "" ] || [ "$check_if_brlan0_hasip" = "" ]; then
                                echo_t "[RDKB_PLATFORM_ERROR] : Either brlan0  not completely up, setting event to recreate brlan0 interface"
                                echo_t "[RDKB_AGG_SELFHEAL_BOOTUP] : brlan0 o/p "
                                ifconfig brlan0;
                                if [ "x$ovs_enable" = "xtrue" ];then
                                    ovs-vsctl list-ifaces brlan0
                                else
                                    brctl show
                                fi
                                logNetworkInfo
                                ipv4_status=$(sysevent get ipv4_4-status)
                                lan_status=$(sysevent get lan-status)
                                if [ "$lan_status" != "started" ]; then
                                    if [ "$ipv4_status" = "" ] || [ "$ipv4_status" = "down" ]; then
                                        echo_t "[RDKB_AGG_SELFHEAL] : ipv4_4-status is not set or lan is not started, setting lan-start event"
                                        sysevent set lan-start
                                    sleep 60
                                else
                                    if [ "$check_if_brlan0_created" = "" ] ; then
                                        echo_t "[RDKB_AGG_SELFHEAL] : Bring up brlan0 bridge"
                                        ip link set brlan0 up
                                        /etc/utopia/registration.d/02_multinet restart
                                    fi
                                    fi
                               else
                                 if [ "$check_if_brlan0_created" = "" ]; then
                                    echo_t "[RDKB_AGG_SELFHEAL] : Bring up brlan0 bridge"
                                    ip link set brlan0 up
                                    /etc/utopia/registration.d/02_multinet restart
                                 fi
                              fi
                           fi
                       fi
                    fi
                else
                    rm -rf /tmp/.router_reboot
                fi
            else
              if [ "$WAN_TYPE" != "EPON" ]; then
                device_mode=$(dmcli eRT retv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode)
                if [ ! -f /tmp/.router_reboot ]; then
                    if [ "$device_mode" != "" ]; then
                        if [ "$device_mode" = "router" ]; then
                            check_if_brlan0_created=$(ifconfig | grep "brlan0")
                            check_if_brlan0_up=$(ifconfig brlan0 | grep "UP")
                            check_if_brlan0_hasip=$(ifconfig brlan0 | grep "inet addr")
                            check_if_l2sd0_100_created=$(ifconfig | grep "l2sd0\.100")
                            check_if_l2sd0_100_up=$(ifconfig l2sd0.100 | grep "UP" )
                            if [ "$check_if_brlan0_created" = "" ] || [ "$check_if_brlan0_up" = "" ] || [ "$check_if_brlan0_hasip" = "" ] || [ "$check_if_l2sd0_100_created" = "" ] || [ "$check_if_l2sd0_100_up" = "" ]; then
                                echo_t "[RDKB_PLATFORM_ERROR] : Either brlan0 or l2sd0.100 is not completely up, setting event to recreate vlan and brlan0 interface"
                                echo_t "[RDKB_AGG_SELFHEAL_BOOTUP] : brlan0 and l2sd0.100 o/p "
                                ifconfig brlan0;ifconfig l2sd0.100; 
                                if [ "x$ovs_enable" = "xtrue" ];then
                                    ovs-vsctl list-ifaces brlan0
                                else
                                    brctl show
                                fi
                                logNetworkInfo

                                ipv4_status=$(sysevent get ipv4_4-status)
                                lan_status=$(sysevent get lan-status)

                                if [ "$lan_status" != "started" ]; then
                                    if [ "$ipv4_status" = "" ] || [ "$ipv4_status" = "down" ]; then
                                        echo_t "[RDKB_AGG_SELFHEAL] : ipv4_4-status is not set or lan is not started, setting lan-start event"
                                        sysevent set lan-start
                                    sleep 60
				else
				    if [ "$check_if_brlan0_created" = "" ] && [ "$check_if_l2sd0_100_created" = "" ]; then
					/etc/utopia/registration.d/02_multinet restart
				    fi

				    sysevent set multinet-down 1
				    sleep 5
				    sysevent set multinet-up 1
				    sleep 30
                                fi
                            else
                                if [ "$check_if_brlan0_created" = "" ] && [ "$check_if_l2sd0_100_created" = "" ]; then
                                    /etc/utopia/registration.d/02_multinet restart
                                fi

                                sysevent set multinet-down 1
                                sleep 5
                                sysevent set multinet-up 1
                                sleep 30
			    fi
                            fi

                        fi
                    else
                        echo_t "[RDKB_PLATFORM_ERROR] : Something went wrong while fetching device mode "
                        t2CountNotify "SYS_ERROR_Error_fetching_devicemode"
                    fi
                else
                    rm -rf /tmp/.router_reboot
                fi
                # Checking whether brlan1 and l2sd0.101 interface are created properly
                if [ "$IS_BCI" != "yes" ]; then
                    check_if_brlan1_created=$(ifconfig | grep "brlan1")
                    check_if_brlan1_up=$(ifconfig brlan1 | grep "UP")
                    check_if_brlan1_hasip=$(ifconfig brlan1 | grep "inet addr")
                    check_if_l2sd0_101_created=$(ifconfig | grep "l2sd0\.101")
                    check_if_l2sd0_101_up=$(ifconfig l2sd0.101 | grep "UP" )

                    if [ "$check_if_brlan1_created" = "" ] || [ "$check_if_brlan1_up" = "" ] || [ "$check_if_brlan1_hasip" = "" ] || [ "$check_if_l2sd0_101_created" = "" ] || [ "$check_if_l2sd0_101_up" = "" ]; then
                        echo_t "[RDKB_PLATFORM_ERROR] : Either brlan1 or l2sd0.101 is not completely up, setting event to recreate vlan and brlan1 interface"
                        echo_t "[RDKB_AGG_SELFHEAL_BOOTUP] : brlan1 and l2sd0.101 o/p "
                        ifconfig brlan1;ifconfig l2sd0.101; 
                        if [ "x$ovs_enable" = "xtrue" ];then
                            ovs-vsctl list-ifaces brlan1
                        else
                            brctl show
                        fi
                        ipv5_status=$(sysevent get ipv4_5-status)
                        lan_l3net=$(sysevent get homesecurity_lan_l3net)

                        if [ "$lan_l3net" != "" ]; then
                            if [ "$ipv5_status" = "" ] || [ "$ipv5_status" = "down" ]; then
                                echo_t "[RDKB_AGG_SELFHEAL] : ipv5_4-status is not set , setting event to create homesecurity lan"
                                sysevent set ipv4-up $lan_l3net
                            sleep 60
			else
			    if [ "$check_if_brlan1_created" = "" ] && [ "$check_if_l2sd0_101_created" = "" ] ; then
				/etc/utopia/registration.d/02_multinet restart
			    fi
			    sysevent set multinet-down 2
			    sleep 5
			    sysevent set multinet-up 2
			    sleep 10
                        fi
                    else
                        if [ "$check_if_brlan1_created" = "" ] && [ "$check_if_l2sd0_101_created" = "" ] ; then
                            /etc/utopia/registration.d/02_multinet restart
                        fi

                        sysevent set multinet-down 2
                        sleep 5
                        sysevent set multinet-up 2
                        sleep 10
                    fi
                fi
            fi
        fi
     fi
        ;;
        "TCCBR")
            # Checking whether brlan0 created properly , if not recreate it
            lanSelfheal=$(sysevent get lan_selfheal)
            echo_t "[RDKB_AGG_SELFHEAL] : Value of lanSelfheal : $lanSelfheal"
            if [ ! -f /tmp/.router_reboot ]; then
                if [ "$lanSelfheal" != "done" ]; then
                    device_mode=$(dmcli eRT retv Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode)
                    if [ "$device_mode" != "" ]; then
                        if [ "$device_mode" = "router" ]; then
                            check_if_brlan0_created=$(ifconfig | grep "brlan0")
                            check_if_brlan0_up=$(ifconfig brlan0 | grep "UP")
                            check_if_brlan0_hasip=$(ifconfig brlan0 | grep "inet addr")

                            if [ "$check_if_brlan0_created" = "" ] || [ "$check_if_brlan0_up" = "" ] || [ "$check_if_brlan0_hasip" = "" ]; then
                                echo_t "[RDKB_PLATFORM_ERROR] : brlan0 is not completely up, setting event to recreate brlan0 interface"
                                t2CountNotify "SYS_ERROR_brlan0_not_created"
                                logNetworkInfo "false"

                                ipv4_status=$(sysevent get ipv4_4-status)
                                lan_status=$(sysevent get lan-status)

                                if [ "$lan_status" != "started" ]; then
                                    if [ "$ipv4_status" = "" ] || [ "$ipv4_status" = "down" ]; then
                                        echo_t "[RDKB_AGG_SELFHEAL] : ipv4_4-status is not set or lan is not started, setting lan-start event"
                                        sysevent set lan-start
                                    sleep 30
				else
				    if [ "$check_if_brlan0_created" = "" ]; then
					/etc/utopia/registration.d/02_multinet restart
				    fi

				    sysevent set multinet-down 1
				    sleep 5
				    sysevent set multinet-up 1
				    sleep 30
                                fi
                            else

                                if [ "$check_if_brlan0_created" = "" ]; then
                                    /etc/utopia/registration.d/02_multinet restart
                                fi

                                sysevent set multinet-down 1
                                sleep 5
                                sysevent set multinet-up 1
                                sleep 30
			    fi
                                sysevent set lan_selfheal "done"
                            fi

                        fi
                    else
                        echo_t "[RDKB_PLATFORM_ERROR] : Something went wrong while fetching device mode "
                        t2CountNotify "SYS_ERROR_Error_fetching_devicemode"
                    fi
                else
                    echo_t "[RDKB_AGG_SELFHEAL] : brlan0 already restarted. Not restarting again"
                    t2CountNotify "SYS_SH_brlan0_restarted"
                    sysevent set lan_selfheal ""
                fi
            else
                rm -rf /tmp/.router_reboot
            fi
            ;;
        "SYSTEMD")
            if [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$BOX_TYPE" != "WNXL11BWL" ]; then
                # Checking whether brlan0 is created properly , if not recreate it
                lanSelfheal=$(sysevent get lan_selfheal)
                echo_t "[RDKB_AGG_SELFHEAL] : Value of lanSelfheal : $lanSelfheal"
                if [ ! -f /tmp/.router_reboot ]; then
                    if [ "$lanSelfheal" != "done" ]; then
                        # Check device is in router mode
                        # Get from syscfg instead of dmcli for performance reasons
                        check_device_in_bridge_mode=$(syscfg get bridge_mode)
                        if [ "$check_device_in_bridge_mode" = "0" ]; then
                            check_if_brlan0_created=$(ifconfig | grep "brlan0")
                            check_if_brlan0_up=$(ifconfig brlan0 | grep "UP")
                            check_if_brlan0_hasip=$(ifconfig brlan0 | grep "inet addr")
                            if [ "$check_if_brlan0_created" = "" ] || [ "$check_if_brlan0_up" = "" ] || [ "$check_if_brlan0_hasip" = "" ]; then
                                echo_t "[RDKB_PLATFORM_ERROR] : brlan0 is not completely up, setting event to recreate vlan and brlan0 interface"
                                t2CountNotify "SYS_ERROR_brlan0_not_created"
                                logNetworkInfo "false"

                                ipv4_status=$(sysevent get ipv4_4-status)
                                lan_status=$(sysevent get lan-status)

                                if [ "$lan_status" != "started" ]; then
                                    if [ "$ipv4_status" = "" ] || [ "$ipv4_status" = "down" ]; then
                                        echo_t "[RDKB_AGG_SELFHEAL] : ipv4_4-status is not set or lan is not started, setting lan-start event"
                                        sysevent set lan-start
                                    sleep 30
				else
				    if [ "$check_if_brlan0_created" = "" ]; then
					/etc/utopia/registration.d/02_multinet restart
				    fi

				    sysevent set multinet-down 1
				    sleep 5
				    sysevent set multinet-up 1
				    sleep 30
                                fi
                            else

                                if [ "$check_if_brlan0_created" = "" ]; then
                                    /etc/utopia/registration.d/02_multinet restart
                                fi

                                sysevent set multinet-down 1
                                sleep 5
                                sysevent set multinet-up 1
                                sleep 30
			    fi
                                sysevent set lan_selfheal "done"
                            fi

                        fi
                    else
                        echo_t "[RDKB_AGG_SELFHEAL] : brlan0 already restarted. Not restarting again"
                        t2CountNotify "SYS_SH_brlan0_restarted"
                        sysevent set lan_selfheal ""
                    fi
                else
                    rm -rf /tmp/.router_reboot
                fi

                # Checking whether brlan1 interface is created properly
                XHSEnabled=$(sysevent get HomeSecuritySupport)
                l3netRestart=$(sysevent get l3net_selfheal)
                echo_t "[RDKB_AGG_SELFHEAL] : Value of l3net_selfheal : $l3netRestart"
                if [ "$MODEL_NUM" = "CVA601ZCOM" ]; then
                    : #Do nothing for XD4
                elif [ "$MODEL_NUM" = "SCER11BEL" ] && [ "$XHSEnabled" == "false" ]; then
                    : # Do nothing for XER10 and if HomeSecuritysupport disabled"
                elif [ "$l3netRestart" != "done" ]; then

                    check_if_brlan1_created=$(ifconfig | grep "brlan1")
                    check_if_brlan1_up=$(ifconfig brlan1 | grep "UP")
                    check_if_brlan1_hasip=$(ifconfig brlan1 | grep "inet addr")

                    if [ "$check_if_brlan1_created" = "" ] || [ "$check_if_brlan1_up" = "" ] || [ "$check_if_brlan1_hasip" = "" ]; then
                        echo_t "[RDKB_PLATFORM_ERROR] : brlan1 is not completely up, setting event to recreate vlan and brlan1 interface"

                        ipv5_status=$(sysevent get ipv4_5-status)
                        lan_l3net=$(sysevent get homesecurity_lan_l3net)

                        if [ "$lan_l3net" != "" ]; then
                            if [ "$ipv5_status" = "" ] || [ "$ipv5_status" = "down" ]; then
                                echo_t "[RDKB_AGG_SELFHEAL] : ipv5_4-status is not set , setting event to create homesecurity lan"
                                sysevent set ipv4-up $lan_l3net
                            sleep 30
			else
			    if [ "$check_if_brlan1_created" = "" ]; then
				/etc/utopia/registration.d/02_multinet restart
			    fi

			    sysevent set multinet-down 2
			    sleep 5
			    sysevent set multinet-up 2
			    sleep 10
                        fi
                    else

                        if [ "$check_if_brlan1_created" = "" ]; then
                            /etc/utopia/registration.d/02_multinet restart
                        fi

                        sysevent set multinet-down 2
                        sleep 5
                        sysevent set multinet-up 2
                        sleep 10
		    fi
                        sysevent set l3net_selfheal "done"
                    fi
                else
                    echo_t "[RDKB_AGG_SELFHEAL] : brlan1 already restarted. Not restarting again"
                fi
            fi
    esac

    WAN_INTERFACE=$(getWanInterfaceName)
    Check_If_Erouter_Exists=$(ifconfig -a | grep "$WAN_INTERFACE")
    ifconfig $WAN_INTERFACE > /dev/null
    wan_exists=$?
    if [ "$Check_If_Erouter_Exists" = "" ] && [ $wan_exists -ne 0 ]; then
        echo_t "RDKB_REBOOT : Erouter0 interface is not up ,Rebooting device"
        echo_t "Setting Last reboot reason Erouter_Down"
        t2CountNotify "SYS_ERROR_ErouterDown_reboot"
        reason="Erouter_Down"
        rebootCount=1
        rebootNeeded RM "" $reason $rebootCount
    fi

    UseLANIFIPV6=`sysevent get LANIPv6GUASupport`
    if [ "$ETHWAN_ENABLED" = "true" ] && [ "$UseLANIFIPV6" != "true" ] ; then
        # Do Not interfere with Auto WAN Hunting for first 15 Minutes of Uptime
        if [ "$SYSCFG_SEL_WANMODE" != "$WAN_AUTO_SEL_MODE" ] || [ $BOOTUP_TIME_SEC -gt 900 ] ; then
           check_if_wan_hasip=$(ip address show "$WAN_INTERFACE" | grep "inet" | grep "scope global")
           if [ "$check_if_wan_hasip" = "" ]; then
              ethWan_if=$(ls /sys/class/net/$WAN_INTERFACE/brif | grep "$ETHWAN_INTF_PREFIX1")
              if [ "$ethWan_if" = "" ]; then
                 echo_t "[RDKB_AGG_SELFHEAL] : Eth Wan Interface Prefix1:$ETHWAN_INTF_PREFIX1 returned empty. Trying Prefix2"
                 ethWan_if=$(ls /sys/class/net/$WAN_INTERFACE/brif | grep "$ETHWAN_INTF_PREFIX2")
              fi

              if [ "$ethWan_if" != "" ]; then
                 # During Eth WAN failover simulation test, skip selfheal for bringing up Eth WAN port.
                 if [ -f /tmp/.EWanLinkDown_TestRunning.txt ]; then
                    echo_t "[RDKB_AGG_SELFHEAL] : Eth WAN failover simulation test is going on. Hence, skipping selfheal this iteration."
                 else
                    echo_t "[RDKB_AGG_SELFHEAL] : $WAN_INTERFACE has no ip address, bring down and up Eth WAN port interface:$ethWan_if"
                    ip link set dev $ethWan_if down
                    sleep 5
                    ip link set dev $ethWan_if up
                 fi
              else
                 echo_t "[RDKB_AGG_SELFHEAL] : Eth Wan Interface returned empty skipping recovery."
              fi
           fi #"$check_if_wan_hasip" = ""
       fi #[ "$SYSCFG_SEL_WANMODE" != "$WAN_AUTO_SEL_MODE" ] || [ $BOOTUP_TIME_SEC -gt 900 ]
    fi #"$ETHWAN_ENABLED" = "true"

    # Recovery in case erouter0 doesn't have LinkLocal Address (XER10). 
    # Force the physical wan interface to re-generate its IPv6 link-local address.
    if [ "$MODEL_NUM" == "SCER11BEL" ]; then
        LL_ADDR=$(ip -6 addr show dev "$WAN_INTERFACE" | awk '/inet6 fe80::/ { print $2 }' | cut -d/ -f1)
        if [ -z "$LL_ADDR" ]; then
            echo_t "[RDKB_AGG_SELFHEAL] :No link-local address assigned on $WAN_INTERFACE. Restarting wan physical interface port to recover"
            ETHWAN_IF=$(ls /sys/class/net/$WAN_INTERFACE/brif | grep "$ETHWAN_INTF_PREFIX1")
            if [ "$ETHWAN_IF" != "" ]; then
                ip link set $ETHWAN_IF down
                sleep 2
                ip link set $ETHWAN_IF up
            fi
        else
            echo_t "[RDKB_AGG_SELFHEAL] :Link-local address is present on $WAN_INTERFACE. No action needed."
        fi
    fi

}

self_heal_dibbler_server()
{
   WAN_INTERFACE=$(getWanInterfaceName)
   DEFAULT_WAN_INTERFACE=$(sysevent get wan_ifname)
   if [ "$WAN_INTERFACE" != "$DEFAULT_WAN_INTERFACE" ]; then
       echo_t "DHCPv6 server disabled when secondary wan is active.."
       return
   fi

    #Checking dibbler server is running or not RDKB_10683
    BR_MODE=`syscfg get bridge_mode`
    DIBBLER_PID=$(busybox pidof dibbler-server)
    if [ "$DIBBLER_PID" = "" ]; then
#       IPV6_STATUS=$(sysevent get ipv6-status)
        DHCPv6_ServerType="`syscfg get dhcpv6s00::servertype`"
        routerMode="`syscfg get last_erouter_mode`"
        DHCPV6C_ENABLED=$(sysevent get dhcpv6c_enabled)
        if [ $BR_MODE -eq 0 ] && [ "$DHCPV6C_ENABLED" = "1" ]; then
            Sizeof_ServerConf=`stat -c %s $DIBBLER_SERVER_CONF`
            case $SELFHEAL_TYPE in
                "BASE"|"TCCBR")
                    DHCPv6EnableStatus=$(syscfg get dhcpv6s00::serverenable)
                    if [ "$IS_BCI" = "yes" ] && [ "0" = "$DHCPv6EnableStatus" ]; then
                        echo_t "DHCPv6 Disabled. Restart of Dibbler process not Required"
                        elif [ "$routerMode" = "1" ] || [ "$routerMode" = "" ] || [ "$Unit_Activated" = "0" ]; then
                        #TCCBR-4398 erouter0 not getting IPV6 prefix address from CMTS so as brlan0 also not getting IPV6 address.So unable to start dibbler service.
                        echo_t "DIBBLER : Non IPv6 mode dibbler server.conf file not present"
                    else
                        if [ "$DHCPv6_ServerType" -ne 2 ] || [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ];then
                            echo_t "RDKB_PROCESS_CRASHED : Dibbler is not running, restarting the dibbler"
                            t2CountNotify "SYS_SH_Dibbler_restart"
                        fi
                        if [ -f "/etc/dibbler/server.conf" ]; then
                            #CBR2-1372 adding log for brlan0 not having link scope address 
                            if [ "$MODEL_NUM" = "CGA4332COM" ]; then
                                BRLAN_CHKIPV6_LINK_ADDR=$(ip -6 addr show dev $PRIVATE_LAN| grep "scope link" )
                                if [ "$BRLAN_CHKIPV6_LINK_ADDR" == "" ]; then
                                   echo_t "DIBBLER: brlan0 does not have link scope address"
                                fi  
                            fi
                            BRLAN_CHKIPV6_DAD_FAILED=$(ip -6 addr show dev $PRIVATE_LAN | grep "scope link" | grep "tentative" | grep "dadfailed")
                            if [ "$BRLAN_CHKIPV6_DAD_FAILED" != "" ]; then
                                echo "DADFAILED : BRLAN0_DADFAILED"
                                t2CountNotify "SYS_ERROR_Dibbler_DAD_failed"
                                if [ "$BOX_TYPE" = "TCCBR" ]; then
                                    echo "DADFAILED : Recovering device from DADFAILED state"
                                    echo "1" > /proc/sys/net/ipv6/conf/$PRIVATE_LAN/disable_ipv6
                                    sleep 1
                                    sysctl -w net.ipv6.conf.$PRIVATE_LAN.accept_dad=0
                                    sleep 1
                                    echo "0" > /proc/sys/net/ipv6/conf/$PRIVATE_LAN/disable_ipv6
                                    sleep 1
                                    sysctl -w net.ipv6.conf.$PRIVATE_LAN.accept_dad=1
                                    sleep 5
                                    Dhcpv6_Client_restart "dibbler-client" "Idle"
                                fi
                            elif [ $Sizeof_ServerConf -le 1 ]; then
                                #some times the size of dibbler conf is 1 which fails empty file check.
                                echo "DIBBLER : Dibbler Server Config is empty"
                                t2CountNotify "SYS_ERROR_DibblerServer_emptyconf"
                                #TCCBR-5359 work around to get server.conf by restart dibbler-client once.
                                Dhcpv6_Client_restart "$DHCPv6_TYPE" "restart_for_dibbler-server"
                                ret_val=`echo $?`
                                if [ "$ret_val" = "1" ];then
                                    echo "DIBBLER : Dibbler Server Config is empty"
                                    t2CountNotify "SYS_ERROR_DibblerServer_emptyconf"
                                fi
                                #dibbler-client selfheal not required on SCER11BEL since WAN Unification use case will cover under WANManager.
                            elif [ "$DHCPv6_ServerType" -eq 2 ] && [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "WNXL11BWL" ] && [ "$BOX_TYPE" != "SR213" ] &&  [ "$BOX_TYPE" != "SCER11BEL" ];then
                                #if servertype is stateless(1-stateful,2-stateless),the ip assignment will be done through zebra process.Hence dibbler-server won't required.
                                echo_t "DHCPv6 servertype is stateless,dibbler-server restart not required"
                            else
                                dibbler-server stop
                                sleep 2
                                dibbler-server start
                            fi
                        else
                            echo_t "RDKB_PROCESS_CRASHED : dibbler server.conf file not present"
                            Dhcpv6_Client_restart "$DHCPv6_TYPE" "restart_for_dibbler-server"
                            ret_val=`echo $?`
                            if [ "$ret_val" = "2" ];then
                                echo_t "DIBBLER : Restart of dibbler failed with reason 2"
                            fi
                        fi
                    fi
                    ;;
                "SYSTEMD")
                    #ARRISXB6-7776 .. check if IANAEnable is set to 0
                    IANAEnable=$(syscfg show | grep "dhcpv6spool00::IANAEnable" | cut -d"=" -f2)
                    if [ "$IANAEnable" = "0" ] ; then
                        echo "[$(getDateTime)] IANAEnable disabled, enable and restart dhcp6 client and dibbler"
                        syscfg set dhcpv6spool00::IANAEnable 1
                        syscfg commit
                        sleep 2
                        #need to restart dhcp client to generate dibbler conf
                        dibbler_client_enable=$(syscfg get dibbler_client_enable_v2)
                        if [ "$dibbler_client_enable" = "true" ]; then
                            Dhcpv6_Client_restart "dibbler-client" "Idle"
                        else
                            Dhcpv6_Client_restart "ti_dhcp6c" "Idle"
                        fi
                    elif [ "$routerMode" = "1" ] || [ "$routerMode" = "" ] || [ "$Unit_Activated" = "0" ]; then
                        #TCCBR-4398 erouter0 not getting IPV6 prefix address from CMTS so as brlan0 also not getting IPV6 address.So unable to start dibbler service.
                        echo_t "DIBBLER : Non IPv6 mode dibbler server.conf file not present"
		    elif [ -s CCSP_COMMON_FIFO ]; then
			echo_t "DHCP renewal taking place"
                    else
                        if [ "$DHCPv6_ServerType" -ne 2 ] || [ "$BOX_TYPE" = "HUB4" ] || [ "$BOX_TYPE" = "SR300" ];then
                            echo_t "RDKB_PROCESS_CRASHED : Dibbler is not running, restarting the dibbler"
                            t2CountNotify "SYS_SH_Dibbler_restart"
                        fi
                        if [ -f "/etc/dibbler/server.conf" ]; then
                            BRLAN_CHKIPV6_DAD_FAILED=$(ip -6 addr show dev $PRIVATE_LAN | grep "scope link" | grep "tentative" | grep "dadfailed")
                            if [ "$BRLAN_CHKIPV6_DAD_FAILED" != "" ]; then
                                echo "DADFAILED : BRLAN0_DADFAILED"
                                t2CountNotify "SYS_ERROR_Dibbler_DAD_failed"
				if [ "$BOX_TYPE" = "XB6" ] && ( [ "$MANUFACTURE" = "Technicolor" ] || [ "$MANUFACTURE" = "Sercomm" ] ); then
                                    echo "DADFAILED : Recovering device from DADFAILED state"
                                    # save global ipv6 address before disable it
                                    v6addr=$(ip -6 addr show dev $PRIVATE_LAN | grep -i global | awk '{print $2}')
                                    echo "1" > /proc/sys/net/ipv6/conf/$PRIVATE_LAN/disable_ipv6
                                    sleep 1
                                    echo "0" > /proc/sys/net/ipv6/conf/$PRIVATE_LAN/disable_ipv6
                                    # re-add global ipv6 address after enabled it
                                    ip -6 addr add $v6addr dev $PRIVATE_LAN
                                    sleep 1
                                    dibbler-server stop
                                    sleep 1
                                    dibbler-server start
                                    sleep 5
                                elif [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ]; then
                                    echo "DADFAILED : Recovering device from DADFAILED state"
                                    # save global ipv6 address before disable it
                                    v6addr=$(ip -6 addr show dev $PRIVATE_LAN | grep -i global | awk '{print $2}')
                                    if [ -f /tmp/dhcpmgr_initialized ]; then
                                        sysevent set dhcpv6_client-stop
                                    else
                                        $DHCPV6_HANDLER dhcpv6_client_service_disable
                                    fi
                                    sysctl -w net.ipv6.conf.$PRIVATE_LAN.disable_ipv6=1
                                    sysctl -w net.ipv6.conf.$PRIVATE_LAN.accept_dad=0
                                    sleep 1
                                    sysctl -w net.ipv6.conf.$PRIVATE_LAN.disable_ipv6=0
                                    sysctl -w net.ipv6.conf.$PRIVATE_LAN.accept_dad=1
                                    sleep 1
                                    if [ -f /tmp/dhcpmgr_initialized ]; then
                                        sysevent set dhcpv6_client-start
                                    else
                                        $DHCPV6_HANDLER dhcpv6_client_service_enable
                                    fi
                                    # re-add global ipv6 address after enabled it
                                    ip -6 addr add $v6addr dev $PRIVATE_LAN
                                    sleep 5
                                fi
                            elif [ $Sizeof_ServerConf -le 1 ]; then
                                #some times the size of dibbler conf is 1 which fails empty file check.
                                Dhcpv6_Client_restart "$DHCPv6_TYPE" "restart_for_dibbler-server"
                                ret_val=`echo $?`
                                if [ "$ret_val" = "1" ];then
                                    echo "DIBBLER : Dibbler Server Config is empty"
                                    t2CountNotify "SYS_ERROR_DibblerServer_emptyconf"
                                fi
                                #dibbler-client selfheal not required on SCER11BEL since WAN Unification use case will cover under WANManager.
                            elif [ "$DHCPv6_ServerType" -eq 2 ] && [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] &&  [ "$BOX_TYPE" != "SCER11BEL" ];then
                                #if servertype is stateless(1-stateful,2-stateless),the ip assignment will be done through zebra process.Hence dibbler-server won't required.
                                echo_t "DHCPv6 servertype is stateless,dibbler-server restart not required"
                            else
                                dibbler-server stop
                                sleep 2
                                dibbler-server start
                            fi
                        else
                            echo_t "RDKB_PROCESS_CRASHED : dibbler server.conf file not present"
                            Dhcpv6_Client_restart "$DHCPv6_TYPE" "restart_for_dibbler-server"
                            ret_val=`echo $?`
                            if [ "$ret_val" = "2" ];then
                                echo_t "DIBBLER : Restart of dibbler failed with reason 2"
                            fi
                        fi
                    fi
                    ;;
            esac
        fi
    fi
}

self_heal_dhcp_clients()
{
    # Parametizing ps+grep "as" part of RDKB-28847
    PS_WW_VAL=$(ps -ww)
    # Checking for WAN_INTERFACE
    WAN_INTERFACE=$(getWanInterfaceName)
    DHCPV6_ERROR_FILE="/tmp/.dhcpv6SolicitLoopError"
    WAN_STATUS=$(sysevent get wan-status)
    WAN_IPv6_Addr=$(ifconfig $WAN_INTERFACE | grep "inet" | grep -v "inet6")

    # Disabling Device.DHCPv6.Client.1.Enable check for now. Will be enabled once parameter is used to Enable or Disable v4/v6 clients in the field.

    #if [ -f /tmp/dhcpmgr_initialized ]; then
    #   DHCPV4C_STATUS=$(dmcli eRT retv Device.DHCPv4.Client.1.Enable)
    #   DHCPV6C_STATUS=$(dmcli eRT retv Device.DHCPv6.Client.1.Enable)
    #else
    #   DHCPV4C_STATUS=true
    #   DHCPV6C_STATUS=true
    #fi

    DHCPV4C_STATUS=true
    DHCPV6C_STATUS=true

    if [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "CGA4131COM" ] || [ "$MODEL_NUM" = "CGM4140COM" ] || [ "$MODEL_NUM" = "CGM4331COM" ] || [ "$MODEL_NUM" = "TG4482A" ] || [ "$MODEL_NUM" = "VTER11QEL" ]
    then
        DHCPV6_HANDLER="/usr/bin/service_dhcpv6_client"
    else
        DHCPV6_HANDLER="/etc/utopia/service.d/service_dhcpv6_client.sh"
    fi

    case $SELFHEAL_TYPE in
        "BASE"|"SYSTEMD")
            if [ "$WAN_STATUS" != "started" ]; then
                echo_t "WAN_STATUS : wan-status is $WAN_STATUS"
                if [ "$WAN_STATUS" = "stopped" ]; then
                    t2CountNotify "RF_ERROR_WAN_stopped"
                fi
            fi
            ;;
        "TCCBR")
            ;;
    esac
    #dibbler-client selfheal not required on SCER11BEL since WAN Unification use case will cover under WANManager.
    if [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$BOX_TYPE" != "WNXL11BWL" ] && [ -f "$DHCPV6_ERROR_FILE" ] && [ "$WAN_STATUS" = "started" ] && [ "$WAN_IPv6_Addr" != "" ] && [ "$BOX_TYPE" != "SCER11BEL" ]; then
        isIPv6=$(ifconfig $WAN_INTERFACE | grep "inet6" | grep "Scope:Global")
        echo_t "isIPv6 = $isIPv6"
        if [ "$isIPv6" = "" ] && [ "$Unit_Activated" != "0" ]; then
            case $SELFHEAL_TYPE in
                "BASE"|"SYSTEMD")
                    echo_t "[RDKB_AGG_SELFHEAL] : $DHCPV6_ERROR_FILE file present and $WAN_INTERFACE ipv6 address is empty, restarting dhcpv6 client"
                    ;;
                "TCCBR")
                    echo_t "[RDKB_AGG_SELFHEAL] : $DHCPV6_ERROR_FILE file present and $WAN_INTERFACE ipv6 address is empty, restarting ti_dhcp6c"
                    ;;
            esac
            rm -rf $DHCPV6_ERROR_FILE
            dibbler_client_enable=$(syscfg get dibbler_client_enable_v2)
            if [ "$dibbler_client_enable" = "true" ]; then
                Dhcpv6_Client_restart "dibbler-client" "Idle"
            else
                Dhcpv6_Client_restart "ti_dhcp6c" "Idle"
            fi
        fi
    fi
    #Logic added in reference to RDKB-25714
    #to check erouter0 has Global IPv6 or not and accordingly kill the process
    #responsible for the same. The killed processes will get restarted
    #by the later stages of this script.
    erouter0_up_check=$(ifconfig $WAN_INTERFACE | grep "UP")
    erouter_mode_check=$(syscfg get last_erouter_mode) #Check given for non IPv6 bootfiles RDKB-27963
    erouter0_globalv6_test=$(ifconfig $WAN_INTERFACE | grep "inet6" | grep "Scope:Global" | awk '{print $(NF-1)}' | cut -f1 -d":")
    IPV6_STATUS_CHECK_GIPV6=$(sysevent get ipv6-status) #Check given for non IPv6 bootfiles RDKB-27963
        if [ "$erouter0_globalv6_test" = "" ] && [ "$WAN_STATUS" = "started" ] && [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$BOX_TYPE" != "WNXL11BWL" ] && [ "$UseLANIFIPV6" != "true" ]; then
            case $SELFHEAL_TYPE in
                "SYSTEMD")
                    udhcpc_enable=`syscfg get UDHCPEnable_v2`
                    if [ "$erouter0_up_check" = "" ] && [ "x$MAPT_CONFIG" != "xset" ]; then
                        echo_t "[RDKB_AGG_SELFHEAL] : erouter0 is DOWN, making it UP"
                        ifconfig $WAN_INTERFACE up
                        if ( ( [ "$MANUFACTURE" = "Technicolor" ] || [ "$MANUFACTURE" = "Sercomm" ] ) && [ "$BOX_TYPE" = "XB6" ] && [ $DHCPV4C_STATUS != "false" ]) || [ "$udhcpc_enable" = "true" ]; then
                        #Adding to kill ipv4 process to solve RDKB-27177
                        task_to_kill=`ps w | grep udhcpc | grep erouter | cut -f1 -d " "`
                        if [ "x$task_to_kill" = "x" ]; then
                            task_to_kill=`ps w | grep udhcpc | grep erouter | cut -f2 -d " "`
                        fi
                        if [ "x$task_to_kill" != "x" ]; then
                            kill $task_to_kill
                        fi
                        #RDKB-27177 fix ends here
                    fi
                    fi
                    if ( [ "x$IPV6_STATUS_CHECK_GIPV6" != "x" ] || [ "x$IPV6_STATUS_CHECK_GIPV6" != "xstopped" ] ) && [ "$erouter_mode_check" -ne 1 ] && [ "$Unit_Activated" != "0" ]; then
                    if ( [ "$MANUFACTURE" = "Technicolor" ] || [ "$MANUFACTURE" = "Sercomm" ] ) && [ "$BOX_TYPE" = "XB6" ] && [ $DHCPV6C_STATUS != "false" ]; then
                        echo_t "[RDKB_AGG_SELFHEAL] : Killing dibbler as Global IPv6 not attached"
                        dibbler_client_pid=$(ps w | grep -i dibbler-client | grep -v grep | awk '{print $1}')
                        if [ -n "$dibbler_client_pid" ]; then
                            echo_t "[RDKB_AGG_SELFHEAL] : Killing dibbler-client with pid $dibbler_client_pid"
                            killall -9 dibbler-client
                        fi
                        if [ -f /tmp/dhcpmgr_initialized ]; then
                            sysevent set dhcpv6_client-stop
                        else
                            /usr/sbin/dibbler-client stop
                        fi
                    elif [ "$BOX_TYPE" = "XB6" ]; then
                        echo_t "DHCP_CLIENT : Killing DHCP Client for v6 as Global IPv6 not attached"
                        dibbler_client_pid=$(ps w | grep -i dibbler-client | grep -v grep | awk '{print $1}')
                        if [ -n "$dibbler_client_pid" ]; then
                            echo_t "[RDKB_AGG_SELFHEAL] :  Killing dibbler-client with pid $dibbler_client_pid"
                            killall -9 dibbler-client
                        fi
                        if [ "$MODEL_NUM" = "CGM4981COM" ] || [ "$MODEL_NUM" = "CGM601TCOM" ] || [ "$MODEL_NUM" = "CWA438TCOM" ] || [ "$MODEL_NUM" = "SG417DBCT" ]
                        then
                            sh $DHCPV6_HANDLER disable
                        else
                            if [ -f /tmp/dhcpmgr_initialized ]; then
                                sysevent set dhcpv6_client-stop
                            else
                                $DHCPV6_HANDLER dhcpv6_client_service_disable
                            fi
                        fi
                    fi
                    fi
                    ;;
                "BASE")
                    if ( [ "x$IPV6_STATUS_CHECK_GIPV6" != "x" ] || [ "x$IPV6_STATUS_CHECK_GIPV6" != "xstopped" ] ) && [ "$erouter_mode_check" -ne 1 ] && [ "$Unit_Activated" != "0" ]; then
                    task_to_be_killed=$(ps | grep -i "dhcp6c" | grep -i "erouter0" | cut -f1 -d" ")
                    if [ "$task_to_be_killed" = "" ]; then
                        task_to_be_killed=$(ps | grep -i "dhcp6c" | grep -i "erouter0" | cut -f2 -d" ")
                    fi
                    if [ "$erouter0_up_check" = "" ]; then
                        echo_t "[RDKB_AGG_SELFHEAL] : erouter0 is DOWN, making it UP"
                        ifconfig $WAN_INTERFACE up
                        #Adding to kill ipv4 process to solve RDKB-27177
                        task_to_kill=`ps w | grep udhcpc | grep erouter | cut -f1 -d " "`
                        if [ "x$task_to_kill" = "x" ]; then
                            task_to_kill=`ps w | grep udhcpc | grep erouter | cut -f2 -d " "`
                        fi
                        if [ "x$task_to_kill" != "x" ]; then
                            kill $task_to_kill
                        fi
                        #RDKB-27177 fix ends here
                    fi
                    if [ "$task_to_be_killed" != "" ]; then
                        echo_t "DHCP_CLIENT : Killing DHCP Client for v6 as Global IPv6 not attached"
                        kill "$task_to_be_killed"
                        sleep 3
                    fi
                    fi
                    ;;
                "TCCBR")
                    if [ "$erouter0_up_check" = "" ] && [ "x$MAPT_CONFIG" != "xset" ]; then
                        echo_t "[RDKB_AGG_SELFHEAL] : erouter0 is DOWN, making it UP"
                        ifconfig $WAN_INTERFACE up
                        #Adding to kill ipv4 process, later restarted to solve RDKB-27177
                        task_to_be_killed=$(ps w | grep "udhcpc" | grep "erouter" | cut -f1 -d" ")
                        if [ "$task_to_be_killed" = "" ]; then
                            task_to_be_killed=$(ps w | grep "udhcpc" | grep "erouter" | cut -f2 -d" ")
                        fi
                        if [ "$task_to_be_killed" != "" ]; then
                            kill "$task_to_be_killed"
                        fi
                        #RDKB-27177 addition ends here
                    fi
                    if ( [ "x$IPV6_STATUS_CHECK_GIPV6" != "x" ] || [ "x$IPV6_STATUS_CHECK_GIPV6" != "xstopped" ] ) && [ "$erouter_mode_check" -ne 1 ] && [ "$Unit_Activated" != "0" ] && [ $DHCPV6C_STATUS != "false" ]; then
                        echo_t "[RDKB_AGG_SELFHEAL] : Killing dibbler as Global IPv6 not attached"
                        dibbler_client_pid=$(ps w | grep -i dibbler-client | grep -v grep | awk '{print $1}')
                        if [ -n "$dibbler_client_pid" ]; then
                            echo_t "[RDKB_AGG_SELFHEAL] : Killing dibbler-client with pid $dibbler_client_pid"
                            killall -9 dibbler-client
                        fi
                        if [ -f /tmp/dhcpmgr_initialized ]; then
                            sysevent set dhcpv6_client-stop
                        else
                            /usr/sbin/dibbler-client stop
                        fi
                    fi
                    ;;
            esac
        elif [ "$erouter0_globalv6_test" != "" ] && [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$BOX_TYPE" != "WNXL11BWL" ] && [ "$UseLANIFIPV6" != "true" ]; then
                echo_t "[RDKB_AGG_SELFHEAL] : Global IPv6 is present"
        else
                if [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "WNXL11BWL" ] && [ "$UseLANIFIPV6" != "true" ]; then
                   echo_t "[RDKB_AGG_SELFHEAL] : Global IPv6 not present or WAN Status Not Started: $WAN_STATUS"
                fi
        fi
    #Logic ends here for RDKB-25714
    #dibbler-client selfheal not required on SCER11BEL since WAN Unification use case will cover under WANManager.
    if [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$WAN_STATUS" = "started" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$BOX_TYPE" != "WNXL11BWL" ] && [ "$BOX_TYPE" = "SCER11BEL" ]; then
        wan_dhcp_client_v4=1
        wan_dhcp_client_v6=1
        case $SELFHEAL_TYPE in
            "BASE"|"SYSTEMD")
                UDHCPC_Enable=$(syscfg get UDHCPEnable_v2)
                dibbler_client_enable=$(syscfg get dibbler_client_enable_v2)

		if ( ( [ "$MANUFACTURE" = "Sercomm" ] || [ "$MANUFACTURE" = "Technicolor" ] ) && [ "$BOX_TYPE" != "XB3" ] ) || [ "$WAN_TYPE" = "EPON" ] || [ "$BOX_TYPE" = "VNTXER5" ] || [ "$BOX_TYPE" = "SCER11BEL" ]; then
                    check_wan_dhcp_client_v4=$(ps ww | grep "udhcpc" | grep "erouter")
                    check_wan_dhcp_client_v6=$(ps w | grep "dibbler-client" | grep -v "grep")
                else
                    if [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ] || [ "$SELFHEAL_TYPE" = "BASE" -a "$BOX_TYPE" = "XB3" ]; then
                        dhcp_cli_output=$(ps w | grep "ti_" | grep "erouter0")

                        if [ "$UDHCPC_Enable" = "true" ]; then
                            check_wan_dhcp_client_v4=$(ps w | grep "sbin/udhcpc" | grep "erouter")
                        else
                            check_wan_dhcp_client_v4=$(echo "$dhcp_cli_output" | grep "ti_udhcpc")
                        fi
                        if [ "$dibbler_client_enable" = "true" ]; then
                            check_wan_dhcp_client_v6=$(ps w | grep "dibbler-client" | grep -v "grep")
                        else
                            check_wan_dhcp_client_v6=$(echo "$dhcp_cli_output" | grep "ti_dhcp6c")
                        fi
                    else
                        dhcp_cli_output=$(ps w | grep "ti_" | grep "erouter0")
                        check_wan_dhcp_client_v4=$(echo "$dhcp_cli_output" | grep "ti_udhcpc")
                        check_wan_dhcp_client_v6=$(echo "$dhcp_cli_output" | grep "ti_dhcp6c")
                    fi
                fi
                ;;
            "TCCBR")
                check_wan_dhcp_client_v4=$(ps ww | grep "udhcpc" | grep "erouter")
                check_wan_dhcp_client_v6=$(ps w | grep "dibbler-client" | grep -v "grep")
                ;;
        esac

        case $SELFHEAL_TYPE in
            "BASE")
                if [ "$BOX_TYPE" = "XB3" ]; then

                    if [ "$check_wan_dhcp_client_v4" != "" ] && [ "$check_wan_dhcp_client_v6" != "" ]; then
                        if [ "$(cat /proc/net/dbrctl/mode)"  = "standbay" ]; then
                            echo_t "RDKB_AGG_SELFHEAL : dbrctl mode is standbay, changing mode to registered"
                            echo "registered" > /proc/net/dbrctl/mode
                        fi
                    fi
                fi

                if [ "$check_wan_dhcp_client_v4" = "" ] && [ "x$MAPT_CONFIG" != "xset" ]; then
                    echo_t "RDKB_PROCESS_CRASHED : DHCP Client for v4 is not running, need restart "
                    t2CountNotify "SYS_ERROR_DHCPV4Client_notrunning"
                    wan_dhcp_client_v4=0
                fi
                ;;
            "TCCBR")
                if [ "$check_wan_dhcp_client_v4" = "" ]; then
                    echo_t "RDKB_PROCESS_CRASHED : DHCP Client for v4 is not running, need restart "
                    t2CountNotify "SYS_ERROR_DHCPV4Client_notrunning"
                    wan_dhcp_client_v4=0
                fi
                ;;
            "SYSTEMD")
                if [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ] || [ "$MODEL_NUM" = "INTEL_PUMA" ] ; then
                    #Intel Proposed RDKB Generic Bug Fix from XB6 SDK
                    LAST_EROUTER_MODE=$(syscfg get last_erouter_mode)
                fi

                if [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ] || [ "$MODEL_NUM" = "INTEL_PUMA" ] ; then
                    #Intel Proposed RDKB Generic Bug Fix from XB6 SDK
                    if [ "$check_wan_dhcp_client_v4" = "" ] && [ "$LAST_EROUTER_MODE" != "2" ] && [ "x$MAPT_CONFIG" != "xset" ]; then
                        echo_t "RDKB_PROCESS_CRASHED : DHCP Client for v4 is not running, need restart "
                        t2CountNotify "SYS_ERROR_DHCPV4Client_notrunning"
                        wan_dhcp_client_v4=0
                    fi
                else
                    if [ "$check_wan_dhcp_client_v4" = "" ] && [ "x$MAPT_CONFIG" != "xset" ] && [ $DHCPV4C_STATUS != "false" ]; then
                        echo_t "RDKB_PROCESS_CRASHED : DHCP Client for v4 is not running, need restart "
                        t2CountNotify "SYS_ERROR_DHCPV4Client_notrunning"
                        wan_dhcp_client_v4=0
                    fi
                fi
                ;;
        esac


        if [ "$WAN_TYPE" != "EPON" ]; then
            case $SELFHEAL_TYPE in
                "BASE"|"TCCBR")
                    if [ "$check_wan_dhcp_client_v6" = "" ] && [ "$Unit_Activated" != "0" ] && [ $DHCPV6C_STATUS != "false" ]; then
                        echo_t "RDKB_PROCESS_CRASHED : DHCP Client for v6 is not running, need restart"
                        t2CountNotify "SYS_ERROR_DHCPV6Client_notrunning"
                        wan_dhcp_client_v6=0
                    fi
                    ;;
                "SYSTEMD")
                    if [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ] || [ "$MODEL_NUM" = "INTEL_PUMA" ] ; then
                        #Intel Proposed RDKB Generic Bug Fix from XB6 SDK
                        if [ "$check_wan_dhcp_client_v6" = "" ] && [ "$LAST_EROUTER_MODE" != "1" ] && [ "$Unit_Activated" != "0" ]; then
                            echo_t "RDKB_PROCESS_CRASHED : DHCP Client for v6 is not running, need restart"
                            t2CountNotify "SYS_ERROR_DHCPV6Client_notrunning"
                            wan_dhcp_client_v6=0
                        fi
                    else
                        if [ "$check_wan_dhcp_client_v6" = "" ] && [ "$Unit_Activated" != "0" ] && [ $DHCPV6C_STATUS != "false" ]; then
                            echo_t "RDKB_PROCESS_CRASHED : DHCP Client for v6 is not running, need restart"
                            t2CountNotify "SYS_ERROR_DHCPV6Client_notrunning"
                            wan_dhcp_client_v6=0
                        fi
                    fi
                    ;;
            esac

            DHCP_STATUS=$(dmcli eRT retv Device.DHCPv4.Client.1.DHCPStatus)

            if [ "$DHCP_STATUS" != "" ] && [ "$DHCP_STATUS" != "Bound" ] && [ "x$MAPT_CONFIG" != "xset" ] && [ $DHCPV4C_STATUS != "false" ]; then

                echo_t "DHCP_CLIENT : DHCPStatusValue is $DHCP_STATUS"
                if [ $wan_dhcp_client_v4 -eq 0 ] || [ $wan_dhcp_client_v6 -eq 0 ]; then
                    case $SELFHEAL_TYPE in
                        "BASE"|"TCCBR")
                            echo_t "DHCP_CLIENT : DHCPStatus is not Bound, restarting WAN"
                            ;;
                        "SYSTEMD")
                            echo_t "DHCP_CLIENT : DHCPStatus is $DHCP_STATUS, restarting WAN"
                            ;;
                    esac
                    sh /etc/utopia/service.d/service_wan.sh wan-stop
                    sh /etc/utopia/service.d/service_wan.sh wan-start
                    wan_dhcp_client_v4=1
                    wan_dhcp_client_v6=1
                fi
            fi
        fi

        case $SELFHEAL_TYPE in
            "BASE")
                if [ $wan_dhcp_client_v4 -eq 0 ] && [ "x$MAPT_CONFIG" != "xset" ]; then
                    if ( [ "$MANUFACTURE" = "Technicolor" ] || [ "$MANUFACTURE" = "Sercomm" ] ) && [ "$BOX_TYPE" != "XB3" ]; then
                        V4_EXEC_CMD="/sbin/udhcpc -i erouter0 -p /tmp/udhcpc.erouter0.pid -s /etc/udhcpc.script"
                    elif [ "$WAN_TYPE" = "EPON" ]; then
                        echo_t "Calling epon_utility.sh to restart udhcpc "
                        sh /usr/ccsp/epon_utility.sh
                    else
                        if [ "$BOX_TYPE" = "XB6" -a "$MANUFACTURE" = "Arris" ] || [ "$BOX_TYPE" = "XB3" ]; then

                            if [ "$UDHCPC_Enable" = "true" ]; then
                                V4_EXEC_CMD="/sbin/udhcpc -i erouter0 -p /tmp/udhcpc.erouter0.pid -s /etc/udhcpc.script"
                            else
                                DHCPC_PID_FILE="/var/run/eRT_ti_udhcpc.pid"
                                V4_EXEC_CMD="ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i $WAN_INTERFACE -H DocsisGateway -p $DHCPC_PID_FILE -B -b 1"
                            fi
                        else
                            DHCPC_PID_FILE="/var/run/eRT_ti_udhcpc.pid"
                            V4_EXEC_CMD="ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i $WAN_INTERFACE -H DocsisGateway -p $DHCPC_PID_FILE -B -b 1"
                        fi
                    fi
                    echo_t "DHCP_CLIENT : Restarting DHCP Client for v4"
                    eval "$V4_EXEC_CMD"
                    sleep 5
                    wan_dhcp_client_v4=1
                fi

                if [ $wan_dhcp_client_v6 -eq 0 ]; then
                    echo_t "DHCP_CLIENT : Restarting DHCP Client for v6"
		    if ( [ "$MANUFACTURE" = "Sercomm" ] || [ "$MANUFACTURE" = "Technicolor" ] ) && [ "$BOX_TYPE" != "XB3" ]; then
                        /lib/rdk/dibbler-init.sh
                        sleep 2
                        /usr/sbin/dibbler-client start
                    elif [ "$WAN_TYPE" = "EPON" ]; then
                        echo_t "Calling dibbler_starter.sh to restart dibbler-client "
                        sh /usr/ccsp/dibbler_starter.sh
                    else
                        dibbler_client_enable=$(syscfg get dibbler_client_enable_v2)
                        if [ "$dibbler_client_enable" = "true" ]; then
                            Dhcpv6_Client_restart "dibbler-client" "Idle"
                        else
                            Dhcpv6_Client_restart "ti_dhcp6c" "Idle"
                        fi
                    fi
                    wan_dhcp_client_v6=1
                fi
                ;;
            "TCCBR")
                if [ $wan_dhcp_client_v4 -eq 0 ] && [ "x$MAPT_CONFIG" != "xset" ]; then
                    V4_EXEC_CMD="sysevent set dhcp_client-start"
                    echo_t "DHCP_CLIENT : Restarting DHCP Client for v4"
                    eval "$V4_EXEC_CMD"
                    sleep 5
                    wan_dhcp_client_v4=1
                fi

                if [ $wan_dhcp_client_v6 -eq 0 ] && [ $DHCPV6C_STATUS != "false" ]; then
                    echo_t "DHCP_CLIENT : Restarting DHCP Client for v6"
                    if [ "$MODEL_NUM" = "CGA4332COM" ]; then
                        /lib/rdk/dibbler-init.sh
                        sleep 2
                        /usr/sbin/dibbler-client start
                    else
                        sysevent set dhcpv6_client-stop
                        sysevent set dhcpv6_client-start
                    fi
                    wan_dhcp_client_v6=1
                fi
                ;;
            "SYSTEMD")
                ;;
        esac

    fi # [ "$WAN_STATUS" = "started" ]

    case $SELFHEAL_TYPE in
	"TCCBR")
	;;
	"SYSTEMD")
        if [ "$WAN_STATUS" = "started" ]; then
            if [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$BOX_TYPE" != "WNXL11BWL" ] && [ "$BOX_TYPE" != "SCER11BEL" ]; then
                if [ $wan_dhcp_client_v4 -eq 0 ] && [ "x$MAPT_CONFIG" != "xset" ] && [ $DHCPV4C_STATUS != "false" ]; then
                    if [ "$MANUFACTURE" = "Technicolor" ] || [ "$MANUFACTURE" = "Sercomm" ]; then
                        V4_EXEC_CMD="sysevent set dhcp_client-start"
                    elif [ "$WAN_TYPE" = "EPON" ]; then
                        echo_t "Calling epon_utility.sh to restart udhcpc "
                        sh /usr/ccsp/epon_utility.sh
                    else
                        if [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ]; then
                            if [ "$UDHCPC_Enable" = "true" ]; then
                                V4_EXEC_CMD="/sbin/udhcpc -i erouter0 -p /tmp/udhcpc.erouter0.pid -s /etc/udhcpc.script"
                            else
                                #For AXB6 b -4 option is added to avoid timeout.
                                DHCPC_PID_FILE="/var/run/eRT_ti_udhcpc.pid"
                                V4_EXEC_CMD="ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i $WAN_INTERFACE -H DocsisGateway -p $DHCPC_PID_FILE -B -b 4"
                            fi
                        else
                            DHCPC_PID_FILE="/var/run/eRT_ti_udhcpc.pid"
                            V4_EXEC_CMD="ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i $WAN_INTERFACE -H DocsisGateway -p $DHCPC_PID_FILE -B -b 1"
                        fi
                    fi
                    echo_t "DHCP_CLIENT : Restarting DHCP Client for v4"
                    eval "$V4_EXEC_CMD"
                    sleep 5
                    wan_dhcp_client_v4=1
                fi
		#ARRISXB6-8319
		#check if interface is down or default route is missing.
		if ([ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ]) && [ "$LAST_EROUTER_MODE" != "2" ] && [ $DHCPV4C_STATUS != "false" ]; then
                    ip route show default | grep "default"
                    if [ $? -ne 0 ] ; then
			ifconfig $WAN_INTERFACE up
			sleep 2
			if [ "$UDHCPC_Enable" = "true" ]; then
                            echo_t "restart udhcp"
                            DHCPC_PID_FILE="/tmp/udhcpc.erouter0.pid"
			else
                            echo_t "restart ti_udhcp"
                            DHCPC_PID_FILE="/var/run/eRT_ti_udhcpc.pid"
			fi
			if [ -f $DHCPC_PID_FILE ]; then
                            echo_t "SERVICE_DHCP : Killing $(cat $DHCPC_PID_FILE)"
                            kill -9 "$(cat $DHCPC_PID_FILE)"
                            rm -f $DHCPC_PID_FILE
			fi
			if [ "$UDHCPC_Enable" = "true" ]; then
                            V4_EXEC_CMD="/sbin/udhcpc -i erouter0 -p /tmp/udhcpc.erouter0.pid -s /etc/udhcpc.script"
			else
                            #For AXB6 b -4 option is added to avoid timeout.
                            V4_EXEC_CMD="ti_udhcpc -plugin /lib/libert_dhcpv4_plugin.so -i $WAN_INTERFACE -H DocsisGateway -p $DHCPC_PID_FILE -B -b 4"
			fi
			echo_t "DHCP_CLIENT : Restarting DHCP Client for v4"
			eval "$V4_EXEC_CMD"
			sleep 5
			wan_dhcp_client_v4=1
                    fi
		fi
		if [ $wan_dhcp_client_v6 -eq 0 ] && [ $DHCPV6C_STATUS != "false" ]; then
            echo_t "DHCP_CLIENT : Restarting DHCP Client for v6"
	    if ( [ "$MANUFACTURE" = "Sercomm" ] || [ "$MANUFACTURE" = "Technicolor" ] ) && [ "$BOX_TYPE" != "XB3" ] && [ ! -f /tmp/dhcpmgr_initialized ]; then
                /lib/rdk/dibbler-init.sh
                sleep 2
                /usr/sbin/dibbler-client start
            elif [ "$WAN_TYPE" = "EPON" ]; then
                echo_t "Calling dibbler_starter.sh to restart dibbler-client "
                sh /usr/ccsp/dibbler_starter.sh
            else
                dibbler_client_enable=$(syscfg get dibbler_client_enable_v2)
                if [ "$dibbler_client_enable" = "true" ] && [ $DHCPV6C_STATUS != "false" ]; then
                    Dhcpv6_Client_restart "dibbler-client" "Idle"
                else
                    Dhcpv6_Client_restart "ti_dhcp6c" "Idle"
                fi
            fi
                    wan_dhcp_client_v6=1
		fi
            fi #Not HUB4//SR300//SE501/SR213/WNXL11BWL
        fi
	    ;;
    esac
}

#Selfheal for dropbear not listening on ipv6 and crash
self_heal_dropbear()
{
    case $SELFHEAL_TYPE in
         "BASE")
             # TODO: move DROPBEAR BASE code with TCCBR,SYSTEMD code!
         ;;
         "TCCBR")
             #Check dropbear is alive to do rsync/scp to/fro ATOM
             if [ "$ARM_INTERFACE_IP" != "" ] && [ ! -f "/nvram/ETHWAN_ENABLE" ]; then
                 DROPBEAR_ENABLE=$(ps -ww | grep "dropbear" | grep "$ARM_INTERFACE_IP")
                 if [ "$DROPBEAR_ENABLE" = "" ]; then
                     echo_t "RDKB_PROCESS_CRASHED : rsync_dropbear_process is not running, need restart"
                     t2CountNotify "SYS_SH_Dropbear_restart"
                     dropbear -E -s -p $ARM_INTERFACE_IP:22 > /dev/null 2>&1
                 fi
             fi
         ;;
         "SYSTEMD")
             if [ "$BOX_TYPE" != "HUB4" ] && [ "$BOX_TYPE" != "SR300" ] && [ "$BOX_TYPE" != "SE501" ] && [ "$BOX_TYPE" != "SR213" ] && [ "$BOX_TYPE" != "WNXL11BWL" ] && [ "$BOX_TYPE" != "SCER11BEL" ]; then
                 #Checking dropbear PID
                 DROPBEAR_PID=$(busybox pidof dropbear)
                 if [ "$DROPBEAR_PID" = "" ]; then
                     echo_t "RDKB_PROCESS_CRASHED : dropbear_process is not running, restarting it"
                     t2CountNotify "SYS_SH_Dropbear_restart"
                     sh /etc/utopia/service.d/service_sshd.sh sshd-restart &
                 else
                     #In platforms with multiple dropbear instances, checking the instance on wan interface
                     PS_DROPBEAR=$(ps ww | grep 'dropbear -E -s -b /etc/sshbanner.txt' | grep -v grep)
                     if [ -z "$PS_DROPBEAR" ];then
    			NUMPROC_DROPBEAR=0;
		     else
                     	NUMPROC_DROPBEAR=$(echo $PS_DROPBEAR | wc -l)
                     fi
                     if [ "$NUMPROC_DROPBEAR" -eq 0 ] ; then
                         echo_t "RDKB_PROCESS_CRASHED : dropbear_process is not running, restarting it"
                         sh /etc/utopia/service.d/service_sshd.sh sshd-restart &
                     else
                         #Checking if dropbear binds to ipv4 but fails with ipv6
                         NUMPROC_DROPBEAR_IPV6=$(echo $PS_DROPBEAR |  egrep -c '([a-f0-9:]+:+)+[a-f0-9]+')
                         NS_DROPBEAR_IPV6=$(netstat -tulpn | grep -c ":22 .*:::\* .*dropbear")
                         if [ "$NUMPROC_DROPBEAR_IPV6" -gt 0 -a "$NS_DROPBEAR_IPV6" -eq "0" ]; then
                              echo_t "Dropbear not listening on ipv6 address, restarting dropbear "
                              sh /etc/utopia/service.d/service_sshd.sh sshd-restart &
                         else
                             #Check dropbear is running with correct erouter0 IPv6 address or not
                             DROPBEAR_INTERFACE=$(cat /etc/device.properties | grep -i DROPBEAR_INTERFACE | cut -d '=' -f2)
                             if [ "$DROPBEAR_INTERFACE" = "erouter0" ] ; then
                                 NUM_OF_DROPBEAR_WITH_IPV6=$(echo $PS_DROPBEAR | pgrep -f dropbear.pid | wc -l)
                                 if [ "$NUM_OF_DROPBEAR_WITH_IPV6" -ge 1 ] ; then
                                     DROPBEAR_PIDS_WITH_IPV6=$(echo $PS_DROPBEAR | pgrep -f dropbear.pid)
                                     DROPBEAR_PID_WITH_IPV6=$(echo $DROPBEAR_PIDS_WITH_IPV6 | awk 'NR==1{print $1}')
                                     DROPBEAR_IPv6=$(cat /proc/$DROPBEAR_PID_WITH_IPV6/cmdline | awk -F"[][]" '{print $2}' | grep -i 2001)
                                     erouter0_globalv6=$(ip -6 addr show dev erouter0 | grep -i "scope global dynamic $")
                                     erouter0_globalv6=$(echo $erouter0_globalv6 | awk '{print $2}' | cut -f1 -d"/")
                                     if [ "$DROPBEAR_IPv6" != "$erouter0_globalv6" ]; then
                                         echo_t "Dropbear was running with eRouter0Ipv6:$DROPBEAR_IPv6, but not with:$erouter0_globalv6 restart the sshd service"
                                         sh /etc/utopia/service.d/service_sshd.sh sshd-restart &
                                     fi
				 fi
                             fi
                         fi
                     fi
                 fi
                 if [ -f "/nvram/ETHWAN_ENABLE" ]; then
                     NUMPROC=$(netstat -tulpn | grep ":22 " | grep -c "dropbear")
                     if [ $NUMPROC -lt 2 ] ; then
                         echo_t "EWAN mode : Dropbear not listening on ipv6 address, restarting dropbear "
                         sh /etc/utopia/service.d/service_sshd.sh sshd-restart &
                     fi
                 fi
             fi
         ;;
    esac
}

CCSP_ERR_NOT_CONNECT=190
CCSP_ERR_TIMEOUT=191
CCSP_ERR_NOT_EXIST=192

self_heal_ccspwifissp_hung()
{
    case $MODEL_NUM in
        *CGA4131COM*) thisREADYFILE="/tmp/.brcm_wifi_ready";;
        *CGM4331COM*) thisREADYFILE="/tmp/.brcm_wifi_ready";;
        *TG3482G*)    thisREADYFILE="/tmp/.qtn_ready";;
        *CGM4140COM*) thisREADYFILE="/tmp/.qtn_ready";;
        *TG4482A*)    thisREADYFILE="/tmp/.puma_wifi_ready";;
        *) ;;
    esac

    case $SELFHEAL_TYPE in
        "BASE")
        ;;
        "TCCBR")
        ;;
        "SYSTEMD")
            WiFi_PID=$(busybox pidof CcspWifiSsp)
            if [ "$WiFi_PID" != "" ]; then
                radioenable=$(dmcli eRT getv Device.WiFi.Radio.1.Enable)
                radioenable_timeout=$(echo "$radioenable" | grep "$CCSP_ERR_TIMEOUT")
                radioenable_notexist=$(echo "$radioenable" | grep "$CCSP_ERR_NOT_EXIST")
                if [ "$radioenable_timeout" != "" ] || [ "$radioenable_notexist" != "" ]; then
                    wifi_name=$(dmcli eRT getv com.cisco.spvtg.ccsp.wifi.Name)
                    wifi_name_timeout=$(echo "$wifi_name" | grep "$CCSP_ERR_TIMEOUT")
                    wifi_name_notexist=$(echo "$wifi_name" | grep "$CCSP_ERR_NOT_EXIST")
                    if [ "$wifi_name_timeout" != "" ] || [ "$wifi_name_notexist" != "" ]; then
                        if [ "$BOX_TYPE" = "XB6" ]; then
                            if [ -f "$thisREADYFILE" ]; then
                                echo_t "[RDKB_PLATFORM_ERROR] : CcspWifiSsp process is hung , restarting it"
                                systemctl restart ccspwifiagent
                                t2CountNotify "WIFI_SH_CcspWifiHung_restart"
                            fi
                        else
                            echo_t "[RDKB_PLATFORM_ERROR] : CcspWifiSsp process is hung , restarting it"
                            systemctl restart ccspwifiagent
                            t2CountNotify "WIFI_SH_CcspWifiHung_restart"
                        fi
                    fi
                fi
            fi
        ;;
    esac
}

#selfheal to assign WAN IP as NAS IP for ccsp-wifi-agent process, as NAS IP is getting Loopback IP
self_heal_nas_ip()
{
    case $SELFHEAL_TYPE in
                "TCCBR")
                    hostapd_enable=$(ps | grep -i hostapd | grep -v grep)
                    if [ "$hostapd_enable" != "" ]; then #issue seen only in selfheal, also hostapd should run while checking this, hence this condition
                        if [ "$MODEL_NUM" == "CGA4332COM" ] ; then
                              WAN_INTERFACE=`sysevent get current_wan_ifname`
                           if [ "$WAN_INTERFACE" = "" ]; then
                                WAN_INTERFACE="erouter0"
                           fi
                           WAN_IPv4_Addr=$(ifconfig $WAN_INTERFACE | grep "inet" | grep -v "inet6" | \
                                     cut -d":" -f2 | cut -d" " -f1)
                           LPBK_IPv4_Addr=127.0.0.1

                           for i in 9 10; do  #checking xfisec hotspot 
                              SSID_ENABLE=$(dmcli eRT getv Device.WiFi.SSID.$i.Enable | grep "value" | \
                                       cut -f3 -d":" | cut -f2 -d" ")
                              WL_INTERFACE=$(dmcli eRT getv Device.WiFi.SSID.$i.Alias | grep "value" | \
                                        cut -f3 -d":" | cut -f2 -d" ")

                              if [ "$SSID_ENABLE" = "true" ]; then #check only if VAP is enabled
                                  IP_SEC=`hostapd_cli -i $WL_INTERFACE get own_ip_addr 2>&1`
                                  if [ "$IP_SEC" != "Failed to connect to hostapd - wpa_ctrl_open: No such file or directory" ]; then
                                     if [ $IP_SEC == $LPBK_IPv4_Addr ]; then
                                        echo_t "[RDKB_AGG_SELFHEAL] : NAS IP of VAP $i is Loopback, changing to WAN IP"
                                        hostapd_cli -i $WL_INTERFACE set own_ip_addr $WAN_IPv4_Addr > /dev/null 2>&1 & #hostapd set only when NAS IP is loopback
                                     fi
                                  fi
                              fi
                           done
                        fi
                    fi
                ;;
                "SYSTEMD")
             wifi_process=$(ps | grep -i "OneWifi" | grep -v grep | head -n1 | cut -d" " -f14 | \
             cut -d"/" -f4)
             hostapd_enable=$(ps | grep -i hostapd | grep -v grep)
             if [ "$wifi_process" != "OneWifi" ] && [ "$hostapd_enable" != "" ]; then #issue seen only in selfheal, also hostapd should run while checking this, hence this condition
                 if [ "$MODEL_NUM" == "CGM4331COM" ] || [ "$MODEL_NUM" == "CGM4981COM" ] || [ "$MODEL_NUM" == "CGM601TCOM" ] || [ "$MODEL_NUM" == "CWA438TCOM" ] || [ "$MODEL_NUM" == "SG417DBCT" ] ; then
                     WAN_INTERFACE=`sysevent get current_wan_ifname`
                     if [ "$WAN_INTERFACE" = "" ]; then
                         WAN_INTERFACE="erouter0"
                     fi
                     WAN_IPv4_Addr=$(ifconfig $WAN_INTERFACE | grep "inet" | grep -v "inet6" | \
                                     cut -d":" -f2 | cut -d" " -f1)
                     LPBK_IPv4_Addr=127.0.0.1

                     for i in 9 10 11 12; do  #checking xfisec hotspot and LnFsec
                         SSID_ENABLE=$(dmcli eRT getv Device.WiFi.SSID.$i.Enable | grep "value" | \
                                       cut -f3 -d":" | cut -f2 -d" ")
                         WL_INTERFACE=$(dmcli eRT getv Device.WiFi.SSID.$i.Alias | grep "value" | \
                                        cut -f3 -d":" | cut -f2 -d" ")

                         if [ "$SSID_ENABLE" = "true" ]; then #check only if VAP is enabled
                             IP_SEC=`hostapd_cli -i $WL_INTERFACE get own_ip_addr 2>&1`
                             if [ "$IP_SEC" != "Failed to connect to hostapd - wpa_ctrl_open: No such file or directory" ]; then
                                 if [ "$IP_SEC" = "$LPBK_IPv4_Addr" ]; then
                                     echo_t "[RDKB_AGG_SELFHEAL] : NAS IP of VAP $i is Loopback, changing to WAN IP"
                                     hostapd_cli -i $WL_INTERFACE set own_ip_addr $WAN_IPv4_Addr > /dev/null 2>&1 & #hostapd set only when NAS IP is loopback
                                 fi
                             fi
                         fi
                     done
                 fi
             fi
         ;;
    esac
}

self_heal_dhcpmgr ()
{
    if [ "x$(busybox pidof CcspDHCPMgr)" == "x" ]; then
       if [ ! "`systemctl restart CcspDHCPMgr  2>&1`" ]; then
          echo_t "[RDKB_AGG_SELFHEAL]: Restarting CcspDHCPMgr!"
       fi
    fi
}

wan_sysevents(){
    sysevent set wan_service-status
    sysevent set wan-restart
}

self_heal_wan(){
     wan_status=$(sysevent get wan-status)
     echo "Current Wan-status:$wan_status"
     if [ "$wan_status" == "starting" ]; then
         if [ ! -f /tmp/wan_starting ]; then
             touch /tmp/wan_starting
         else
             echo "======ip route show =========" >> /rdklogs/logs/wan-status_stuck.txt
             ip route show >> /rdklogs/logs/wan-status_stuck.txt
             echo "======ip -6 route show =========" >> /rdklogs/logs/wan-status_stuck.txt
             ip -6 route show >> /rdklogs/logs/wan-status_stuck.txt
             echo "====sysevent show output to /rdklogs/logs/sysevents_wan_stuck.txt ====" >> /rdklogs/logs/wan-status_stuck.txt
             sysevent show /rdklogs/logs/sysevents_wan_stuck.txt
             echo "======ifconfig -a=========" >> /rdklogs/logs/wan-status_stuck.txt
             ifconfig -a >> /rdklogs/logs/wan-status_stuck.txt
             echo "======ps=========" >> /rdklogs/logs/wan-status_stuck.txt
             ps >> /rdklogs/logs/wan-status_stuck.txt

             if [ ! -f /tmp/numOfTimesRan.txt ]; then
                 echo "1" > /tmp/numOfTimesRan.txt
                 wan_sysevents
             else
                 varFile="/tmp/numOfTimesRan.txt"
                 numOfTimesRan=$(cat "$varFile")
                 numOfTimesRan=$((numOfTimesRan + 1))
                 echo "$numOfTimesRan" > "$varFile"
                 if [ $numOfTimesRan -lt 3 ]; then
                     echo "wan-status stuck in $wan_status,recoverying for $numOfTimesRan time"
                     wan_sysevents
                 fi
             fi
             rm -f /tmp/wan_starting
         fi
     fi
}

self_heal_sedaemon()
{
    accessmgr=`pidof accessManager`
    if [ "$kdftype" == "RSA" ]; then
          ssadeamon=`pidof se05xd`
    elif [ "$kdftype" == "ECC" ]; then
          ssadeamon=`pidof rdkssaecckdf`
    fi
    if [[ -z "$ssadeamon" ]] || [[ -z "$accessmgr" ]]; then
          echo_t "[RDKB_AGG_SELFHEAL] : Restarting accessmanager and se05xd"
          t2CountNotify "SYS_SH_SERestart"
          systemctl stop startse05xd.service
          systemctl stop accessmanager.service
          systemctl start accessmanager.service
          systemctl start startse05xd.service
    fi
}

self_heal_conntrack()
{
    conntrack_max="`sysctl net.netfilter.nf_conntrack_max | cut -d "=" -f 2 `"
    conntrack_count="`conntrack -C`"
    if [ $conntrack_count -ge $conntrack_max ]; then
        echo_t "[RDKB_AGG_SELFHEAL] : Conntrack Max Count reached. Conntrack count=$conntrack_count, nf_conntrack_max=$conntrack_max"
    fi
}

# ARRIS XB6 => MODEL_NUM=TG3482G
# Tech CBR  => MODEL_NUM=CGA4131COM
# Tech XB6  => MODEL_NUM=CGM4140COM
# Tech XB7  => MODEL_NUM=CGM4331COM
# CMX  XB7  => MODEL_NUM=TG4482A
# Tech CBR2 => MODEL_NUM=CGA4332COM
# Tech XB8  => MODEL_NUM=CGM4981COM
# Tech XD4  => MODEL_NUM=CVA601ZCOM
# Vant XER5 => MODEL_NUM=VTER11QEL
# Tech XB10    => MODEL_NUM=CGM601TCOM
# Tech XB9    => MODEL_NUM=CWA438TCOM
# Sercomm XB10 => MODEL_NUM=SG417DBCT
# Sercomm XER10 => MODEL_NUM=SCER11BEL

if [ "$MODEL_NUM" != "TG3482G" ] && [ "$MODEL_NUM" != "CGA4131COM" ] &&
   [ "$MODEL_NUM" != "CGM4140COM" ] && [ "$MODEL_NUM" != "CGM4331COM" ] && 
   [ "$MODEL_NUM" != "CGM4981COM" ] && [ "$MODEL_NUM" != "TG4482A" ] && 
   [ "$MODEL_NUM" != "CGA4332COM" ] && [ "$MODEL_NUM" != "CVA601ZCOM" ] &&
   [ "$MODEL_NUM" != "VTER11QEL" ] &&
   [ "$MODEL_NUM" != "CGM601TCOM" ] && [ "$MODEL_NUM" != "SG417DBCT" ] &&
   [ "$MODEL_NUM" != "CWA438TCOM" ] &&
   [ "$MODEL_NUM" != "SCER11BEL" ] && [ "$MODEL_NAME" != "RPI" ] &&
   [ "$MODEL_NAME" != "BPI" ]
then
    exit
fi

while [ $(syscfg get selfheal_enable) = "true" ]
do
    INTERVAL=$(syscfg get AggressiveInterval)

    if [ "$INTERVAL" = "" ]
    then
        INTERVAL=5
    fi
    echo_t "[RDKB_AGG_SELFHEAL] : INTERVAL is: $INTERVAL"
    sleep ${INTERVAL}m
    
    WAN_INTERFACE=$(getWanInterfaceName)

    BOOTUP_TIME_SEC=$(cut -d. -f1 /proc/uptime)
    # This Feature is only enabled on devices that have Comcast Product Requirement to be up[ WEB PA Up] within 3:00
    if [ ! -f /tmp/selfheal_bootup_completed ] && [ $BOOTUP_TIME_SEC -lt 180 ] ; then
        continue
    fi
    
    #Find the DHCPv6 client type
    ti_dhcpv6_type="$(busybox pidof ti_dhcp6c)"
    dibbler_client_type="$(busybox pidof dibbler-client)"
    if [ "$ti_dhcpv6_type" = "" ] && [ "$dibbler_client_type" = "" ];then
    	DHCPv6_TYPE=""
    elif [ "$DHCPv6_TYPE" = "" ];then 
		if [ "$ti_dhcpv6_type" = "" ] && [ ! -z "$dibbler_client_type" ];then
			DHCPv6_TYPE="dibbler-client"
		elif [ ! -z "$ti_dhcpv6_type" ] && [ "$dibbler_client_type" = "" ];then
			DHCPv6_TYPE="ti_dhcp6c"
		fi
    fi

    MAPT_CONFIG=`sysevent get mapt_config_flag`

    START_TIME_SEC=$(cut -d. -f1 /proc/uptime)

    self_heal_conntrack
    if [ "$MULTI_CORE" = "yes" ]; then
        self_heal_peer_ping
    fi

    if [ -f /tmp/dhcpmgr_initialized ]; then
    self_heal_dnsmasq
    fi

    self_heal_dhcpmgr
    self_heal_dnsmasq_zombie
    self_heal_interfaces
    self_heal_dibbler_server
    if [ "$DHCPcMonitoring" != "false" ]; then
    self_heal_dhcp_clients
    fi
    self_heal_dropbear
    self_heal_ccspwifissp_hung
    self_heal_nas_ip
    self_heal_wan
    if [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ]
    then
       self_heal_process
    fi
    if [ -f /tmp/started_ssad ]; then
         self_heal_sedaemon
    fi

    if [ -f /etc/SelfHeal_Driver_Sanity_Check.sh ]; then
         /etc/SelfHeal_Driver_Sanity_Check.sh &
    fi

    STOP_TIME_SEC=$(cut -d. -f1 /proc/uptime)
    TOTAL_TIME_SEC=$((STOP_TIME_SEC-START_TIME_SEC))
    echo_t "[RDKB_AGG_SELFHEAL]: Total execution time: $TOTAL_TIME_SEC sec"
done
