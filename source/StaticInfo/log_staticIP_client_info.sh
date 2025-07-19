#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
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


if [ -f "/etc/log_timestamp.sh" ];then
        source /etc/log_timestamp.sh
fi
echo_t "The script is used to dump staticIP Ethernet devices" >> /rdklogs/logs/Consolelog.txt.0
static_ip=`psmcli get dmsb.truestaticip.Ipaddress | cut -d"." -f1-2`
static_ip_status=`psmcli get dmsb.truestaticip.Enable`
Online_cnt=0
Offline_cnt=0
Online_mac="/tmp/Online_mac"
Offline_mac="/tmp/Offline_mac"
Traffic_count="/tmp/Traffic_count"

if [ "$static_ip_status" = "1" ]; then
      rm -f $Online_mac $Offline_mac $Traffic_count
      rm -f /tmp/list /tmp/dbg_log
      count=`dmcli eRT retv Device.Hosts.HostNumberOfEntries`
      for i in `seq 1 $count`; do
        ip=`dmcli eRT retv Device.Hosts.Host.$i.IPAddress`
        if [ "$static_ip"  == "$ip" ]; then
              mac=`dmcli eRT retv Device.Hosts.Host.$i.PhysAddress`
              Status=`dmcli eRT retv Device.Hosts.Host.$i.Active`
              if [ "$Status" == "false" ]; then
                    Offline_cnt=`expr $Offline_cnt + 1`
                    echo -n $mac, >> $Offline_mac
              else
                    Online_cnt=`expr $Online_cnt + 1`
                    echo -n $mac, >> $Online_mac
              fi
              traffic_count -A $mac
        fi
      done
      eth_api CcspHalExtSw_getAssociatedDevice  > /tmp/dbg_log
      Total_cnt=`cat /tmp/dbg_log | grep Total_ETH | awk '{print $2}'`
      cat /tmp/dbg_log | grep eth_devMacAddress | awk '{ print $4}' | tr '\n' ',' > /tmp/list
      echo_t "Total Ethernet clients(static and dynamic)detected from HAL/driver:$Total_cnt,`cat /tmp/list`" >> /rdklogs/logs/Consolelog.txt.0
      total_static_clients=`expr $Online_cnt + $Offline_cnt`
      if [[ $total_static_clients -gt 0 && $total_static_clients -eq $Offline_cnt ]]; then
	      echo_t "Static IP connection issue, all clients are down" >> /rdklogs/logs/Consolelog.txt.0
      fi

      traffic_count -L > $Traffic_count
      Dump_StaticIP=`sed 'H;1h;$!d;x;y/\n/ /' $Traffic_count | sed 's/ /,/g' | sed -e 's/[^a-zA-Z0-9:/,|]//g;s/1M30M//g'`
      echo_t "Total_Static_IP_Ethernet_clients=$total_static_clients" >> /rdklogs/logs/Consolelog.txt.0
      echo_t "Online_StaticIP_clients:$Online_cnt,`cat $Online_mac`"  >> /rdklogs/logs/Consolelog.txt.0
      echo_t "Offline_StaticIP_clients:$Offline_cnt,`cat $Offline_mac`"  >> /rdklogs/logs/Consolelog.txt.0     
      echo_t "Dumping staticIP Ethernet Rx/Tx rate:$Dump_StaticIP" >> /rdklogs/logs/Consolelog.txt.0

      wan_staticip=`psmcli get dmsb.truestaticip.Ipaddress | cut -d"." -f1-3`
      static_conntrack_cnt=`cat /proc/net/nf_conntrack | grep  "$wan_staticip" | wc -l`
      Unreplied_cnt=`cat /proc/net/nf_conntrack | grep  "$wan_staticip" | grep UNREPLIED | wc -l`
      if [ $static_conntrack_cnt -eq $Unreplied_cnt ]; then
            echo_t "Static IP connectivity issue, UNREPLIED status for all the static IP range" >> /rdklogs/logs/Consolelog.txt.0
      fi
fi

