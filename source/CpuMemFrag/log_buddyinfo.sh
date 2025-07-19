#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
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
source /etc/log_timestamp.sh
source /etc/device.properties

HOST_BUDDYINFO_FILE=/proc/buddyinfo
LOG_FILE=/rdklogs/logs/CPUInfo.txt.0

# Get the buddyinfo content and keep the Field separator as new line
host_buddyinfo=`cat $HOST_BUDDYINFO_FILE`
IFS=$'\n'

#
# This function takes care of parsing the buddyinfo contents passed from main.
# This function will process the info, save to DB and log the message in telemetry format
# args : $1 - buddyinfo
#        $2 - cpu
#
parse_buddyinfo()
{
  if [ "`echo $1 | grep Normal`" != "" ]
  then
     data=`echo "$1" | awk -F'Normal ' '{print $2}' | sed -e 's/^[ \t]*//' | sed 's/[[:space:]][[:space:]]*/,/g'`
     # Remove last character which will be (,)
     data=${data%?};
     if [ "$2" = "host" ]
     then
        syscfg set CpuMemFrag_Host_Normal $data
        echo_t "PROC_BUDDYINFO_HOST:CPU_MEM_FRAG-Normal,$data" >> $LOG_FILE
	OutputData=`MemFrag_Calc $data`
        OverallFragPercentage=`echo $OutputData | cut -d' ' -f1`
	FragPercentage=`echo $OutputData | cut -d' ' -f2`
	syscfg set CpuMemFrag_Host_Percentage $FragPercentage
	echo_t "PROC_BUDDYINFO_HOST:CPU_MEM_FRAG_PERCENTAGE-Normal,$FragPercentage" >> $LOG_FILE
	echo_t "PROC_BUDDYINFO_HOST:CPU_MEM_FRAG_OVERALL_PERCENTAGE-Normal,$OverallFragPercentage" >> $LOG_FILE
     elif [ "$2" = "peer" ]
     then
        syscfg set CpuMemFrag_Peer_Normal $data
        echo_t "PROC_BUDDYINFO_PEER:CPU_MEM_FRAG-Normal,$data" >> $LOG_FILE
	OutputData=`MemFrag_Calc $data`
        OverallFragPercentage=`echo $OutputData | cut -d' ' -f1`
	FragPercentage=`echo $OutputData | cut -d' ' -f2`
	syscfg set CpuMemFrag_Peer_Percentage $FragPercentage
	echo_t "PROC_BUDDYINFO_PEER:CPU_MEM_FRAG_PERCENTAGE-Normal,$FragPercentage" >> $LOG_FILE
	echo_t "PROC_BUDDYINFO_PEER:CPU_MEM_FRAG_OVERALL_PERCENTAGE-Normal,$OverallFragPercentage" >> $LOG_FILE
     fi
  elif [ "`echo $1 | grep DMA | grep -v DMA32`" != "" ]
  then
     data=`echo "$1" | awk -F'DMA ' '{print $2}' | sed -e 's/^[ \t]*//' | sed 's/[[:space:]][[:space:]]*/,/g'`
     data=${data%?};
     if [ "$2" = "host" ]
     then
        syscfg set CpuMemFrag_Host_Dma $data
        echo_t "PROC_BUDDYINFO_HOST:CPU_MEM_FRAG-DMA,$data" >> $LOG_FILE
        OutputData=`MemFrag_Calc $data`
        OverallFragPercentage=`echo $OutputData | cut -d' ' -f1`
	FragPercentage=`echo $OutputData | cut -d' ' -f2`
	syscfg set CpuMemFrag_Host_Percentage $FragPercentage
	echo_t "PROC_BUDDYINFO_HOST:CPU_MEM_FRAG_PERCENTAGE-DMA,$FragPercentage" >> $LOG_FILE
	echo_t "PROC_BUDDYINFO_HOST:CPU_MEM_FRAG_OVERALL_PERCENTAGE-DMA,$OverallFragPercentage" >> $LOG_FILE
     elif [ "$2" = "peer" ]
     then
        syscfg set CpuMemFrag_Peer_Dma $data
        echo_t "PROC_BUDDYINFO_PEER:CPU_MEM_FRAG-DMA,$data" >> $LOG_FILE
        OutputData=`MemFrag_Calc $data`
        OverallFragPercentage=`echo $OutputData | cut -d' ' -f1`
	FragPercentage=`echo $OutputData | cut -d' ' -f2`
	syscfg set CpuMemFrag_Peer_Percentage $FragPercentage
	echo_t "PROC_BUDDYINFO_PEER:CPU_MEM_FRAG_PERCENTAGE-DMA,$FragPercentage" >> $LOG_FILE
	echo_t "PROC_BUDDYINFO_PEER:CPU_MEM_FRAG_OVERALL_PERCENTAGE-DMA,$OverallFragPercentage" >> $LOG_FILE
     fi
  elif [ "`echo $1 | grep DMA32`" != "" ]
  then
     data=`echo "$1" | awk -F'DMA32 ' '{print $2}' | sed -e 's/^[ \t]*//' | sed 's/[[:space:]][[:space:]]*/,/g'`
     data=${data%?}
     if [ "$2" = "host" ]
     then
        syscfg set CpuMemFrag_Host_Dma32 $data
        echo_t "PROC_BUDDYINFO_HOST:CPU_MEM_FRAG-DMA32,$data" >> $LOG_FILE
     elif [ "$2" = "peer" ]
     then
        syscfg set CpuMemFrag_Peer_Dma32 $data
        echo_t "PROC_BUDDYINFO_PEER:CPU_MEM_FRAG-DMA32,$data" >> $LOG_FILE
     fi
  elif [ "`echo $1 | grep -i HighMem`" != "" ]
  then
     data=`echo "$1" | awk -F'HighMem ' '{print $2}' | sed -e 's/^[ \t]*//' | sed 's/[[:space:]][[:space:]]*/,/g'`
     data=${data%?}
     if [ "$2" = "host" ]
     then
        syscfg set CpuMemFrag_Host_Highmem $data
        echo_t "PROC_BUDDYINFO_HOST:CPU_MEM_FRAG-HIGHMEM,$data" >> $LOG_FILE
     elif [ "$2" = "peer" ]
     then
        syscfg set CpuMemFrag_Peer_Highmem $data
        echo_t "PROC_BUDDYINFO_PEER:CPU_MEM_FRAG-HIGHMEM,$data" >> $LOG_FILE
     fi
  else
     echo_t "BuddyInfo : Unknown zone found in $1"
  fi

  syscfg commit
}

# Call parser function for each line found in /proc/buddyinfo of host processor
for line in $host_buddyinfo;
do
  parse_buddyinfo $line "host"
done

# Check if we need to collect peer buddyinfo, then do rpcclient 
if [ "$CR_IN_PEER" = "yes" ]
then                                    
    if [ "$MODEL_NUM" = "TG1682G" ]
    then                 
         ip=$PEER_ARPING_IP
    else                                      
         ip=$PEER_INTERFACE_IP                                          
    fi                    
    peer_buddyinfo=`rpcclient $ip "cat $HOST_BUDDYINFO_FILE" | grep -v CONNECTED`
                                               
   for line in $peer_buddyinfo;                                          
   do  
     parse_buddyinfo $line "peer"                      
   done
else                   
  echo_t "BuddyInfo: Peer buddyinfo not needed"                                                                 
fi 

