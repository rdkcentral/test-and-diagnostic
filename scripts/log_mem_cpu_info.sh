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

source /usr/ccsp/tad/corrective_action.sh
source /etc/log_timestamp.sh

#if [ -f /etc/device.properties ]; then
#   source /etc/device.properties
#fi

FW_START="/nvram/.FirmwareUpgradeStartTime"
FW_END="/nvram/.FirmwareUpgradeEndTime"

TMPFS_THRESHOLD=85
max_count=12
DELAY=30
timestamp=`getDate`

logTmpFs()
{
   TMPFS_CUR_USAGE=`df /tmp | tail -1 | awk '{print $(NF-1)}' | cut -d"%" -f1`

   if [ $TMPFS_CUR_USAGE -ge $TMPFS_THRESHOLD ] || [ "$1" = "log" ]
   then   
      echo_t "================================================================================"
      echo_t ""
      echo_t "RDKB_DISK_USAGE: Systems Disk Space Usage log at $timestamp is"
      echo_t ""
      disk_usage="df"
      eval $disk_usage

      nvram2_avail=`eval $disk_usage | grep nvram2`
      if [ "$nvram2_avail" = "" ]
      then
         echo_t "RDKB_DISK_USAGE: nvram2 not available"
         t2CountNotify "SYS_ERROR_NVRAM2_NOT_AVAILABLE"
      fi

      if [ "$1" = "log" ]
      then
        echo_t "RDKB_TMPFS_USAGE_PERIODIC:$TMPFS_CUR_USAGE"
        t2ValNotify "TMPFS_USAGE_PERIODIC" "$TMPFS_CUR_USAGE"
      fi

      if [ $TMPFS_CUR_USAGE -ge $TMPFS_THRESHOLD ]
      then
        echo_t "TMPFS_USAGE:$TMPFS_CUR_USAGE"
        t2CountNotify  "SYS_ERROR_TMPFS_ABOVE85"
      fi
      echo_t "================================================================================"
      echo_t "RDKB_TMPFS_FILELIST"
      ls -al /tmp/
      echo_t "================================================================================"
   fi

   t2ValNotify "TMPFS_USE_PERCENTAGE_split" "$TMPFS_CUR_USAGE"
}

get_high_mem_processes() {
    busybox top -mbn1 | head -n10 | tail -6 > /tmp/mem_info.txt
    sed -i '/top/d' /tmp/mem_info.txt
    sed -i -e 's/^/ /' /tmp/mem_info.txt

    local process_pid1=`awk -F ' ' '{ print $1}' /tmp/mem_info.txt | head -n1`
    local process_pid2=`awk -F ' ' '{ print $1}' /tmp/mem_info.txt | head -n2 | tail -1`
    local process_pid3=`awk -F ' ' '{ print $1}' /tmp/mem_info.txt | head -n3 | tail -1`
    local process_name1=`cat /proc/$process_pid1/cmdline`
    local process_name2=`cat /proc/$process_pid2/cmdline`
    local process_name3=`cat /proc/$process_pid3/cmdline`
    local process_mem1=`awk -F ' ' '{ print $2}' /tmp/mem_info.txt | head -n1`
    local process_mem2=`awk -F ' ' '{ print $2}' /tmp/mem_info.txt | head -n2 | tail -1`
    local process_mem3=`awk -F ' ' '{ print $2}' /tmp/mem_info.txt | head -n3 | tail -1`

    t2ValNotify "$1" "$process_name1, $process_mem1, $process_name2, $process_mem2, $process_name3, $process_mem3 "
}

    totalMemSys=`free | awk 'FNR == 2 {print $2}'`
    usedMemSys=`free | awk 'FNR == 2 {print $3}'`
    freeMemSys=`free | awk 'FNR == 2 {print $4}'`

    echo_t "RDKB_SYS_MEM_INFO_SYS : Total memory in system is $totalMemSys at timestamp $timestamp"
    echo_t "RDKB_SYS_MEM_INFO_SYS : Used memory in system is $usedMemSys at timestamp $timestamp"
    echo_t "RDKB_SYS_MEM_INFO_SYS : Free memory in system is $freeMemSys at timestamp $timestamp"

    # RDKB-7017	
    echo_t "USED_MEM:$usedMemSys"
    if [ "$BOX_TYPE" = "XB3" ]; then
        t2ValNotify "UsedMem_split" "$usedMemSys"
    else
        t2ValNotify "USED_MEM_ATOM_split" "$usedMemSys"
    fi

    echo "USED_MEM:$usedMemSys" | grep -q "USED_MEM:55"
    if [ $? -eq 0 ]; then 
        get_high_mem_processes "SYS_ERROR_MemAbove550"
    fi
    echo "USED_MEM:$usedMemSys" | grep -q "USED_MEM:6"
    if [ $? -eq 0 ]; then 
        get_high_mem_processes "SYS_ERROR_MemAbove600"
    fi
    
    echo_t "FREE_MEM:$freeMemSys"

    # RDKB-7195
    if [ "$BOX_TYPE" == "XB3" ]; then
        iccctl_info=`iccctl mal`
        echo_t "ICCCTL_INFO : $iccctl_info"

        #RDKB-7474
        iccctlMemInfo=`echo $iccctl_info | sed -e 's/.*Total in use//g'`
        inUse=`echo "$iccctlMemInfo" | cut -f2 -d: | cut -f1 -d, | tr -d " "`
        freeMem=`echo "$iccctlMemInfo" | cut -f3 -d: | cut -f1 -d, | tr -d " "`
        total=`echo "$iccctlMemInfo" | cut -f4 -d: | cut -f2 -d" "`

        # Calculate the threshold if in use memory is greater than zero
        if [ $inUse -ne 0 ]
        then
           echo_t "ICCCTL_IN_USE:$inUse"
           thresholdReached=$(( $inUse * 100 / $total ))

           # Log a message if threshold value of 25 is reached
           if [ $thresholdReached -gt 25 ]
           then
              echo_t "ICCCTL_INFO:ICC Memory is above threshold $thresholdReached"
              t2CountNotify "SYS_ERROR_ICC_ABOVE_THRESHOLD"
           else
              echo_t "ICCCTL_INFO:ICC Memory is below threshold $thresholdReached"
              t2CountNotify "SYS_ERROR_ICC_BELOW_THRESHOLD"
           fi
        else
            echo_t "ICCCTL_IN_USE:0"
        fi

    fi

    LOAD_AVG=`uptime | awk -F'[a-z]:' '{ print $2}' | sed 's/^ *//g' | sed 's/,//g' | sed 's/ /:/g'`
    # RDKB-7017	
    echo_t "RDKB_LOAD_AVERAGE : Load Average is $LOAD_AVG at timestamp $timestamp"
    
    #RDKB-7411
    LOAD_AVG_15=`echo $LOAD_AVG | cut -f3 -d:`
    echo_t "LOAD_AVERAGE:$LOAD_AVG_15"
    if [ "$BOX_TYPE" = "XB3" ]; then
        t2ValNotify "LoadAvg_split" "$LOAD_AVG_15"
    else
        t2ValNotify "LOAD_AVG_ATOM_split" "$LOAD_AVG_15"
    fi
    
    # Feature overkill - follow up with triage for marker cleanup. Required data is already sent above
    echo $LOAD_AVG_15 | grep -q '2\.' 
    if [ $? -eq 0 ]; then 
        t2CountNotify "SYS_ERROR_LoadAbove2"
    fi
    echo $LOAD_AVG_15 | grep -q "3\." 
    if [ $? -eq 0 ]; then 
        t2CountNotify "SYS_ERROR_LoadAbove3"
    fi
    echo $LOAD_AVG_15 | grep -q "4\." 
    if [ $? -eq 0 ]; then 
        t2CountNotify "SYS_ERROR_LoadAbove4"
    fi
    echo $LOAD_AVG_15 | grep -q "5\." 
    if [ $? -eq 0 ]; then 
        t2CountNotify "SYS_ERROR_LoadAbove5"
    fi
    echo $LOAD_AVG_15 | grep -q "8\."
    if [ $? -eq 0 ]; then
        t2CountNotify "SYS_ERROR_LoadAbove8"
    fi
    echo $LOAD_AVG_15 | grep -q "9\."
    if [ $? -eq 0 ]; then
        t2CountNotify "SYS_ERROR_LoadAbove9"
    fi

    #Record the start statistics

    STARTSTAT=$(getstat)

    sleep $DELAY

    #Record the end statistics
	ENDSTAT=$(getstat)

	USR=$(change 1)
	SYS=$(change 3)
	IDLE=$(change 4)
	IOW=$(change 5)
	IRQ=$(change 6)
	SIRQ=$(change 7)
	STEAL=$(change 8)

	ACTIVE=$(( $USR + $SYS + $IOW + $IRQ + $SIRQ + $STEAL))

	TOTAL=$(($ACTIVE + $IDLE))

	Curr_CPULoad=$(( $ACTIVE * 100 / $TOTAL ))
	timestamp=`getDate`
    # RDKB-7017	
    echo_t "RDKB_CPU_USAGE : CPU usage is $Curr_CPULoad at timestamp $timestamp"
    if [ $Curr_CPULoad -eq 100 ]; then 
        t2CountNotify "SYS_ERROR_CPU100"
    fi
    echo_t "USED_CPU:$Curr_CPULoad"
    if [ "$BOX_TYPE" = "XB3" ]; then
        t2ValNotify "UsedCPU_split" "$Curr_CPULoad"
    else
        t2ValNotify "USED_CPU_ATOM_split" "$Curr_CPULoad"
    fi

    # RDKB-7412
   	CPU_INFO=`mpstat 1 1 | tail -1 | tr -s ' ' ':' | cut -d':' -f3-`
	MPSTAT_USR=`echo $CPU_INFO | cut -d':' -f1`
	MPSTAT_SYS=`echo $CPU_INFO | cut -d':' -f3`
	MPSTAT_NICE=`echo $CPU_INFO | cut -d':' -f2`
	MPSTAT_IRQ=`echo $CPU_INFO | cut -d':' -f5`
	MPSTAT_SOFT=`echo $CPU_INFO | cut -d':' -f6`
	MPSTAT_IDLE=`echo $CPU_INFO | cut -d':' -f9`

	echo_t "MPSTAT_USR:$MPSTAT_USR"
	echo_t "MPSTAT_SYS:$MPSTAT_SYS"
	echo_t "MPSTAT_NICE:$MPSTAT_NICE"
	echo_t "MPSTAT_IRQ:$MPSTAT_IRQ"
	echo_t "MPSTAT_SOFT:$MPSTAT_SOFT"
	t2ValNotify "MPSTAT_SOFT_split" "$MPSTAT_SOFT"
	echo_t "MPSTAT_IDLE:$MPSTAT_IDLE"
	t2ValNotify "FreeCPU_split" "$MPSTAT_IDLE"

	USER_CPU=`echo $MPSTAT_USR | cut -d'.' -f1`
	count=`syscfg get process_memory_log_count`
	count=$((count + 1))
	echo_t "Count is $count"

	if [ "$count" -eq "$max_count" ]
	then
		echo_t "RDKB_PROC_MEM_LOG: Process Memory log at $timestamp is" >> /rdklogs/logs/CPUInfo.txt.0
		echo_t "" >> /rdklogs/logs/CPUInfo.txt.0
		busybox top -mbn1 >> /rdklogs/logs/CPUInfo.txt.0
                
                # Log tmpfs data
                logTmpFs "log"                

		syscfg set process_memory_log_count 0	
		syscfg commit
	
	else
                
		# RDKB-6162
		if [ "$USER_CPU" -ge "25" ]; then
			echo_t "RDKB_PROC_USAGE_LOG: Top 5 CPU USAGE Process at $timestamp is" >> /rdklogs/logs/CPUInfo.txt.0
			echo_t "" >> /rdklogs/logs/CPUInfo.txt.0
			top_cmd="busybox top -mbn1 | head -n10 | tail -6"
			eval $top_cmd >> /rdklogs/logs/CPUInfo.txt.0
		fi
                # Log tmpfs data
                logTmpFs "max"

		syscfg set process_memory_log_count $count	
		syscfg commit
	fi

	count=$((count + 1))

	RDKLOGS_USAGE=`df /rdklogs | tail -1 | awk '{print $(NF-1)}' | cut -d"%" -f1`
	t2ValNotify "RDKLOGS_USE_PERCENTAGE_split" "$RDKLOGS_USAGE"

	NVRAM_USAGE=`df /nvram | tail -1 | awk '{print $(NF-1)}' | cut -d"%" -f1`
	t2ValNotify "NVRAM_USE_PERCENTAGE_split" "$NVRAM_USAGE"

	swap=`free | awk 'FNR == 4 {print $3}'`
	cache=`cat /proc/meminfo | awk 'FNR == 4 {print $2}'`
	buff=`cat /proc/meminfo | awk 'FNR == 3 {print $2}'`

	t2ValNotify "SWAP_MEMORY_split" "$swap"
	t2ValNotify "CACHE_MEMORY_split" "$cache"
	t2ValNotify "BUFFER_MEMORY_split" "$buff"

	nvram_ro_fs=`mount | grep "nvram " | grep dev | grep "[ (]ro[ ,]"`
	if [ "$nvram_ro_fs" != "" ]; then
		echo_t "[RDKB_SELFHEAL] : NVRAM IS READ-ONLY"
	fi

	nvram2_ro_fs=`mount | grep "nvram2 " | grep dev | grep "[ (]ro[ ,]"`
	if [ "$nvram2_ro_fs" != "" ]; then
		echo_t "[RDKB_SELFHEAL] : NVRAM2 IS READ-ONLY"
	fi

	if [ "$BOX_TYPE" = "XB3" ]  || [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ]; then
		if [ "$UTC_ENABLE" == "true" ]
		then
			cur_hr=`LTime H`
			cur_min=`LTime M`
		else
			cur_hr=`date +"%H"`
			cur_min=`date +"%M"`
		fi

		SNMPv2_RDKB_MIBS_SUPPORT=`syscfg get V2Support`
		SNMP_RESTART_ENABLE=`syscfg get SNMP_RestartMaintenanceEnable`
		if [ "$cur_hr" -ge 02 ] && [ "$cur_hr" -le 05 ] && [[ "$SNMPv2_RDKB_MIBS_SUPPORT" = "true" || "$SNMPv2_RDKB_MIBS_SUPPORT" = "" ]] && [ "$SNMP_RESTART_ENABLE" = "true" ]
		then
				if [ ! -f "/tmp/snmp_agent_restarted" ]; then
					echo_t  "RDKB_SELFHEAL : Restarting snmp subagent in maintanance window" 
					touch /tmp/.snmp_agent_restarting
					if [ "$MODEL_NUM" = "TG3482G" ] || [ "$MODEL_NUM" = "TG4482A" ]; then
						systemctl restart snmpSubAgent
						sleep 2
					else
						SNMP_PID=`busybox ps ww | grep snmp_subagent | grep -v cm_snmp_ma_2 | grep -v grep | awk '{print $1}'`
						kill -9 $SNMP_PID
						resetNeeded snmp snmp_subagent maintanance_window
					fi
					rm -rf /tmp/.snmp_agent_restarting
					touch /tmp/snmp_agent_restarted
				fi
		else 
			if [ -f "/tmp/snmp_agent_restarted" ]; then
				rm "/tmp/snmp_agent_restarted"
			fi
		fi
	fi	
	
	# swap usage information
        # vmInfoHeader: swpd,free,buff,cache,si,so
        # vmInfoValues: <int>,<int>,<int>,<int>,<int>,<int>
        echo "VM STATS SINCE BOOT ARM"
        swaped=`free | grep Swap | awk '{print $3}'`
        cache=`awk 'FNR == 4 {print $2}' /proc/meminfo`
        buff=`awk 'FNR == 3 {print $2}' /proc/meminfo`
        swaped_in=`grep pswpin /proc/vmstat | cut -d ' ' -f2`
        swaped_out=`grep pswpout /proc/vmstat | cut -d ' ' -f2`
        # conversion to kb assumes 4kb page, which is quite standard
        swaped_in_kb=$((swaped_in * 4))
        swaped_out_kb=$((swaped_out * 4))
        echo vmInfoHeader: swpd,free,buff,cache,si,so
        echo vmInfoValues: $swaped,$freeMemSys,$buff,$cache,$swaped_in,$swaped_out
        # end of swap usage information block

        if [ "$UTC_ENABLE" == "true" ]
        then
            cur_hr=`LTime H | sed 's/^0*//'`
            cur_min=`LTime M | sed 's/^0*//'`
            cur_sec=`date +"%S" | sed 's/^0*//'`
        else
            cur_hr=`date +"%H" | sed 's/^0*//'`
            cur_min=`date +"%M" | sed 's/^0*//'`
            cur_sec=`date +"%S" | sed 's/^0*//'`
        fi

        curr_hr_in_sec=$((cur_hr*60*60))
        curr_min_in_sec=$((cur_min*60))
        curr_time_in_sec=$((curr_hr_in_sec+curr_min_in_sec+cur_sec))

# Extract maintenance window start and end time
        if [ -f "$FW_START" ] && [ -f "$FW_END" ]
        then
           start_time=`cat $FW_START`
           end_time=`cat $FW_END`
        else
           start_time=7200
           end_time=14400
        fi

	 if [ $curr_time_in_sec -ge $start_time ] && [ $curr_time_in_sec -le $end_time ] ; then

                if [ ! -f "/tmp/mem_frag_calc" ]; then

                        touch /tmp/mem_frag_calc
                        free_memory_reach=0
                        mem_frag_reach=0

                        free_memory_threshold=`syscfg get Free_Mem_Threshold`
                        free_memory_threshold=`expr $free_memory_threshold \* 1024`
                        if [ $free_memory_threshold -ne 0 ]; then
                            echo_t "[RDKB_SELFHEAL] : Free memory = $freeMemSys, Memory Threshold = $free_memory_threshold"

                            if [ "$BOX_TYPE" = "XB3" ]; then
                                Committed_AS=`cat /proc/meminfo | grep Committed_AS | sed 's/[^0-9]*//g'`
                                CommitLimit=`cat /proc/meminfo | grep CommitLimit | sed 's/[^0-9]*//g'`
                                free_mem_avail=$(($CommitLimit - $Committed_AS))
                                echo_t "[RDKB_SELFHEAL] : Committed_AS = $Committed_AS, CommitLimit = $CommitLimit, free_mem_avail = $free_mem_avail"

                                if [ $free_mem_avail -le $free_memory_threshold ]; then
                                    free_memory_reach=1
                                    echo_t "Free Memory available is less than Threshold , reboot required"
                                    t2CountNotify "SYS_ERROR_LOW_FREE_MEMORY"
                                fi

                            fi

                            if [ $freeMemSys -le $free_memory_threshold ]; then
                                    free_memory_reach=1
                                    echo_t "Free memory threshold reached..."
                            fi
                        fi

                        memory_frag_threshold=`syscfg get Mem_Frag_Threshold`
                        if [ $memory_frag_threshold -ne 0 ]; then
                             sh /usr/ccsp/tad/log_buddyinfo.sh
                             mem_frag_calc=`syscfg get CpuMemFrag_Host_Percentage`
                             echo_t "[RDKB_SELFHEAL] : Fragmentation percentage = $mem_frag_calc, Fragmentation threshold =  $memory_frag_threshold"
                             if [ $mem_frag_calc -ge $memory_frag_threshold ]; then
                                mem_frag_reach=1
                                echo_t "Memory fragmentation threshold reached..."
                             fi

                        fi


                        if [ $free_memory_reach -eq 1 ] || [ $mem_frag_reach -eq 1 ]; then
                                reason="Low_Memory"
                                rebootCount=1
                                echo_t "[RDKB_SELFHEAL] : Device reboot due to Low Memory"
                                rebootNeeded RM "" $reason $rebootCount
                        fi
              fi
        else
                if [ -f "/tmp/mem_frag_calc" ]; then
                        rm "/tmp/mem_frag_calc"
                fi
        fi
