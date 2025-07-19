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
UTOPIA_PATH="/etc/utopia/service.d"
rebootDeviceNeeded=0
rebootNeededforbrlan1=0
batteryMode=0
prevBatteryMode=0
IsAlreadyCountReseted=0
AtomHighLoadCount=0
AtomHighLoadCountThreshold=0
snmp_cm_agent_count=0
source $UTOPIA_PATH/log_env_var.sh
source $TAD_PATH/corrective_action.sh
#source /etc/device.properties
source /etc/log_timestamp.sh
Last_reboot_reason="`syscfg get X_RDKCENTRAL-COM_LastRebootReason`"

exec 3>&1 4>&2 >>$SELFHEALFILE 2>&1

touch /tmp/.resource_monitor_started

DELAY=30
threshold_reached=0
SELFHEAL_ENABLE=`syscfg get selfheal_enable`
COUNT=0

sysevent set atom_hang_count 0

while [ $SELFHEAL_ENABLE = "true" ]
do
	RESOURCE_MONITOR_INTERVAL=`syscfg get resource_monitor_interval`
	if [ "$RESOURCE_MONITOR_INTERVAL" = "" ]
	then
		RESOURCE_MONITOR_INTERVAL=15
	fi 
	RESOURCE_MONITOR_INTERVAL=$(($RESOURCE_MONITOR_INTERVAL*60))

	sleep $RESOURCE_MONITOR_INTERVAL

        BOOTUP_TIME_SEC=$(cut -d. -f1 /proc/uptime)
        #IHC should be called once when a reboot happens
        if [ $BOOTUP_TIME_SEC -ge 800 ] && [ $BOOTUP_TIME_SEC -le 1100 ] && [ "$Last_reboot_reason" = "Software_upgrade" ]
        then
            IHC_Enable="`syscfg get IHC_Mode`"
            #starting the IHC now
            if [[ "$IHC_Enable" = "Monitor" ]]
            then
                echo_t "Starting the ImageHealthChecker from bootup-check mode"
                /usr/bin/ImageHealthChecker bootup-check &
            fi
        fi

	totalMemSys=`free | awk 'FNR == 2 {print $2}'`
	usedMemSys=`free | awk 'FNR == 2 {print $3}'`
	freeMemSys=`free | awk 'FNR == 2 {print $4}'`

	timestamp=`getDate`

	# Memory info reading using free linux utility

	AvgMemUsed=$(( ( $usedMemSys * 100 ) / $totalMemSys ))

	MEM_THRESHOLD=`syscfg get avg_memory_threshold`

	if [ "$AvgMemUsed" -ge "$MEM_THRESHOLD" ]
	then

		echo_t "RDKB_SELFHEAL : Total memory in system is $totalMemSys at timestamp $timestamp"
		echo_t "RDKB_SELFHEAL : Used memory in system is $usedMemSys at timestamp $timestamp"
		echo_t "RDKB_SELFHEAL : Free memory in system is $freeMemSys at timestamp $timestamp"
		echo_t "RDKB_SELFHEAL : AvgMemUsed in % is  $AvgMemUsed"
		vendor=`getVendorName`
		modelName=`getModelName`
		CMMac=`getCMMac`
		timestamp=`getDate`

		echo_t "<$level>CABLEMODEM[$vendor]:<99000006><$timestamp><$CMMac><$modelName> RM Memory threshold reached"
		
		threshold_reached=1

		#echo_t "Setting Last reboot reason"
		reason="MEM_THRESHOLD"
		rebootCount=1
		#setRebootreason $reason $rebootCount

		rebootNeeded RM MEM $reason $rebootCount
	fi
	# Avg CPU usage reading from /proc/stat
#	AvgCpuUsed=`grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage }'`
#	AvgCpuUsed=`echo $AvgCpuUsed | cut -d "." -f1`
#	IdleCpuVal=`top -bn1  | head -n10 | grep "CPU:" | cut -c 34-35`

#	LOAD_AVG=`cat /proc/loadavg`
#	echo "[`getDateTime`] RDKB_LOAD_AVERAGE : Load Average is $LOAD_AVG"

#	AvgCpuUsed=$((100 - $IdleCpuVal))
#	echo "[`getDateTime`] RDKB_CPU_USAGE : CPU usage is $AvgCpuUsed"

#Record the start statistics

	STARTSTAT=$(getstat)
	
	user_ini=`echo $STARTSTAT | cut -d 'x' -f 1`
	system_ini=`echo $STARTSTAT | cut -d 'x' -f 3`
	idle_ini=`echo $STARTSTAT | cut -d 'x' -f 4`
	iowait_ini=`echo $STARTSTAT | cut -d 'x' -f 5`
	irq_ini=`echo $STARTSTAT | cut -d 'x' -f 6`
	softirq_ini=`echo $STARTSTAT | cut -d 'x' -f 7`
	steal_ini=`echo $STARTSTAT | cut -d 'x' -f 8`

#echo "[`getDateTime`] RDKB_SELFHEAL : Initial CPU stats are"
#echo "user_ini: $user_ini system_ini: $system_ini idle_ini=$idle_ini iowait_ini=$iowait_ini irq_ini=$irq_ini softirq_ini=$softirq_ini steal_ini=$steal_ini"
	sleep $DELAY

#Record the end statistics
	ENDSTAT=$(getstat)

	user_end=`echo $ENDSTAT | cut -d 'x' -f 1`
	system_end=`echo $ENDSTAT | cut -d 'x' -f 3`
	idle_end=`echo $ENDSTAT | cut -d 'x' -f 4`
	iowait_end=`echo $ENDSTAT | cut -d 'x' -f 5`
	irq_end=`echo $ENDSTAT | cut -d 'x' -f 6`
	softirq_end=`echo $ENDSTAT | cut -d 'x' -f 7`
	steal_end=`echo $ENDSTAT | cut -d 'x' -f 8`

#echo "[`getDateTime`] RDKB_SELFHEAL : CPU stats after $DELAY sec are"
#echo "user_end: $user_end system_end: $system_end idle_end=$idle_end iowait_end=$iowait_end irq_end=$irq_end softirq_end=$softirq_end steal_end=$steal_end"
	
	user_diff=$(change 1)
	system_diff=$(change 3)
	idle_diff=$(change 4)
	iowait_diff=$(change 5)
	irq_diff=$(change 6)
	softirq_diff=$(change 7)
	steal_diff=$(change 8)

#echo "[`getDateTime`] RDKB_SELFHEAL : CPU stats diff btw 2 intervals is"
#echo "user_diff= $user_diff system_diff=$system_diff and idle_diff=$idle_diff iowait_diff=$iowait_diff irq_diff=$irq_diff softirq_diff=$softirq_diff steal_diff=$steal_diff"

	active=$(( $user_diff + $system_diff + $iowait_diff + $irq_diff + $softirq_diff + $steal_diff))
	total=$(($active + $idle_diff))
	Curr_CPULoad=$(( $active * 100 / $total ))

	echo_t "RDKB_SELFHEAL : CPU usage is $Curr_CPULoad at timestamp $timestamp"
        # From XF3-4272 which was added as platform specific patch 
        if [ "$BOX_TYPE" = "XF3" ]; then
            OUTPUT="$(cat /proc/loadavg)"
            echo_t "RDKB_SELFHEAL : LOAD_AVERAGE $OUTPUT"
            MEMTOTAL="$(cat /proc/meminfo | grep MemTotal | sed -e 's/MemTotal://g' | sed -e 's/kB//g' | sed -e 's/^[ \t]*//' )"
            MEMFREE="$(cat /proc/meminfo | grep MemFree| sed -e 's/MemFree://g' | sed -e 's/kB//g' | sed -e 's/^[ \t]*//' )"
            echo_t "RDKB_SELFHEAL : MEM_TOTAL kB $MEMTOTAL"
            echo_t "RDKB_SELFHEAL : MEM_FREE kB $MEMFREE"
            MEM_USED=$(expr $MEMTOTAL - $MEMFREE)
            echo_t "RDKB_SELFHEAL : USED_MEM kB $MEM_USED"
        fi

	CPU_THRESHOLD=`syscfg get avg_cpu_threshold`

	count_val=0
	if [ "$Curr_CPULoad" -ge "$CPU_THRESHOLD" ]
	then
		echo_t "RDKB_SELFHEAL : Interrupts"
		echo "`cat /proc/interrupts`"

		if [ ! -f /tmp/CPUUsageReachedMAXThreshold ]
		then
			top -bn1 | head -n10 | tail -6 > /tmp/Process_info.txt
			sed -i '/top/d' /tmp/Process_info.txt
			Process1=`cut -d "%" -f 3 /tmp/Process_info.txt | head -n1`
			Process2=`cut -d "%" -f 3 /tmp/Process_info.txt | head -n2 | tail -1`
			Process3=`cut -d "%" -f 3 /tmp/Process_info.txt | head -n3 | tail -1`
			Process1_cpu_usage=`cut -d "%" -f 2 /tmp/Process_info.txt | tr -d [:blank:] | head -n1`
			Process2_cpu_usage=`cut -d "%" -f 2 /tmp/Process_info.txt | tr -d [:blank:] | head -n2 | tail -1`
			Process3_cpu_usage=`cut -d "%" -f 2 /tmp/Process_info.txt | tr -d [:blank:] | head -n3 | tail -1`
			echo_t "RDKB_SELFHEAL : CPU load at 100, top process:$Process1, $Process1_cpu_usage%,$Process2, $Process2_cpu_usage%,$Process3, $Process3_cpu_usage%"
			t2ValNotify "TopCPU_split" "$Process1, $Process1_cpu_usage%,$Process2, $Process2_cpu_usage%,$Process3, $Process3_cpu_usage%"            
			rm -rf /tmp/Process_info.txt
			touch /tmp/CPUUsageReachedMAXThreshold
		fi

		echo_t "RDKB_SELFHEAL : Monitoring CPU Load in a 5 minutes window"
	        Curr_CPULoad=0
		# Calculating CPU avg in 5 mins window		
		while [ "$count_val" -lt 10 ]
		do

			count_val=$(($count_val + 1))

			#Record the start statistics
			STARTSTAT=$(getstat)
	
			user_ini=`echo $STARTSTAT | cut -d 'x' -f 1`
			system_ini=`echo $STARTSTAT | cut -d 'x' -f 3`
			idle_ini=`echo $STARTSTAT | cut -d 'x' -f 4`
			iowait_ini=`echo $STARTSTAT | cut -d 'x' -f 5`
			irq_ini=`echo $STARTSTAT | cut -d 'x' -f 6`
			softirq_ini=`echo $STARTSTAT | cut -d 'x' -f 7`
			steal_ini=`echo $STARTSTAT | cut -d 'x' -f 8`

			echo_t "RDKB_SELFHEAL : Initial CPU stats are"
			echo_t "user_ini: $user_ini system_ini: $system_ini idle_ini=$idle_ini iowait_ini=$iowait_ini irq_ini=$irq_ini softirq_ini=$softirq_ini steal_ini=$steal_ini"

			sleep $DELAY

			#Record the end statistics
			ENDSTAT=$(getstat)

			user_end=`echo $ENDSTAT | cut -d 'x' -f 1`
			system_end=`echo $ENDSTAT | cut -d 'x' -f 3`
			idle_end=`echo $ENDSTAT | cut -d 'x' -f 4`
			iowait_end=`echo $ENDSTAT | cut -d 'x' -f 5`
			irq_end=`echo $ENDSTAT | cut -d 'x' -f 6`
			softirq_end=`echo $ENDSTAT | cut -d 'x' -f 7`
			steal_end=`echo $ENDSTAT | cut -d 'x' -f 8`

			echo_t "RDKB_SELFHEAL : CPU stats after $DELAY sec are"
			echo_t "user_end: $user_end system_end: $system_end idle_end=$idle_end iowait_end=$iowait_end irq_end=$irq_end softirq_end=$softirq_end steal_end=$steal_end"
	
			user_diff=$(change 1)
			system_diff=$(change 3)
			idle_diff=$(change 4)
			iowait_diff=$(change 5)
			irq_diff=$(change 6)
			softirq_diff=$(change 7)
			steal_diff=$(change 8)

			echo_t "RDKB_SELFHEAL : CPU stats diff btw 2 intervals is"
			echo_t "user_diff= $user_diff system_diff=$system_diff and idle_diff=$idle_diff iowait_diff=$iowait_diff irq_diff=$irq_diff softirq_diff=$softirq_diff steal_diff=$steal_diff"

			active=$(( $user_diff + $system_diff + $iowait_diff + $irq_diff + $softirq_diff + $steal_diff))
			total=$(($active + $idle_diff))
			Curr_CPULoad_calc=$(( $active * 100 / $total ))
			echo_t "RDKB_SELFHEAL : CPU load is $Curr_CPULoad_calc in iteration $count_val"
			Curr_CPULoad=$(($Curr_CPULoad + $Curr_CPULoad_calc))
			
		done

		Curr_CPULoad_Avg=$(( $Curr_CPULoad / 10 ))

		echo_t "RDKB_SELFHEAL : Avg CPU usage after 5 minutes of CPU Avg monitor window is $Curr_CPULoad_Avg"

        if [ "$BOX_TYPE" = "XB3" ];then
            if [ "$Curr_CPULoad_Avg" -ge "$CPU_THRESHOLD" ];then
                checkMaintenanceWindow
                if [ $reb_window -eq 1 ];then
                    top -bn1 | head -n10 | tail -6 > /tmp/Process_info.txt
                    sed -i '/top/d' /tmp/Process_info.txt
                    Process1=`cut -d "%" -f 3 /tmp/Process_info.txt | head -n1`
                    Process2=`cut -d "%" -f 3 /tmp/Process_info.txt | head -n2 | tail -1`
                    Process3=`cut -d "%" -f 3 /tmp/Process_info.txt | head -n3 | tail -1`
                    Process1_cpu_usage=`cut -d "%" -f 2 /tmp/Process_info.txt | tr -d [:blank:] | head -n1`
                    Process2_cpu_usage=`cut -d "%" -f 2 /tmp/Process_info.txt | tr -d [:blank:] | head -n2 | tail -1`
                    Process3_cpu_usage=`cut -d "%" -f 2 /tmp/Process_info.txt | tr -d [:blank:] | head -n3 | tail -1`
                    echo_t "RDKB_SELFHEAL : CPU load at 100 on ARM side in XB3, top process:$Process1, $Process1_cpu_usage%,$Process2, $Process2_cpu_usage%,$Process3, $Process3_cpu_usage%"

                    if [ `echo $Process1|grep -c "snmp_agent_cm"` -gt 0 ] || [ `echo $Process2|grep -c "snmp_agent_cm"` -gt 0 ] || [ `echo $Process3|grep -c "snmp_agent_cm"` -gt 0 ]
                    then
                        snmp_cm_agent_count=$((snmp_cm_agent_count+1))
                    else
                        snmp_cm_agent_count=0
                    fi
                    if [ $snmp_cm_agent_count -ge 4 ]
                    then
                        #In maintenance window, add telemetry and reboot
                        t2CountNotify "SYS_ERROR_SnmpCMHighCPU_reboot"
                        reason="SNMP_AGENT_CM_HIGH_CPU"
                        rebootCount=1
                        rebootNeeded RM SNMP_AGENT_CM_HIGH_CPU $reason $rebootCount
                    fi

                    rm -rf /tmp/Process_info.txt
                fi
            fi
        fi

		if [ ! -f /tmp/CPU5MinsUsageReachedMAXThreshold ]
		then
			if [ "$Curr_CPULoad_Avg" -ge "$CPU_THRESHOLD" ];then
				echo_t "RDKB_SELFHEAL : CPU load is $Curr_CPULoad_Avg"
				echo_t "RDKB_SELFHEAL : Top 5 tasks running on device"
				top -bn1 | head -n10 | tail -6 > /tmp/Process_info.txt
				sed -i '/top/d' /tmp/Process_info.txt
				cat /tmp/Process_info.txt
				Process1=`cut -d "%" -f 3 /tmp/Process_info.txt | head -n1`
				Process2=`cut -d "%" -f 3 /tmp/Process_info.txt | head -n2 | tail -1`
				Process3=`cut -d "%" -f 3 /tmp/Process_info.txt | head -n3 | tail -1`
				Process1_cpu_usage=`cut -d "%" -f 2 /tmp/Process_info.txt | tr -d [:blank:] | head -n1`
				Process2_cpu_usage=`cut -d "%" -f 2 /tmp/Process_info.txt | tr -d [:blank:] | head -n2 | tail -1`
				Process3_cpu_usage=`cut -d "%" -f 2 /tmp/Process_info.txt | tr -d [:blank:] | head -n3 | tail -1`
				echo_t "RDKB_SELFHEAL : CPU load at 100, top process:$Process1, $Process1_cpu_usage%,$Process2, $Process2_cpu_usage%,$Process3, $Process3_cpu_usage%"
				t2ValNotify "TopCPU_split" "$Process1, $Process1_cpu_usage%,$Process2, $Process2_cpu_usage%,$Process3, $Process3_cpu_usage%"
				rm -rf /tmp/Process_info.txt
				touch /tmp/CPU5MinsUsageReachedMAXThreshold
			fi
		fi

		if [ "$Curr_CPULoad_Avg" = "100" ]
		then
			t2CountNotify "SYS_ERROR_5min_avg_cpu_100"
		fi

		LOAD_AVG=`cat /proc/loadavg`
		echo_t "RDKB_SELFHEAL : LOAD_AVG is : $LOAD_AVG"

		echo_t "RDKB_SELFHEAL : Interrupts after calculating Avg CPU usage (after 5 minutes)"
		echo "`cat /proc/interrupts`"

#		if [ "$Curr_CPULoad_Avg" -ge "$CPU_THRESHOLD" ]
#		then
#			vendor=`getVendorName`
#			modelName=`getModelName`
#			CMMac=`getCMMac`
#			timestamp=`getDate`
#
#			echo "<$level>CABLEMODEM[$vendor]:<99000005><$timestamp><$CMMac><$modelName> RM CPU threshold reached"
#		
#			threshold_reached=1
#
#			echo "[`getDateTime`] Setting Last reboot reason"
#			reason="CPU_THRESHOLD"
#			rebootCount=1
#			setRebootreason $reason $rebootCount
#
#			rebootNeeded RM CPU
#		fi


####################################################
# Logic : 	If total CPU is 100% and boot time is more than 45 min,
#		Take sum of the cpu consumption of top 5 downstream_manager processes.
#		If total is more than 25%, reboot the box.

		if [ "$BOX_TYPE" = "XB3" ]
                then
			if [ $Curr_CPULoad_Avg -ge $CPU_THRESHOLD ]; then
				bootup_time_sec=$(cut -d. -f1 /proc/uptime)
				if [ $bootup_time_sec -ge 2700 ]; then
					total_ds_cpu=0
					ds_cpu_usage=`top -bn1 | grep downstream_manager | head -n5 | awk -F'%' '{print $2}' | sed -e 's/^[ \t]*//'`
					for each_ds_cpu_usage in $ds_cpu_usage
					do
						total_ds_cpu=`expr $total_ds_cpu + $each_ds_cpu_usage`
					done

					if [ $total_ds_cpu -ge 25 ]; then

						#echo_t "Setting Last reboot reason"
						reason="DS_MANAGER_HIGH_CPU"
						rebootCount=1
						#setRebootreason $reason $rebootCount

						rebootNeeded RM DS_MANAGER_HIGH_CPU $reason $rebootCount
					fi				
				fi
			fi
		fi
fi

# Checking fans rotor lock. If not running log the telemetry string.
if [ "$BOX_TYPE" == "WNXL11BWL" ] || [ "$BOX_TYPE" == "SE501" ]; then
	if [ "x$THERMALCTRL_ENABLE" == "xtrue" ]; then
		/bin/sh /usr/ccsp/tad/check_fan.sh
	fi
fi

if [ "$BOX_TYPE" = "XB3" ] ; then
####################################################
#Logic:We will read ATOM load average on ARM side using rpcclient, 
#	based on the load average threshold value,reboot the box.
Curr_AtomLoad_Avg=`rpcclient $ATOM_ARPING_IP "cat /proc/loadavg" | sed '4q;d'`
Load_Avg1=`echo $Curr_AtomLoad_Avg | awk  '{print $1}'`
Load_Avg10=`echo $Curr_AtomLoad_Avg | awk  '{print $2}'`
Load_Avg15=`echo $Curr_AtomLoad_Avg | awk  '{print $3}'`
# Calculate value of AtomHighLoad threshold for an hour based on RESOURCE_MONITOR_INTERVAL
AtomHighLoadCountThreshold=$((3600/$RESOURCE_MONITOR_INTERVAL))
if [ "$AtomHighLoadCountThreshold" -eq 0 ]; then
    AtomHighLoadCountThreshold=1
fi
    if [ ${Load_Avg1%%.*} -ge 5 ] && [ ${Load_Avg10%%.*} -ge 5 ] && [ ${Load_Avg15%%.*} -ge 5 ]; then
        if [ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
            AtomHighLoadCount=$(($AtomHighLoadCount + 1))
            echo_t "RDKB_SELFHEAL : ATOM_HIGH_LOADAVG detected. $AtomHighLoadCount / $AtomHighLoadCountThreshold"
            if [ "$AtomHighLoadCount" -ge "$AtomHighLoadCountThreshold" ]; then
		#echo_t "Setting Last reboot reason as ATOM_HIGH_LOADAVG"
                reason="ATOM_HIGH_LOADAVG"
		rebootCount=1
		#setRebootreason $reason $rebootCount
		rebootNeeded RM ATOM_HIGH_LOADAVG $reason $rebootCount
            fi
        else
	    #echo_t "Setting Last reboot reason as ATOM_HIGH_LOADAVG"
            reason="ATOM_HIGH_LOADAVG"
            rebootCount=1
	    #setRebootreason $reason $rebootCount
	    rebootNeeded RM ATOM_HIGH_LOADAVG $reason $rebootCount
        fi
    else
        AtomHighLoadCount=0
    fi
fi

####################################################
	
#	sh $TAD_PATH/task_health_monitor.sh
	if [ "$MODEL_NUM" = "DPC3939B" ] || [ "$MODEL_NUM" = "DPC3941B" ]; then
       		batteryMode=0
     	else
	if [ -f  /usr/bin/Selfhealutil ]
  	then
  		Selfhealutil power_mode
  		batteryMode=$?
                # When batterymode is not 1 or 0, then instead of exiting from script
                # consider previous successful batterymode
                if [ "$batteryMode" != "0" ] && [ "$batteryMode" != "1" ]
                then
                    echo_t "RDKB_SELFHEAL : batteryMode failed"
                    echo_t  "Error received: $batteryMode"
                    batteryMode=$prevBatteryMode
                else
  	            echo_t "RDKB_SELFHEAL : batteryMode is  $batteryMode"
                    prevBatteryMode=$batteryMode
  	            if [ $batteryMode -eq 1 ]; then 
  	              t2CountNotify "SYS_INFO_Invoke_batterymode"
  	           fi
    	fi	fi
     	fi

  	if [ $batteryMode = 0 ]
  	then
	    checkMaintenanceWindow
	    if [ $reb_window -eq 1 ]
	    then
                if [ ! -f "/nvram/syscfg_clean" ]; then
                    echo_t "Calling syscfg cleanup during maintenance window..."
                    sh /usr/ccsp/tad/syscfg_cleanup.sh
                fi
	        if [ $IsAlreadyCountReseted -eq 0 ]
			then
			    syscfg set todays_reset_count 0
			    syscfg commit
			    IsAlreadyCountReseted=1
			    RES_COUNT=`syscfg get todays_reset_count`
	  	        echo_t "RDKB_SELFHEAL : Resetted todays_reset_count during maintenance Window"
	  	        echo_t "RDKB_SELFHEAL : Current Reset Count is $RES_COUNT"	  	        

			sysevent set firewall_selfheal_count 0
			echo_t "RDKB_SELFHEAL : Resetted firewall_selfheal_count during maintenance Window"
		    fi
	    else
		    IsAlreadyCountReseted=0
	    fi
	    sh $TAD_PATH/task_health_monitor.sh
	fi

	SELFHEAL_ENABLE=`syscfg get selfheal_enable`
	COUNT=$((COUNT+1))
    if [ "$COUNT" -eq 4 ]
    then
        ######DUMP MEMORY INFO######
        echo_t "*************************"
        echo_t "`date`"
        echo_t "`busybox top -mbn1 | sort -k4 -r`"
        echo_t "`cat /proc/meminfo`"
	cachedMem=`awk '/^Cached:/ {print $2,$3}' /proc/meminfo`
        echo_t "CachedMemory: $cachedMem"
	t2ValNotify "cachedMem_split" "$cachedMem"
        COUNT=0
    fi

    #Kernel Memory info -> Slab
    while read name value
    do
        if [ "$name" = "Slab:" ]
        then
            echo_t "RDKB_SELFHEAL : $name $value"
            t2ValNotify "Slab_split" "$value"
            break
        fi
    done < /proc/meminfo

    if [ -x /usr/bin/slabtop ]
    then
        (
            set -- $(/usr/bin/slabtop -o -sc | head -n10 | tail -3)
            echo_t "RDKB_SELFHEAL : Top Slab usage: ${8},${7},${16},${15},${24},${23}"
            t2ValNotify "SlabUsage_split" "${8},${7},${16},${15},${24},${23}"
        )
    fi

done
