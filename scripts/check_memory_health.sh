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

source /etc/utopia/service.d/log_capture_path.sh
source /lib/rdk/t2Shared_api.sh

Min_Mem_Value=`syscfg get MinMemoryThreshold_Value`

free_mem=`free | awk 'FNR == 2 {print $4}'`
free_mem_in_mb=$(($free_mem/1024))
echo_t "RDKB_MEM_HEALTH : Min Memory Threshold Value is $Min_Mem_Value"
echo_t "RDKB_MEM_HEALTH : Free Memory $free_mem_in_mb MB"

if [ "$Min_Mem_Value" -ne 0 ] && [ "$free_mem_in_mb" -le "$Min_Mem_Value" ]
then
	# No need todo corrective action during box is in DiagnosticMode state
	DiagnosticMode=`syscfg get Selfheal_DiagnosticMode`
	if [ "$DiagnosticMode" == "true" ]
	then
		echo_t "RDKB_MEM_HEALTH : System free memory reached minimum threshold"
		echo_t "RDKB_MEM_HEALTH : Box is in diagnositic mode, so system not allow to clear the cache memory"				
	else
		echo_t "RDKB_MEM_HEALTH : System free memory reached minimum threshold , clearing the cache memory"
		t2CountNotify "SYS_ERROR_Drop_cache"
		sync
		echo 1 > /proc/sys/vm/drop_caches	
	fi
fi



