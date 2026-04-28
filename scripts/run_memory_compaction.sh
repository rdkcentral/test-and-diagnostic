#!/bin/sh
#######################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
#  Copyright 2026 RDK Management
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

source /etc/utopia/service.d/log_capture_path.sh

RUNONCEFILE=/tmp/.run_memory_compaction_done
if [ -f "$RUNONCEFILE" ]; then
	exit 0
fi

TAD_PATH="/usr/ccsp/tad/"
DEF_TARGET_UPTIME=900

TARGET_UPTIME_SECS=$(syscfg get MemCompactionDelaySecs)
current_uptime_secs=$(cut -d. -f1 /proc/uptime)
if [ -z "$TARGET_UPTIME_SECS" ]; then
	TARGET_UPTIME_SECS="$DEF_TARGET_UPTIME"
fi

if [ "$current_uptime_secs"  -ge "$TARGET_UPTIME_SECS" ]; then
	wait_secs=0
else
	wait_secs=$((TARGET_UPTIME_SECS - current_uptime_secs))
fi

echo_t "RDKB_MEM_COMPACT : MemCompactionDelaySecs $TARGET_UPTIME_SECS"
echo_t "RDKB_MEM_COMPACT : uptime $current_uptime_secs wait time $wait_secs"

if [ "$wait_secs" -gt "0" ]; then
	sleep "$wait_secs"
fi

if [ -f "$TAD_PATH/check_memory_health.sh" ]; then
	/bin/sh $TAD_PATH/check_memory_health.sh check_frag_mem
else
	echo_t "RDKB_MEM_COMPACT : check_memory_health.sh file missing"
fi

touch "$RUNONCEFILE"
