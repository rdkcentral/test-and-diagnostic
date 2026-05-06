#!/bin/sh
#######################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:

# Copyright 2026 RDK Management

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

ZRAM_LOGFILE="/rdklogs/logs/zram.log"
T2_MSG_CLIENT="/usr/bin/telemetry2_0_client"

t2ValNotify() {
    if [ -f $T2_MSG_CLIENT ]; then
        marker=$1
        shift
        $T2_MSG_CLIENT "$marker" "$*"
    fi
}

echo_t() {
    echo "$(date +"%y%m%d-%T.%6N") $1" >>$ZRAM_LOGFILE
}

# ZRAM statistics
zram_disksize_path="/sys/block/zram0/disksize"
zram_mm_stat_path="/sys/block/zram0/mm_stat"
zram_disk_size=0
mem_used_total=0
orig_data_size=0
compr_data_size=0

if [ -r "$zram_disksize_path" ] && [ -r "$zram_mm_stat_path" ]; then
    zram_disk_size="$(cat "$zram_disksize_path" 2>/dev/null)"
    mm_stat="$(cat "$zram_mm_stat_path" 2>/dev/null)"
    mem_used_total="$(echo "$mm_stat" | awk '{print $3}')"
    orig_data_size="$(echo "$mm_stat" | awk '{print $1}')"
    compr_data_size="$(echo "$mm_stat" | awk '{print $2}')"
    echo_t "ZRAM stats - Disk Size: $zram_disk_size, Mem Used Total: $mem_used_total, Original Data Size: $orig_data_size, Compressed Data Size: $compr_data_size"
else
    echo_t "ZRAM stats unavailable - $zram_disksize_path or $zram_mm_stat_path is missing/unreadable"
    exit 1
fi

pswpin_prev=0
if [ -f /tmp/pswpin_prev ]; then
    pswpin_prev="$(cat /tmp/pswpin_prev)"
fi

pswpout_prev=0
if [ -f /tmp/pswpout_prev ]; then
    pswpout_prev="$(cat /tmp/pswpout_prev)"
fi

pswpin_current="$(cat /proc/vmstat 2>/dev/null | grep "pswpin" | awk '{print $2}')"
pswpout_current="$(cat /proc/vmstat 2>/dev/null | grep "pswpout" | awk '{print $2}')"
echo_t "Swap stats - pswpin: $pswpin_current, pswpout: $pswpout_current, pswpin_prev: $pswpin_prev, pswpout_prev: $pswpout_prev"

# Calculate telemetry marker values
zram_disk_size_mb=$((zram_disk_size / 1024 / 1024))
zram_cur_used_mb=$((mem_used_total / 1024 / 1024))
zram_original_data_size_mb=$((orig_data_size / 1024 / 1024))
zram_compressed_mb=$((compr_data_size / 1024 / 1024))

pswpin_delta=0
if [ "$pswpin_current" -gt "$pswpin_prev" ]; then
    pswpin_delta=$((pswpin_current - pswpin_prev))
fi

pswpout_delta=0
if [ "$pswpout_current" -gt "$pswpout_prev" ]; then
    pswpout_delta=$((pswpout_current - pswpout_prev))
fi

echo_t "Telemetry values - ZRAM Disk Size MB: $zram_disk_size_mb, ZRAM Used MB: $zram_cur_used_mb, ZRAM Original Data Size MB: $zram_original_data_size_mb, ZRAM Compressed MB: $zram_compressed_mb, pswpin delta: $pswpin_delta, pswpout delta: $pswpout_delta"

t2ValNotify "ZRAM_SWAP_split" "$zram_disk_size_mb,$zram_cur_used_mb,$zram_original_data_size_mb,$zram_compressed_mb,$pswpin_delta,$pswpout_delta"

# Save current pswpin and pswpout values for next run
echo "$pswpin_current" >/tmp/pswpin_prev
echo "$pswpout_current" >/tmp/pswpout_prev
