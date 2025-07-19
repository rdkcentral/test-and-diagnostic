#! /bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2024 RDK Management
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

LOG_FILE="/rdklogs/logs/SelfHeal.txt.0"
T2_MSG_CLIENT=/usr/bin/telemetry2_0_client

t2ValNotify() {
    if [ -f $T2_MSG_CLIENT ]; then
        marker=$1
        shift
        $T2_MSG_CLIENT "$marker" "$*"
    fi
}

echo_t()
{
        echo "`date +"%y%m%d-%T.%6N"` $1"
}

input=$(dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.TrackRemotePortUsage | awk '/value:/ {print $NF}')

interval=$(echo "$input" | cut -d';' -f1)
pairs=$(echo "$input" | cut -d';' -f2)

echo_t "Checking RemotePortUsage for $pairs" >> $LOG_FILE

# Temporary file to store conntrack output
conntrack_output="/tmp/conntrack_output.txt"
temp_output=$(mktemp)
> "$temp_output"

echo -n "RemotePortUsageDetected: " >> "$temp_output"

# Extract and process each protocol and port from the input
echo $pairs | tr ',' '\n' | while read proto_port; do
    protocol=$(echo $proto_port | cut -d: -f1)
    port=$(echo $proto_port | cut -d: -f2)

    # Fetch conntrack entries for the specified protocol and port
    conntrack -L -p $protocol --dport $port > $conntrack_output 2>/dev/null

    # Process conntrack output - 3 entries per protocol-port
    seen_dst=()
    dst_count=0
    max_dst=3

    while read -r line; do
        [ $dst_count -ge $max_dst ] && break
        # Extract sport, dport, dst, and bytes fields
        sport=$(echo "$line" | grep -o 'sport=[0-9]*' | head -n1 | sed 's/sport=//')
        dst=$(echo "$line" | grep -o 'dst=[0-9.]*' | head -n1 | sed 's/dst=//')
        up_bytes=$(echo "$line" | grep -o 'bytes=[0-9]*' | head -n1 | sed 's/bytes=//')
        down_bytes=$(echo "$line" | grep -o 'bytes=[0-9]*' | head -n2 | tail -n1 | sed 's/bytes=//')

        # Keep track of unique first dst
        if [ -n "$dst" ] && ! [[ " ${seen_dst[@]} " =~ " $dst " ]]; then
            seen_dst+=("$dst")
            echo -n "$protocol,$port,$dst,$sport,$down_bytes,$up_bytes; " >> "$temp_output"
            dst_count=$((dst_count + 1))
        fi
    done < "$conntrack_output"
done

# Remove trailing space and semicolon if present
output=$(cat "$temp_output" | sed 's/; $//')

# Print the accumulated output
echo_t "$output" >> $LOG_FILE
t2ValNotify "RemotePortUsage_split" "$output"

# Clean up temporary file
rm "$temp_output"
rm -f $conntrack_output