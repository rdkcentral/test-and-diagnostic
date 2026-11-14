#!/bin/sh
#######################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:

#  Copyright 2026 RDK Management

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

MODE_FILE="/tmp/.boot_check_cron.mode"
RDKLOG_FILE="/rdklogs/logs/Consolelog.txt.0"

#waiting for syscfg to initialize
RETRIES=0
MAX_RETRIES=30
while [ ! -f /tmp/syscfg.db ] && [ $RETRIES -lt $MAX_RETRIES ]; do
    echo_t "Waiting for syscfg initialization... ($RETRIES)" >> "$RDKLOG_FILE"
    sleep 2
    RETRIES=$((RETRIES + 1))
done

# Double check the status of the daemon if necessary
if [ "$RETRIES" -eq "$MAX_RETRIES" ]; then
    echo_t "Error: syscfg timed out. Proceeding with default." >> "$RDKLOG_FILE"
fi
# INTERNAL BOOT-CHECK: 
# If the .mode file doesn't exist, this is the FIRST run since reboot.
if [ ! -f "$MODE_FILE" ]; then
    CRON_ENABLED=$(syscfg get SelfHealCronEnable)
    if [ "$CRON_ENABLED" = "true" ]; then
        echo "CRON" > "$MODE_FILE"
    else
        echo "PROCESS" > "$MODE_FILE"
    fi
fi
SELFHEAL_EXECUTION_MODE=$(cat "$MODE_FILE")

# Usage: acquire_lock "LOCK_NAME" "SCRIPT_FILENAME"
acquire_lock() {
    LOCK_NAME="$1"
    SCRIPT_NAME="$2"
    LOCKDIR="/tmp/${LOCK_NAME}.lock"
    PIDFILE="$LOCKDIR/pid"

    # Try to acquire the lock atomically
    if mkdir "$LOCKDIR" 2>/dev/null; then
        echo "$$" > "$PIDFILE"
        trap 'rm -rf "$LOCKDIR"' EXIT INT TERM
    else
        pid="$(cat "$PIDFILE" 2>/dev/null)"

        if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
            cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"

            case "$cmd" in
                *"$SCRIPT_NAME"*)
                    echo_t "$SCRIPT_NAME already running (pid=$pid); skipping"
                    exit 0
                    ;;
            esac
        fi

        # Stale lock recovery
        echo_t "Stale lock detected for $SCRIPT_NAME; cleaning up"
        rm -rf "$LOCKDIR" 2>/dev/null
        mkdir "$LOCKDIR" || exit 1
        echo "$$" > "$PIDFILE"
        trap 'rm -rf "$LOCKDIR"' EXIT INT TERM
    fi
}
