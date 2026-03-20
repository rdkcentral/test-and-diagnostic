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

echo_t "Entering to check cron mode at boot time" >> "$RDKLOG_FILE"
# INTERNAL BOOT-CHECK: 
# If the .mode file doesn't exist, this is the FIRST run since reboot.
if [ ! -f "$MODE_FILE" ]; then
    echo_t "First run since reboot; determining execution mode" >> "$RDKLOG_FILE"
    CRON_ENABLED=$(syscfg get SelfHealCronEnable)
    echo_t "SelfHealCronEnable is set to: $CRON_ENABLED" >> "$RDKLOG_FILE"
        if [ "$CRON_ENABLED" = "true" ]; then
            echo_t "Cron is enabled; setting mode to CRON" >> "$RDKLOG_FILE"
            echo "CRON" > "$MODE_FILE"
        else
            echo_t "Cron is disabled; setting mode to PROCESS" >> "$RDKLOG_FILE"
            echo "PROCESS" > "$MODE_FILE"
        fi
    fi
fi
SELFHEAL_EXECUTION_MODE=$(cat "$MODE_FILE")
echo_t "Current execution mode: $SELFHEAL_EXECUTION_MODE" >> "$RDKLOG_FILE"

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
