#! /bin/sh
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


UTOPIA_PATH="/etc/utopia/service.d"
TAD_PATH="/usr/ccsp/tad"

source /etc/device.properties
source /etc/log_timestamp.sh
source $UTOPIA_PATH/log_env_var.sh
source /lib/rdk/t2Shared_api.sh

exec 3>&1 4>&2 >>$SELFHEALFILE 2>&1

SELFHEAL_ENABLE=$(syscfg get selfheal_enable)
if [ "$SELFHEAL_ENABLE" = "true" ] && [ -f /tmp/.resource_monitor_started ]; then
        SelfHealScript_PID=$(busybox pidof resource_monitor.sh)
        if [ -z "$SelfHealScript_PID" ]; then
		echo_t "RDKB_PROCESS_CRASHED : resource_monitor.sh is not running, need restart"
                echo_t "Restarting resource monitor script"
		t2CountNotify "SYS_SH_ResourceMonitor_restart"
                $TAD_PATH/resource_monitor.sh &
        fi
fi

