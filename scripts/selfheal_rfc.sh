#!/bin/sh
#######################################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
#  Copyright 2025 RDK Management
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

# Define 'echo_t'
if [ -f /etc/log_timestamp.sh ]; then
    source /etc/log_timestamp.sh
else
    echo_t() { echo "$@"; }
fi

if [ -f /lib/rdk/rfc.service ]; then
    echo_t "[RFC_SELFHEAL] : Restarting RFC service"
    systemctl restart rfc.service
else
    echo_t "[RFC_SELFHEAL] : rfc.service not found. Unable to Restart it."
fi
