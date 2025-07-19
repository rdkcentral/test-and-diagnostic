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
UTOPIA_PATH="/etc/utopia/service.d"
source $UTOPIA_PATH/log_env_var.sh
source /lib/rdk/t2Shared_api.sh
source /etc/device.properties

exec 3>&1 4>&2 >>$SELFHEALFILE 2>&1

STATUS=`dmcli eRT getv Device.NAT.X_Comcast_com_EnablePortMapping | grep value | awk '{print $5}'`
echo_t "Port mapping status is:$STATUS"
t2ValNotify "PortMappingEnable_split" "$STATUS"

if [ "$MODEL_NUM" = "TG4482A" ]
then
   radio_enum_count=`lspci -mk | grep mtlk | wc -l`
   echo_t "pci_enumeration_count:$radio_enum_count"
   t2ValNotify "PciEnumeration_split" "$radio_enum_count"
fi

