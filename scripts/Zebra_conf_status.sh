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
ZEBRA_CONF="/var/zebra.conf"
source $UTOPIA_PATH/log_env_var.sh

exec 3>&1 4>&2 >>$SELFHEALFILE 2>&1
if [ -f "$ZEBRA_CONF" ]
then
        if [ -s "$ZEBRA_CONF" ]
        then
            Isvalid=`cat $ZEBRA_CONF | wc -c`
            #Checking zebra.conf is non empty (not a null character only present in the file)
            if [ $Isvalid -gt 3 ]
            then
                    echo_t "[RDKB_SELFHEAL]:Zebra.conf content"
                    echo_t "`cat $ZEBRA_CONF | grep -v password`"
            else
                    echo_t "[RDKB_SELFHEAL]:Zebra.conf has no valid configuration"
            fi
        else
            echo_t "[RDKB_SELFHEAL]:Zebra.conf is empty"
        fi
else
    echo_t "[RDKB_SELFHEAL]:Zebra.conf is not present"
fi