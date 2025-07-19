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

UTOPIA_PATH="/etc/utopia/service.d"
	
source $UTOPIA_PATH/log_env_var.sh
source /etc/log_timestamp.sh
source /lib/rdk/t2Shared_api.sh

exec 3>&1 4>&2 >>$SELFHEALFILE 2>&1

file_nr="/proc/sys/fs/file-nr"
nr_open="/proc/sys/fs/nr_open"

echo_t "[RDKB_SELHEAL]Output of file-nr $file_nr `cat $file_nr`"
output_file_nr=`cat $file_nr`
t2ValNotify "FileNr_split" "$output_file_nr"
echo_t "[RDKB_SELHEAL]Output of nr_open $nr_open `cat $nr_open`"
