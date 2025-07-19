#!/bin/sh
#######################################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
#  Copyright 2022 RDK Management
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
source /etc/log_timestamp.sh

tmp_file=$(find /tmp -maxdepth 1 -name "*sess*")
for file in $tmp_file
do
        diff=$((($(date +%s) - $(stat $file -c %Y)) / 60 ))
        if [ "$diff" -ge 15 ]; then
           echo_t "[GUI] Deleted $file due to session inactivity" >> /rdklogs/logs/Consolelog.txt.0
           rm -f $file
        fi
done
