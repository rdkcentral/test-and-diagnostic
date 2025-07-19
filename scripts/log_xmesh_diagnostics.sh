#! /bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2019 RDK Management
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

source /etc/device.properties

# Mesh diagnostics logs for XLE and XB7
WFO_ARG=

if [ "$MODEL_NUM" == "CGM4331COM" ] || [ "$MODEL_NUM" == "TG4482A" ]; then
    ACT_IFACE=`dmcli eRT getv Device.X_RDK_WanManager.CurrentActiveInterface | grep 'value: ' | cut -d':' -f3 | xargs`
    if [ "$ACT_IFACE" == "brRWAN" ]; then
        WFO_ARG="-w"
    fi
elif [ "$MODEL_NUM" == "WNXL11BWL" ]; then
    WFO_ENABLED=`sysevent get mesh_wfo_enabled`
    if [ "$WFO_ENABLED" == "true" ]; then
        WFO_ARG="-w"
    fi
fi

echo  "================== Periodic xmesh_diagnostics logging ==================" >> /rdklogs/logs/MeshBlackbox.log
echo  "================== Periodic xmesh_diagnostics logging ==================" >> /rdklogs/logs/MeshBlackboxDumps.log
xmesh_diagnostics -d $WFO_ARG
