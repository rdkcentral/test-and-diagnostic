#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
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

source /etc/utopia/service.d/log_env_var.sh
source /etc/utopia/service.d/log_capture_path.sh
source /lib/rdk/t2Shared_api.sh
source /etc/device.properties
# RDKB-6628 : Periodically log whether SSIDs are same or not
ssid24value=""
ssid5value=""
got_24=0
got_5=0
if [ "$triband_radio" == "true" ]; then
    radioenable_6=$(dmcli eRT getv Device.WiFi.Radio.3.Enable)
    isRadioEnabled_6=$(echo "$radioenable_6" | grep "false")
    ssid6value=""
    got_6=0
fi
if [ "x$BOX_TYPE" = "xXB3" ]; then
GET_PID_FROM_PEER=`rpcclient $ATOM_ARPING_IP "busybox pidof CcspWifiSsp"`
WiFi_PID=`echo "$GET_PID_FROM_PEER" | awk 'END{print}' | grep -v "RPC CONNECTED"`
else
   if [ "$OneWiFiEnabled" == "true" ]; then
          WiFi_PID=$(busybox pidof OneWifi)
      else
          WiFi_PID=$(busybox pidof CcspWifiSsp)
  fi
fi
if [ "x$WiFi_PID" != "x" ]; then
    # check for wifi params only if wifi agent is up and running
    # Get 2.4GHz SSID and do sanity check
    ssid24value=`dmcli eRT retv Device.WiFi.SSID.1.SSID`
    ssid5value=`dmcli eRT retv Device.WiFi.SSID.2.SSID`
    if [ "$ssid24value" = "" ]
    then
        echo "`date +'%Y-%m-%d:%H:%M:%S:%6N'` [RDKB_PLATFORM_ERROR] Didn't get WiFi 2.4 GHz SSID from agent"
        t2CountNotify "WIFI_ERROR_atomConsoleDown_2G" 
    else
        got_24=1
    fi
    
    # Get 5GHz SSID and do sanity check
    if [ "$ssid5value" = "" ]
    then
        echo "`date +'%Y-%m-%d:%H:%M:%S:%6N'` [RDKB_PLATFORM_ERROR] Didn't get WiFi 5 GHz SSID from agent"
        t2CountNotify "WIFI_ERROR_atomConsoleDown_5G"
    else
        got_5=1
    fi

    if [ "$triband_radio" == "true" ]; then
        ssid6value=`dmcli eRT retv Device.WiFi.SSID.17.SSID`
        # Get 6GHz SSID and do sanity check
        if [ "$isRadioEnabled_6" == "" ]; then
            if [ "$ssid6value" = "" ]; then
                echo "`date +'%Y-%m-%d:%H:%M:%S:%6N'` [RDKB_PLATFORM_ERROR] Didn't get WiFi 6 GHz SSID from agent"
                t2CountNotify "WIFI_ERROR_atomConsoleDown_6G"
            else
                got_6=1
            fi
        else
            echo "Radio 3(6GHz) is not enabled"
        fi

        # Compare 2.4GHz, 5GHz and 6GHz SSID and log

        isRadioExecutionSucceed_6=$(echo "$radioenable_6" | grep "Execution succeed")

        if [ "$isRadioExecutionSucceed_6" != "" ]; then
            isRadioEnabled_6=$(echo "$radioenable_6" | grep "false")

            if [ "$isRadioEnabled_6" == "" ]; then
                if [ $got_24 -eq 1 ] && [ $got_5 -eq 1 ] && [ $got_6 -eq 1 ]; then
                    if [[ "$ssid6value" == "$ssid5value" && "$ssid5value" == "$ssid24value" ]]; then
                        echo "`date +'%Y-%m-%d:%H:%M:%S:%6N'` [RDKB_STAT_LOG] 2.4G, 5G and 6G SSIDs are same"
                        t2CountNotify "SYS_INFO_sameSSID"
                    else
                        echo "`date +'%Y-%m-%d:%H:%M:%S:%6N'` [RDKB_STAT_LOG] 2.4G, 5G and 6G SSIDs are different"
                        t2CountNotify "SYS_INFO_differentSSID"
                    fi
                else
                    echo "Failed to fetch SSID's from their respective radios"
                    got_6=0
                fi
            else
                echo "Radio 3(6GHz) was not enabled"
            fi
        else
            echo "Radio execution got failed"
        fi

    else
        # Triband radio is'nt present
        # Compare 2.4GHz and 5GHz SSID and log
        if [ $got_24 -eq 1 ] && [ $got_5 -eq 1 ]; then
            if [ "$ssid5value" == "$ssid24value" ]; then
                echo "`date +'%Y-%m-%d:%H:%M:%S:%6N'` [RDKB_STAT_LOG] 2.4G and 5G SSIDs are same"
                t2CountNotify "SYS_INFO_sameSSID"
            else
                echo "`date +'%Y-%m-%d:%H:%M:%S:%6N'` [RDKB_STAT_LOG] 2.4G and 5G SSIDs are different"
                t2CountNotify "SYS_INFO_differentSSID"
            fi
        fi
        got_24=0
        got_5=0
    fi

else
    echo "`date +'%Y-%m-%d:%H:%M:%S:%6N'` [RDKB_PLATFORM_ERROR] WiFi Agent is not running skipping getSsidNames"
    t2CountNotify "WIFI_INFO_skipSSID"
fi
