/*********************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
******************************************************************************/

#include <stdio.h>

#define XLE_SELFHEAL_COMP "xle_selfheal"
#define NTP_SYNC_FILE "/tmp/.ntp_time_synced"
#define TIME_SYNC_FROM_LTE "/tmp/.time_synced_from_lte"
#define NTP_STARTED_ONCE_GW_TIMESYNC "/tmp/.ntp_tried_timesyncfromGW"

extern FILE *logFp ;

#define  xle_log( msg ...){ \
                ANSC_UNIVERSAL_TIME ut; \
                AnscGetLocalTime(&ut); \
                if ( logFp != NULL){ \
                fprintf(logFp, "%.2d%.2d%.2d-%.2d:%.2d:%.2d ", ut.Year,ut.Month,ut.DayOfMonth,ut.Hour,ut.Minute,ut.Second); \
                fprintf(logFp, msg);} \
}

rbusError_t xle_selfheal_rbus_init();
int rbus_getStringValue(char* value, char* path);
int rbus_setStringValue(char* value, char* path);
int rbus_getUInt32Value(ULONG* value, char* path);
int ntpd_selfheal_sync_primary();
void create_ntp_restart_File(void);
