/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include "ccsp_trace.h"

#define BUILD_TIME_PATH 	"/version.txt"
#define TIMEOFFSET_VALUE 	"timeoffset_ethwan_enable"
#define CLOCK_EVENT_PATH 	"/tmp/clock-event"
#define SLEEP_TIME 		3600
#define MAX_BUF_SIZE		128

bool IsEthWanEnabled (void);
time_t getEpochTime();
time_t convert_to_epoch(const char *date_str);
time_t getBuildEpoch(const char *file_path);
long long str_to_int_conv(char *str_value);
bool setSystemTime(time_t desired_epoch_time);
void* updateTimeThread(void* arg);
void get_sleep_time(unsigned int *sleep_time);
void updateTimeThread_create();
void UpdatedeviceTimeorbuildTime(long long currentEpochTime, long long build_epoch);
