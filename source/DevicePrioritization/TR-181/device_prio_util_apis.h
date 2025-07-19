/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 RDK Management
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


#ifndef  __DEVICE_PRIO_UTIL_APIS_H
#define  __DEVICE_PRIO_UTIL_APIS_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <rbus.h>
#include "safec_lib_common.h"
#include "ansc_platform.h"

/*** DevicePrio Util Apis ***/
char const* getParamName(char const* path);

char* getDevicePrioParamName(devicePrioParam_t param);

/*** APIs for publishing event ***/
rbusError_t
DevicePrio_PublishToEvent
    (
        char* event_name,
        char* eventNewData,
        char* eventOldData,
        rbusValueType_t valueType
    );
#endif


