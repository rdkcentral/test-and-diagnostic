/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2017 RDK Management
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


#ifndef  _LOWLATENCY_UTIL_APIS_H
#define  _LOWLATENCY_UTIL_APIS_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <rbus.h>
#include "safec_lib_common.h"
#include "ansc_platform.h"


/*** LowLatency Util Apis ***/
char const* GetParamName(char const* path);

char* getLatencyParamName(lowLatencyParam_t param);

BOOL
LowLatency_CastValueFromString
	(
		char* fromValue,
		void* toValue,
		rbusValueType_t ValueType
	);

BOOL
LowLatency_GetValueFromDb
    (
        char*                 	ParamName,
        void*                   pValue,
		rbusValueType_t			ValueType,
        paramDbName_t           DbName
    );

BOOL
LowLatency_SetValueToDb
    (
        char*                 	ParamName,
        char*                   pValue,
        paramDbName_t           DbName
    );

/*** APIs for publishing event ***/	
rbusError_t 
LatencyMeasure_PublishToEvent
	(
		char* event_name, 
		char* eventData
	);
#endif


