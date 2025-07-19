/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "syscfg/syscfg.h"
#include "safec_lib_common.h"
#include "lowlatency_rbus_handler_apis.h"
#include "lowlatency_apis.h"

extern rbusHandle_t g_rbusHandle;


char const* GetParamName(char const* path)
{
    char const* p = path + strlen(path);
    while(p > path && *(p-1) != '.')
        p--;
    return p;
}

char* getLatencyParamName(lowLatencyParam_t param) {
    switch(param) {
        case LL_IPv4ENABLE:
            return LM_IPv4Enable;
        case LL_IPv6ENABLE:
            return LM_IPv6Enable;
		case LL_TCP_REPORTINTERVAL:
            return LM_TCP_ReportInterval;
		case LL_TCP_STATS_REPORT:
            return LM_TCP_Stats_Report;
		case LL_PERCENTILECALC_ENABLE:
			return LM_PERCENTILECALC_ENABLE;
        default:
            return NULL;
    }
}

BOOL
LowLatency_CastValueFromString
	(
		char* fromValue,
		void* toValue,
		rbusValueType_t ValueType
	)
{
    int ind = -1;
	
	switch(ValueType) 
	{
		case RBUS_BOOLEAN:
			if((strcmp_s("true",strlen("true"),fromValue, &ind) == EOK) && (!ind))
			{
				*((bool*) toValue) = true;
				break;
			}
			else if((strcmp_s("false",strlen("false"),fromValue, &ind) == EOK) && (!ind))
			{
				*((bool*) toValue) = false;
				break;
			}
			else
			{
				CcspTraceError(("%s failed for the parameter '%s' in %d\n", __FUNCTION__, fromValue, __LINE__));
				return FALSE;
			}

		case RBUS_UINT32:
			*((uint32_t*) toValue) = atoi(fromValue);
			break;

		case RBUS_INT32:
			*((int32_t*) toValue) = atoi(fromValue);
			break;

		case RBUS_STRING:
			strcpy(toValue, fromValue);
			break;
			
		default:
			strcpy(toValue, fromValue);
			break;
	}
	return TRUE;
}


BOOL
LowLatency_GetValueFromDb
    (
        char*                 	ParamName,
        void*                   pValue,
		rbusValueType_t			ValueType,
        paramDbName_t           DbName
    )
{	

	if (DbName == SYSCFG_DB) {

		char out_value[64] = {0};
		memset(out_value, 0, sizeof(out_value));
    
		if(!syscfg_get(NULL, ParamName, out_value, sizeof(out_value))) {
			if(!LowLatency_CastValueFromString(out_value, pValue, ValueType)){
				CcspTraceError(("syscfg_get failed for the parameter '%s' in %d\n", ParamName, __LINE__));
				return FALSE;
			}
			CcspTraceInfo(("syscfg_get success for the parameter '%s'\n", ParamName));
			return TRUE;
		}
		else {
			CcspTraceError(("syscfg_get failed for the parameter '%s'\n", ParamName));
			return FALSE;
		}
		return FALSE;
	}

	return FALSE;
}

BOOL
LowLatency_SetValueToDb
    (
        char*                 	ParamName,
        char*                   pValue,
        paramDbName_t           DbName
    )
{
	if (DbName == SYSCFG_DB){

		if( syscfg_set( NULL, ParamName, pValue ) != 0 )
		{
			CcspTraceError(("syscfg_set failed for the parameter '%s'\n", ParamName));
			return FALSE;
		}
		else
		{
			if ( 0 != syscfg_commit( ) )
			{
				CcspTraceError(("syscfg_set commit failed for the parameter '%s'\n", ParamName));
				return FALSE;
			}
		}
		return TRUE;
	}
	
	return FALSE;
}

/*** APIs for publishing event ***/	
rbusError_t 
LatencyMeasure_PublishToEvent
	(
		char* event_name, 
		char* eventData 
	)
{
    int ret = RBUS_ERROR_BUS_ERROR ;
    rbusEvent_t event;
    rbusObject_t data;
    rbusValue_t value;
    rbusValue_Init(&value);
    rbusValue_SetString(value, eventData);
    rbusObject_Init(&data, NULL);
    rbusObject_SetValue(data, event_name, value);
    event.name = event_name;
    event.data = data;
    event.type = RBUS_EVENT_GENERAL;

	/* Process the event publish*/
	ret = rbusEvent_Publish(g_rbusHandle, &event);
	if(ret != RBUS_ERROR_SUCCESS)
	{
		if (ret == RBUS_ERROR_NOSUBSCRIBERS) {
			ret = RBUS_ERROR_SUCCESS;
			CcspTraceError(("%s: No subscribers found\n", __FUNCTION__));
		}
		else {
			CcspTraceError(("Unable to Publish event data %s  rbus error code : %d\n",event_name, ret));
		}
	}
	else
	{
		CcspTraceInfo(("%s : Publish to %s ret value is %d\n", __FUNCTION__,event_name,ret));
	}
    /* release rbus value and object variable */
    rbusValue_Release(value);    
    return ret;
}