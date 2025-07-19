/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "syscfg/syscfg.h"
#include "safec_lib_common.h"
#include "device_prio_rbus_handler_apis.h"
#include "device_prio_apis.h"

extern rbusHandle_t g_rbusHandle;


char const* getParamName(char const* path)
{
    char const* p = path + strlen(path);
    while(p > path && *(p-1) != '.')
        p--;
    return p;
}

char* getDevicePrioParamName(devicePrioParam_t param) {
    switch(param) {
		case DP_QOS_ACTIVE_RULES:
			return DM_DSCP_CONTROL_ACTIVE_RULES;
        default:
            return NULL;
    }
}

/*** APIs for publishing event ***/
rbusError_t
DevicePrio_PublishToEvent
    (
        char* event_name,
		char* eventNewData,
        char* eventOldData,
        rbusValueType_t ValueType
	)
{
    int ret = RBUS_ERROR_BUS_ERROR ;
    rbusEvent_t event;
    rbusObject_t rbusObj;
    rbusValue_t val;
    rbusValue_t oldVal;
    rbusValue_t byVal;
    bool rbusStrRet;

    rbusValue_Init(&val);
    rbusValue_Init(&oldVal);

    rbusStrRet = rbusValue_SetFromString(val, ValueType, eventNewData);

    if(rbusStrRet == false)
    {
        CcspTraceError(("%s-%d Rbus Error code:'%d' \n",__FUNCTION__,__LINE__,rbusStrRet));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusStrRet = rbusValue_SetFromString(oldVal, ValueType, eventOldData);

    if(rbusStrRet == false)
    {
        CcspTraceError(("%s-%d Rbus Error code:'%d' \n",__FUNCTION__,__LINE__,rbusStrRet));
        return RBUS_ERROR_BUS_ERROR;
    }
    rbusValue_Init(&byVal);
    rbusValue_SetString(byVal, TAD_COMPONENT_NAME);

    rbusObject_Init(&rbusObj, NULL);
    rbusObject_SetValue(rbusObj, "value", val);
    rbusObject_SetValue(rbusObj, "oldValue", oldVal);
    rbusObject_SetValue(rbusObj, "by", byVal);

    event.name = event_name;
    event.data = rbusObj;
    event.type = RBUS_EVENT_VALUE_CHANGED;

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
    rbusValue_Release(val);
    rbusValue_Release(oldVal);
    rbusValue_Release(byVal);
    rbusObject_Release(rbusObj);

    return ret;
}
