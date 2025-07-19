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
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include "device_prio_rbus_handler_apis.h"
#include "device_prio_dml.h"
#include "device_prio_apis.h"
#include "device_prio_util_apis.h"

#define DP_NUM_OF_RBUS_PARAMS  sizeof(DevicePrioRbusDataElements)/sizeof(DevicePrioRbusDataElements[0])

extern rbusHandle_t g_rbusHandle;
extern char *g_pTCPStatsReport;

rbusDataElement_t DevicePrioRbusDataElements[] = 
{	
    /* RBUS_STRING */
#ifdef RDK_SCHEDULER_ENABLED
    {DM_DSCP_CONTROL_PER_CLIENT_DATA, RBUS_ELEMENT_TYPE_PROPERTY, {TestDiagnostic_DscpControl_GetStringHandler, TestDiagnostic_DscpControl_SetStringHandler, NULL, NULL, NULL, NULL}},
#endif //#ifdef RDK_SCHEDULER_ENABLED
    {DM_DSCP_CONTROL_ACTIVE_RULES, RBUS_ELEMENT_TYPE_PROPERTY, {TestDiagnostic_DscpControl_GetStringHandler, NULL, NULL, NULL, TestDiagnostic_DevicePrio_EventStringHandler, NULL}},
};

/*************************************************************************************

  DevicePrioRbusInit(): Initialize Rbus and data elements for Device Prioritization

 *************************************************************************************/
int DevicePrioRbusInit()
{
	int rc = RBUS_ERROR_SUCCESS;

	if(g_rbusHandle == NULL)
    {
		CcspTraceError(("%s: RBUS not initialized. Handle is NULL.\n", __FUNCTION__));
		return RBUS_ERROR_NOT_INITIALIZED;
    }

	// Register data elements
	rc = rbus_regDataElements(g_rbusHandle, DP_NUM_OF_RBUS_PARAMS, DevicePrioRbusDataElements);

	if (rc != RBUS_ERROR_SUCCESS)
	{
		CcspTraceError(("rbus register data elements failed\n"));
		rc = rbus_close(g_rbusHandle);
		return rc;
	}

	return rc;
}

/***********************************************************************

  Event subscribe handler API for objects of type RBUS_STRING for objects:
 
    DM_DSCP_CONTROL_ACTIVE_RULES

 ***********************************************************************/
rbusError_t TestDiagnostic_DevicePrio_EventStringHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish)
{
	(void)handle;
	(void)filter;
	(void)interval;
    bool rc = false;
    *autoPublish = false;
    char* param = strdup(getParamName(eventName));

    CcspTraceInfo(("%s called for event '%s'\n", __FUNCTION__, eventName));

    rc = DevicePrio_EventParamStringValue(param, action);
    free(param);
    if(!rc)
    {
        CcspTraceError(("[%s]: DevicePrio_EventParamStringValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }
	return RBUS_ERROR_SUCCESS;
}


/*** API for Event handling***/	

BOOL
DevicePrio_EventParamStringValue
    (
        char*                       pParamName,
        rbusEventSubAction_t 		action
    )
{

    if (strcmp(pParamName, "ActiveRules") == 0) {
		if (action == RBUS_EVENT_ACTION_SUBSCRIBE)
		{
			CcspTraceInfo(("Subscribers count increased for event [%s] \n", pParamName));
		}
		else if (action == RBUS_EVENT_ACTION_UNSUBSCRIBE)
		{
			CcspTraceInfo(("Subscribers count decreased for event [%s] \n", pParamName));
		}
		return TRUE;
	}

	CcspTraceWarning(("[%s]: Unsupported parameter '%s'\n", __FUNCTION__, pParamName));
	return FALSE;
}


/***********************************************************************

 Get Handler API for objects of type RBUS_STRING for objects:
 
    Device.QOS.X_RDK_DscpControlPerClient.

***********************************************************************/

rbusError_t TestDiagnostic_DscpControl_GetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;

	int32_t rc;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(getParamName(propName));
    rbusValue_t val;
    char value[QOS_ACTIVE_RULES_MAX_SIZE];
    ULONG ulen = QOS_ACTIVE_RULES_MAX_SIZE;

    CcspTraceInfo(("Called %s for [%s]\n", __FUNCTION__, param));

    rc = DscpControl_GetParamStringValue(NULL, param, value, &ulen);
    free(param);
    if(rc != 0)
    {
        CcspTraceError(("[%s]: DscpControl_GetParamStringValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }
    rbusValue_Init(&val);
    rbusValue_SetString(val, value);
    rbusProperty_SetValue(property, val);
    rbusValue_Release(val);
    return RBUS_ERROR_SUCCESS;
}

/***********************************************************************

 Set Handler API for objects of type RBUS_STRING for objects:
 
    Device.QOS.X_RDK_DscpControlPerClient.

***********************************************************************/

rbusError_t TestDiagnostic_DscpControl_SetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;

    bool rc = false;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(getParamName(propName));
    rbusValue_t val = rbusProperty_GetValue(property);

    CcspTraceInfo(("Called %s for [%s]\n", __FUNCTION__, param));

    rc = DscpControl_SetParamStringValue(NULL, param, (char*) rbusValue_GetString(val,NULL));
    free(param);
    if(!rc)
    {
        CcspTraceError(("[%s]: DscpControl_SetParamStringValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }
    return RBUS_ERROR_SUCCESS;
}
