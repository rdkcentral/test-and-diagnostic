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
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include "lowlatency_rbus_handler_apis.h"
#include "lowlatency_dml.h"
#include "lowlatency_apis.h"
#include "lowlatency_util_apis.h"

#define LL_NUM_OF_RBUS_PARAMS  sizeof(LatencyMeasurementRbusDataElements)/sizeof(LatencyMeasurementRbusDataElements[0])

extern rbusHandle_t g_rbusHandle;
extern char *g_pTCPStatsReport;

rbusDataElement_t LatencyMeasurementRbusDataElements[] = 
{	
	/* RBUS_BOOLEAN */
	{LM_IPv4Enable, RBUS_ELEMENT_TYPE_PROPERTY, {TestDiagnostic_LatencyMeasure_GetBoolHandler, TestDiagnostic_LatencyMeasure_SetBoolHandler, NULL, NULL, NULL, NULL}},
	{LM_IPv6Enable, RBUS_ELEMENT_TYPE_PROPERTY, {TestDiagnostic_LatencyMeasure_GetBoolHandler, TestDiagnostic_LatencyMeasure_SetBoolHandler, NULL, NULL, NULL, NULL}},
	{LM_PERCENTILECALC_ENABLE, RBUS_ELEMENT_TYPE_PROPERTY, {TestDiagnostic_LatencyMeasure_GetBoolHandler, TestDiagnostic_LatencyMeasure_SetBoolHandler, NULL, NULL, NULL, NULL}},
	/* RBUS_UINT32 */
	{LM_TCP_ReportInterval, RBUS_ELEMENT_TYPE_PROPERTY, {TestDiagnostic_LatencyMeasure_GetUintHandler, TestDiagnostic_LatencyMeasure_SetUintHandler, NULL, NULL, NULL, NULL}},

    /* RBUS_STRING */
	{LM_TCP_Stats_Report, RBUS_ELEMENT_TYPE_PROPERTY, {TestDiagnostic_LatencyMeasure_GetStringHandler, TestDiagnostic_LatencyMeasure_SetStringHandler, NULL, NULL, TestDiagnostic_LatencyMeasure_EventStringHandler, NULL}},
};

/***********************************************************************

  LatencyMeasurementRbusInit(): Initialize Rbus and data elements for Low Latency

 ***********************************************************************/
int LatencyMeasurementRbusInit()
{
	int rc = RBUS_ERROR_SUCCESS;

	if(g_rbusHandle == NULL)
    {
		CcspTraceError(("%s: RBUS not initialized. Handle is NULL.\n", __FUNCTION__));
		return RBUS_ERROR_NOT_INITIALIZED;
    }

	// Register data elements
	rc = rbus_regDataElements(g_rbusHandle, LL_NUM_OF_RBUS_PARAMS, LatencyMeasurementRbusDataElements);

	if (rc != RBUS_ERROR_SUCCESS)
	{
		CcspTraceError(("rbus register data elements failed\n"));
		rc = rbus_close(g_rbusHandle);
		return rc;
	}

	return rc;
}

/***********************************************************************

 Get Handler API for objects of type RBUS_BOOLEAN for objects:
 
    LM_IPv4Enable
    LM_IPv6Enable

***********************************************************************/

rbusError_t TestDiagnostic_LatencyMeasure_GetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;

    bool rc = false;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val;
    BOOL value;

	CcspTraceInfo(("Called %s for [%s]\n", __FUNCTION__, param));

    rc = LatencyMeasure_GetParamBoolValue(NULL, param, &value);
    free(param);
    if(!rc)
    {
		CcspTraceError(("[%s]: LatencyMeasure_GetParamBoolValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_Init(&val);
    rbusValue_SetBoolean(val, value);
    rbusProperty_SetValue(property, val);
    rbusValue_Release(val);
    return RBUS_ERROR_SUCCESS;
}

/***********************************************************************

 Set Handler API for objects of type RBUS_BOOLEAN for objects:
 
    LM_IPv4Enable
    LM_IPv6Enable

***********************************************************************/

rbusError_t TestDiagnostic_LatencyMeasure_SetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    
    bool rc = false;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t value = rbusProperty_GetValue(property);

	CcspTraceInfo(("%s called for param='%s'\n", __FUNCTION__, param));
 
    if(value)
    {
        if(rbusValue_GetType(value) == RBUS_BOOLEAN)
        {
            rc = LatencyMeasure_SetParamBoolValue(NULL, param, rbusValue_GetBoolean(value));
            free(param);
            if(!rc)
            {
				CcspTraceError(("LatencyMeasure_SetParamBoolValue failed\n"));
                return RBUS_ERROR_BUS_ERROR;
            }
            return RBUS_ERROR_SUCCESS;
        }
		else
        {
			CcspTraceError(("%s result:FAIL error:'unexpected type %d'\n", __FUNCTION__, rbusValue_GetType(value)));
        }
    }
    else
    {
		CcspTraceError(("%s result:FAIL value=NULL param='%s'\n", __FUNCTION__, param));
    }
    free(param);
    return RBUS_ERROR_BUS_ERROR;
}

/***********************************************************************

 Get Handler API for objects of type uint32 for objects:
 
    LM_TCP_ReportInterval

***********************************************************************/
rbusError_t TestDiagnostic_LatencyMeasure_GetUintHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;

    bool rc = false;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val;
    ULONG value;

	CcspTraceInfo(("Called %s for [%s]\n", __FUNCTION__, param));

    rc = LatencyMeasure_GetParamUlongValue(NULL, param, &value);
    free(param);
    if(!rc)
    {
		CcspTraceError(("[%s]: LatencyMeasure_GetParamUlongValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_Init(&val);
    rbusValue_SetUInt32(val, (uint32_t) value);
    rbusProperty_SetValue(property, val);
    rbusValue_Release(val);
    return RBUS_ERROR_SUCCESS;
}

/***********************************************************************

 Set Handler API for objects of type uint32 for objects:
 
    LM_TCP_ReportInterval

***********************************************************************/
rbusError_t TestDiagnostic_LatencyMeasure_SetUintHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    
    bool rc = false;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t value = rbusProperty_GetValue(property);

	CcspTraceInfo(("%s called for param='%s'\n", __FUNCTION__, param));
 
    if(value)
    {
        if(rbusValue_GetType(value) == RBUS_UINT32)
        {
            rc = LatencyMeasure_SetParamUlongValue(NULL, param, (ULONG) rbusValue_GetUInt32(value));
            free(param);
            if(!rc)
            {
				CcspTraceError(("LatencyMeasure_SetParamUlongValue failed\n"));
                return RBUS_ERROR_BUS_ERROR;
            }
            return RBUS_ERROR_SUCCESS;
        }
		else
        {
			CcspTraceError(("%s result:FAIL error:'unexpected type %d'\n", __FUNCTION__, rbusValue_GetType(value)));
        }
    }
    else
    {
		CcspTraceError(("%s result:FAIL value=NULL param='%s'\n", __FUNCTION__, param));
    }
    free(param);
    return RBUS_ERROR_BUS_ERROR;
}

/***********************************************************************

Get Handler API for objects of type RBUS_STRING for objects:
 
    LM_TCP_Stats_Report

***********************************************************************/

rbusError_t TestDiagnostic_LatencyMeasure_GetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;

	int32_t rc=0;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val;
    char value[256];

    CcspTraceInfo(("Called %s for [%s]\n", __FUNCTION__, param));

    rbusValue_Init(&val);

    if (strcmp(param, "X_RDK_LatencyMeasure_TCP_Stats_Report") == 0){
		rbusValue_SetString(val, g_pTCPStatsReport);
	}
    else {
        rc = LatencyMeasure_GetParamStringValue(NULL, param, value, NULL);
        free(param);
        if(rc != 0)
        {
            CcspTraceError(("[%s]: LatencyMeasure_GetParamStringValue failed\n", __FUNCTION__));
            return RBUS_ERROR_BUS_ERROR;
        }
        rbusValue_SetString(val, value);
    }

    rbusProperty_SetValue(property, val);
    rbusValue_Release(val);

    return RBUS_ERROR_SUCCESS;
}

/***********************************************************************

Set Handler API for objects of type RBUS_STRING for objects:
 
    LM_TCP_Stats_Report

***********************************************************************/

rbusError_t TestDiagnostic_LatencyMeasure_SetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    (void)handle;
    (void)options;

    BOOL rc = FALSE;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val = rbusProperty_GetValue(property);

    CcspTraceInfo(("Called %s for [%s]\n", __FUNCTION__, param));

    rc = LatencyMeasure_SetParamStringValue(NULL, param, (char*) rbusValue_GetString(val,NULL));
    free(param);
    if(!rc)
    {
        CcspTraceError(("[%s]: LatencyMeasure_SetParamStringValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }
    return RBUS_ERROR_SUCCESS;
}


/***********************************************************************

  Event subscribe handler API for objects of type RBUS_STRING for objects:
 
    LM_TCP_Stats_Report

 ***********************************************************************/
rbusError_t TestDiagnostic_LatencyMeasure_EventStringHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish)
{
	(void)handle;
	(void)filter;
	(void)interval;
    bool rc = false;
    *autoPublish = false;
    char* param = strdup(GetParamName(eventName));

    CcspTraceInfo(("%s called for event '%s'\n", __FUNCTION__, eventName));

    rc = LatencyMeasure_EventParamStringValue(param, action);
    free(param);
    if(!rc)
    {
        CcspTraceError(("[%s]: LatencyMeasure_EventParamStringValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }
	return RBUS_ERROR_SUCCESS;
}


/*** API for Event handling***/	

BOOL
LatencyMeasure_EventParamStringValue
    (
        char*                       pParamName,
        rbusEventSubAction_t 		action
    )
{

	if (strcmp(pParamName, "X_RDK_LatencyMeasure_TCP_Stats_Report") == 0) {
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

