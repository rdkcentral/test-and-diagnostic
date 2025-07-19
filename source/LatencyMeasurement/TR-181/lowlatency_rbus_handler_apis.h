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

#ifndef  LL_RBUS_HANDLER_APIS_H
#define  LL_RBUS_HANDLER_APIS_H

#include <rbus.h>
#include "ansc_platform.h"
#include "tad_rbus_apis.h"

/* TR181 params*/
#define LM_IPv4Enable "Device.QOS.X_RDK_LatencyMeasure_IPv4Enable"
#define LM_IPv6Enable "Device.QOS.X_RDK_LatencyMeasure_IPv6Enable"
#define LM_TCP_ReportInterval "Device.QOS.X_RDK_LatencyMeasure_TCP_ReportInterval"
#define LM_TCP_Stats_Report "Device.QOS.X_RDK_LatencyMeasure_TCP_Stats_Report"
#define LM_PERCENTILECALC_ENABLE "Device.QOS.X_RDK_LatencyMeasure_PercentileCalc_Enable"
int LatencyMeasurementRbusInit(); 

rbusError_t TestDiagnostic_LatencyMeasure_GetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t TestDiagnostic_LatencyMeasure_SetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);

rbusError_t TestDiagnostic_LatencyMeasure_GetUintHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t TestDiagnostic_LatencyMeasure_SetUintHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);

rbusError_t TestDiagnostic_LatencyMeasure_GetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t TestDiagnostic_LatencyMeasure_SetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);
rbusError_t TestDiagnostic_LatencyMeasure_EventStringHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish);

/*** APIs for subscribe event handling***/	
BOOL
LatencyMeasure_EventParamStringValue
    (
        char*                       pParamName,
        rbusEventSubAction_t 		action
    );

#endif
