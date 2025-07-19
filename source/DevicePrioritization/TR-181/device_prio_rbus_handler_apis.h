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

#ifndef  __DEVICE_PRIO_RBUS_HANDLER_APIS_H
#define  __DEVICE_PRIO_RBUS_HANDLER_APIS_H

#include <rbus.h>
#include "ansc_platform.h"
#include "tad_rbus_apis.h"

/* TR181 params*/
#define DM_DSCP_CONTROL_PER_CLIENT_DATA  "Device.QOS.X_RDK_DscpControlPerClient.Data"
#define DM_DSCP_CONTROL_ACTIVE_RULES  "Device.QOS.X_RDK_DscpControlPerClient.ActiveRules"

int DevicePrioRbusInit(); 

rbusError_t TestDiagnostic_DevicePrio_EventStringHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish);
rbusError_t TestDiagnostic_DscpControl_GetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t TestDiagnostic_DscpControl_SetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);


/*** APIs for subscribe event handling***/	
BOOL
DevicePrio_EventParamStringValue
    (
        char*                       pParamName,
        rbusEventSubAction_t 		action
    );

#endif
