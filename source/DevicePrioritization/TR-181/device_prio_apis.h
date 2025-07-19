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


#ifndef  __DEVICE_PRIO_APIS_H
#define  __DEVICE_PRIO_APIS_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <rbus.h>
#include "safec_lib_common.h"
#include "ansc_platform.h"

#define QOS_ACTIVE_RULES_MAX_SIZE	8000

/* SYSCFG parameters */
/*None */

typedef struct 
_devicePrioInfo
{
	char QOS_Active_Rules[QOS_ACTIVE_RULES_MAX_SIZE];

} devicePrioInfo, *p_devicePrioInfo;

/* Enum to map devicePrioInfo members */
typedef enum _devicePrioParam
{
	DP_QOS_ACTIVE_RULES
} devicePrioParam_t;

void DevicePrioInit();
void initDevicePrioInfo(); 
bool DevicePrio_SyseventInit();
/****************************************************************************

	Api				-	int 
						DevicePrio_Get_Parameter_Struct_Value
						(
							devicePrioParam_t param, 
							void* pValue
						)
	Function		-	DevicePrio Get Functionality
	Arguments		-	param  -> devicePrioParam_t
						pValue -> pointer to hold the fetched value
	Return Values	-	TRUE or FALSE

*******************************************************************************/
BOOL
DevicePrio_Get_Parameter_Struct_Value
	(
		devicePrioParam_t param,
		void* pValue
	);

/*********************************************************************************

	Api					-	int DevicePrio_Set_QOS_Active_Rules()
	Function			-	DevicePrio Set Functionality
	Parameter			-	Device.QOS.X_RDK_DscpControlPerClient.ActiveRules
	Supported Values	-	Internally generate "|" delimited list

**********************************************************************************/
int DevicePrio_Set_QOS_Active_Rules();

/*********************************************************************************

	Api					-	int DevicePrio_Set_QOS_Active_Rules()
	Function			-	DevicePrio Set Functionality
	Parameter			-	char *result --> buffer to hold return
	Return				-	0 - success, 1- failure

**********************************************************************************/
int DevicePrio_Generate_QOS_Active_Rules(char *result);

#endif


