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
#include <sysevent/sysevent.h>
#include <sys/sysinfo.h>
#include "syscfg/syscfg.h"
#include <sys/statvfs.h>
#include "safec_lib_common.h"
#include "device_prio_rbus_handler_apis.h"
#include "device_prio_apis.h"
#include "device_prio_util_apis.h"

#ifdef RDK_SCHEDULER_ENABLED
#include "device_prio_webconfig_apis.h"
#include "device_prio_scheduler_apis.h"
#endif //#ifdef RDK_SCHEDULER_ENABLED

devicePrioInfo DevicePrioInfo;

int sysevent_fd = -1;
token_t sysevent_token = 0;

void DevicePrioInit()
{
	DevicePrioRbusInit();
	initDevicePrioInfo();
	DevicePrio_SyseventInit();
#ifdef RDK_SCHEDULER_ENABLED
	// Init DevicePrio webconfig framework
    webConfigFrameworkInit();
	
	// Init rdkscheduler
	device_prio_scheduler_init();
#endif

}

void initDevicePrioInfo()
{
	DevicePrio_Set_QOS_Active_Rules();
}

BOOL
DevicePrio_Get_Parameter_Struct_Value
	(
		devicePrioParam_t param,
		void* pValue
	) 
{
	BOOL ret = FALSE;
	CcspTraceInfo(("'%s': getting value for '%s'\n", __FUNCTION__, getDevicePrioParamName(param)));
    switch(param)
    {
		case DP_QOS_ACTIVE_RULES:
			strncpy((char*)pValue, DevicePrioInfo.QOS_Active_Rules, strlen(DevicePrioInfo.QOS_Active_Rules)+1);
			ret = TRUE;
            break;
		default:
			ret = FALSE;
			break;
    }

	return ret;
}

bool DevicePrio_SyseventInit()
{		
	if (0 > sysevent_fd)
	{
		if ((sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "CcspTandDSsp", &sysevent_token)) < 0)
		{
			CcspTraceError(("Failed to open sysevent.\n"));
			return FALSE;
		}
		CcspTraceInfo(("sysevent_open success.\n"));
		return TRUE;
	}
	CcspTraceInfo(("Failed to open sysevent. sysevent_fd already have a value '%d'\n", sysevent_fd));
	return FALSE;
}

/*********************************************************************************

	Api					-	int DevicePrio_Set_QOS_Active_Rules()
	Function			-	DevicePrio Set Functionality
	Parameter			-	Device.QOS.X_RDK_DscpControlPerClient.ActiveRules
	Supported Values	-	Internally generate "|" delimited list

**********************************************************************************/
int DevicePrio_Set_QOS_Active_Rules() {

	//update and publish the value
	CcspTraceInfo(("%s: request for value update\n", __FUNCTION__));

	char old_val[QOS_ACTIVE_RULES_MAX_SIZE] = {0};

	strncpy(old_val, DevicePrioInfo.QOS_Active_Rules, sizeof(old_val)-1);

	memset(DevicePrioInfo.QOS_Active_Rules, 0, QOS_ACTIVE_RULES_MAX_SIZE);

	if (0 != DevicePrio_Generate_QOS_Active_Rules(DevicePrioInfo.QOS_Active_Rules)) {
		CcspTraceError(("%s : Generating value failed for QoS Active Rules.\n", __FUNCTION__));
		return 1;
	}

	if (0 != strcmp(old_val, DevicePrioInfo.QOS_Active_Rules)) {

		CcspTraceInfo(("%s: New Active Rule is : %s\n", __FUNCTION__, DevicePrioInfo.QOS_Active_Rules));

		if (RBUS_ERROR_SUCCESS != DevicePrio_PublishToEvent(DM_DSCP_CONTROL_ACTIVE_RULES, DevicePrioInfo.QOS_Active_Rules, old_val, RBUS_STRING)) {
			CcspTraceError(("%s : publish value '%s' failed.\n", __FUNCTION__, DevicePrioInfo.QOS_Active_Rules));
			return 1;
		}
	}
	else {
		CcspTraceInfo(("%s: No value change : %s\n", __FUNCTION__, DevicePrioInfo.QOS_Active_Rules));
	}

	return 0;
}

/*********************************************************************************

	Api					-	int DevicePrio_Set_QOS_Active_Rules()
	Function			-	DevicePrio Set Functionality
	Parameter			-	char *result --> buffer to hold return
	Return				-	0 - success, 1- failure

**********************************************************************************/
int DevicePrio_Generate_QOS_Active_Rules(char *result) {

	CcspTraceInfo(("'%s': called\n", __FUNCTION__));

	char count_buf[64] = {0};
    char mac_buf[128] = {0};
    char dscp_buf[128] = {0};
	char traffic_buf[128] = {0};
	char mac[32] = {0};
    char dscp_val[16] = {0};
    char traffic_val[128] = {0};
	int count = 0;

	strncpy(result, "", 1); // Initialize result as an empty string

	if ( syscfg_get( NULL, "DCPC_PrioClients_Count", count_buf, sizeof(count_buf)) == 0 )
	{
		count = atoi(count_buf);
		if(count <= 0) {
			CcspTraceError(("%s: Invalid count: %d\n", __FUNCTION__, count));
			return 1;
		}
	}
	memset(count_buf, 0, sizeof(count_buf));

	for (int i=1; i<=count; i++){
		memset(dscp_buf,0,sizeof(dscp_buf));
		memset(traffic_buf,0,sizeof(traffic_buf));
		memset(mac_buf,0,sizeof(mac_buf));

		memset(mac,0,sizeof(mac));
        memset(traffic_val,0,sizeof(traffic_val));
        memset(dscp_val,0,sizeof(dscp_val));

		snprintf(mac_buf, sizeof(mac_buf), "DCPC_PrioClients_Mac_%d",i);
		snprintf(dscp_buf, sizeof(dscp_buf), "DCPC_PrioClients_DSCP_%d",i);
		snprintf(traffic_buf, sizeof(traffic_buf), "DCPC_PrioClients_Action_%d",i);

		if (syscfg_get(NULL, mac_buf, mac, sizeof(mac)) == 0 && strlen(mac) != 0 &&
			syscfg_get(NULL, dscp_buf, dscp_val, sizeof(dscp_val)) == 0 && strlen(dscp_val) != 0 &&
			syscfg_get(NULL, traffic_buf, traffic_val, sizeof(traffic_val)) == 0 && strlen(traffic_val) != 0) {

				strcat(result, mac);
				strcat(result, ",");
				strcat(result, traffic_val);
				strcat(result, ",");
				strcat(result, dscp_val);

				// Add a separator if it's not the last iteration
				if (i < count) {
					strcat(result, "|");
				}
		}
		else {
			CcspTraceError(("%s: syscfg get failed\n", __FUNCTION__));
			return 1;
		} 
	}

	return 0;
}
