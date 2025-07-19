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
#include <sysevent/sysevent.h>
#include <sys/sysinfo.h>
#include "syscfg/syscfg.h"
#include <sys/statvfs.h>
#include "safec_lib_common.h"
#include "lowlatency_rbus_handler_apis.h"
#include "lowlatency_apis.h"
#include "lowlatency_util_apis.h"
#include "ServiceMonitor.h"

lowLatencyInfo LowLatencyInfo;

char *g_pTCPStatsReport = NULL;
int latencyMeasurementCount=0;
static int sysevent_fd 	  = -1;
static token_t sysevent_token = 0;
void LatencyMeasurementInit()
{
	char Count[ARRAY_LEN];
	//int latencyMeasurementCount=0;
	LatencyMeasurementRbusInit();
	initLatencyMeasurementInfo();
	LatencyMeasurement_SyseventInit();
	syscfg_get(NULL,LATENCY_MEASUREMENT_ENABLE_COUNT, Count, sizeof(Count));
	latencyMeasurementCount=atoi(Count);
	if(latencyMeasurementCount>0)
	{
		CcspTraceInfo(("'%s':latencyMeasurementCount:%d'",__FUNCTION__,latencyMeasurementCount));
		LatencyMeasurement_Config_Init();
	}
}

void initLatencyMeasurementInfo()
{
	// Allocate memory for storing TCP stats report
	g_pTCPStatsReport = (char*) malloc(MAX_TCP_STATS_REPORT_SIZE);
	if (g_pTCPStatsReport == NULL) {
		CcspTraceError(("%s : TCP stats report memory allocation failed.\n", __FUNCTION__));
	}

	/* init RBUS_BOOLEAN parameters */
	LowLatency_GetValueFromDb(IPV4_LATENCY_MEASUREMENT_ENABLE, &(LowLatencyInfo.IPv4Enable), RBUS_BOOLEAN, SYSCFG_DB);
	LowLatency_GetValueFromDb(IPV6_LATENCY_MEASUREMENT_ENABLE, &(LowLatencyInfo.IPv6Enable), RBUS_BOOLEAN, SYSCFG_DB);
	LowLatency_GetValueFromDb(PERCENTILE_CALCULATION_ENABLE, &(LowLatencyInfo.PercentileCalc_Enable), RBUS_BOOLEAN, SYSCFG_DB);
	/* init RBUS_UINT32 parameters */
	LowLatency_GetValueFromDb(TCPREPORTINTERVAL, &(LowLatencyInfo.TCP_ReportInterval), RBUS_UINT32, SYSCFG_DB);
}

/****************************************************************************

	Api				-	testdiagError_t 
						TestDiag_Get_Parameter_Struct_Value
						(
							testdiagParameter_t param, 
							void* pValue
						)
	Function		-	LowLatency Get Functionality
	Arguments		-	param  -> testdiagParameter_t
						pValue -> pointer to hold the fetched value
	Return Values	-	TD_STATUS_SUCCESS or TD_STATUS_FAILURE

*******************************************************************************/
BOOL
LowLatency_Get_Parameter_Struct_Value
	(
		lowLatencyParam_t param,
		void* pValue
	) 
{
	BOOL ret = FALSE;
	CcspTraceInfo(("'%s': getting value for '%s'\n", __FUNCTION__, getLatencyParamName(param)));
    switch(param)
    {
        case LL_IPv4ENABLE:
            *((bool*)pValue) = LowLatencyInfo.IPv4Enable;
			ret = TRUE;
            break; 
			
		case LL_IPv6ENABLE:
            *((bool*)pValue) = LowLatencyInfo.IPv6Enable;
			ret = TRUE;
            break;
			
		case LL_TCP_REPORTINTERVAL:
            *((uint32_t*)pValue) = LowLatencyInfo.TCP_ReportInterval;
			ret = TRUE;
            break;
		case LL_PERCENTILECALC_ENABLE:
            *((bool*)pValue) = LowLatencyInfo.PercentileCalc_Enable;
			ret = TRUE;
            break;

		default:
			ret = FALSE;
			break;
    }

	return ret;
}

/***************************************************************************

	Api					-	int LowLatency_Set_TCP_ReportInterval(uint32_t new_val)
	Function			-	LowLatency Set Functionality
	Parameter			-	Device.QOS.X_RDK_LatencyMeasure.TCP_ReportInterval
	Supported Values	-	1-1440

****************************************************************************/
int LowLatency_Set_TCP_ReportInterval(uint32_t new_val) { //---->check

	CcspTraceInfo(("'%s': setting value '%d'\n", __FUNCTION__, new_val));
	//check the value is in permitted range and there is value change
	if ((new_val >= 1) || (new_val <= 1440)) {
		uint32_t old_val = LowLatencyInfo.TCP_ReportInterval;;
		if (old_val != new_val) {
			char new_val_buf[10];
			CcspTraceInfo(("%s: request for value update\n", __FUNCTION__));
			//set updated value in db
			sprintf(new_val_buf, "%d", new_val);
			if (!LowLatency_SetValueToDb(TCPREPORTINTERVAL, new_val_buf, SYSCFG_DB)) {
				CcspTraceError(("%s: db set failed for value '%s'\n", __FUNCTION__, new_val_buf));
				return 1;
			}
			LowLatencyInfo.TCP_ReportInterval = new_val;
			SendConditional_pthread_cond_signal();
		}
		return 0;
	}
	
	CcspTraceError(("'%s': unsupported value '%d'\n", __FUNCTION__, new_val));
	return 1;
}

/*********************************************************************************************

	Api					-	int LowLatency_Set_IPv4Enable(bool new_val)
	Function			-	LowLatency Set Functionality
	Parameter			-	Device.QOS.X_RDK_LatencyMeasure.IPv4Enable
	Supported Values	-	True or False

**********************************************************************************************/
int LowLatency_Set_IPv4Enable(bool new_val) {

	CcspTraceInfo(("'%s': setting value '%d'\n", __FUNCTION__, new_val));
	// fetch previous value
	bool old_val = LowLatencyInfo.IPv4Enable;
	//update and publish the value
	if (old_val != new_val) {
		CcspTraceInfo(("%s: request for value update\n", __FUNCTION__));
		if (!LowLatency_SetValueToDb(IPV4_LATENCY_MEASUREMENT_ENABLE, new_val? "true":"false", SYSCFG_DB)) {
			CcspTraceError(("%s: db set failed for value '%s'\n", __FUNCTION__, new_val? "true":"false"));
			return 1;
		}
		LowLatencyInfo.IPv4Enable = new_val;
		UpdateLatencyMeasurement_EnableCount(LowLatencyInfo.IPv4Enable);
	}
	return 0;
}

/*********************************************************************************************

	Api					-	int LowLatency_Set_IPv6Enable(bool new_val)
	Function			-	LowLatency Set Functionality
	Parameter			-	Device.QOS.X_RDK_LatencyMeasure.IPv6Enable
	Supported Values	-	True or False

**********************************************************************************************/
int LowLatency_Set_IPv6Enable(bool new_val) {

	CcspTraceInfo(("'%s': setting value '%d'\n", __FUNCTION__, new_val));
	// fetch previous value
	bool old_val = LowLatencyInfo.IPv6Enable;
	//update and publish the value
	if (old_val != new_val) {
		CcspTraceInfo(("%s: request for value update\n", __FUNCTION__));
		if (!LowLatency_SetValueToDb(IPV6_LATENCY_MEASUREMENT_ENABLE, new_val? "true":"false", SYSCFG_DB)) {
			CcspTraceError(("%s: db set failed for value '%s'\n", __FUNCTION__, new_val? "true":"false"));
			return 1;
		}
		LowLatencyInfo.IPv6Enable = new_val;
		UpdateLatencyMeasurement_EnableCount(LowLatencyInfo.IPv6Enable);
	}
	return 0;
}


/*********************************************************************************

	Api					-	int LowLatency_Set_TCP_Stats_Report(char* new_val)
	Function			-	LowLatency Set Functionality
	Parameter			-	Device.QOS.X_RDK_LatencyMeasure_TCP_Stats_Report
	Supported Values	-	Comma delimited list

**********************************************************************************/
int LowLatency_Set_TCP_Stats_Report(char* new_val) {

	CcspTraceInfo(("'%s': setting value '%s'\n", __FUNCTION__, new_val));

	if ((strlen(new_val)+1) > MAX_TCP_STATS_REPORT_SIZE) {
		CcspTraceError(("%s : TCP stats report max size exceeded.\n", __FUNCTION__));
		return 1;
	}

	//update and publish the value
	CcspTraceInfo(("%s: request for value update\n", __FUNCTION__));

	if (RBUS_ERROR_SUCCESS != LatencyMeasure_PublishToEvent(LM_TCP_Stats_Report, new_val)) {
		CcspTraceError(("%s : publish value '%s' failed.\n", __FUNCTION__, new_val));
		return 1;
	}

	if (g_pTCPStatsReport != NULL) 
	{
		memset(g_pTCPStatsReport, 0, MAX_TCP_STATS_REPORT_SIZE);
		strcpy(g_pTCPStatsReport, new_val);	
	}
	return 0;
}

/*********************************************************************************

	Api					-	int LowLatency_Set_PercentileCalc_Enable(bool new_val)
	Function			-	LowLatency Set Functionality
	Parameter			-	Device.QOS.X_RDK_LatencyMeasure.PercentileCalc_Enable
	Supported Values	-	True or False

**********************************************************************************/
int LowLatency_Set_PercentileCalc_Enable(bool new_val)
{
	CcspTraceInfo(("'%s': setting value '%d'\n", __FUNCTION__, new_val));
	// fetch previous value
	bool old_val = LowLatencyInfo.PercentileCalc_Enable;
	//update and publish the value
	if (old_val != new_val) {
		CcspTraceInfo(("%s: request for value update\n", __FUNCTION__));
		if (!LowLatency_SetValueToDb(PERCENTILE_CALCULATION_ENABLE, new_val? "true":"false", SYSCFG_DB)) {
			CcspTraceError(("%s: db set failed for value '%s'\n", __FUNCTION__, new_val? "true":"false"));
			return 1;
		}

		if (0 > sysevent_fd)
		{
			CcspTraceError(("Failed to execute sysevent_set. sysevent_fd have no value:'%d'\n", sysevent_fd));
			return FALSE;
		}
		
		if(sysevent_set(sysevent_fd, sysevent_token, PERCENTILE_CALCULATION_ENABLE, new_val? "true":"false", 0) != 0)
		{
			CcspTraceError(("Failed to execute sysevent_set from %s:%d\n", __FUNCTION__, __LINE__));
			return FALSE;
		}
		LowLatencyInfo.PercentileCalc_Enable = new_val;
	}
	return 0;
}

bool LatencyMeasurement_SyseventInit()
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