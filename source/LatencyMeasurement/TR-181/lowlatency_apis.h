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


#ifndef  _LOWLATENCY_APIS_H
#define  _LOWLATENCY_APIS_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <rbus.h>
#include "safec_lib_common.h"
#include "ansc_platform.h"

#define MAX_TCP_STATS_REPORT_SIZE	1048576

/* SYSCFG parameters */
#define	IPV4_LATENCY_MEASUREMENT_ENABLE		"LatencyMeasure_IPv4Enable"
#define	IPV6_LATENCY_MEASUREMENT_ENABLE		"LatencyMeasure_IPv6Enable"
#define	TCPREPORTINTERVAL					"LatencyMeasure_TCPReportInterval"
#define	LATENCY_MEASUREMENT_ENABLE_COUNT	"LatencyMeasure_EnableCount"
#define LATENCY_MEASUREMENT_DISABLE			"LatencyMeasure_Disable"
#define PERCENTILE_CALCULATION_ENABLE 		"LatencyMeasure_PercentileCalc_Enable"
typedef struct 
_lowLatencyInfo
{
	bool IPv4Enable;
	bool IPv6Enable;
	bool PercentileCalc_Enable;
	uint32_t TCP_ReportInterval;
	uint32_t LatencyMeasurementEnableCount;

} lowLatencyInfo, *p_lowLatencyInfo;

/* Enum to map lowLatencyInfo members */
typedef enum _lowLatencyParam
{
	LL_IPv4ENABLE = 0,
	LL_IPv6ENABLE,
	LL_TCP_REPORTINTERVAL,
	LL_TCP_STATS_REPORT,
	LL_PERCENTILECALC_ENABLE
} lowLatencyParam_t;

typedef enum _paramDbName
{
    SYSCFG_DB = 0,
    PSM_DB,
	SQL_DB
} paramDbName_t;

void LatencyMeasurementInit();
void initLatencyMeasurementInfo(); 
bool LatencyMeasurement_SyseventInit();
/****************************************************************************

	Api				-	int 
						LowLatency_Get_Parameter_Struct_Value
						(
							lowLatencyParam_t param, 
							void* pValue
						)
	Function		-	LowLatency Get Functionality
	Arguments		-	param  -> lowLatencyParam_t
						pValue -> pointer to hold the fetched value
	Return Values	-	TRUE or FALSE

*******************************************************************************/
BOOL
LowLatency_Get_Parameter_Struct_Value
	(
		lowLatencyParam_t param,
		void* pValue
	);

/*********************************************************************************

	Api					-	int LowLatency_Set_IPv4Enable(bool new_val)
	Function			-	LowLatency Set Functionality
	Parameter			-	Device.QOS.X_RDK_LatencyMeasure.IPv4Enable
	Supported Values	-	True or False

**********************************************************************************/
int 
LowLatency_Set_IPv4Enable
	(
		bool new_val
	);

/*********************************************************************************

	Api					-	int LowLatency_Set_IPv6Enable(bool new_val)
	Function			-	LowLatency Set Functionality
	Parameter			-	Device.QOS.X_RDK_LatencyMeasure.IPv6Enable
	Supported Values	-	True or False

**********************************************************************************/
int 
LowLatency_Set_IPv6Enable
	(
		bool new_val
	);

/***************************************************************************

	Api					-	int LowLatency_Set_DeviceIndex(uint32_t new_val)
	Function			-	LowLatency Set Functionality
	Parameter			-	Device.QOS.X_RDK_LatencyMeasure.TCP_ReportInterval
	Supported Values	-	1 - 1440

****************************************************************************/
int 
LowLatency_Set_TCP_ReportInterval
	(
		uint32_t new_val
	);
	
/*********************************************************************************

	Api					-	int LowLatency_Set_TCP_Stats_Report(char* new_val)
	Function			-	LowLatency Set Functionality
	Parameter			-	Device.QOS.X_RDK_LatencyMeasure_TCP_Stats_Report
	Supported Values	-	Comma delimited list

**********************************************************************************/
int LowLatency_Set_TCP_Stats_Report(char* new_val); 
/*********************************************************************************

	Api					-	int LowLatency_Set_PercentileCalc_Enable(bool new_val)
	Function			-	LowLatency Set Functionality
	Parameter			-	Device.QOS.X_RDK_LatencyMeasure_PercentileCalc_Enable
	Supported Values	-	True or False

**********************************************************************************/
int LowLatency_Set_PercentileCalc_Enable(bool new_val);

#endif


