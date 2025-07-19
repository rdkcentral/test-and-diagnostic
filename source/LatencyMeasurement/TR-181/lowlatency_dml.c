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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "lowlatency_dml.h"
#include "lowlatency_apis.h"


BOOL
LatencyMeasure_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pParamName,
        BOOL*                       pBool
    )
{
	UNREFERENCED_PARAMETER(hInsContext);

	if (strcmp(pParamName, "X_RDK_LatencyMeasure_IPv4Enable") == 0)
	{
		if (!LowLatency_Get_Parameter_Struct_Value(LL_IPv4ENABLE, pBool)) {
			CcspTraceError(("%s for parameter '%s' failed.\n", __FUNCTION__, pParamName));
			return FALSE;
		}
		return TRUE;
	}

	if (strcmp(pParamName, "X_RDK_LatencyMeasure_IPv6Enable") == 0)
	{
		if (!LowLatency_Get_Parameter_Struct_Value(LL_IPv6ENABLE, pBool)) {
			CcspTraceError(("%s for parameter '%s' failed.\n", __FUNCTION__, pParamName));
			return FALSE;
		}
		return TRUE;
	}

	if (strcmp(pParamName, "X_RDK_LatencyMeasure_PercentileCalc_Enable") == 0)
	{
		if (!LowLatency_Get_Parameter_Struct_Value(LL_PERCENTILECALC_ENABLE, pBool)) {
			CcspTraceError(("%s for parameter '%s' failed.\n", __FUNCTION__, pParamName));
			return FALSE;
		}
		return TRUE;
	}
	CcspTraceWarning(("Unsupported parameter '%s'\n", pParamName));

    return FALSE;
}

BOOL
LatencyMeasure_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pParamName,
        BOOL                        bValue
    )
{
	UNREFERENCED_PARAMETER(hInsContext);

	if (strcmp(pParamName, "X_RDK_LatencyMeasure_IPv4Enable") == 0)
    {
		if (0 != LowLatency_Set_IPv4Enable(bValue)) {
			CcspTraceError(("%s result: value set failed, pParamName='%s'\n", __FUNCTION__, pParamName));
			return FALSE;
		}
		return TRUE;
    }
	
	if (strcmp(pParamName, "X_RDK_LatencyMeasure_IPv6Enable") == 0)
    {
		if (0 != LowLatency_Set_IPv6Enable(bValue)) {
			CcspTraceError(("%s result: value set failed, pParamName='%s'\n", __FUNCTION__, pParamName));
			return FALSE;
		}
		return TRUE;
    }

	if (strcmp(pParamName, "X_RDK_LatencyMeasure_PercentileCalc_Enable") == 0)
    {
		if (0 != LowLatency_Set_PercentileCalc_Enable(bValue)) {
			CcspTraceError(("%s result: value set failed, pParamName='%s'\n", __FUNCTION__, pParamName));
			return FALSE;
		}
		return TRUE;
    }
	return FALSE;
}
 
BOOL
LatencyMeasure_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pParamName,
        ULONG*                      puLong
    )
{
	UNREFERENCED_PARAMETER(hInsContext);

	if (strcmp(pParamName, "X_RDK_LatencyMeasure_TCP_ReportInterval") == 0)
	{
		if (!LowLatency_Get_Parameter_Struct_Value(LL_TCP_REPORTINTERVAL, puLong)) {
			CcspTraceError(("%s for parameter '%s' failed.\n", __FUNCTION__, pParamName));
			return FALSE;
		}
		return TRUE;
	}
    
	CcspTraceWarning(("Unsupported parameter '%s'\n", pParamName));
    return FALSE;
}
 
BOOL
LatencyMeasure_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pParamName,
        ULONG                       uValue
    )
{
	UNREFERENCED_PARAMETER(hInsContext);

	if (strcmp(pParamName, "X_RDK_LatencyMeasure_TCP_ReportInterval") == 0)
    {
		if ((uValue < 1) || (uValue > 1440))
		{
			CcspTraceError(("%s result:FAIL value not in range, pParamName='%s'\n", __FUNCTION__, pParamName));
			return FALSE;
		}
		if (0 != LowLatency_Set_TCP_ReportInterval(uValue)) {
			CcspTraceError(("%s result: value set failed, pParamName='%s'\n", __FUNCTION__, pParamName));

			return FALSE;
		}
		return TRUE;
    }

	CcspTraceWarning(("Unsupported parameter '%s'\n", pParamName));

    return FALSE;
}


LONG
LatencyMeasure_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
	UNREFERENCED_PARAMETER(hInsContext);
	UNREFERENCED_PARAMETER(pUlSize);
	UNREFERENCED_PARAMETER(pValue);

	CcspTraceWarning(("%s:Unsupported parameter '%s'\n", __FUNCTION__, pParamName));
    return -1;
}


BOOL
LatencyMeasure_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
	
    if (strcmp(pParamName, "X_RDK_LatencyMeasure_TCP_Stats_Report") == 0)
    {
        if (0 != LowLatency_Set_TCP_Stats_Report(pString))
        {
			CcspTraceError(("%s for parameter '%s' failed.\n", __FUNCTION__, pParamName));
			return FALSE;
		}
        return TRUE;
    }

	CcspTraceWarning(("%s:Unsupported parameter '%s'\n", __FUNCTION__, pParamName));
    return FALSE;
}