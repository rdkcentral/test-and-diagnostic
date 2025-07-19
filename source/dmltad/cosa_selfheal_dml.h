/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

#ifndef  _COSA_SELFHEAL_DML_H
#define  _COSA_SELFHEAL_DML_H


/***********************************************************************

 APIs for Object:

    SelfHeal.


***********************************************************************/
/***********************************************************************

 APIs for Object:

    SelfHeal.ConnectivityTest.

    *  ConnectivityTest_GetParamUlongValue
    *  ConnectivityTest_SetParamUlongValue
    *  ConnectivityTest_GetParamIntValue
    *  ConnectivityTest_SetParamIntValue
    *  ConnectivityTest_Validate
    *  ConnectivityTest_Commit
    *  ConnectivityTest_Rollback

***********************************************************************/

BOOL
ConnectivityTest_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

BOOL
ConnectivityTest_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
ConnectivityTest_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
ConnectivityTest_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         pInt
    );

BOOL
ConnectivityTest_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
ConnectivityTest_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
ConnectivityTest_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    SelfHeal.ConnectivityTest.PingServerList.IPv4PingServerTable.{i}.

    *  IPv4PingServerTable_GetEntryCount
    *  IPv4PingServerTable_GetEntry
    *  IPv4PingServerTable_IsUpdated
    *  IPv4PingServerTable_Synchronize
    *  IPv4PingServerTable_AddEntry
    *  IPv4PingServerTable_DelEntry
    *  IPv4PingServerTable_GetParamStringValue
    *  IPv4PingServerTable_SetParamStringValue
    *  IPv4PingServerTable_Validate
    *  IPv4PingServerTable_Commit
    *  IPv4PingServerTable_Rollback

***********************************************************************/

ULONG
IPv4PingServerTable_GetEntryCount
    (
        ANSC_HANDLE
    );

ANSC_HANDLE
IPv4PingServerTable_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

BOOL
IPv4PingServerTable_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
IPv4PingServerTable_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    );

ANSC_HANDLE
IPv4PingServerTable_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    );

ULONG
IPv4PingServerTable_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    );

ULONG
IPv4PingServerTable_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
IPv4PingServerTable_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
IPv4PingServerTable_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
IPv4PingServerTable_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
IPv4PingServerTable_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    SelfHeal.ConnectivityTest.PingServerList.IPv6PingServerTable.{i}.

    *  IPv6PingServerTable_GetEntryCount
    *  IPv6PingServerTable_GetEntry
    *  IPv6PingServerTable_IsUpdated
    *  IPv6PingServerTable_Synchronize
    *  IPv6PingServerTable_AddEntry
    *  IPv6PingServerTable_DelEntry
    *  IPv6PingServerTable_GetParamStringValue
    *  IPv6PingServerTable_SetParamStringValue
    *  IPv6PingServerTable_Validate
    *  IPv6PingServerTable_Commit
    *  IPv6PingServerTable_Rollback

***********************************************************************/

ULONG
IPv6PingServerTable_GetEntryCount
    (
        ANSC_HANDLE
    );

ANSC_HANDLE
IPv6PingServerTable_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

BOOL
IPv6PingServerTable_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
IPv6PingServerTable_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    );

ANSC_HANDLE
IPv6PingServerTable_AddEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      pInsNumber
    );

ULONG
IPv6PingServerTable_DelEntry
    (
        ANSC_HANDLE                 hInsContext,
        ANSC_HANDLE                 hInstance
    );

ULONG
IPv6PingServerTable_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
IPv6PingServerTable_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
IPv6PingServerTable_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
IPv6PingServerTable_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
IPv6PingServerTable_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
CpuMemFrag_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );

ANSC_HANDLE
CpuMemFrag_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

ULONG
CpuMemFrag_GetParamStringValue
		(
				ANSC_HANDLE 	hInsContext,
				char* 			ParamName,
				char* 			pValue,
				ULONG*			pUlSize
		);
BOOL
CpuMemFrag_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLen
    );

/***********************************************************************
 APIs for Object:

    SelfHeal.CPUProcAnalyzer.

    *  CPUProcAnalyzer_GetParamUlongValue
    *  CPUProcAnalyzer_SetParamUlongValue
    *  CPUProcAnalyzer_GetParamBoolValue
    *  CPUProcAnalyzer_SetParamBoolValue
    *  CPUProcAnalyzer_GetParamStringValue
    *  CPUProcAnalyzer_SetParamStringValue
***********************************************************************/

BOOL
CPUProcAnalyzer_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       bValue
    );

BOOL
CPUProcAnalyzer_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
CPUProcAnalyzer_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );

BOOL
CPUProcAnalyzer_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    );

ULONG
CPUProcAnalyzer_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
CPUProcAnalyzer_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

#endif
