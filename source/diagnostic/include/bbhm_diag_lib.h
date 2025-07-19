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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/**********************************************************************

    module: bbhm_diagns_lib.h

        For Advanced Networking Service Container (ANSC),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines the exported apis for SNMP plugin.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        06/25/03    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGNS_LIB_H
#define  _BBHM_DIAGNS_LIB_H


#define ANSC_EXPORT_API

#ifdef __cplusplus 
extern "C"{
#endif

#include "cosa_plugin_api.h"

extern COSAGetParamValueStringProc        g_GetParamValueString;
extern COSANotifyDiagCompleteProc         g_NotifyDiagComplete;

typedef ANSC_STATUS
(* CosaDiagExportFuncProc)
    (
        ULONG                       uVersion, 
        void*                       hCosaPlugInfo       
    );   

typedef ANSC_HANDLE
(* CosaDiagGetConfigsProc)
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext
    );

typedef ANSC_HANDLE
(* CosaDiagGetResultsProc)
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext
    );

typedef ANSC_STATUS
(* CosaDiagScheduleDiagnosticProc)
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext,
        ANSC_HANDLE                 hDiagInfo
    );

typedef ANSC_STATUS
(* CosaDiagSetDiagParamsProc)
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext,
        ANSC_HANDLE                 hDiagInfo
    );

typedef  ANSC_STATUS
(* CosaDiagSetDiagStateProc)
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext,
        ULONG                       ulDiagState
    );

typedef ANSC_STATUS
(* CosaDiagCancelDiagnosticProc)
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext
    );

typedef ANSC_STATUS
(* CosaDiagMemoryUsageProc)
    (
        void
    );

typedef ANSC_STATUS
(* CosaDiagMemoryTableProc)
    (
        void
    );

typedef ANSC_STATUS
(* COSADiagInitProc)
    (
        void * hMessageBus
    );

typedef void
(* COSADiagUnloadProc)
    (
        void
    );

typedef struct 
_COSA_DIAG_PLUGIN_INFO
{
    ULONG                           uPluginVersion;
    ULONG                           uLoadStatus;
    COSADiagInitProc                InitProc;
    COSADiagUnloadProc              UnloadProc;
    CosaDiagGetResultsProc          GetResultsProc;
    CosaDiagScheduleDiagnosticProc  ScheduleDiagnosticProc;
    CosaDiagSetDiagParamsProc       SetDiagParamsProc;
    CosaDiagSetDiagStateProc        SetDiagStateProc;
    CosaDiagCancelDiagnosticProc    CancelDiagnosticProc;
    CosaDiagMemoryUsageProc         MemoryUsageProc;
    CosaDiagMemoryTableProc         MemoryTableProc;
    CosaDiagGetConfigsProc          GetConfigsProc;
    CosaDiagExportFuncProc          ExportFuncProc;
}
COSA_DIAG_PLUGIN_INFO,  *PCOSA_DIAG_PLUGIN_INFO;


/***************************************************************************
 *
 *  BMEL stands for "Broadway Diagnostic Dynamic Library"
 *
 ***************************************************************************/
ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_Init
    (
        void * hMessageBus
    );


ANSC_HANDLE ANSC_EXPORT_API
COSA_Diag_GetResults
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext
    );

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_ScheduleDiagnostic
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext,
        ANSC_HANDLE                 hDiagInfo
    );

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_SetDiagParams
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext,
        ANSC_HANDLE                 hDiagInfo
    );

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_SetDiagState
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext,
        ULONG                       ulDiagState
    );

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_CancelDiagnostic
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext
    );

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_MemoryUsage
    (
        void
    );

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_MemoryTable
    (
        void
    );

void ANSC_EXPORT_API
COSA_Diag_Unload
    (
        void
    );

ANSC_HANDLE ANSC_EXPORT_API
COSA_Diag_GetConfigs
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext
    );

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_ExportFunc
    (
        ULONG                       uVersion, 
        void*                       hCosaPlugInfo       
    );     

ANSC_STATUS
CosaSendDiagCompleteSignal
	(
		void
	);

#ifdef __cplusplus 
}
#endif

#endif
