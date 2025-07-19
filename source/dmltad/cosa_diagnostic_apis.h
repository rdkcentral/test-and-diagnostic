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

/**************************************************************************

    module: cosa_diagnostic_apis.h

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file defines the apis for diagnostic related
        objects to support Data Model Library.

    -------------------------------------------------------------------


    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**************************************************************************/


#ifndef  _COSA_DIAGNOSTIC_APIS_H
#define  _COSA_DIAGNOSTIC_APIS_H

#include "cosa_apis.h"
#include "dslh_definitions_tr143.h"

/***********************************
    Actual definition declaration
************************************/

/**********************************
    NSLookup Diagnostic Part
***********************************/

#define   COSA_DML_DIAG_ARP_TABLE_ACCESS_INTERVAL   60 /* seconds*/

typedef  struct
_COSA_DML_DIAG_ARP_TABLE
{
    UCHAR                           IPAddress[40];  /* IPv4 or IPv4 string address */
    UCHAR                           MACAddress[6];
    BOOLEAN                         Static;
}
COSA_DML_DIAG_ARP_TABLE,  *PCOSA_DML_DIAG_ARP_TABLE;

typedef  struct
_COSA_DML_DIAG_SPEEDTEST_SERVER
{
    BOOLEAN                           Capability;
    UCHAR                           Key[1024];
    UCHAR                           Username[13];
    UCHAR                           Password[13];
}
COSA_DML_DIAG_SPEEDTEST_SERVER,*PCOSA_DML_DIAG_SPEEDTEST_SERVER;

#define RXTX_INTFLIST_SZ 256
#define RXTX_PORTLIST_SZ 256
typedef  struct
_COSA_DML_DIAG_RXTX_STATS
{
    UCHAR                           Interfacelist[RXTX_INTFLIST_SZ];
    UCHAR                           Portlist[RXTX_PORTLIST_SZ];
}
COSA_DML_DIAG_RXTX_STATS,*PCOSA_DML_DIAG_RXTX_STATS;

/*******************************************************
    NSLookup Diagnostic Manager Object Definition
********************************************************/

#define  COSA_DATAMODEL_DIAG_CLASS_CONTENT                                                  \
    /* duplication of the base object class content */                                      \
    COSA_BASE_CONTENT                                                                       \
    /* start of Diagnostic object class content */                                          \
    ANSC_HANDLE                 hDiagPingInfo;                                              \
    ANSC_HANDLE                 hDiagTracerouteInfo;                                        \
    ANSC_HANDLE                 hDiagNSLookInfo;                                            \
    ANSC_HANDLE                 hDiagDownloadInfo;                                          \
    ANSC_HANDLE                 hDiagUploadInfo;                                            \
    ANSC_HANDLE                 hDiagUdpechoSrvInfo;                                        \
    ULONG                       PreviousVisitTime;                                    \
    ULONG                       ArpEntryCount;                                    \
    PCOSA_DML_DIAG_ARP_TABLE    pArpTable;                                        \
    PCOSA_DML_DIAG_SPEEDTEST_SERVER    pSpeedTestServer;                                    \
    PCOSA_DML_DIAG_RXTX_STATS   pRxTxStats;                                                 \
    /* end of Diagnostic object class content */                                                    \

typedef  struct
_COSA_DATAMODEL_DIAG
{
    COSA_DATAMODEL_DIAG_CLASS_CONTENT
}
COSA_DATAMODEL_DIAG,  *PCOSA_DATAMODEL_DIAG;


/**********************************
    Standard function declaration
***********************************/
ANSC_HANDLE
CosaDiagCreate
    (
        VOID
    );

ANSC_STATUS
CosaDiagInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaDiagRemove
    (
        ANSC_HANDLE                 hThisObject
    );

/*************************************
    The actual function declaration
**************************************/
ANSC_STATUS
CosaDmlDiagScheduleDiagnostic
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hDiagInfo
    );

ANSC_STATUS
CosaDmlDiagCancelDiagnostic
    (
        ULONG                       ulDiagType
    );

ANSC_HANDLE
CosaDmlDiagGetResults
    (
        ULONG                       ulDiagType
    );

ANSC_HANDLE
CosaDmlDiagGetConfigs
    (
        ULONG                       ulDiagType
    );

ANSC_STATUS
CosaDmlDiagSetState
    (
        ULONG                       ulDiagType,
        ULONG                       ulDiagState
    );

#if !defined (RESOURCE_OPTIMIZATION)
PCOSA_DML_DIAG_ARP_TABLE
CosaDmlDiagGetARPTable
    (
        ANSC_HANDLE                 hContext,
        PULONG                      pulCount
    );

PCOSA_DML_DIAG_ARP_TABLE
CosaDmlDiagGetARPTablePriv

    (
        ANSC_HANDLE                 hContext,
        PULONG                      pulCount
    );
#endif

ANSC_STATUS CosaDmlInitializeRxTxStats
    (PCOSA_DML_DIAG_RXTX_STATS pRxTxStats);
#endif

