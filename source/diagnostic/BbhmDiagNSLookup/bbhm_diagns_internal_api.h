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

    module:     bbhm_diagns_internal_api.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the internal functions provided by the Bbhm NSLookup Diagnostic
        Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Ding Hua

    ---------------------------------------------------------------

    revision:

        2007/02/08    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGNS_INTERNAL_API_
#define  _BBHM_DIAGNS_INTERNAL_API_


/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGNS_STATES.C
***********************************************************/

ANSC_STATUS
BbhmDiagnsReset
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsSetControl
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulControl
    );

ANSC_STATUS
BbhmDiagnsResetPropertyCounter
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsSetStatus
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulStatus
    );

PUCHAR
BbhmDiagnsGetDstIp
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsSetDstIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      Dst
    );

ANSC_STATUS
BbhmDiagnsCopyDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

ULONG
BbhmDiagnsGetNumPkts
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsSetNumPkts
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulNumPkts
    );

ULONG
BbhmDiagnsGetTimeOut
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsSetTimeOut
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulTimeOut
    );

PUCHAR
BbhmDiagnsGetSrcIp
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsSetSrcIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      Interface
    );

ULONG
BbhmDiagnsGetPktsSent
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsSetPktsSent
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktsSent
    );

ANSC_STATUS
BbhmDiagnsResetProperty
    (
        ANSC_HANDLE                 hThisObject
    );

ULONG
BbhmDiagnsGetStatus
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsSetDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGNS_OPERATION.C
***********************************************************/

ANSC_STATUS
BbhmDiagnsStart
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsStop
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsExpire1
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsExpire2
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsAddEchoEntry
    (
        ANSC_HANDLE                 hThisObject,
        char*                       DstIpName,
        USHORT                      Index,
        ULONG                       StartTime
    );

ANSC_STATUS
BbhmDiagnsPopEchoEntry
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsOpen
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsAddPquery
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hPquery
    );

ANSC_HANDLE
BbhmDiagnsGetPqueryById
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                      id
    );

ANSC_STATUS
BbhmDiagnsDelPquery
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hPquery
    );

ANSC_STATUS
BbhmDiagnsDelAllPqueries
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsSetStopTime
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 pQuery,
        ANSC_HANDLE                 hDnsHeader,
        ULONG                       StopTime
    );

ANSC_STATUS
BbhmDiagnsClose
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsCalculateResult
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       Num
    );


/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGNS_PROCESS.C
***********************************************************/

ANSC_STATUS
BbhmDiagnsStartDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsStopDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hXsinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    );

ANSC_STATUS
BbhmDiagnsSend
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hXsinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    );


/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGNS_XSINK_BASE.C
***********************************************************/

ANSC_HANDLE
BbhmDiagnsXsinkCreate
    (
        ANSC_HANDLE                 hOwnerContext
    );

ANSC_STATUS
BbhmDiagnsXsinkRemove
    (
        ANSC_HANDLE                 hThisObject
    );



/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGNS_XSINK_OPERATION.C
***********************************************************/

PVOID
BbhmDiagnsXsinkGetRecvBuffer
    (
        ANSC_HANDLE                 hThisObject,
        PANSC_HANDLE                phRecvHandle,
        PULONG                      pulSize
    );

ANSC_STATUS
BbhmDiagnsXsinkAccept
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hNewSocket
    );

ANSC_STATUS
BbhmDiagnsXsinkRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hRecvHandle,
        PVOID                       buffer,
        ULONG                       ulSize
    );

ANSC_STATUS
BbhmDiagnsXsinkClose
    (
        ANSC_HANDLE                 hThisObject,
        BOOL                        bByPeer
    );

ANSC_STATUS
BbhmDiagnsXsinkAbort
    (
        ANSC_HANDLE                 hThisObject
    );



/***********************************************************
       FUNCTIONS IMPLEMENTED IN BBHM_DIAGNS_XSINK_STATES.C
***********************************************************/

ANSC_HANDLE
BbhmDiagnsXsinkGetXsocket
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsXsinkSetXsocket
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket
    );

ANSC_STATUS
BbhmDiagnsXsinkAttach
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket
    );

ANSC_STATUS
BbhmDiagnsXsinkDetach
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsXsinkReset
    (
        ANSC_HANDLE                 hThisObject
    );


/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGNS_TDO_BASE.C
***********************************************************/

ANSC_HANDLE
BbhmDiagnsTdoCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );

ANSC_STATUS
BbhmDiagnsTdoRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsTdoEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsTdoInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_IPPING_TDO_OPERATION.C
***********************************************************/

ANSC_STATUS
BbhmDiagnsTdoInvoke
    (
        ANSC_HANDLE                 hThisObject
    );

ULONG
BbhmDiagnsTdoGetStopTime
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsTdoSetStopTime
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulStopTime
    );

ULONG
BbhmDiagnsTdoGetCounter
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagnsTdoSetCounter
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulCounter
    );

#endif

