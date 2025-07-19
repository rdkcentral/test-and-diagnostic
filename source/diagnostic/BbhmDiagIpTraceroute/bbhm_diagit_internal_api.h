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

    module:     bbhm_diagit_internal_api.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the internal functions provided by the Bbhm IpPing Diagnostic
        Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Du Li, Li Shi

    ---------------------------------------------------------------

    revision:

        2009/07/30    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGIT_INTERNAL_API_
#define  _BBHM_DIAGIT_INTERNAL_API_


/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGIT_STATES.C
***********************************************************/

ANSC_STATUS
BbhmDiagitCopyDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

ANSC_STATUS
BbhmDiagitReset
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitGetProperty
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                    hProperty
    );

ANSC_STATUS
BbhmDiagitSetProperty
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                    hProperty
    );

ULONG
BbhmDiagitGetSrcIpType
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetSrcIpType
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulType
    );

ULONG
BbhmDiagitGetDstIpType
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetDstIpType
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulType
    );

PUCHAR
BbhmDiagitGetSrcIp
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetSrcIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                        IpAddr
    );

PUCHAR
BbhmDiagitGetDstIp
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetDstIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                        IpAddr
    );

ULONG
BbhmDiagitGetNumPkts
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetNumPkts
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulNumPkts
    );

ULONG
BbhmDiagitGetPktSize
    (
        ANSC_HANDLE                 hThisObject
    );


ANSC_STATUS
BbhmDiagitSetPktSize
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulPktSize
    );

ULONG
BbhmDiagitGetTimeBetween
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetTimeBetween
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulTimeOut
    );

ULONG
BbhmDiagitGetTimeOut
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetTimeOut
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulTimeOut
    );

ULONG
BbhmDiagitGetControl
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetControl
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulControl
    );

ULONG
BbhmDiagitGetStatus
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetStatus
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulStatus
    );

ULONG
BbhmDiagitGetPktsSent
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetPktsSent
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulPktsSent
    );

ULONG
BbhmDiagitGetPktsRecv
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetPktsRecv
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulPktsRecv
    );

ULONG
BbhmDiagitGetAvgRTT
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetAvgRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulRTT
    );

ULONG
BbhmDiagitGetMaxRTT
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetMaxRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulRTT
    );

ULONG
BbhmDiagitGetMinRTT
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetMinRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulRTT
    );

ULONG
BbhmDiagitGetNumIcmpError
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetNumIcmpError
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulThroughput
    );

ULONG
BbhmDiagitGetIcmpError
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetIcmpError
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulThroughput
    );

ULONG
BbhmDiagitGetTtl
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetTtl
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       Ttl
    );

ANSC_STATUS
BbhmDiagitSetStateUpdated
    (
        ANSC_HANDLE                 hThisObject,
        BOOL                        StateUpdated
    );

BOOL
BbhmDiagitGetStateUpdated
    (
        ANSC_HANDLE                 hThisObject
    );

ULONG
BbhmDiagitGetDstIpVal
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetDstIpVal
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       IpVal
    );

char*
BbhmDiagitGetDstAddrName
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitResetProperty
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitResetPropertyCounter
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

/***********************************************************
     FUNCTIONS IMPLEMENTED IN BBHM_DIAGIT_PROCESS.C
***********************************************************/

ANSC_STATUS
BbhmDiagitStartDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitStopDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitResultQueryTask
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitAccept
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hNewSocket
    );

ANSC_STATUS
BbhmDiagitRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                    hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    );

ANSC_STATUS
BbhmDiagitSend
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                    hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    );

/***********************************************************
       FUNCTIONS IMPLEMENTED IN BBHM_DIAGIT_OPERATION.C
***********************************************************/
ANSC_STATUS
BbhmDiagitOpen
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitStart
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSendEcho
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitStop
    (
        ANSC_HANDLE                 hThisObject
    );

ULONG
BbhmDiagitResolveHost
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hHostName
    );

PUCHAR
BbhmDiagitResolveHostName
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       IpAddr
    );

ANSC_STATUS
BbhmDiagitExpire1
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitExpire2
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitClose
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSetStopTime
    (
        ANSC_HANDLE                    hThisObject,
        USHORT                        SeqNumber,
        ULONG                        StopTime
    );

ANSC_STATUS
BbhmDiagitAddEchoEntry
    (
        ANSC_HANDLE                  hThisObject,
        USHORT                       SeqNumber,
        ULONG                        StartTime,
        ULONG                        TimeToLive
    );

ANSC_STATUS
BbhmDiagitCalculateResult
    (
        ANSC_HANDLE                    hThisObject
    );

ANSC_STATUS
BbhmDiagitUpdateEntry
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       seqId,
        xskt_addrinfo*              pHopAddrInfo,
        ULONG                       StopTime,
        ULONG                       ErrorCode
    );

ANSC_STATUS
BbhmDiagitSetDiagInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

ANSC_HANDLE
BbhmDiagitGetDiagInfo
    (
        ANSC_HANDLE                 hThisObject
    );

/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGIT_SINK_BASE.C
***********************************************************/

ANSC_HANDLE
BbhmDiagitSinkCreate
    (
        ANSC_HANDLE                 hOwnerContext
    );

ANSC_STATUS
BbhmDiagitSinkRemove
    (
        ANSC_HANDLE                 hThisObject
    );



/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGIT_SINK_OPERATION.C
***********************************************************/

PVOID
BbhmDiagitSinkGetRecvBuffer
    (
        ANSC_HANDLE                 hThisObject,
        PANSC_HANDLE                phRecvHandle,
        PULONG                      pulSize
    );

ANSC_STATUS
BbhmDiagitSinkAccept
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hNewSocket
    );

ANSC_STATUS
BbhmDiagitSinkRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hRecvHandle,
        PVOID                       buffer,
        ULONG                       ulSize
    );

ANSC_STATUS
BbhmDiagitSinkClose
    (
        ANSC_HANDLE                 hThisObject,
        BOOL                        bByPeer
    );

ANSC_STATUS
BbhmDiagitSinkAbort
    (
        ANSC_HANDLE                 hThisObject
    );



/***********************************************************
       FUNCTIONS IMPLEMENTED IN BBHM_DIAGIT_SINK_STATES.C
***********************************************************/

ANSC_HANDLE
BbhmDiagitSinkGetSocket
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSinkSetSocket
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket
    );

ANSC_STATUS
BbhmDiagitSinkAttach
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket
    );

ANSC_STATUS
BbhmDiagitSinkDetach
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitSinkReset
    (
        ANSC_HANDLE                 hThisObject
    );


/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGIT_TDO_BASE.C
***********************************************************/

ANSC_HANDLE
BbhmDiagitTdoCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );

ANSC_STATUS
BbhmDiagitTdoRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitTdoEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitTdoInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGIT_TDO_OPERATION.C
***********************************************************/

ANSC_STATUS
BbhmDiagitTdoInvoke
    (
        ANSC_HANDLE                 hThisObject
    );

ULONG
BbhmDiagitTdoGetStopTime
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitTdoSetStopTime
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulStopTime
    );

ULONG
BbhmDiagitTdoGetCounter
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagitTdoSetCounter
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulCounter
    );

#endif
