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

    module:     bbhm_diagip_internal_api.h

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

        Ding Hua, Li Shi

    ---------------------------------------------------------------

    revision:

        2007/02/08    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGIP_INTERNAL_API_
#define  _BBHM_DIAGIP_INTERNAL_API_


/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGIP_STATES.C
***********************************************************/

ANSC_STATUS
BbhmDiagipCopyDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

ANSC_STATUS
BbhmDiagipReset
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipGetProperty
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    );

ANSC_STATUS
BbhmDiagipSetProperty
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    );

ULONG
BbhmDiagipGetSrcIpType
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetSrcIpType
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulType
    );

ULONG
BbhmDiagipGetDstIpType
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetDstIpType
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulType
    );

PUCHAR
BbhmDiagipGetSrcIp
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetSrcIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      IpAddr
    );

PUCHAR
BbhmDiagipGetDstIp
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetDstIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      IpAddr
    );

ULONG
BbhmDiagipGetNumPkts
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetNumPkts
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulNumPkts
    );

ULONG
BbhmDiagipGetPktSize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetPktSize
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktSize
    );

ULONG
BbhmDiagipGetTimeBetween
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetTimeBetween
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulTimeOut
    );

ULONG
BbhmDiagipGetTimeOut
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetTimeOut
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulTimeOut
    );

ULONG
BbhmDiagipGetControl
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetControl
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulControl
    );

ULONG
BbhmDiagipGetStatus
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetStatus
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulStatus
    );

ULONG
BbhmDiagipGetPktsSent
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetPktsSent
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktsSent
    );

ULONG
BbhmDiagipGetPktsRecv
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetPktsRecv
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktsRecv
    );

ULONG
BbhmDiagipGetAvgRTT
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetAvgRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulRTT
    );

ULONG
BbhmDiagipGetMaxRTT
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetMaxRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulRTT
    );

ULONG
BbhmDiagipGetMinRTT
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetMinRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulRTT
    );

ULONG
BbhmDiagipGetNumIcmpError
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetNumIcmpError
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulThroughput
    );

ULONG
BbhmDiagipGetIcmpError
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetIcmpError
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulThroughput
    );

ULONG
BbhmDiagipGetNumCalculate
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetNumCalculate
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulNumCalculate
    );

ULONG
BbhmDiagipGetSumRTT
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetSumRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulRTT
    );

ANSC_STATUS
BbhmDiagipResetProperty
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipReset
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipResetPropertyCounter
    (
        ANSC_HANDLE                 hThisObject
    );

CHAR*
BbhmDiagipGetMiddleResult
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

/***********************************************************
     FUNCTIONS IMPLEMENTED IN BBHM_DIAGIP_PROCESS.C
***********************************************************/

ANSC_STATUS
BbhmDiagipStartDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipStopDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipResultQueryTask
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipAccept
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hNewSocket
    );

ANSC_STATUS
BbhmDiagipRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    );

ANSC_STATUS
BbhmDiagipSend
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    );

/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGIP_OPERATION.C
***********************************************************/

ANSC_STATUS
BbhmDiagipOpen
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipStart
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagResolvAddr
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipStop
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipExpire1
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipExpire2
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipClose
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSetStopTime
    (
        ANSC_HANDLE                    hThisObject,
        USHORT                        SeqNumber,
        ULONG                        PktSize,
        UCHAR                        TTL,
        ULONG                        StopTime
    );

ANSC_STATUS
BbhmDiagipAddEchoEntry
    (
        ANSC_HANDLE                    hThisObject,
        USHORT                        SeqNumber,
        ULONG                        StartTime
    );

ANSC_STATUS
BbhmDiagipCalculateResult
    (
        ANSC_HANDLE                    hThisObject
    );

ANSC_STATUS
BbhmDiagipSetEnv
    (
        ANSC_HANDLE                    hThisObject
    );

/***********************************************************
      FUNCTIONS IMPLEMENTED IN DSLM_DIAGIP_SINK_BASE.C
***********************************************************/

ANSC_HANDLE
BbhmDiagipSinkCreate
    (
        ANSC_HANDLE                 hOwnerContext
    );

ANSC_STATUS
BbhmDiagipSinkRemove
    (
        ANSC_HANDLE                 hThisObject
    );



/***********************************************************
      FUNCTIONS IMPLEMENTED IN DSLM_DIAGIP_SINK_OPERATION.C
***********************************************************/

PVOID
BbhmDiagipSinkGetRecvBuffer
    (
        ANSC_HANDLE                 hThisObject,
        PANSC_HANDLE                phRecvHandle,
        PULONG                      pulSize
    );

ANSC_STATUS
BbhmDiagipSinkAccept
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hNewSocket
    );

ANSC_STATUS
BbhmDiagipSinkRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hRecvHandle,
        PVOID                       buffer,
        ULONG                       ulSize
    );

ANSC_STATUS
BbhmDiagipSinkClose
    (
        ANSC_HANDLE                 hThisObject,
        BOOL                        bByPeer
    );

ANSC_STATUS
BbhmDiagipSinkAbort
    (
        ANSC_HANDLE                 hThisObject
    );



/***********************************************************
       FUNCTIONS IMPLEMENTED IN DSLM_DIAGIP_SINK_STATES.C
***********************************************************/

ANSC_HANDLE
BbhmDiagipSinkGetXsocket
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSinkSetXsocket
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket
    );

ANSC_STATUS
BbhmDiagipSinkAttach
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket
    );

ANSC_STATUS
BbhmDiagipSinkDetach
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipSinkReset
    (
        ANSC_HANDLE                 hThisObject
    );


/***********************************************************
      FUNCTIONS IMPLEMENTED IN DSLM_DIAGIP_TDO_BASE.C
***********************************************************/

ANSC_HANDLE
BbhmDiagipTdoCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );

ANSC_STATUS
BbhmDiagipTdoRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipTdoEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipTdoInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

/***********************************************************
      FUNCTIONS IMPLEMENTED IN DSLM_DIAGIP_TDO_OPERATION.C
***********************************************************/

ANSC_STATUS
BbhmDiagipTdoInvoke
    (
        ANSC_HANDLE                 hThisObject
    );

ULONG
BbhmDiagipTdoGetStopTime
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipTdoSetStopTime
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulStopTime
    );

ULONG
BbhmDiagipTdoGetCounter
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiagipTdoSetCounter
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulCounter
    );

#endif
