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

    module:    bbhm_diagip_operation.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced operation functions
        of the Pingection Speed Tool Object.

        *    BbhmDiagipStart
        *    BbhmDiagipOpen
        *    BbhmDiagipStop
        *    BbhmDiagipClose
        *    BbhmDiagipExpire1
        *    BbhmDiagipExpire2
        *    BbhmDiagipSetStopTime
        *    BbhmDiagipAddEchoEntry
        *    BbhmDiagipCalculateResult
        *    BbhmDiagipSetEnv

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Li Shi

    ---------------------------------------------------------------

    revision:

        08/08/09    initial revision.

**********************************************************************/


#include "bbhm_diagip_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipStart
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to send the packets.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipStart
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PDSLH_PING_INFO                 pDiagInfo    = (PDSLH_PING_INFO)pMyObject->hDslhDiagInfo;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY  )&pMyObject->Property;
    PBBHM_IP_PING_TDO_OBJECT        pStateTimer  = (PBBHM_IP_PING_TDO_OBJECT)pMyObject->hStateTimer;
    PBBHM_IP_PING_SINK_OBJECT       pSink        = (PBBHM_IP_PING_SINK_OBJECT)pMyObject->hSinkObject;
    PANSC_XSOCKET_OBJECT            pSocket      = (PANSC_XSOCKET_OBJECT     )pSink->GetXsocket((ANSC_HANDLE)pSink);
    ULONG                           pktSize      = pProperty->PktSize;
    PCHAR                           pSendBuffer  = pMyObject->hSendBuffer;
    ULONG                           i            = 0;
    PICMPV4_ECHO_MESSAGE            pIcmpHeaderIpv4  = NULL;
    PICMPV6_ECHO_MESSAGE            pIcmpHeaderIpv6  = NULL;
    ULONG                           StartTime    = 0;
    
    if ( !pMyObject->bActive )
    {
        pProperty->Status = BBHM_IP_PING_STATUS_ABORT;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    pMyObject->ResetPropertyCounter((ANSC_HANDLE)pMyObject);

    pSocket->SetPeerName     ((ANSC_HANDLE)pSocket, pProperty->pDstAddrName);
    pSocket->SetHostName     ((ANSC_HANDLE)pSocket, pProperty->pSrcAddrName);
    /*
    pSocket->SetHostAddress  ((ANSC_HANDLE)pSocket, SrcIp                 );
    pSocket->SetHostPort     ((ANSC_HANDLE)pSocket, 0                     );
    */

    /*pSocket->SetTransportType((ANSC_HANDLE)pSocket, ICMP_TRANSPORT        );*/
    pSocket->SetType         ((ANSC_HANDLE)pSocket, ANSC_XSOCKET_TYPE_RAW );
    pSocket->SetMode         ((ANSC_HANDLE)pSocket, 0                     );

    pSocket->SetXsink        ((ANSC_HANDLE)pSocket, (ANSC_HANDLE)pSink    );

    /*
     * The underlying socket wrapper may require an explicit startup() call, such is the case on
     * Microsoft windows platforms. The wrapper initialization has to done for each task. On most
     * real-time operating systems, this call is not required.
     */
    AnscStartupXsocketWrapper((ANSC_HANDLE)pMyObject);

    /* For IPv4/IPv6 compatible purpose we shall resolve the address first */
	returnStatus = BbhmDiagResolvAddr(hThisObject);

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        pProperty->Status = BBHM_IP_PING_STATUS_ERROR_HostName;

        pMyObject->Stop(hThisObject);

        return ANSC_STATUS_FAILURE;
    }

    pMyObject->IPProtocol = pSocket->GetIpProtocol((ANSC_HANDLE)pSocket);

    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        pSocket->SetTransportType((ANSC_HANDLE)pSocket, IP4_PROTOCOL_ICMP);
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        pSocket->SetTransportType((ANSC_HANDLE)pSocket, IP6_PROTOCOL_ICMP);
    }
    else
    {
        pProperty->Status = BBHM_IP_PING_STATUS_ABORT;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    /*
     * We shall open the socket and listen on it right away. Since we're still in the context of
     * initialiation, the wrapper module must be aware of the fact that the socket is opened before
     * the first call returns.
     */
    returnStatus = pSocket->Bind((ANSC_HANDLE)pSocket);

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        pProperty->Status = BBHM_IP_PING_STATUS_ABORT;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    returnStatus = pSocket->Open((ANSC_HANDLE)pSocket); /* Create recv task */

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        AnscTrace("Socket Open Failed!\n");
        pProperty->Status = BBHM_IP_PING_STATUS_ABORT;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    if ( !pSendBuffer )
    {
        returnStatus = ANSC_STATUS_FAILURE;
        pProperty->Status = BBHM_IP_PING_STATUS_ABORT;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    /* Set DSCP */
    if ( pDiagInfo->DSCP != 0 )
    {
        pSocket->ApplyDSCP((ANSC_HANDLE)pSocket, pDiagInfo->DSCP);
    }

    AnscSleep(100);

    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        pIcmpHeaderIpv4 = (PICMPV4_ECHO_MESSAGE)pMyObject->hSendBuffer;

        AnscIcmpv4EchoSetType        (pIcmpHeaderIpv4, ICMP_TYPE_ECHO_REQUEST   );
        AnscIcmpv4EchoSetCode        (pIcmpHeaderIpv4, 0                        );
        AnscIcmpv4EchoSetId          (pIcmpHeaderIpv4, tempId                   );
        AnscIcmpv4EchoSetSeqNumber   (pIcmpHeaderIpv4, (USHORT)pMyObject->GetPktsSent((ANSC_HANDLE)pMyObject));

        for ( i = 0; i < pktSize; i++ )
        {
            ((PUCHAR)pMyObject->hSendBuffer)[i + sizeof(ICMPV4_HEADER)] = (UCHAR)i;
        }

        AnscIcmpv4EchoSetChecksum   (pIcmpHeaderIpv4, 0                                 );
        AnscIcmpv4CalculateChecksum (((PICMPV4_HEADER)pIcmpHeaderIpv4), pktSize + sizeof(ICMPV4_HEADER));
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        pIcmpHeaderIpv6 = (PICMPV6_ECHO_MESSAGE)pMyObject->hSendBuffer;

        AnscIcmpv6EchoSetType        (pIcmpHeaderIpv6, ICMP6_TYPE_ECHO_REQUEST  );
        AnscIcmpv6EchoSetCode        (pIcmpHeaderIpv6, 0                        );
        AnscIcmpv6EchoSetId          (pIcmpHeaderIpv6, tempId                   );
        AnscIcmpv6EchoSetSeqNumber   (pIcmpHeaderIpv6, (USHORT)pMyObject->GetPktsSent((ANSC_HANDLE)pMyObject));

        for ( i = 0; i < pktSize; i++ )
        {
            ((PUCHAR)pMyObject->hSendBuffer)[i + sizeof(ICMPV6_HEADER)] = (UCHAR)i;
        }
    }

    pStateTimer->SetTimerType((ANSC_HANDLE)pStateTimer, ANSC_TIMER_TYPE_SPORADIC);
    pStateTimer->SetInterval ((ANSC_HANDLE)pStateTimer, pProperty->TimeBetween  );
    pStateTimer->SetCounter  ((ANSC_HANDLE)pStateTimer, pProperty->NumPkts      );
/*
    pSocket->SetPeerAddress  ((ANSC_HANDLE)pSocket    , pProperty->DstIp.Dot    );
    pSocket->SetPeerPort     ((ANSC_HANDLE)pSocket    , 0                       );
*/
    pMyObject->SetStatus((ANSC_HANDLE)pMyObject, BBHM_IP_PING_STATUS_RUNNING);

    pStateTimer->Start       ((ANSC_HANDLE)pStateTimer);

    StartTime = AnscGetTickInMilliSeconds();

    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        returnStatus =
            pMyObject->AddEchoEntry
                (
                    (ANSC_HANDLE)pMyObject,
                    AnscIcmpv4EchoGetSeqNumber(pIcmpHeaderIpv4),
                    StartTime
                );

        returnStatus =
            pMyObject->Send
                (
                    (ANSC_HANDLE)pMyObject,
                    (ANSC_HANDLE)pMyObject->hSinkObject,
                    (PVOID)pMyObject->hSendBuffer,
                    pktSize + sizeof(ICMPV4_HEADER)
                );
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        returnStatus =
            pMyObject->AddEchoEntry
                (
                    (ANSC_HANDLE)pMyObject,
                    AnscIcmpv6EchoGetSeqNumber(pIcmpHeaderIpv6),
                    StartTime
                );

        returnStatus =
            pMyObject->Send
                (
                    (ANSC_HANDLE)pMyObject,
                    (ANSC_HANDLE)pMyObject->hSinkObject,
                    (PVOID)pMyObject->hSendBuffer,
                    pktSize + sizeof(ICMPV6_HEADER)
                );
    }

    pProperty->PktsSent++;

    return  returnStatus;

}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipOpen
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to open the socket and start the send task.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipOpen
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT       )hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY          )&pMyObject->Property;
    PBBHM_IP_PING_SINK_OBJECT       pSink        = NULL;
    PANSC_XSOCKET_OBJECT            pSocket      = NULL;
    
    if ( pMyObject->bActive )
    {
        return  ANSC_STATUS_SUCCESS;
    }

    if ( pProperty->Status == BBHM_IP_PING_STATUS_RUNNING )
    {
        return  ANSC_STATUS_FAILURE;
    }

    pSink = (PBBHM_IP_PING_SINK_OBJECT)BbhmDiagipSinkCreate((ANSC_HANDLE)pMyObject);

    if ( !pSink )
    {
        return  ANSC_STATUS_FAILURE;
    }

    pSocket =
        (PANSC_XSOCKET_OBJECT)AnscCreateXsocket
            (
                pMyObject->hContainerContext,
                (ANSC_HANDLE)pMyObject,
                (ANSC_HANDLE)NULL
            );

    if ( !pSocket )
    {
        pSink->Remove((ANSC_HANDLE)pSink);

        return  ANSC_STATUS_FAILURE;
    }
    else
    {
        pSink->SetXsocket((ANSC_HANDLE)pSink, (ANSC_HANDLE)pSocket);
    }

    pMyObject->hSinkObject    = pSink;

    pMyObject->ResetPropertyCounter((ANSC_HANDLE)pMyObject);

    pMyObject->bActive = TRUE;

    return  returnStatus;

}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipStop
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to abort the send task.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipStop
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT     )hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;
    PBBHM_IP_PING_TDO_OBJECT        pStateTimer  = (PBBHM_IP_PING_TDO_OBJECT      )pMyObject->hStateTimer;
    PBBHM_IP_PING_SINK_OBJECT       pSink        = (PBBHM_IP_PING_SINK_OBJECT     )pMyObject->hSinkObject;
    PANSC_XSOCKET_OBJECT            pSocket      = NULL;
    PDSLH_PING_INFO                 pDslhDiagInfo= (PDSLH_PING_INFO               )pMyObject->hDslhDiagInfo;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    PBBHM_IP_PING_ECHO_ENTRY        pMEchoEntry  = NULL;
    SLIST_HEADER                    MiddleResult;
    ULONG                           i            = 0;
    ULONG                           MaxRetrieve  = 10;
    ULONG                           nRead        = 0;

    if ( pMyObject->bActive )
    {
        ULONG                       ulMin = 0;
        ULONG                       ulMax = 0;
        ULONG                       ulSum = 0;
        ULONG                       ulTime;

        pStateTimer->Stop((ANSC_HANDLE)pStateTimer);
        pStateTimer->SetStopTime((ANSC_HANDLE)pStateTimer, AnscGetTickInMilliSeconds());

        returnStatus =
            pMyObject->CalculateResult
                (
                    (ANSC_HANDLE)pMyObject
                );

        for (i = 0; i < MaxRetrieve; i++)
        {
            AnscAcquireLock(&pMyObject->MiddleResultLock);
            MiddleResult = pMyObject->MiddleResult;
            AnscReleaseLock(&pMyObject->MiddleResultLock);
            if (MiddleResult.Depth == 0)
            {
                break;
            }
            AnscSleep(100);
        }

        AnscAcquireLock(&pMyObject->MiddleResultLock);

        nRead = pMyObject->MiddleResult.Depth;
        pSLinkEntry = AnscSListPopEntry(&pMyObject->MiddleResult);
        while ( pSLinkEntry )
        {
            pMEchoEntry = (PBBHM_IP_PING_ECHO_ENTRY)ACCESS_BBHM_IP_PING_ECHO_ENTRY(pSLinkEntry);
            pSLinkEntry = AnscSListPopEntry(&pMyObject->MiddleResult);

            ulTime = pMEchoEntry->StopTime - pMEchoEntry->StartTime;

            /* calculate min, max, sum */
            if ( ulSum == 0 )
            {
                ulMin = ulMax = ulSum = ulTime;
            }
            else
            {
                if ( ulMin > ulTime )
                {
                    ulMin = ulTime;
                }

                if ( ulMax < ulTime )
                {
                    ulMax = ulTime;
                }

                ulSum += ulTime;
            }

            AnscFreeMemory(pMEchoEntry);
        }

        AnscReleaseLock(&pMyObject->MiddleResultLock);

        if ( nRead != 0 )
        {
            pProperty->AvgRTT   = ulSum/nRead;
            pProperty->MinRTT   = ulMin;
            pProperty->MaxRTT   = ulMax;
        }

        if ( pSink )
        {
            pSocket = (PANSC_XSOCKET_OBJECT             )pSink->GetXsocket((ANSC_HANDLE)pSink);
            pSocket->Close((ANSC_HANDLE)pSocket);
        }
    }

    switch ( pMyObject->GetStatus((ANSC_HANDLE)pMyObject) )
    {
        case  BBHM_IP_PING_STATUS_COMPLETE:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Complete;

                break;

        case  BBHM_IP_PING_STATUS_ABORT:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_PING_Error_Internal;

                break;

        case  BBHM_IP_PING_STATUS_STOP:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Complete;

                break;

        case  BBHM_IP_PING_STATUS_ERROR_HostName:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Error_HostName;

                break;

        case  BBHM_IP_PING_STATUS_TIMEOUT:

                pMyObject->SetMaxRTT((ANSC_HANDLE)pMyObject, 0);
                pMyObject->SetMinRTT((ANSC_HANDLE)pMyObject, 0);
                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Complete;

                break;

        default:

                return  returnStatus;
    }

    pMyObject->bResultQueryRunning     = FALSE;
    pDslhDiagInfo->SuccessCount        = nRead;
    pDslhDiagInfo->FailureCount        = pProperty->PktsSent - nRead;
    pDslhDiagInfo->AverageResponseTime = pProperty->AvgRTT;
    pDslhDiagInfo->MinimumResponseTime = pProperty->MinRTT;
    pDslhDiagInfo->MaximumResponseTime = pProperty->MaxRTT;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipExpire1
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to abort the send task.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipExpire1
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT       )hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY          )&pMyObject->Property;
    ULONG                           pktSize      = pProperty->PktSize;
    PICMPV4_ECHO_MESSAGE            pIcmpHeaderIpv4  = NULL;
    PICMPV6_ECHO_MESSAGE            pIcmpHeaderIpv6  = NULL;
    /*USHORT                          oldSeqNumber = AnscIcmpv4EchoGetSeqNumber(pIcmpHeader);*/
    ULONG                           StartTime    = 0;
    /*
    AnscIcmpv4EchoSetSeqNumber(pIcmpHeader, AnscReadUshort(&pProperty->PktsSent));
    AnscIcmpv4UpdateChecksumUshort(pIcmpHeader, oldSeqNumber, AnscReadUshort(&pProperty->PktsSent));
*/
    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        pIcmpHeaderIpv4  = (PICMPV4_ECHO_MESSAGE)pMyObject->hSendBuffer;

        AnscIcmpv4EchoSetSeqNumber  (pIcmpHeaderIpv4, (USHORT)pMyObject->GetPktsSent((ANSC_HANDLE)pMyObject));

        AnscIcmpv4EchoSetChecksum   (pIcmpHeaderIpv4, 0                                                     );
        AnscIcmpv4CalculateChecksum (((PICMPV4_HEADER)pIcmpHeaderIpv4), pktSize + sizeof(ICMPV4_HEADER)     );

        StartTime = AnscGetTickInMilliSeconds();

        returnStatus =
            pMyObject->AddEchoEntry
                (
                    (ANSC_HANDLE)pMyObject,
                    AnscIcmpv4EchoGetSeqNumber(pIcmpHeaderIpv4),
                    StartTime
                );

        returnStatus =
            pMyObject->Send
                (
                    (ANSC_HANDLE)pMyObject,
                    (ANSC_HANDLE)pMyObject->hSinkObject,
                    (PVOID)pMyObject->hSendBuffer,
                    pktSize + sizeof(ICMPV4_HEADER)
                );
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        pIcmpHeaderIpv6  = (PICMPV6_ECHO_MESSAGE)pMyObject->hSendBuffer;

        AnscIcmpv6EchoSetSeqNumber  (pIcmpHeaderIpv6, (USHORT)pMyObject->GetPktsSent((ANSC_HANDLE)pMyObject));

        AnscIcmpv6EchoSetChecksum   (pIcmpHeaderIpv6, 0                                                     );

        StartTime = AnscGetTickInMilliSeconds();

        returnStatus =
            pMyObject->AddEchoEntry
                (
                    (ANSC_HANDLE)pMyObject,
                    AnscIcmpv6EchoGetSeqNumber(pIcmpHeaderIpv6),
                    StartTime
                );

        returnStatus =
            pMyObject->Send
                (
                    (ANSC_HANDLE)pMyObject,
                    (ANSC_HANDLE)pMyObject->hSinkObject,
                    (PVOID)pMyObject->hSendBuffer,
                    pktSize + sizeof(ICMPV6_HEADER)
                );
    }
    else
    {
        CcspTraceError(("IPProtocol error !!\n"));
    }

    pProperty->PktsSent++;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipExpire2
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to abort the send task.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipExpire2
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT     )hThisObject;
    
    pMyObject->SetStatus((ANSC_HANDLE)pMyObject, BBHM_IP_PING_STATUS_TIMEOUT);
    pMyObject->Stop((ANSC_HANDLE)pMyObject);

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipClose
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to close this object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipClose
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT     )hThisObject;
    PBBHM_IP_PING_SINK_OBJECT       pSink        = (PBBHM_IP_PING_SINK_OBJECT     )pMyObject->hSinkObject;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    PBBHM_IP_PING_ECHO_ENTRY        pEchoEntry   = NULL;
    ULONG                           i            = 0;

    if ( !pMyObject->bActive )
    {
        return  ANSC_STATUS_SUCCESS;
    }

    if ( pSink )
    {
        pSink->Detach((ANSC_HANDLE)pSink);
        pSink->Remove((ANSC_HANDLE)pSink);
        pMyObject->hSinkObject = NULL;
    }

    AnscAcquireLock(&pMyObject->EchoTableLock);

    for ( i = 0; i < MAX_ECHO_TABLE_SIZE; i ++ )
    {
        pSLinkEntry = AnscSListPopEntry(&pMyObject->EchoTable[i]);

        while ( pSLinkEntry )
        {
            pEchoEntry  = ACCESS_BBHM_IP_PING_ECHO_ENTRY(pSLinkEntry);
            pSLinkEntry = AnscSListPopEntry(&pMyObject->EchoTable[i]);

            AnscFreeMemory(pEchoEntry);
        }
    }

    AnscReleaseLock(&pMyObject->EchoTableLock);

    pMyObject->bActive = FALSE;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetStopTime
            (
                ANSC_HANDLE                 hThisObject,
                USHORT                        SeqNumber,
                ULONG                        StopTime
            );

    description:

        This function is called to close this object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipSetStopTime
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                      SeqNumber,
        ULONG                       PktSize,
        UCHAR                       TTL,
        ULONG                       StopTime
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_FAILURE;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    PBBHM_IP_PING_ECHO_ENTRY        pEchoEntry   = NULL;
    PBBHM_IP_PING_ECHO_ENTRY        pMEchoEntry  = NULL;
    ULONG                           ulHashIndex  = SeqNumber % MAX_ECHO_TABLE_SIZE;

    AnscAcquireLock(&pMyObject->EchoTableLock);
    pSLinkEntry = AnscSListGetFirstEntry(&pMyObject->EchoTable[ulHashIndex]);

    while ( pSLinkEntry )
    {
        pEchoEntry = (PBBHM_IP_PING_ECHO_ENTRY)ACCESS_BBHM_IP_PING_ECHO_ENTRY(pSLinkEntry);
        pSLinkEntry = AnscSListGetNextEntry(pSLinkEntry);

        if ( pEchoEntry->SeqId == SeqNumber )
        {
            if ( (StopTime - pEchoEntry->StartTime <= pProperty->TimeOut) && (pEchoEntry->StopTime == 0) )
            {
                returnStatus = ANSC_STATUS_SUCCESS;
                pEchoEntry->StopTime    = StopTime;
                pEchoEntry->TTL         = TTL;
                pEchoEntry->PktSize     = PktSize;
                pEchoEntry->ICMPType    = 0;
                pMEchoEntry = (PBBHM_IP_PING_ECHO_ENTRY)AnscAllocateMemory(sizeof(BBHM_IP_PING_ECHO_ENTRY));
                if ( pMEchoEntry )
                {
                    pMEchoEntry->StartTime = pEchoEntry->StartTime;
                    pMEchoEntry->StopTime  = pEchoEntry->StopTime;
                    pMEchoEntry->SeqId     = pEchoEntry->SeqId;
                    pMEchoEntry->PktSize   = pEchoEntry->PktSize;
                    pMEchoEntry->TTL       = pEchoEntry->TTL;
                    pMEchoEntry->ICMPType  = pEchoEntry->ICMPType;
                    AnscAcquireLock(&pMyObject->MiddleResultLock);
                    AnscSListPushEntryAtBack(&pMyObject->MiddleResult, &pMEchoEntry->Linkage);
                    AnscReleaseLock(&pMyObject->MiddleResultLock);
                }
            }

            break;
        }
    }

    AnscReleaseLock(&pMyObject->EchoTableLock);

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipAddEchoEntry
            (
                ANSC_HANDLE                 hThisObject,
                USHORT                        SeqNumber,
                ULONG                        StartTime
            );

    description:

        This function is called to close this object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipAddEchoEntry
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                      SeqNumber,
        ULONG                       StartTime
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT     )hThisObject;
    PBBHM_IP_PING_ECHO_ENTRY        pEchoEntry   = NULL;
    ULONG                           ulHashIndex  = SeqNumber % MAX_ECHO_TABLE_SIZE;

    pEchoEntry = (PBBHM_IP_PING_ECHO_ENTRY)AnscAllocateMemory(sizeof(BBHM_IP_PING_ECHO_ENTRY));
    if ( !pEchoEntry )
    {
        return  ANSC_STATUS_FAILURE;
    }

    pEchoEntry->SeqId     = SeqNumber;
    pEchoEntry->StartTime = StartTime;
    pEchoEntry->StopTime  = 0;

    AnscAcquireLock(&pMyObject->EchoTableLock);
    AnscSListPushEntry(&pMyObject->EchoTable[ulHashIndex], &pEchoEntry->Linkage);
    AnscReleaseLock(&pMyObject->EchoTableLock);

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipCalculateResult
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to close this object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipCalculateResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    PBBHM_IP_PING_ECHO_ENTRY        pEchoEntry   = NULL;
    ULONG                           i            = 0;

    AnscAcquireLock(&pMyObject->EchoTableLock);

    for ( i = 0; i < MAX_ECHO_TABLE_SIZE; i++ )
    {
        pSLinkEntry = AnscSListPopEntry(&pMyObject->EchoTable[i]);

        while ( pSLinkEntry )
        {
            pEchoEntry = (PBBHM_IP_PING_ECHO_ENTRY)ACCESS_BBHM_IP_PING_ECHO_ENTRY(pSLinkEntry);
            pSLinkEntry = AnscSListPopEntry(&pMyObject->EchoTable[i]);
            AnscFreeMemory(pEchoEntry);
        }
    }

    AnscReleaseLock(&pMyObject->EchoTableLock);

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetEnv
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to close this object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipSetEnv
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus    = ANSC_STATUS_SUCCESS;
    
    return returnStatus;
}
