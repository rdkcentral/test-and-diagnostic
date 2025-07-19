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

    module:    bbhm_diagit_operation.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced operation functions
        of the Tracertection Speed Tool Object.

        *    BbhmDiagitStart
        *    BbhmDiagitOpen
        *    BbhmDiagitStop
        *    BbhmDiagitClose
        *    BbhmDiagitResolveHost
        *    BbhmDiagitExpire1
        *    BbhmDiagitExpire2
        *    BbhmDiagitSetStopTime
        *    BbhmDiagitAddEchoEntry
        *    BbhmDiagitCalculateResult

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Du Li, Li Shi

    ---------------------------------------------------------------

    revision:

        08/06/09    initial revision.

**********************************************************************/


#include "bbhm_diagit_global.h"
#include "safec_lib_common.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitStart
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
BbhmDiagitStart
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus     = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject        = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty        = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;
    PBBHM_TRACERT_TDO_OBJECT        pStateTimer      = (PBBHM_TRACERT_TDO_OBJECT          )pMyObject->hStateTimer;
    PBBHM_TRACERT_SINK_OBJECT       pSink            = (PBBHM_TRACERT_SINK_OBJECT         )pMyObject->hSinkObject;
    PANSC_XSOCKET_OBJECT            pSocket          = (PANSC_XSOCKET_OBJECT              )pSink->GetXsocket((ANSC_HANDLE)pSink);
    PDSLH_TRACEROUTE_INFO           pDslhTracertObj  = (PDSLH_TRACEROUTE_INFO             )pMyObject->hDslhDiagInfo;

    ULONG                           pktSize          = pProperty->PktSize;
    PCHAR                           pSendBuffer      = pMyObject->hSendBuffer;
    ULONG                           i                = 0;
    PICMPV4_ECHO_MESSAGE            pIcmpHeaderIpv4  = NULL;
    PICMPV6_ECHO_MESSAGE            pIcmpHeaderIpv6  = NULL;
    ULONG                           StartTime        = 0;
    ULONG                           ttl              = (ULONG)pMyObject->GetTtl((ANSC_HANDLE)pMyObject);
    
    if ( !pMyObject->bActive )
    {
        pProperty->Status = BBHM_TRACERT_STATUS_ABORT;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }
    /* CID 66014: Dereference after null check */
    if ( !pDslhTracertObj )
    {
        pMyObject->Stop(hThisObject);
        return  ANSC_STATUS_FAILURE;
    }
    if ( pProperty->pDstAddrName == NULL )
    {
         pDslhTracertObj->DiagnosticState = DSLH_DIAG_STATE_TYPE_TRAC_Error_HostName;

         pMyObject->Stop(hThisObject);

         return  returnStatus;
    }
    pDslhTracertObj->DiagnosticState = DSLH_DIAG_STATE_TYPE_Requested;

    pMyObject->ResetPropertyCounter((ANSC_HANDLE)pMyObject);

    pSocket->SetPeerName     ((ANSC_HANDLE)pSocket, pProperty->pDstAddrName);
    pSocket->SetHostName     ((ANSC_HANDLE)pSocket, pProperty->pSrcAddrName);
    /*
    pSocket->SetHostAddress  ((ANSC_HANDLE)pSocket, SrcIp                  );
    pSocket->SetHostPort     ((ANSC_HANDLE)pSocket, 0                      );
    pSocket->SetTransportType((ANSC_HANDLE)pSocket, ICMP_TRANSPORT         );
    */
    pSocket->SetType         ((ANSC_HANDLE)pSocket, ANSC_XSOCKET_TYPE_RAW  );
    pSocket->SetXsink        ((ANSC_HANDLE)pSocket, (ANSC_HANDLE)pSink     );

    /*
     * The underlying socket wrapper may require an explicit startup() call, such is the case on
     * Microsoft windows platforms. The wrapper initialization has to done for each task. On most
     * real-time operating systems, this call is not required.
     */
    AnscStartupXsocketWrapper((ANSC_HANDLE)pMyObject);

    /* For IPv4/IPv6 compatible purpose we shall resolve the address first */
    returnStatus = pSocket->ResolveAddr((ANSC_HANDLE)pSocket);

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        pDslhTracertObj->DiagnosticState = DSLH_DIAG_STATE_TYPE_TRAC_Error_HostName;

        pMyObject->Stop(hThisObject);

        return  returnStatus;
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
        pProperty->Status = BBHM_TRACERT_STATUS_ABORT;

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
        pProperty->Status = BBHM_TRACERT_STATUS_ABORT;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    returnStatus = pSocket->Open((ANSC_HANDLE)pSocket);

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        AnscTrace("Socket Open Failed!\n");
        pProperty->Status = BBHM_TRACERT_STATUS_ABORT;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    if ( !pSendBuffer )
    {
        returnStatus = ANSC_STATUS_FAILURE;
        pProperty->Status = BBHM_TRACERT_STATUS_ABORT;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    /* Set DSCP */
    if ( pDslhTracertObj->DSCP != 0 )
    {
        pSocket->ApplyDSCP((ANSC_HANDLE)pSocket, pDslhTracertObj->DSCP);
    }

    StartTime = AnscGetTickInMilliSeconds();

    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        pIcmpHeaderIpv4 = (PICMPV4_ECHO_MESSAGE)pMyObject->hSendBuffer;

        AnscIcmpv4EchoSetType         (pIcmpHeaderIpv4, ICMP_TYPE_ECHO_REQUEST);
        AnscIcmpv4EchoSetCode         (pIcmpHeaderIpv4, 0                     );
        AnscIcmpv4EchoSetId           (pIcmpHeaderIpv4, (USHORT)pMyObject->GetPktsSent((ANSC_HANDLE)pMyObject) );
        AnscIcmpv4EchoSetSeqNumber    (pIcmpHeaderIpv4, 0                     );

        for ( i = 0; i < pktSize; i++ )
        {
            ((PUCHAR)pMyObject->hSendBuffer)[i + sizeof(ICMPV4_HEADER)] = (UCHAR)i;
        }

        AnscIcmpv4EchoSetChecksum    (pIcmpHeaderIpv4, 0                        );
        AnscIcmpv4CalculateChecksum (((PICMPV4_HEADER)pIcmpHeaderIpv4), pktSize + sizeof(IPV4_HEADER) + sizeof(ICMPV4_ECHO_MESSAGE));

        returnStatus =
            pMyObject->AddEchoEntry
                (
                    (ANSC_HANDLE)pMyObject,
                    AnscIcmpv4EchoGetId(pIcmpHeaderIpv4),
                    StartTime,
                    ttl
                );

        if ( _xskt_setsocketopt
                (
                    pSocket->Xsocket,
                    IPPROTO_IP,
                    IP_TTL,
                    (char *)&ttl,
                    sizeof(ttl)
                ) != 0 )
        {
            AnscTrace("Fail to set IPv4 socketopt.\n");
        }   
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        pIcmpHeaderIpv6 = (PICMPV6_ECHO_MESSAGE)pMyObject->hSendBuffer;

        AnscIcmpv6EchoSetType        (pIcmpHeaderIpv6, ICMP6_TYPE_ECHO_REQUEST  );
        AnscIcmpv6EchoSetCode        (pIcmpHeaderIpv6, 0                        );
        AnscIcmpv6EchoSetId          (pIcmpHeaderIpv6, (USHORT)pMyObject->GetPktsSent((ANSC_HANDLE)pMyObject) );
        AnscIcmpv6EchoSetSeqNumber   (pIcmpHeaderIpv6, 0                        );

        for ( i = 0; i < pktSize; i++ )
        {
            ((PUCHAR)pMyObject->hSendBuffer)[i + sizeof(ICMPV6_HEADER)] = (UCHAR)i;
        }

        AnscIcmpv6EchoSetChecksum    (pIcmpHeaderIpv6, 0                        );

        returnStatus =
            pMyObject->AddEchoEntry
                (
                    (ANSC_HANDLE)pMyObject,
                    AnscIcmpv6EchoGetId(pIcmpHeaderIpv6),
                    StartTime,
                    ttl
                );

        if ( _xskt_setsocketopt
                (
                    pSocket->Xsocket,
                    IPPROTO_IPV6,
                    IPV6_UNICAST_HOPS,
                    (char *)&ttl,
                    sizeof(ttl)
                ) != 0)
        {
	    AnscTrace("Fail to set IPv6 socketopt.\n");
	}
    }

    pMyObject->SetStatus     ((ANSC_HANDLE)pMyObject, BBHM_TRACERT_STATUS_RUNNING);

    pStateTimer->SetTimerType((ANSC_HANDLE)pStateTimer, ANSC_TIMER_TYPE_SPORADIC);
    pStateTimer->SetInterval ((ANSC_HANDLE)pStateTimer, pProperty->TimeBetween  );
    pStateTimer->SetCounter  ((ANSC_HANDLE)pStateTimer, pProperty->NumPkts        );
    pStateTimer->Start       ((ANSC_HANDLE)pStateTimer);
/*
    pSocket->SetPeerAddress  ((ANSC_HANDLE)pSocket, pProperty->DstIp.Dot);
    pSocket->SetPeerPort     ((ANSC_HANDLE)pSocket, 0            );
*/
/*
    returnStatus =
        _ansc_setsocketopt (
            pSocket->Xsocket, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(ttl)
        );
*/
    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        returnStatus =
            pMyObject->Send
                (
                    (ANSC_HANDLE)pMyObject,
                    (ANSC_HANDLE)pMyObject->hSinkObject,
                    (PVOID)pMyObject->hSendBuffer,
                    pktSize + sizeof(ICMPV4_ECHO_MESSAGE)
                );
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        returnStatus =
            pMyObject->Send
                (
                    (ANSC_HANDLE)pMyObject,
                    (ANSC_HANDLE)pMyObject->hSinkObject,
                    (PVOID)pMyObject->hSendBuffer,
                    pktSize + sizeof(ICMPV6_ECHO_MESSAGE)
                );
    }

    pProperty->PktsSent++;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSendEcho
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
BbhmDiagitSendEcho
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;
    PBBHM_TRACERT_TDO_OBJECT        pStateTimer  = (PBBHM_TRACERT_TDO_OBJECT          )pMyObject->hStateTimer;
    PBBHM_TRACERT_SINK_OBJECT       pSink        = (PBBHM_TRACERT_SINK_OBJECT         )pMyObject->hSinkObject;
    PANSC_XSOCKET_OBJECT            pSocket      = (PANSC_XSOCKET_OBJECT              )pSink->GetXsocket((ANSC_HANDLE)pSink);
    PDSLH_TRACEROUTE_INFO           pDslhTracertObj  = (PDSLH_TRACEROUTE_INFO         )pMyObject->hDslhDiagInfo;
    ULONG                           pktSize      = pProperty->PktSize;
    PCHAR                           pSendBuffer  = pMyObject->hSendBuffer;
    ULONG                           i            = 0;
    PICMPV4_ECHO_MESSAGE            pIcmpHeaderIpv4  = NULL;
    PICMPV6_ECHO_MESSAGE            pIcmpHeaderIpv6  = NULL;
    ULONG                           StartTime    = 0;
    ULONG                           ttl          = 0;
    
    if ( !pMyObject->bActive )
    {
        pProperty->Status = BBHM_TRACERT_STATUS_ABORT;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    if ( !pSendBuffer )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        pProperty->Status = BBHM_TRACERT_STATUS_ABORT;
        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    if ( pProperty->pDstAddrName == NULL )
    {
        pDslhTracertObj->DiagnosticState = DSLH_DIAG_STATE_TYPE_TRAC_Error_HostName;

        return  returnStatus;
    }

    AnscSleep(100);

    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        pIcmpHeaderIpv4 = (PICMPV4_ECHO_MESSAGE)((PUCHAR)pMyObject->hSendBuffer);

        _ansc_memset((PUCHAR)pIcmpHeaderIpv4, 0, sizeof(ICMPV4_ECHO_MESSAGE) + BBHM_TRACERT_MAX_PACKET_SIZE);

        AnscIcmpv4EchoSetType        (pIcmpHeaderIpv4, ICMP_TYPE_ECHO_REQUEST);
        AnscIcmpv4EchoSetCode        (pIcmpHeaderIpv4, 0                     );
        AnscIcmpv4EchoSetId          (pIcmpHeaderIpv4, (USHORT)pMyObject->GetPktsSent((ANSC_HANDLE)pMyObject) );
        AnscIcmpv4EchoSetSeqNumber   (pIcmpHeaderIpv4, 0                     );

        for ( i = 0; i < pktSize; i++ )
        {
            ((PUCHAR)pMyObject->hSendBuffer)[i + sizeof(ICMPV4_HEADER)] = (UCHAR)i;
        }

        AnscIcmpv4EchoSetChecksum    (pIcmpHeaderIpv4, 0                        );
        AnscIcmpv4CalculateChecksum (((PICMPV4_HEADER)pIcmpHeaderIpv4), pktSize + sizeof(IPV4_HEADER) + sizeof(ICMPV4_ECHO_MESSAGE));
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        pIcmpHeaderIpv6 = (PICMPV6_ECHO_MESSAGE)pMyObject->hSendBuffer;

        _ansc_memset((PUCHAR)pIcmpHeaderIpv6, 0, sizeof(ICMPV6_ECHO_MESSAGE) + BBHM_TRACERT_MAX_PACKET_SIZE);

        AnscIcmpv6EchoSetType        (pIcmpHeaderIpv6, ICMP6_TYPE_ECHO_REQUEST);
        AnscIcmpv6EchoSetCode        (pIcmpHeaderIpv6, 0                      );
        AnscIcmpv6EchoSetId          (pIcmpHeaderIpv6, (USHORT)pMyObject->GetPktsSent((ANSC_HANDLE)pMyObject) );
        AnscIcmpv6EchoSetSeqNumber   (pIcmpHeaderIpv6, 0                      );

        for ( i = 0; i < pktSize; i++ )
        {
            ((PUCHAR)pMyObject->hSendBuffer)[i + sizeof(ICMPV6_HEADER)] = (UCHAR)i;
        }

        AnscIcmpv6EchoSetChecksum    (pIcmpHeaderIpv6, 0                      );
    }

    pStateTimer->Stop       ((ANSC_HANDLE)pStateTimer);

    pStateTimer->SetTimerType((ANSC_HANDLE)pStateTimer, ANSC_TIMER_TYPE_SPORADIC);
    pStateTimer->SetInterval ((ANSC_HANDLE)pStateTimer, pProperty->TimeBetween  );
    pStateTimer->SetCounter  ((ANSC_HANDLE)pStateTimer, pProperty->NumPkts      );

    pStateTimer->Start       ((ANSC_HANDLE)pStateTimer);

    ttl = pMyObject->GetTtl  ((ANSC_HANDLE)pMyObject);
/*
    pSocket->SetPeerAddress  ((ANSC_HANDLE)pSocket, pProperty->DstIp.Dot );
    pSocket->SetPeerPort     ((ANSC_HANDLE)pSocket, 0                    );
*/
    pMyObject->SetStatus     ((ANSC_HANDLE)pMyObject, BBHM_TRACERT_STATUS_RUNNING);

    StartTime = AnscGetTickInMilliSeconds();

    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        if ( _xskt_setsocketopt
                (
                    pSocket->Xsocket,
                    IPPROTO_IP,
                    IP_TTL,
                    (char *)&ttl,
                    sizeof(ttl)
                ) != 0)
	{
	   AnscTrace("Fail to set IPv4 socketopt.\n");
	}

        returnStatus =
            pMyObject->AddEchoEntry
                (
                    (ANSC_HANDLE)pMyObject,
                    AnscIcmpv4EchoGetId(pIcmpHeaderIpv4),
                    StartTime,
                    ttl
                );

        returnStatus =
            pMyObject->Send
                (
                    (ANSC_HANDLE)pMyObject,
                    (ANSC_HANDLE)pMyObject->hSinkObject,
                    (PVOID)pMyObject->hSendBuffer,
                    pktSize + sizeof(ICMPV4_ECHO_MESSAGE)
                );
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        if ( _xskt_setsocketopt
                (
                    pSocket->Xsocket,
                    IPPROTO_IPV6,
                    IPV6_UNICAST_HOPS,
                    (char *)&ttl,
                    sizeof(ttl)
                ) != 0)
        {
           AnscTrace("Fail to set IPv6 socketopt.\n");
	}

        returnStatus =
            pMyObject->AddEchoEntry
                (
                    (ANSC_HANDLE)pMyObject,
                    AnscIcmpv6EchoGetId(pIcmpHeaderIpv6),
                    StartTime,
                    ttl
                );

        returnStatus =
            pMyObject->Send
                (
                    (ANSC_HANDLE)pMyObject,
                    (ANSC_HANDLE)pMyObject->hSinkObject,
                    (PVOID)pMyObject->hSendBuffer,
                    pktSize + sizeof(ICMPV6_ECHO_MESSAGE)
                );

    }

    pProperty->PktsSent++;

    /* AnscTrace("Client Send : %d Packet, TTL %d\n", pProperty->PktsSent, ttl ); */

    return  returnStatus;
}




/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitOpen
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
BbhmDiagitOpen
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT  )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY           )&pMyObject->Property;
    PBBHM_TRACERT_SINK_OBJECT       pSink        = NULL;
    PANSC_XSOCKET_OBJECT            pSocket      = NULL;
    
    if ( pMyObject->bActive )
    {
        return  ANSC_STATUS_SUCCESS;
    }

    if ( pProperty->Status == BBHM_TRACERT_STATUS_RUNNING )
    {
        return  ANSC_STATUS_FAILURE;
    }

    AnscTrace("Tracert is about to create new socket and sink objects!\n");

    pSink = (PBBHM_TRACERT_SINK_OBJECT)BbhmDiagitSinkCreate((ANSC_HANDLE)pMyObject);

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

    AnscTrace("Reset the property conter\n");

    pMyObject->ResetPropertyCounter((ANSC_HANDLE)pMyObject);

    pMyObject->bActive = TRUE;

    goto  EXIT1;

EXIT1:

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitStop
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
BbhmDiagitStop
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT        )hThisObject;
    PBBHM_TRACERT_TDO_OBJECT        pStateTimer  = (PBBHM_TRACERT_TDO_OBJECT               )pMyObject->hStateTimer;
    PBBHM_TRACERT_SINK_OBJECT       pSink        = (PBBHM_TRACERT_SINK_OBJECT              )pMyObject->hSinkObject;
    PANSC_XSOCKET_OBJECT            pSocket      = NULL;
    PDSLH_TRACEROUTE_INFO           pDslhTracertObj  = (PDSLH_TRACEROUTE_INFO              )pMyObject->hDslhDiagInfo;

    if ( pMyObject->bActive )
    {
        pStateTimer->Stop((ANSC_HANDLE)pStateTimer);
        pStateTimer->SetStopTime((ANSC_HANDLE)pStateTimer, AnscGetTickInMilliSeconds());

        if ( pDslhTracertObj->DiagnosticState == DSLH_DIAG_STATE_TYPE_Requested
            || pDslhTracertObj->DiagnosticState == DSLH_DIAG_STATE_TYPE_Inprogress )
        {
            pDslhTracertObj->DiagnosticState = DSLH_DIAG_STATE_TYPE_Complete;
        }
        else if ( pDslhTracertObj->DiagnosticState == DSLH_DIAG_STATE_TYPE_Canceled )
        {
            pDslhTracertObj->RouteHopsNumberOfEntries--;
        }

        returnStatus =
            pMyObject->CalculateResult
                (
                    (ANSC_HANDLE)pMyObject
                );

        if ( pDslhTracertObj->DiagnosticState == DSLH_DIAG_STATE_TYPE_Canceled
            && pDslhTracertObj->RouteHopsNumberOfEntries > 0 )
        {
            pDslhTracertObj->RouteHopsNumberOfEntries--;
        }

        AnscTrace("Return from DiagitStop!\n");

        if ( pSink )
        {
            pSocket = (PANSC_XSOCKET_OBJECT    )pSink->GetXsocket((ANSC_HANDLE)pSink);
            pSocket->Close((ANSC_HANDLE)pSocket);
        }

        pDslhTracertObj->UpdatedAt = AnscGetTickInSeconds();
    }

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitResolveHost
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

ULONG
BbhmDiagitResolveHost
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hHostName
    )
{
    PUCHAR                          pHostName    = (PUCHAR                            )hHostName;
    ULONG                           IpAddr;
    ansc_hostent*                   pHostent;

    pHostent = _ansc_gethostbyname(pHostName);

    if ( !pHostent || !pHostent->h_addr_list[0] )
    {
        return _ansc_inet_addr(pHostName);
    }

    AnscCopyMemory((PUCHAR)&IpAddr, pHostent->h_addr_list[0], sizeof(ULONG));

    return  IpAddr;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        PUCHAR
        BbhmDiagitResolveHostName
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       IpAddr,
            );

    description:

        This function is called to abort the send task.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

PUCHAR
BbhmDiagitResolveHostName
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       IpAddr
    )
{
    ansc_hostent                    *pHostent;

    pHostent = _ansc_gethostbyaddr((PUCHAR)&IpAddr, 4, AF_INET);

    if ( !pHostent)
    {
        return (PUCHAR)NULL;
    }

    return pHostent->h_name;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitExpire1
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
BbhmDiagitExpire1
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT  pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    
    returnStatus = pMyObject->SendEcho ( (ANSC_HANDLE)pMyObject );

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitExpire2
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
BbhmDiagitExpire2
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT    )hThisObject;
    PDSLH_TRACEROUTE_INFO           pDslhTracertObj  = (PDSLH_TRACEROUTE_INFO        )pMyObject->hDslhDiagInfo;

    pDslhTracertObj->RouteHopsNumberOfEntries = pMyObject->GetTtl((ANSC_HANDLE)pMyObject);

    pMyObject->SetStatus ((ANSC_HANDLE)pMyObject, BBHM_TRACERT_STATUS_TIMEOUT);
    pMyObject->Stop      ((ANSC_HANDLE)pMyObject                        );

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitClose
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
BbhmDiagitClose
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_SINK_OBJECT       pSink        = (PBBHM_TRACERT_SINK_OBJECT         )pMyObject->hSinkObject;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    PBBHM_TRACERT_ECHO_ENTRY        pEchoEntry   = NULL;
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
            pEchoEntry  = ACCESS_BBHM_TRACERT_ECHO_ENTRY(pSLinkEntry);
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
        BbhmDiagitSetStopTime
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
BbhmDiagitSetStopTime
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                        SeqNumber,
        ULONG                        StopTime
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_FAILURE;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    PBBHM_TRACERT_ECHO_ENTRY        pEchoEntry   = NULL;
    ULONG                           ulHashIndex  = SeqNumber % MAX_ECHO_TABLE_SIZE;

    AnscAcquireLock(&pMyObject->EchoTableLock);
    pSLinkEntry = AnscSListGetFirstEntry(&pMyObject->EchoTable[ulHashIndex]);

    while ( pSLinkEntry )
    {
        pEchoEntry = (PBBHM_TRACERT_ECHO_ENTRY)ACCESS_BBHM_TRACERT_ECHO_ENTRY(pSLinkEntry);
        pSLinkEntry = AnscSListGetNextEntry(pSLinkEntry);

        if ( pEchoEntry->SeqId == SeqNumber )
        {
            if ( StopTime - pEchoEntry->StartTime <= pProperty->TimeOut )
            {
                /* AnscTrace("StopTime for SeqId: %d is %d\n", SeqNumber, StopTime); */
                returnStatus            = ANSC_STATUS_SUCCESS;
                pEchoEntry->StopTime    = StopTime;
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
        BbhmDiagitAddEchoEntry
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
BbhmDiagitAddEchoEntry
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                      SeqNumber,
        ULONG                       StartTime,
        ULONG                       TimeToLive
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_ECHO_ENTRY        pEchoEntry   = NULL;
    ULONG                           ulHashIndex  = SeqNumber % MAX_ECHO_TABLE_SIZE;

    pEchoEntry = (PBBHM_TRACERT_ECHO_ENTRY)AnscAllocateMemory(sizeof(BBHM_TRACERT_ECHO_ENTRY));
    if ( !pEchoEntry )
    {
        return  ANSC_STATUS_FAILURE;
    }

    pEchoEntry->TimeToLive    = TimeToLive;
    pEchoEntry->SeqId         = SeqNumber;
    pEchoEntry->StartTime     = StartTime;
    pEchoEntry->StopTime      = 0;
    pEchoEntry->pHostAddrInfo = NULL;

    /* AnscTrace("StartTime for SeqId: %d is %d, TTL %d\n", SeqNumber, StartTime, TimeToLive); */

    CcspTraceInfo(("pEchoEntry SeqId %d is added\n", pEchoEntry->SeqId));

    AnscAcquireLock(&pMyObject->EchoTableLock);
    AnscSListPushEntry(&pMyObject->EchoTable[ulHashIndex], &pEchoEntry->Linkage);
    AnscReleaseLock(&pMyObject->EchoTableLock);


    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitCalculateResult
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
BbhmDiagitCalculateResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus     = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject        = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty        = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;
    PSINGLE_LINK_ENTRY              pSLinkEntry      = NULL;
    PBBHM_TRACERT_ECHO_ENTRY        pEchoEntry       = NULL;
    PDSLH_TRACEROUTE_INFO           pDslhTracertObj  = (PDSLH_TRACEROUTE_INFO             )pMyObject->hDslhDiagInfo;
    PDSLH_ROUTEHOPS_INFO            pDslhHopObj      = (PDSLH_ROUTEHOPS_INFO              )NULL;
    SLIST_HEADER                    pTempHeader;

    ULONG                           i              = 0;
    ULONG                           ulHashIndex    = 0;
    UCHAR                           Temp[32]      = { 0 };
    ULONG                           duration       = 0;

    if ( !pDslhTracertObj )
    {
        return  ANSC_STATUS_FAILURE;
    }

    AnscSListInitializeHeader(&pTempHeader);

    AnscAcquireLock(&pMyObject->EchoTableLock);

    for ( i = 0; i < MAX_ECHO_TABLE_SIZE; i++ )
    {
        pSLinkEntry = AnscSListPopEntry(&pMyObject->EchoTable[i]);

        while ( pSLinkEntry )
        {
            pEchoEntry  = (PBBHM_TRACERT_ECHO_ENTRY)ACCESS_BBHM_TRACERT_ECHO_ENTRY(pSLinkEntry);
            pSLinkEntry = AnscSListPopEntry(&pMyObject->EchoTable[i]);

            if ( pEchoEntry->SeqId >= (pProperty->PktsRecv / pProperty->NumPkts) * pProperty->NumPkts
                || !pEchoEntry->StopTime )
            {
                AnscSListPushEntry(&pTempHeader, &pEchoEntry->Linkage);

                continue;
            }

            ulHashIndex = pEchoEntry->TimeToLive - 1;
            pDslhHopObj = (PDSLH_ROUTEHOPS_INFO)&pDslhTracertObj->hDiagRouteHops[ulHashIndex];
            errno_t rc = -1;

            if ( pEchoEntry->StopTime == BBHM_TRACERT_ICMP_TIMEOUT )
            {
                rc = strcpy_s(Temp, 8, "*");
                ERR_CHK(rc);

                pDslhTracertObj->ResponseTime = 0;
            }
            else if ( pEchoEntry->StopTime > 0 )
            {
                duration    = pEchoEntry->StopTime-pEchoEntry->StartTime;
                duration    = duration > 0 ? duration : 1;
                rc = sprintf_s(Temp, sizeof(Temp), "%lu", duration);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }

                pDslhTracertObj->ResponseTime = duration;
            }

            if ( !AnscSizeOfString(pDslhHopObj->HopRTTimes) )
            {
                pDslhHopObj->HopErrorCode = pEchoEntry->ErrorCode;

                rc = strcpy_s(pDslhHopObj->HopRTTimes, sizeof(pDslhHopObj->HopRTTimes) ,Temp);
                ERR_CHK(rc);
            }
            else
            {
                AnscCatString(pDslhHopObj->HopRTTimes, ",");
                AnscCatString(pDslhHopObj->HopRTTimes, Temp);

                /* Guarantee that the last abnormal code is recorded */

                if ( pDslhHopObj->HopErrorCode != ICMP_TYPE_ECHO_REPLY
                    && pDslhHopObj->HopErrorCode != ICMP_TYPE_TIME_EXCEEDED )
                {
                    pDslhHopObj->HopErrorCode = pEchoEntry->ErrorCode;
                }
            }

            if ( pDslhTracertObj->RouteHopsNumberOfEntries < pEchoEntry->TimeToLive )
            {
                pDslhTracertObj->RouteHopsNumberOfEntries = pEchoEntry->TimeToLive;
            }

            pMyObject->SetStateUpdated ((ANSC_HANDLE)pMyObject, TRUE);

            AnscFreeMemory(pEchoEntry);
        }

        pSLinkEntry = AnscSListPopEntry(&pTempHeader);

        while ( pSLinkEntry )
        {
            pEchoEntry  = (PBBHM_TRACERT_ECHO_ENTRY)ACCESS_BBHM_TRACERT_ECHO_ENTRY(pSLinkEntry);
            pSLinkEntry = AnscSListPopEntry(&pTempHeader);

            AnscSListPushEntry(&pMyObject->EchoTable[i], &pEchoEntry->Linkage);
        }
    }

    AnscReleaseLock(&pMyObject->EchoTableLock);

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

    ANSC_STATUS
    BbhmDiagitUpdateEntry
        (
            ANSC_HANDLE                 hThisObject,
            ULONG                       SeqId,
            xskt_addrinfo*              pHopAddrInfo,
            ULONG                       StopTime,
            ULONG                       ErrorCode,
            ULONG                       TimeToLive
        );

    description:

        This function is called to close this object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitUpdateEntry
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       SeqId,
        xskt_addrinfo*              pHopAddrInfo,
        ULONG                       StopTime,
        ULONG                       ErrorCode
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PSINGLE_LINK_ENTRY              pSLinkEntry      = NULL;
    PBBHM_TRACERT_ECHO_ENTRY        pEchoEntry       = NULL;
    PDSLH_TRACEROUTE_INFO           pDslhTracertObj  = (PDSLH_TRACEROUTE_INFO    )pMyObject->hDslhDiagInfo;
    PDSLH_ROUTEHOPS_INFO            pDslhHopObj      = (PDSLH_ROUTEHOPS_INFO     )NULL;
    ULONG                           ulHashIndex      = SeqId % MAX_ECHO_TABLE_SIZE;
    ULONG                           ulIndex          = 0;
    int                             iReturn          = 0;

    AnscAcquireLock(&pMyObject->EchoTableLock);

    CcspTraceInfo(("SeqId in DiagitUpdateEntry: %lu\n", SeqId));

    pSLinkEntry = AnscSListGetFirstEntry(&pMyObject->EchoTable[ulHashIndex]);

    while ( pSLinkEntry )
    {
        pEchoEntry  = (PBBHM_TRACERT_ECHO_ENTRY)ACCESS_BBHM_TRACERT_ECHO_ENTRY(pSLinkEntry);
        pSLinkEntry = AnscSListGetNextEntry(pSLinkEntry);

        if ( pEchoEntry->SeqId == SeqId )
        {
            ulIndex = pEchoEntry->TimeToLive - 1;
            pDslhHopObj = (PDSLH_ROUTEHOPS_INFO)&pDslhTracertObj->hDiagRouteHops[ulIndex];

            pEchoEntry->StopTime      = StopTime;
            pEchoEntry->pHostAddrInfo = pHopAddrInfo;
            pEchoEntry->ErrorCode     = ErrorCode;

            if ( !AnscSizeOfString(pDslhHopObj->HopHost) && pHopAddrInfo )
            {
                iReturn = _xskt_getnameinfo
                    (
                         (struct sockaddr *)pHopAddrInfo->ai_addr,
                         pHopAddrInfo->ai_addrlen,
                         pDslhHopObj->HopHost,
                         NI_MAXHOST,
                         NULL,
                         NI_MAXSERV,
                         NI_NAMEREQD /* Don't return numeric addresses.  */
                    );

                if ( iReturn != 0 )
                {
                    CcspTraceInfo(("Return from getnameinfo: %s\n", gai_strerror(iReturn)));
                    /*when the name can't be resolved, obtain the numeric string*/
		    /* CID 176164 -  Unchecked return value */
                    iReturn = _xskt_getnameinfo
                        (
                            (struct sockaddr *)pHopAddrInfo->ai_addr,
                            pHopAddrInfo->ai_addrlen,
                            pDslhHopObj->HopHost,
                            NI_MAXHOST,
                            NULL,
                            NI_MAXSERV,
                            NI_NUMERICHOST
                        );
                    if ( iReturn != 0 )
                    {
                        CcspTraceInfo(("Return from getnameinfo: %s\n", gai_strerror(iReturn)));
                    }
                }

                iReturn = _xskt_getnameinfo
                        (
                            (struct sockaddr *)pHopAddrInfo->ai_addr,
                            pHopAddrInfo->ai_addrlen,
                            pDslhHopObj->HopHostAddress,
                            NI_MAXHOST,
                            NULL,
                            NI_MAXSERV,
                            NI_NUMERICHOST
                        );

                if ( iReturn != 0 )
                {
                    CcspTraceInfo(("Return from getnameinfo: %s\n", gai_strerror(iReturn)));
                }
/*
                if ( ! AnscSizeOfString(pDslhHopObj->HopHost) )
                {
                    CcspTraceInfo(("!!! Should not be here !!!\n"));
                    AnscCopyString(pDslhHopObj->HopHost, pHopAddrInfo->ai_canonname);
                }
                else
                {
                    _xskt_getnameinfo
                        (
                            (struct sockaddr *)pHopAddrInfo->ai_addr,
                            sizeof(struct sockaddr),
                            pDslhHopObj->HopHostAddress,
                            NI_MAXHOST,
                            NULL,
                            NI_MAXSERV,
                            NI_NUMERICHOST
                        );
                    //AnscCopyString(pDslhHopObj->HopHostAddress, pHopAddrInfo->ai_canonname);
                }
                */
            }

            break;
        }
    }

    pMyObject->SetStateUpdated ((ANSC_HANDLE)pMyObject, TRUE);

    AnscReleaseLock(&pMyObject->EchoTableLock);

    return  returnStatus;
}

