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

    module:     bbhm_diagit_process.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the processing functions
        of the Bbhm IpTraceroute Diagnostic Object.

        *   BbhmDiagitStartDiag
        *   BbhmDiagitStopDiag
        *   BbhmDiagitRetrieveResult
        *   BbhmDiagitAccept
        *   BbhmDiagitRecv
        *   BbhmDiagitSend

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


#include "bbhm_diagit_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitStartDiag
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to start the diagnostic process.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_STATUS
BbhmDiagitStartDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject           = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT  )hThisObject;
    PDSLH_TRACEROUTE_INFO           pDslhDiagInfo       = (PDSLH_TRACEROUTE_INFO            )pMyObject->hDslhDiagInfo;

    if ( pMyObject->CheckCanStart((ANSC_HANDLE)pMyObject) )
    {
        AnscTraceFlow(("BbhmDiagitStartDiag -- enter...\n"));

        returnStatus = pMyObject->ResetProperty((ANSC_HANDLE)pMyObject);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            return  ANSC_STATUS_INTERNAL_ERROR;
        }

        if ( pMyObject->GetDstAddrName((ANSC_HANDLE)pMyObject) != NULL )
        {
            returnStatus = pMyObject->Start((ANSC_HANDLE)pMyObject);

            if ( returnStatus == ANSC_STATUS_SUCCESS )
            {
                returnStatus = BbhmDiageoStartDiag((ANSC_HANDLE)pMyObject);
            }
        }
        else
        {
            pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_TRAC_Error_HostName;
        }

        return  returnStatus;
    }
    else
    {
        AnscTraceFlow(("BbhmDiagitStartDiag -- query task is running...\n"));

        return  ANSC_STATUS_PENDING;
    }
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitStopDiag
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to stop the diagnostic process.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_STATUS
BbhmDiagitStopDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject           = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT)hThisObject;
    PDSLH_TRACEROUTE_INFO           pDiagInfo           = (PDSLH_TRACEROUTE_INFO          )pMyObject->hDslhDiagInfo;

    returnStatus = pMyObject->Stop((ANSC_HANDLE)pMyObject);
    pDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitRetrieveResult
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the diagnostic result.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_STATUS
BbhmDiagitRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject           = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT  )hThisObject;

    AnscAcquireLock(&pMyObject->AccessLock);
    pMyObject->CalculateResult((ANSC_HANDLE)pMyObject);
    AnscReleaseLock(&pMyObject->AccessLock);

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_STATUS
        BbhmDiagitAccept
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                    hNewSocket
            );

    description:

        This function constructs the Dhcps Interface Owner Object and
        initializes the member variables and functions.

    argument:   ANSC_HANDLE                 hContainerContext
                This handle is used by the container object to interact
                with the outside world. It could be the real container
                or an target object.

                PVOID                        buffer
                This is received buffer.

                ULONG                        ulSize
                This is the size of the buffer.

    return:     newly created container object.

**********************************************************************/

ANSC_STATUS
BbhmDiagitAccept
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                    hNewSocket
    )
{
    
    return  ANSC_STATUS_UNAPPLICABLE;

}



/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_STATUS
        BbhmDiagitRecv
            (
                ANSC_HANDLE                 hThisObject,
                PVOID                       buffer,
                ULONG                       ulSize
            );

    description:

        This function constructs the Dhcps Interface Owner Object and
        initializes the member variables and functions.

    argument:   ANSC_HANDLE                 hContainerContext
                This handle is used by the container object to interact
                with the outside world. It could be the real container
                or an target object.

                PVOID                        buffer
                This is received buffer.

                ULONG                        ulSize
                This is the size of the buffer.

    return:     newly created container object.

**********************************************************************/

ANSC_STATUS
BbhmDiagitRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;
    PBBHM_TRACERT_TDO_OBJECT        pStateTimer  = (PBBHM_TRACERT_TDO_OBJECT          )pMyObject->hStateTimer;
    PBBHM_TRACERT_SINK_OBJECT       pSink        = (PBBHM_TRACERT_SINK_OBJECT         )hSinkObject;
    PANSC_XSOCKET_OBJECT            pSocket      = (PANSC_XSOCKET_OBJECT              )pSink->GetXsocket((ANSC_HANDLE)pSink);
    PIPV4_HEADER                    pIpv4Header  = (PIPV4_HEADER                      )NULL;
    PICMPV4_ECHO_MESSAGE            pIcmpHeaderIpv4  = (PICMPV4_ECHO_MESSAGE              )NULL;
    PICMPV6_ECHO_MESSAGE            pIcmpHeaderIpv6  = (PICMPV6_ECHO_MESSAGE              )NULL;
    PICMPV4_ECHO_MESSAGE            pOriIcmpHeaderIpv4  = (PICMPV4_ECHO_MESSAGE              )NULL;
    PICMPV6_ECHO_MESSAGE            pOriIcmpHeaderIpv6  = (PICMPV6_ECHO_MESSAGE              )NULL;
    PICMPV4_TIME_EXCEEDED_MESSAGE   pIcmpTeHeaderIpv4 = (PICMPV4_TIME_EXCEEDED_MESSAGE    )NULL;
    PICMPV6_TIME_EXCEEDED_MESSAGE   pIcmpTeHeaderIpv6 = (PICMPV6_TIME_EXCEEDED_MESSAGE    )NULL;
    PDSLH_TRACEROUTE_INFO           pDslhTracertObj  = (PDSLH_TRACEROUTE_INFO         )pMyObject->hDslhDiagInfo;
    PIPV4_HEADER                    pOriIpv4Header  = (PIPV4_HEADER                      )NULL;
    PIPV6_HEADER                    pOriIpv6Header  = (PIPV6_HEADER                      )NULL;
    ULONG                           SeqId        = 0;
    ULONG                           uIndex       = 0;
    ULONG                           StopTime     = 0;
    ULONG                           ttl          = (ULONG)pMyObject->GetTtl((ANSC_HANDLE)pMyObject);

     /* CID 61899: Dereference after null check */
    if ( !pDslhTracertObj )
    {
        return  ANSC_STATUS_FAILURE;
    }

    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        pIpv4Header = (PIPV4_HEADER)buffer;
        pIcmpHeaderIpv4 = (PICMPV4_ECHO_MESSAGE)AnscIpv4GetPayload(pIpv4Header);

        /*SeqId = AnscIcmpv4EchoGetId(pIcmpHeaderIpv4);

        CcspTraceInfo(("SeqId in DiagitRecv: %d\n", SeqId));*/
/*
        if ( (AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) == ICMP_TYPE_DESTINATION_UNREACHABLE &&
             AnscIcmpv4EchoGetCode(pIcmpHeaderIpv4) == ICMP_DUCODE_PORT_UNREACHABLE) ||
             AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) == ICMP_TYPE_ECHO_REQUEST ) */
        if ( AnscIcmpv4GetType(pIcmpHeaderIpv4) != ICMP_TYPE_TIME_EXCEEDED &&
             AnscIcmpv4GetType(pIcmpHeaderIpv4) != ICMP_TYPE_ECHO_REPLY )
        {
            /* This is usually caused by DNS lookup failure, can be ignored */
            CcspTraceInfo(("None traceroute releated icmp received, discard...\n"));

            return  returnStatus;
        }
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        pIcmpHeaderIpv6 = (PICMPV6_ECHO_MESSAGE)buffer;
/*
        if ( (AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) == ICMP6_TYPE_DESTINATION_UNREACHABLE &&
             AnscIcmpv6EchoGetCode(pIcmpHeaderIpv6) == ICMP6_DUCODE_PORT_UNREACHABLE) ||
             AnscIcmpv4EchoGetType(pIcmpHeaderIpv6) == ICMP6_TYPE_ECHO_REQUEST )*/
        if ( AnscIcmpv6GetType(pIcmpHeaderIpv6) != ICMP6_TYPE_TIME_EXCEEDED &&
             AnscIcmpv6GetType(pIcmpHeaderIpv6) != ICMP6_TYPE_ECHO_REPLY )
        {
            /* This is usually caused by DNS lookup failure, can be ignored */
            CcspTraceInfo(("None traceroute releated icmp received, discard...\n"));

            return  returnStatus;
        }
    }

    if ( pProperty->PktsRecv + 1 != pProperty->PktsSent )
    {
        return  returnStatus;
    }

    StopTime = AnscGetTickInMilliSeconds();

    pStateTimer->Stop ((ANSC_HANDLE)pStateTimer);

    if ( pProperty->Status != BBHM_TRACERT_STATUS_RUNNING )
    {
        return  ANSC_STATUS_UNAPPLICABLE;
    }

    pProperty->PktsRecv ++;

    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        if ( AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) == ICMP_TYPE_TIME_EXCEEDED )
        {
            pIcmpTeHeaderIpv4 = (PICMPV4_TIME_EXCEEDED_MESSAGE)pIcmpHeaderIpv4;

            pOriIpv4Header = (PIPV4_HEADER)AnscIcmpv4TeGetOrgIp(pIcmpTeHeaderIpv4);

            pOriIcmpHeaderIpv4 = (PICMPV4_ECHO_MESSAGE)((PUCHAR)pOriIpv4Header + AnscIpv4GetHeaderSize(pOriIpv4Header));

            SeqId = AnscIcmpv4EchoGetId(pOriIcmpHeaderIpv4);
        }
        else if ( AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) == ICMP_TYPE_ECHO_REPLY )
        {
            SeqId = AnscIcmpv4EchoGetId(pIcmpHeaderIpv4);
        }

        pMyObject->UpdateEntry
            (
                (ANSC_HANDLE)pMyObject,
                SeqId/*pProperty->PktsRecv*/,
                pSocket->pPeerAddrInfo,
                StopTime,
                AnscIcmpv4EchoGetType(pIcmpHeaderIpv4)
            );

        /* AnscTrace("Client Recv : %d Packet, IP %s\n", pProperty->PktsRecv, inet_ntoa(*(ansc_in_addr *)(&pSocket->PeerAddress.Value))); */

        if ( AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) != ICMP_TYPE_ECHO_REPLY &&
             AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) != ICMP_TYPE_TIME_EXCEEDED )
        {
            pMyObject->SetIcmpError
                (
                    (ANSC_HANDLE)pMyObject, pMyObject->GetIcmpError((ANSC_HANDLE)pMyObject) + 1
                );
        }

        if ( AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) == ICMP_TYPE_ECHO_REPLY )
        {
            pProperty->LastHopReached = TRUE;
        }
        else if ( AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) != ICMP_TYPE_TIME_EXCEEDED )
        {
            if ( pMyObject->GetIcmpError((ANSC_HANDLE)pMyObject) == pProperty->NumPkts )
            {
                pProperty->LastHopReached = TRUE;
            }
        }
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        CcspTraceInfo(("!!!!!! Recv ICMP6 type: %d !!!!!!\n", AnscIcmpv6EchoGetType(pIcmpHeaderIpv6)));

        if ( AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) == ICMP6_TYPE_TIME_EXCEEDED )
        {
            pIcmpTeHeaderIpv6 = (PICMPV6_TIME_EXCEEDED_MESSAGE)pIcmpHeaderIpv6;

            pOriIpv6Header = (PIPV6_HEADER)AnscIcmpv6TeGetOrgIp(pIcmpTeHeaderIpv6);

            pOriIcmpHeaderIpv6 = (PICMPV6_ECHO_MESSAGE)((ULONG)pOriIpv6Header + IP6_HEADER_LENGTH);

            SeqId = AnscIcmpv6EchoGetId(pOriIcmpHeaderIpv6);

            CcspTraceInfo(("!!!!!! Recv ICMP6_TYPE_TIME_EXCEEDED SeqId = %lu !!!!!!\n", SeqId));
        }
        else if ( AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) == ICMP6_TYPE_ECHO_REPLY )
        {
            SeqId = AnscIcmpv6EchoGetId(pIcmpHeaderIpv6);

            CcspTraceInfo(("!!!!!! Recv ICMP6_TYPE_ECHO_REPLY SeqId = %lu !!!!!!\n", SeqId));
        }

        pMyObject->UpdateEntry
            (
                (ANSC_HANDLE)pMyObject,
                SeqId/*pProperty->PktsRecv*/,
                pSocket->pPeerAddrInfo,
                StopTime,
                AnscIcmpv6EchoGetType(pIcmpHeaderIpv6)
            );

        /* AnscTrace("Client Recv : %d Packet, IP %s\n", pProperty->PktsRecv, inet_ntoa(*(ansc_in_addr *)(&pSocket->PeerAddress.Value))); */

        if ( AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) != ICMP6_TYPE_ECHO_REPLY &&
             AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) != ICMP6_TYPE_TIME_EXCEEDED )
        {
            pMyObject->SetIcmpError
                (
                    (ANSC_HANDLE)pMyObject, pMyObject->GetIcmpError((ANSC_HANDLE)pMyObject) + 1
                );
        }

        if ( AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) == ICMP6_TYPE_ECHO_REPLY )
        {
            pProperty->LastHopReached = TRUE;
        }
        else if ( AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) != ICMP6_TYPE_TIME_EXCEEDED )
        {
            if ( pMyObject->GetIcmpError((ANSC_HANDLE)pMyObject) == pProperty->NumPkts )
            {
                pProperty->LastHopReached = TRUE;
            }
        }
    }

    uIndex = pProperty->PktsRecv % pProperty->NumPkts;

    if ( !uIndex  )
    {
        if ( pProperty->LastHopReached )
        {
            pDslhTracertObj->DiagnosticState = DSLH_DIAG_STATE_TYPE_Complete;
        }
        else if ( pDslhTracertObj->MaxHopCount > ttl )
        {
            pMyObject->SetTtl( (ANSC_HANDLE)pMyObject, ++ttl );
        }
        else
        {
            pDslhTracertObj->DiagnosticState = DSLH_DIAG_STATE_TYPE_TRAC_Error_MaxHopCount;
        }

        pMyObject->SetIcmpError((ANSC_HANDLE)pMyObject, 0);
    }

    if ( pDslhTracertObj->DiagnosticState == DSLH_DIAG_STATE_TYPE_Requested
        || pDslhTracertObj->DiagnosticState == DSLH_DIAG_STATE_TYPE_Inprogress)
    {
        pMyObject->SendEcho( (ANSC_HANDLE)pMyObject );
    }
    else
    {
        pMyObject->SetStatus((ANSC_HANDLE)pMyObject, BBHM_TRACERT_STATUS_COMPLETE);

        pMyObject->Stop((ANSC_HANDLE)pMyObject);

        AnscTrace("return from TracertCoRecv\n");
    }

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_STATUS
        BbhmDiagitSend
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                    hSinkObject,
                PVOID                       buffer,
                ULONG                       ulSize
            );

    description:

        This function constructs the Dhcps Interface Owner Object and
        initializes the member variables and functions.

    argument:   ANSC_HANDLE                 hContainerContext
                This handle is used by the container object to interact
                with the outside world. It could be the real container
                or an target object.

                PVOID                        buffer
                This is received buffer.

                ULONG                        ulSize
                This is the size of the buffer.

    return:     newly created container object.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSend
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_TRACERT_SINK_OBJECT       pSink        = (PBBHM_TRACERT_SINK_OBJECT       )hSinkObject;
    PANSC_XSOCKET_OBJECT            pSocket      = (PANSC_XSOCKET_OBJECT            )pSink->GetXsocket((ANSC_HANDLE)pSink);
    xskt_addrinfo*                  pAddrInfo    = (xskt_addrinfo*                  )pSocket->pOriPeerAddrInfo;
    /*ANSC_SOCKET_ADDRESS             PeerAddress;*/
/*
    PeerAddress.Address.Value   = pSocket->PeerAddress.Value;
    PeerAddress.Port            = pSocket->PeerPort;

    returnStatus =
        pSocket->Send
            (
                (ANSC_HANDLE)pSocket,
                buffer,
                ulSize,
                &PeerAddress
            );
*/
    returnStatus =
        pSocket->Send2
            (
                (ANSC_HANDLE)pSocket,
                buffer,
                ulSize,
                pAddrInfo
            );

    return  returnStatus;
}
