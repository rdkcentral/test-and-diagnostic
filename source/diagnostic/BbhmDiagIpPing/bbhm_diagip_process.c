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

    module:     bbhm_diagip_process.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the processing functions
        of the Bbhm IpPing Diagnostic Object.

        *   BbhmDiagipStartDiag
        *   BbhmDiagipStopDiag
        *   BbhmDiagipRetrieveResult
        *   BbhmDiagipAccept
        *   BbhmDiagipRecv
        *   BbhmDiagipSend

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


#include "bbhm_diagip_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipStartDiag
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
BbhmDiagipStartDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject           = (PBBHM_DIAG_IP_PING_OBJECT  )hThisObject;
    PDSLH_PING_INFO                 pDiagInfo           = (PDSLH_PING_INFO)pMyObject->hDslhDiagInfo;

    if ( pMyObject->CheckCanStart((ANSC_HANDLE)pMyObject) )
    {
        AnscTraceFlow(("BbhmDiagipStartDiag -- enter...\n"));

        pMyObject->SetEnv(pMyObject);
        pMyObject->ResetProperty((ANSC_HANDLE)pMyObject);

        /* TODO set source interface name here */
        pMyObject->SetSrcIp((ANSC_HANDLE)pMyObject, pDiagInfo->IfAddrName);

        if ( pMyObject->SetDstIp((ANSC_HANDLE)pMyObject, pDiagInfo->Host) == ANSC_STATUS_SUCCESS)
        {
            pMyObject->SetNumPkts((ANSC_HANDLE)pMyObject, pDiagInfo->NumberOfRepetitions);
            pMyObject->SetPktSize((ANSC_HANDLE)pMyObject, pDiagInfo->DataBlockSize);
            pMyObject->SetTimeOut((ANSC_HANDLE)pMyObject, pDiagInfo->Timeout);

            pMyObject->Open(pMyObject);

            if ( pMyObject->hSendBuffer )
            {
                AnscFreeMemory(pMyObject->hSendBuffer);
                pMyObject->hSendBuffer = NULL;
            }

            pMyObject->hSendBuffer = (PCHAR)AnscAllocateMemory(pDiagInfo->DataBlockSize + sizeof(ICMPV4_HEADER));

            if ( !pMyObject->hSendBuffer )
            {
                return  ANSC_STATUS_RESOURCES;
            }

            returnStatus =
                pMyObject->SetControl
                    (
                        (ANSC_HANDLE)pMyObject,
                        BBHM_IP_PING_CONTROL_START
                    );

            if ( returnStatus == ANSC_STATUS_SUCCESS )
            {
                BbhmDiageoStartDiag((ANSC_HANDLE)pMyObject);
            }
            else
            {
                return returnStatus;
            }
        }
        else
        {
            pDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_PING_Error_HostName;
        }

        return ANSC_STATUS_SUCCESS;
    }
    else
    {
        AnscTraceFlow(("BbhmDiagipStartDiag -- query task is running...\n"));

        return  ANSC_STATUS_PENDING;
    }
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipStopDiag
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
BbhmDiagipStopDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject           = (PBBHM_DIAG_IP_PING_OBJECT  )hThisObject;
    PDSLH_PING_INFO                 pDiagInfo           = (PDSLH_PING_INFO)pMyObject->hDslhDiagInfo;

    if ( !(pMyObject->CheckCanStart((ANSC_HANDLE)pMyObject)))
    {
        returnStatus = pMyObject->SetControl((ANSC_HANDLE)pMyObject, BBHM_IP_PING_CONTROL_STOP);
        pDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        return  returnStatus;
    }
    else
    {
        return  ANSC_STATUS_SUCCESS;
    }
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipRetrieveResult
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
BbhmDiagipRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject           = (PBBHM_DIAG_IP_PING_OBJECT  )hThisObject;

    if ( pMyObject->hDslhDiagInfo )
    {
        return  returnStatus;
    }
    else
    {
        return  ANSC_STATUS_INTERNAL_ERROR;
    }
}

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_STATUS
        BbhmDiagipAccept
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hNewSocket
            );

    description:

        This function constructs the Dhcps Interface Owner Object and
        initializes the member variables and functions.

    argument:   ANSC_HANDLE                 hContainerContext
                This handle is used by the container object to interact
                with the outside world. It could be the real container
                or an target object.

                PVOID                       buffer
                This is received buffer.

                ULONG                       ulSize
                This is the size of the buffer.

    return:     newly created container object.

**********************************************************************/

ANSC_STATUS
BbhmDiagipAccept
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hNewSocket
    )
{
    
    return  ANSC_STATUS_UNAPPLICABLE;
}

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_STATUS
        BbhmDiagipRecv
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
BbhmDiagipRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;
    PBBHM_IP_PING_SINK_OBJECT       pSink        = (PBBHM_IP_PING_SINK_OBJECT     )hSinkObject;
    PANSC_XSOCKET_OBJECT            pSocket      = (PANSC_XSOCKET_OBJECT          )pSink->GetXsocket((ANSC_HANDLE)pSink);
    PIPV4_HEADER                    pIpv4Header  = (PIPV4_HEADER                  )NULL;
    /*PIPV6_HEADER                    pIpv6Header  = (PIPV6_HEADER                  )NULL;*/
    PICMPV4_ECHO_MESSAGE            pIcmpHeaderIpv4  = (PICMPV4_ECHO_MESSAGE          )NULL;
    PICMPV6_ECHO_MESSAGE            pIcmpHeaderIpv6  = (PICMPV6_ECHO_MESSAGE          )NULL;
    PBBHM_IP_PING_ECHO_ENTRY        pMEchoEntry  = NULL;
    ULONG                           StopTime     = 0;

    StopTime = AnscGetTickInMilliSeconds();

    if ( pProperty->Status != BBHM_IP_PING_STATUS_RUNNING )
    {
        return  ANSC_STATUS_UNAPPLICABLE;
    }

    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET )
    {
        pIpv4Header = (PIPV4_HEADER)buffer;
        pIcmpHeaderIpv4 = (PICMPV4_ECHO_MESSAGE)AnscIpv4GetPayload(pIpv4Header);

        if ((strcmp(pSocket->PeerName, pProperty->pDstAddrName) != 0) /*(pSocket->PeerAddress.Value != pProperty->DstIp.Value)*/
            || (AnscIcmpv4EchoGetId(pIcmpHeaderIpv4) !=  tempId) )
        {
            return  ANSC_STATUS_FAILURE;
        }

        if ( (AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) == ICMP_TYPE_DESTINATION_UNREACHABLE)
            || (AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) == ICMP_TYPE_TIME_EXCEEDED)
            || (AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) == ICMP_TYPE_PARAMETER_PROBLEM)
            || (AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) == ICMP_TYPE_SOURCE_QUENCH)
            || (AnscIcmpv4EchoGetType(pIcmpHeaderIpv4) == ICMP_TYPE_REDIRECT))
        {
            pProperty->NumIcmpError ++;
            pProperty->IcmpError = AnscIcmpv4EchoGetType(pIcmpHeaderIpv4);

            pMEchoEntry = (PBBHM_IP_PING_ECHO_ENTRY)AnscAllocateMemory(sizeof(BBHM_IP_PING_ECHO_ENTRY));
            if ( pMEchoEntry )
            {
                pMEchoEntry->ICMPType = AnscIcmpv4EchoGetType(pIcmpHeaderIpv4);
                AnscAcquireLock(&pMyObject->MiddleResultLock);
                AnscSListPushEntryAtBack(&pMyObject->MiddleResult, &pMEchoEntry->Linkage);
                AnscReleaseLock(&pMyObject->MiddleResultLock);
            }

            return  ANSC_STATUS_FAILURE;
        }

        returnStatus =
            pMyObject->SetStopTime
                (
                    (ANSC_HANDLE)pMyObject,
                    AnscIcmpv4EchoGetSeqNumber(pIcmpHeaderIpv4),
                    AnscIpv4GetTotalLength(pIpv4Header) - sizeof(IPV4_HEADER) - sizeof(ICMPV4_HEADER),
                    AnscIpv4GetTtl(pIpv4Header),
                    StopTime
                );
    }
    else if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        pIcmpHeaderIpv6 = (PICMPV6_ECHO_MESSAGE)buffer;

        if ((strcmp(pSocket->PeerName, pProperty->pDstAddrName) != 0) /*(pSocket->PeerAddress.Value != pProperty->DstIp.Value)*/
            || (AnscIcmpv6EchoGetId(pIcmpHeaderIpv6) !=  tempId) )
        {
            return  ANSC_STATUS_FAILURE;
        }

        if ( (AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) == ICMP6_TYPE_DESTINATION_UNREACHABLE)
            || (AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) == ICMP6_TYPE_TIME_EXCEEDED)
            || (AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) == ICMP6_TYPE_PARAMETER_PROBLEM)
            || (AnscIcmpv6EchoGetType(pIcmpHeaderIpv6) == ICMP6_TYPE_PACKET_TOO_BIG))
        {
            pProperty->NumIcmpError ++;
            pProperty->IcmpError = AnscIcmpv6EchoGetType(pIcmpHeaderIpv6);

            pMEchoEntry = (PBBHM_IP_PING_ECHO_ENTRY)AnscAllocateMemory(sizeof(BBHM_IP_PING_ECHO_ENTRY));
            if ( pMEchoEntry )
            {
                pMEchoEntry->ICMPType = AnscIcmpv6EchoGetType(pIcmpHeaderIpv6);
                AnscAcquireLock(&pMyObject->MiddleResultLock);
                AnscSListPushEntryAtBack(&pMyObject->MiddleResult, &pMEchoEntry->Linkage);
                AnscReleaseLock(&pMyObject->MiddleResultLock);
            }

            return  ANSC_STATUS_FAILURE;
        }

        returnStatus =
            pMyObject->SetStopTime
                (
                    (ANSC_HANDLE)pMyObject,
                    AnscIcmpv6EchoGetSeqNumber(pIcmpHeaderIpv6),
                    ulSize,
                    0,           /* Hop Limit */
                    StopTime
                );
    }

    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        pProperty->PktsRecv ++;
    }

    if ( pProperty->PktsRecv == pProperty->NumPkts )
    {
        pMyObject->SetStatus((ANSC_HANDLE)pMyObject, BBHM_IP_PING_STATUS_COMPLETE);
        pMyObject->Stop((ANSC_HANDLE)pMyObject);
    }

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_STATUS
        BbhmDiagipSend
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hSinkObject,
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

                PVOID                       buffer
                This is received buffer.

                ULONG                       ulSize
                This is the size of the buffer.

    return:     newly created container object.

**********************************************************************/

ANSC_STATUS
BbhmDiagipSend
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_IP_PING_SINK_OBJECT       pSink        = (PBBHM_IP_PING_SINK_OBJECT)hSinkObject;
    PANSC_XSOCKET_OBJECT            pSocket      = (PANSC_XSOCKET_OBJECT     )pSink->GetXsocket((ANSC_HANDLE)pSink);
    xskt_addrinfo*                  pAddrInfo    = (xskt_addrinfo*           )pSocket->pOriPeerAddrInfo;
    /*ANSC_SOCKET_ADDRESS             PeerAddress;*/
/*
    PeerAddress.Address.Value      = pSocket->PeerAddress.Value;
    PeerAddress.Port               = pSocket->PeerPort;

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
