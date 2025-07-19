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

    module:     bbhm_diagns_process.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the processing functions
        of the Bbhm NSLookup Diagnostic Object.

        *   BbhmDiagnsStartDiag
        *   BbhmDiagnsStopDiag
        *   BbhmDiagnsRetrieveResult
        *   BbhmDiagnsRecv
        *   BbhmDiagnsSend

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


#include "bbhm_diagns_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsStartDiag
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
BbhmDiagnsStartDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject           = (PBBHM_DIAG_NS_LOOKUP_OBJECT)hThisObject;
    PDSLH_NSLOOKUP_INFO             pDiagInfo           = (PDSLH_NSLOOKUP_INFO)pMyObject->hDslhDiagInfo;
    
    if ( pDiagInfo->bForced != FALSE )
    {
        if ( !(pMyObject->CheckCanStart((ANSC_HANDLE)pMyObject)))
        {
            pMyObject->SetControl((ANSC_HANDLE)pMyObject, BBHM_NS_LOOKUP_CONTROL_STOP);
        }
        pMyObject->ResetProperty    ((ANSC_HANDLE)pMyObject);

        if ( pMyObject->SetDstIp    ((ANSC_HANDLE)pMyObject, pDiagInfo->DNSServer) == ANSC_STATUS_SUCCESS)
        {
            pMyObject->SetNumPkts   ((ANSC_HANDLE)pMyObject, pDiagInfo->NumberOfRepetitions);
            pMyObject->SetSrcIp     ((ANSC_HANDLE)pMyObject, pDiagInfo->IfAddr );
            pMyObject->SetTimeOut   ((ANSC_HANDLE)pMyObject, pDiagInfo->Timeout);

            pMyObject->Open         (pMyObject);
            pMyObject->SetControl   ((ANSC_HANDLE)pMyObject, BBHM_NS_LOOKUP_CONTROL_START);
            BbhmDiageoStartDiag     ((ANSC_HANDLE)pMyObject);
        }
        else
        {
            pDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Error_NSLookup_DNSServer;
        }
        return ANSC_STATUS_SUCCESS;
    }
    else
    {
        if ( pMyObject->CheckCanStart   ((ANSC_HANDLE)pMyObject) )
        {
            pMyObject->ResetProperty    ((ANSC_HANDLE)pMyObject);

            if ( pMyObject->SetDstIp    ((ANSC_HANDLE)pMyObject, pDiagInfo->DNSServer) == ANSC_STATUS_SUCCESS)
            {
                pMyObject->SetNumPkts   ((ANSC_HANDLE)pMyObject, pDiagInfo->NumberOfRepetitions);
                pMyObject->SetSrcIp     ((ANSC_HANDLE)pMyObject, pDiagInfo->IfAddr );
                pMyObject->SetTimeOut   ((ANSC_HANDLE)pMyObject, pDiagInfo->Timeout);

                pMyObject->Open         ((ANSC_HANDLE)pMyObject);
                pMyObject->SetControl   ((ANSC_HANDLE)pMyObject, BBHM_NS_LOOKUP_CONTROL_START);
                BbhmDiageoStartDiag     ((ANSC_HANDLE)pMyObject);
            }
            else
            {
                pDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Error_NSLookup_DNSServer;
            }
            return ANSC_STATUS_SUCCESS;
        }
        else
        {
            AnscTraceFlow(("BbhmDiagnsStartDiag -- query task is already running...\n"));

            return  ANSC_STATUS_PENDING;
        }
    }
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsStopDiag
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
BbhmDiagnsStopDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject           = (PBBHM_DIAG_NS_LOOKUP_OBJECT  )hThisObject;

    if ( !(pMyObject->CheckCanStart((ANSC_HANDLE)pMyObject)))
    {
        returnStatus = pMyObject->SetControl((ANSC_HANDLE)pMyObject, BBHM_NS_LOOKUP_CONTROL_STOP);

        return  returnStatus;
    }
    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsRetrieveResult
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
BbhmDiagnsRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject           = (PBBHM_DIAG_NS_LOOKUP_OBJECT  )hThisObject;

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
        BbhmDiagnsRecv
            (
                ANSC_HANDLE                 hThisObject,
                PVOID                       buffer,
                ULONG                       ulSize
            );

    description:

        This function receive packets.

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
BbhmDiagnsRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hXsinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY    )&pMyObject->Property;
    PBBHM_NS_LOOKUP_TDO_OBJECT      pStateTimer  = (PBBHM_NS_LOOKUP_TDO_OBJECT  )pMyObject->hStateTimer;
    PDSLH_NSLOOKUP_INFO             pDiagInfo    = (PDSLH_NSLOOKUP_INFO         )pMyObject->hDslhDiagInfo;
    PDNS_HEADER                     pDnsHeader   = (PDNS_HEADER)buffer;
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pEchoEntry   = NULL;
    PBBHM_NS_LOOKUP_QUERY_ENTRY     pQuery       = NULL;
    ULONG                           StopTime     = 0;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    char*                           p            = NULL;

    StopTime = AnscGetTickInMilliSeconds();


    if ( pProperty->Status != BBHM_NS_LOOKUP_STATUS_RUNNING )
    {
        return  ANSC_STATUS_UNAPPLICABLE;
    }

    /* Temporarily disable this check since we will check pQuery later */
/*
    if ( pXsocket->PeerAddress.Value != pProperty->DstIp.Value )
    {
        return  ANSC_STATUS_FAILURE;
    }
*/

    pQuery = pMyObject->GetPqueryById(pMyObject, AnscDnsGetId(pDnsHeader));
    if ( pQuery )
    {
        if ( AnscDnsGetRcode(pDnsHeader) != 0 )
        {
            if ( AnscDnsGetRcode(pDnsHeader) == DNS_RCODE_NAME_ERROR )
            {
                p = pDiagInfo->HostName + AnscSizeOfString(pDiagInfo->HostName) + 1;

                if ( AnscSizeOfString(p) )
                {
                    if (strcmp(p - AnscSizeOfString(p) - 1, p) != 0)
                    {
                        pStateTimer->Stop((ANSC_HANDLE)pStateTimer);
                        pProperty->Control = BBHM_NS_LOOKUP_CONTROL_STOP;
                        pMyObject->DelAllPqueries(hThisObject);
                        pMyObject->PopEchoEntry(hThisObject);
                        pMyObject->ResetPropertyCounter(hThisObject);

                        *(p - 1) = '.';
                        pMyObject->SetControl   ((ANSC_HANDLE)pMyObject, BBHM_NS_LOOKUP_CONTROL_START);
                        BbhmDiageoStartDiag     ((ANSC_HANDLE)pMyObject);
                        return  ANSC_STATUS_SUCCESS;
                    }
                }
            }


            pSLinkEntry = AnscSListGetFirstEntry(&pMyObject->EchoTable);

            while ( pSLinkEntry )
            {
                pEchoEntry  = ACCESS_BBHM_NS_LOOKUP_ECHO_ENTRY(pSLinkEntry);
                pSLinkEntry = AnscSListGetNextEntry(pSLinkEntry);

                if ( pQuery->QueryId == pEchoEntry->QueryId )
                {
                    break;
                }
            }

            if ( AnscDnsGetRcode(pDnsHeader) == DNS_RCODE_NAME_ERROR )
            {
                pEchoEntry->Status = BBHM_NS_LOOKUP_STATUS_Error_HostNameNotResolved;
            }
            else if ( AnscDnsGetRcode(pDnsHeader) == DNS_RCODE_SERVER_FAILURE ||  AnscDnsGetRcode(pDnsHeader) == DNS_RCODE_REFUSED )
            {
                pEchoEntry->Status = BBHM_NS_LOOKUP_STATUS_Error_DNSServerNotAvailable;
            }
            else
            {
                pEchoEntry->Status = BBHM_NS_LOOKUP_STATUS_Error_Other;
            }
            pEchoEntry->AnswerType = AnscDnsIsAuthoritativeAnswer(pDnsHeader) ? BBHM_NS_LOOKUP_RESULT_Authoritative : BBHM_NS_LOOKUP_RESULT_NonAuthoritative;
            pEchoEntry->HostNameReturned = NULL;
            pEchoEntry->IPAddresses = NULL;
            pMyObject->DelPquery(pMyObject, pQuery);

            pProperty->PktsRecv++;
        }
        else
        {
            returnStatus = pMyObject->SetStopTime((ANSC_HANDLE)pMyObject, pQuery, pDnsHeader, StopTime);

            if ( returnStatus == ANSC_STATUS_SUCCESS )
            {
                pProperty->PktsRecv++;
            }
        }

        if ( pProperty->PktsRecv == pProperty->NumPkts )
        {
            pMyObject->SetStatus((ANSC_HANDLE)pMyObject, BBHM_NS_LOOKUP_STATUS_COMPLETE);
            pMyObject->Stop((ANSC_HANDLE)pMyObject);
        }

        return  returnStatus;
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_STATUS
        BbhmDiagnsSend
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hXsinkObject,
                PVOID                       buffer,
                ULONG                       ulSize
            );

    description:

        This function sends packets to the specific destination.

    argument:   ANSC_HANDLE                 hContainerContext
                This handle is used by the container object to interact
                with the outside world. It could be the real container
                or an target object.

                ANSC_HANDLE                 hXsinkObject
                Handle of sink object.

                PVOID                       buffer
                Handle of send buffer.

                ULONG                       ulSize
                Size of packet sent.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsSend
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hXsinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT )hThisObject;
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink       = (PBBHM_NS_LOOKUP_XSINK_OBJECT)pMyObject->hXsinkObject;
    PANSC_XSOCKET_OBJECT            pXsocket     = (PANSC_XSOCKET_OBJECT        )pXsink->GetXsocket((ANSC_HANDLE)pXsink);
    xskt_addrinfo*                  pAddrInfo    = (xskt_addrinfo*              )pXsocket->pOriPeerAddrInfo;

    /*
    ANSC_SOCKET_ADDRESS             PeerAddress;

    PeerAddress.Address.Value   = pXsocket->PeerAddress.Value;
    PeerAddress.Port            = pXsocket->PeerPort;

    returnStatus =
        pXsocket->Send
            (
                (ANSC_HANDLE)pXsocket,
                buffer,
                ulSize,
                &PeerAddress
            );
    */

    returnStatus =
        pXsocket->Send2
            (
                (ANSC_HANDLE)pXsocket,
                buffer,
                ulSize,
                pAddrInfo
            );

    return  returnStatus;
}

