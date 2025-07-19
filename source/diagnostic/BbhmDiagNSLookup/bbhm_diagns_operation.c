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

    module:     bbhm_diagns_operation.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the processing functions
        of the Bbhm NSLookup Diagnostic Object.

        *   BbhmDiagnsStart
        *   BbhmDiagnsStop
        *   BbhmDiagnsExpire1
        *   BbhmDiagnsExpire2
        *   BbhmDiagnsAddEchoEntry
        *   BbhmDiagnsPopEchoEntry
        *   BbhmDiagnsOpen
        *   BbhmDiagnsAddPquery
        *   BbhmDiagnsGetPqueryById
        *   BbhmDiagnsDelPquery
        *   BbhmDiagnsDelAllPqueries
        *   BbhmDiagnsSetStopTime
        *   BbhmDiagnsClose
        *   BbhmDiagnsCalculateResult

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
#include "safec_lib_common.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsStart
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
BbhmDiagnsStart
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT )hThisObject;
    PDSLH_NSLOOKUP_INFO             pDiagInfo    = (PDSLH_NSLOOKUP_INFO         )pMyObject->hDslhDiagInfo;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY    )&pMyObject->Property;
    PBBHM_NS_LOOKUP_TDO_OBJECT      pStateTimer  = (PBBHM_NS_LOOKUP_TDO_OBJECT  )pMyObject->hStateTimer;
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink       = (PBBHM_NS_LOOKUP_XSINK_OBJECT)pMyObject->hXsinkObject;
    PANSC_XSOCKET_OBJECT            pXsocket     = (PANSC_XSOCKET_OBJECT        )pXsink->GetXsocket((ANSC_HANDLE)pXsink);
    PBBHM_NS_LOOKUP_QUERY_ENTRY     pQuery       = NULL;
    PCHAR                           pSendBuffer  = pMyObject->hSendBuffer;
    PDNS_HEADER                     pDnsHeader   = NULL;
    char*                           pDnsQdSection= NULL;
    ULONG                           StartTime    = 0;
    char*                           pDnsQdEntry  = NULL;
    char*                           query_name   = NULL;
    ULONG                           EntrySize    = 0;

    if ( !pMyObject->bActive )
    {
        pProperty->Status = BBHM_NS_LOOKUP_STATUS_INTERNAL;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    pMyObject->ResetPropertyCounter((ANSC_HANDLE)pMyObject);

    /* Need to set source ip address accord to the interface */
    /*
    pXsocket->SetHostAddress  ((ANSC_HANDLE)pXsocket, pProperty->SrcIp.Dot  );
    pXsocket->SetHostPort     ((ANSC_HANDLE)pXsocket, 0                     );
    */

    pXsocket->SetHostName     ((ANSC_HANDLE)pXsocket, pProperty->SrcAddrName);
    pXsocket->SetPeerName     ((ANSC_HANDLE)pXsocket, pProperty->DstAddrName);
    pXsocket->SetPeerPort     ((ANSC_HANDLE)pXsocket, DNS_SERVER_PORT       );

    pXsocket->SetTransportType((ANSC_HANDLE)pXsocket, UDP_TRANSPORT         );
    pXsocket->SetType         ((ANSC_HANDLE)pXsocket, ANSC_XSOCKET_TYPE_UDP );
    pXsocket->SetMode         ((ANSC_HANDLE)pXsocket, 0                     );

    pXsocket->SetXsink        ((ANSC_HANDLE)pXsocket, (ANSC_HANDLE)pXsink   );

    /*
     * The underlying socket wrapper may require an explicit startup() call, such is the case on
     * Microsoft windows platforms. The wrapper initialization has to done for each task. On most
     * real-time operating systems, this call is not required.
     */
    AnscStartupXsocketWrapper((ANSC_HANDLE)pMyObject);

    /* For IPv4/IPv6 compatible purpose we shall resolve the address first */
    returnStatus = pXsocket->ResolveAddr((ANSC_HANDLE)pXsocket);

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        pProperty->Status = BBHM_NS_LOOKUP_STATUS_Error_DNSServerNotAvailable;

        pMyObject->Stop(hThisObject);

        return ANSC_STATUS_FAILURE;
    }

    pMyObject->IPProtocol = pXsocket->GetIpProtocol((ANSC_HANDLE)pXsocket);

    /*
     * We shall open the socket and listen on it right away. Since we're still in the context of
     * initialiation, the wrapper module must be aware of the fact that the socket is opened before
     * the first call returns.
     */
    returnStatus = pXsocket->Bind((ANSC_HANDLE)pXsocket);

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        pProperty->Status = BBHM_NS_LOOKUP_STATUS_INTERNAL;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    returnStatus = pXsocket->Open((ANSC_HANDLE)pXsocket);

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        AnscTrace("Xsocket Open Failed!\n");
        pProperty->Status = BBHM_NS_LOOKUP_STATUS_INTERNAL;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    if ( !pSendBuffer )
    {
        returnStatus = ANSC_STATUS_FAILURE;
        pProperty->Status = BBHM_NS_LOOKUP_STATUS_INTERNAL;

        pMyObject->Stop(hThisObject);

        return  ANSC_STATUS_FAILURE;
    }

    AnscSleep(100);
    pDnsHeader = (PDNS_HEADER)pMyObject->hSendBuffer;

    AnscDnsSetId                 (pDnsHeader, (USHORT)pMyObject->QueryId++   );
    AnscDnsSetMessageType        (pDnsHeader, (USHORT)DNS_MESSAGE_TYPE_QUERY );
    AnscDnsSetOpCode             (pDnsHeader, (USHORT)DNS_OPCODE_QUERY       );
    AnscDnsSetAuthoritativeAnswer(pDnsHeader, (USHORT)1                      );
    AnscDnsSetTruncated          (pDnsHeader, (USHORT)0                      );
    AnscDnsSetRecursionDesired   (pDnsHeader, (USHORT)1                      );
    AnscDnsSetRecursionAvailable (pDnsHeader, (USHORT)0                      );
    AnscDnsSetRcode              (pDnsHeader, (USHORT)DNS_RCODE_NO_ERROR     );
    AnscDnsSetQdCount            (pDnsHeader, (USHORT)1                      );
    AnscDnsSetAnCount            (pDnsHeader, (USHORT)0                      );
    AnscDnsSetNsCount            (pDnsHeader, (USHORT)0                      );
    AnscDnsSetArCount            (pDnsHeader, (USHORT)0                      );
    AnscDnsGetQdSection          (pDnsHeader, pDnsQdSection                  );
    AnscDnsQdSectionGetEntry     (pDnsHeader, pDnsQdSection, 0, pDnsQdEntry  );

    query_name = (char*)AnscAllocateMemory(AnscSizeOfString(pDiagInfo->HostName) + 4);

    if ( !query_name )
    {
        return ANSC_STATUS_RESOURCES;
    }

    errno_t rc = -1;
    rc = strcpy_s(query_name, AnscSizeOfString(pDiagInfo->HostName) + 4 , pDiagInfo->HostName);
    ERR_CHK(rc);

    if ( query_name[AnscSizeOfString(query_name) - 1] != '.' )
    {
        query_name[AnscSizeOfString(query_name)] = '.';
    }

    AnscDnsQdEntrySetQNameString(pDnsHeader, pDnsQdEntry, query_name, AnscSizeOfString(query_name));

    if ( pMyObject->IPProtocol == XSKT_SOCKET_AF_INET6 )
    {
        CcspTraceInfo(("IPv6 DNS Server detected, use \"AAAA\" type.\n"));

        AnscDnsQdEntrySetQType(pDnsHeader, pDnsQdEntry, DNS_RR_TYPE_AAAA);
    }
    else
    {
        CcspTraceInfo(("Use \"A\" type.\n"));

        AnscDnsQdEntrySetQType(pDnsHeader, pDnsQdEntry, DNS_RR_TYPE_A);
    }

    AnscDnsQdEntrySetQClass  (pDnsHeader, pDnsQdEntry, DNS_RR_CLASS_IN          );

    pStateTimer->SetTimerType((ANSC_HANDLE)pStateTimer, ANSC_TIMER_TYPE_SPORADIC);
    pStateTimer->SetInterval ((ANSC_HANDLE)pStateTimer, pProperty->TimeBetween  );
    pStateTimer->SetCounter  ((ANSC_HANDLE)pStateTimer, pProperty->NumPkts      );

    pMyObject->SetStatus     ((ANSC_HANDLE)pMyObject, BBHM_NS_LOOKUP_STATUS_RUNNING);

    pStateTimer->Start       ((ANSC_HANDLE)pStateTimer);
    AnscDnsQdEntryGetSize    (pDnsHeader, pDnsQdEntry, EntrySize);
    pProperty->PktSize = sizeof(DNS_HEADER) + EntrySize;

    pQuery = AnscAllocateMemory(sizeof(BBHM_NS_LOOKUP_QUERY_ENTRY));
    if ( !pQuery )
    {
        pProperty->Status = BBHM_NS_LOOKUP_STATUS_ABORT;
        pMyObject->Stop(hThisObject);
        AnscFreeMemory(query_name); /*RDKB-7453, CID-32901, free unused memory*/
        return  ANSC_STATUS_FAILURE;
    }
    pQuery->QueryId = AnscDnsGetId(pDnsHeader);
    pMyObject->AddPquery(pMyObject, pQuery);

    StartTime = AnscGetTickInMilliSeconds();

    returnStatus =
        pMyObject->AddEchoEntry
            (
                (ANSC_HANDLE)pMyObject,
                pProperty->DstAddrName,
                AnscDnsGetId(pDnsHeader),
                StartTime
            );

    returnStatus =
        pMyObject->Send
            (
                (ANSC_HANDLE)pMyObject,
                (ANSC_HANDLE)pMyObject->hXsinkObject,
                (PVOID)pMyObject->hSendBuffer,
                pProperty->PktSize
             );

    pProperty->PktsSent++;

    AnscFreeMemory(query_name); /*RDKB-7453, CID-32901, free unused memory*/
    return  returnStatus;

}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsStop
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
BbhmDiagnsStop
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;
    PBBHM_NS_LOOKUP_TDO_OBJECT      pStateTimer  = (PBBHM_NS_LOOKUP_TDO_OBJECT    )pMyObject->hStateTimer;
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink       = (PBBHM_NS_LOOKUP_XSINK_OBJECT  )pMyObject->hXsinkObject;
    PANSC_XSOCKET_OBJECT            pXsocket     = NULL;
    PDSLH_NSLOOKUP_INFO             pDslhDiagInfo= (PDSLH_NSLOOKUP_INFO           )pMyObject->hDslhDiagInfo;
    ULONG                           MaxRetrieve  = 0;

    if ( pMyObject->bActive )
    {
        pStateTimer->Stop((ANSC_HANDLE)pStateTimer);
        pStateTimer->SetStopTime((ANSC_HANDLE)pStateTimer, AnscGetTickInMilliSeconds());

        AnscAcquireLock(&pMyObject->EchoTableLock);
        MaxRetrieve = AnscSListQueryDepth(&pMyObject->EchoTable);
        AnscReleaseLock(&pMyObject->EchoTableLock);

        returnStatus = pMyObject->CalculateResult((ANSC_HANDLE)pMyObject, MaxRetrieve);

        if ( pXsink )
        {
            pXsocket = (PANSC_XSOCKET_OBJECT)pXsink->GetXsocket((ANSC_HANDLE)pXsink);
            pXsocket->Close((ANSC_HANDLE)pXsocket);
        }
    }

    switch ( pMyObject->GetStatus((ANSC_HANDLE)pMyObject) )
    {
        case  BBHM_NS_LOOKUP_STATUS_COMPLETE:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Complete;

                break;

        case  BBHM_NS_LOOKUP_STATUS_ABORT:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Error_NSLookup_Internal;

                break;

        case  BBHM_NS_LOOKUP_STATUS_STOP:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Complete;

                break;

        case  BBHM_NS_LOOKUP_STATUS_TIMEOUT:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Complete;

                break;

        case  BBHM_NS_LOOKUP_STATUS_DNS:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Error_NSLookup_DNSServer;

                break;

        case  BBHM_NS_LOOKUP_STATUS_INTERNAL:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Error_NSLookup_Internal;

                break;

        case  BBHM_NS_LOOKUP_STATUS_OTHER:

                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Error_NSLookup_Other;

                break;

        default:
                pDslhDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;

                return  returnStatus;
    }

    pMyObject->bResultQueryRunning          = FALSE;
    pMyObject->ResultTimestamp              = AnscGetTickInSeconds();
    pDslhDiagInfo->ResultNumberOfEntries    = MaxRetrieve;
    pDslhDiagInfo->SuccessCount             = pProperty->NumDnsSuccess;
    pDslhDiagInfo->UpdatedAt                = AnscGetTickInSeconds();

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsExpire1
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retry the send task.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsExpire1
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY    )&pMyObject->Property;
    PDNS_HEADER                     pDnsHeader   = (PDNS_HEADER                 )pMyObject->hSendBuffer;
    ULONG                           StartTime    = 0;
    PBBHM_NS_LOOKUP_QUERY_ENTRY     pQuery       = NULL;

    AnscDnsSetId(pDnsHeader, (USHORT)pMyObject->QueryId++);
    StartTime = AnscGetTickInMilliSeconds();

    pQuery = AnscAllocateMemory(sizeof(BBHM_NS_LOOKUP_QUERY_ENTRY));

    if ( !pQuery )
    {
        pProperty->Status = BBHM_NS_LOOKUP_STATUS_ABORT;
        pMyObject->Stop(hThisObject);
        return  ANSC_STATUS_RESOURCES;
    }

    pQuery->QueryId = AnscDnsGetId(pDnsHeader);
    pMyObject->AddPquery(pMyObject, pQuery);


    returnStatus =
        pMyObject->AddEchoEntry
            (
                (ANSC_HANDLE)pMyObject,
                pProperty->DstAddrName,
                AnscDnsGetId(pDnsHeader),
                StartTime
            );

    returnStatus =
        pMyObject->Send
            (
                (ANSC_HANDLE)pMyObject,
                (ANSC_HANDLE)pMyObject->hXsinkObject,
                (PVOID)pMyObject->hSendBuffer,
                pProperty->PktSize
             );

    pProperty->PktsSent++;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsExpire2
            (
                ANSC_HANDLE                 hThisObject
            )

    description:

        This function is called to abort the send task.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsExpire2
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT )hThisObject;

    pMyObject->SetStatus((ANSC_HANDLE)pMyObject, BBHM_NS_LOOKUP_STATUS_TIMEOUT);
    pMyObject->Stop((ANSC_HANDLE)pMyObject);

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsAddEchoEntry
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       Dstip,
                USHORT                      Index,
                ULONG                       StartTime
            );

    description:

        This function is called to set  Echo Entry information.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ULONG                       Dstip
                The destination of the packets.

                USHORT                      Index
                Index of packets sent

                ULONG                       StartTime
                Time to start the query.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsAddEchoEntry
    (
        ANSC_HANDLE                 hThisObject,
        char*                       DstIpName,
        USHORT                      Index,
        ULONG                       StartTime
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pEchoEntry   = NULL;
    PBBHM_NS_LOOKUP_QUERY_ENTRY     pPquery      = NULL;
    
    pEchoEntry = (PBBHM_NS_LOOKUP_ECHO_ENTRY)AnscAllocateMemory(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));

    if ( !pEchoEntry )
    {
        return  ANSC_STATUS_RESOURCES;
    }

    pEchoEntry->Status              = BBHM_NS_LOOKUP_STATUS_Error_Other;
    pEchoEntry->QueryId             = Index;
    pEchoEntry->StartTime           = StartTime;
    pEchoEntry->StopTime            = 0;
    pEchoEntry->DNSServerIPName     = AnscCloneString(DstIpName);

    if (strlen(pProperty->DstAddrName) == 0)
    {
        pEchoEntry->Status              = BBHM_NS_LOOKUP_STATUS_Error_DNSServerNotAvailable;
        pEchoEntry->AnswerType          = BBHM_NS_LOOKUP_RESULT_None;
        pEchoEntry->HostNameReturned    = NULL;
        pEchoEntry->IPAddresses         = NULL;

        if ( pEchoEntry->DNSServerIPName )
        {
            AnscFreeMemory(pEchoEntry->DNSServerIPName);
            pEchoEntry->DNSServerIPName = NULL;
        }

        pProperty->Status               = BBHM_NS_LOOKUP_STATUS_DNS;

        pPquery = pMyObject->GetPqueryById(pMyObject, Index);
        pMyObject->DelPquery(pMyObject, pPquery);
    }

    AnscAcquireLock(&pMyObject->EchoTableLock);
    AnscSListPushEntry(&pMyObject->EchoTable, &pEchoEntry->Linkage);
    AnscReleaseLock(&pMyObject->EchoTableLock);

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsPopEchoEntry
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
BbhmDiagnsPopEchoEntry
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pEchoEntry   = NULL;
    
    AnscAcquireLock(&pMyObject->EchoTableLock);
    pSLinkEntry = AnscSListPopEntry(&pMyObject->EchoTable);

    while ( pSLinkEntry )
    {
        pEchoEntry                      = ACCESS_BBHM_NS_LOOKUP_ECHO_ENTRY(pSLinkEntry);
        pSLinkEntry                     = AnscSListPopEntry(&pMyObject->EchoTable);

        AnscFreeMemory(pEchoEntry->HostNameReturned);
        pEchoEntry->HostNameReturned = NULL;
        AnscFreeMemory(pEchoEntry->IPAddresses);
        pEchoEntry->IPAddresses = NULL;
        AnscFreeMemory(pEchoEntry->DNSServerIPName);
        pEchoEntry->DNSServerIPName = NULL;
        AnscFreeMemory(pEchoEntry);
        pEchoEntry = NULL;
    }

    AnscReleaseLock(&pMyObject->EchoTableLock);

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsOpen
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to open the Xsocket and start the send task.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsOpen
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink        = NULL;
    PANSC_XSOCKET_OBJECT            pXsocket      = NULL;

    if ( pMyObject->bActive == TRUE )
    {
        return returnStatus;
    }

    if ( pProperty->Status == BBHM_NS_LOOKUP_STATUS_RUNNING )
    {
        return  ANSC_STATUS_FAILURE;
    }

    pXsink = (PBBHM_NS_LOOKUP_XSINK_OBJECT)BbhmDiagnsXsinkCreate((ANSC_HANDLE)pMyObject);

    if ( !pXsink )
    {
        return  ANSC_STATUS_FAILURE;
    }

    pXsocket =
        (PANSC_XSOCKET_OBJECT)AnscCreateXsocket
            (
                pMyObject->hContainerContext,
                (ANSC_HANDLE)pMyObject,
                (ANSC_HANDLE)NULL
            );

    if ( !pXsocket )
    {
        pXsink->Remove((ANSC_HANDLE)pXsink);

        return  ANSC_STATUS_FAILURE;
    }
    else
    {
        pXsink->SetXsocket((ANSC_HANDLE)pXsink, (ANSC_HANDLE)pXsocket);
    }

    pMyObject->hXsinkObject = pXsink;

    pMyObject->ResetPropertyCounter((ANSC_HANDLE)pMyObject);

    pMyObject->bActive = TRUE;

    return  returnStatus;
}



/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsAddPquery
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hPquery
            );

    description:

        This function is called to add a pending query.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hPquery
                Specifies the pquery entry to be added.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsAddPquery
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hPquery
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject       = (PBBHM_DIAG_NS_LOOKUP_OBJECT  )hThisObject;
    PBBHM_NS_LOOKUP_QUERY_ENTRY     pPquery         = (PBBHM_NS_LOOKUP_QUERY_ENTRY  )hPquery;

    AnscAcquireLock(&pMyObject->PqueryTableLock);
    AnscSListPushEntry (&pMyObject->PqueryTable, &pPquery->Linkage);
    AnscReleaseLock(&pMyObject->PqueryTableLock);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        BbhmDiagnsGetPqueryById
            (
                ANSC_HANDLE                 hThisObject,
                USHORT                      id
            );

    description:

        This function is called to search a pending query.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                USHORT                      id
                Specifies the query id to be matched.

    return:     matched entry.

**********************************************************************/

ANSC_HANDLE
BbhmDiagnsGetPqueryById
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                      id
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject       = (PBBHM_DIAG_NS_LOOKUP_OBJECT  )hThisObject;
    PBBHM_NS_LOOKUP_QUERY_ENTRY     pPquery         = NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry     = NULL;

    AnscAcquireLock(&pMyObject->PqueryTableLock);

    pSLinkEntry = AnscSListGetFirstEntry(&pMyObject->PqueryTable);

    while ( pSLinkEntry )
    {
        pPquery     = ACCESS_BBHM_NS_LOOKUP_QUERY_ENTRY(pSLinkEntry);
        pSLinkEntry = AnscSListGetNextEntry(pSLinkEntry);

        if ( pPquery->QueryId == id )
        {
            AnscReleaseLock(&pMyObject->PqueryTableLock);

            return  (ANSC_HANDLE)pPquery;
        }
    }

    AnscReleaseLock(&pMyObject->PqueryTableLock);

    return  (ANSC_HANDLE)NULL;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsDelPquery
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hPquery
            );

    description:

        This function is called to delete a pending query.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hPquery
                Specifies the pquery entry to be deleted.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsDelPquery
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hPquery
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject       = (PBBHM_DIAG_NS_LOOKUP_OBJECT  )hThisObject;
    PBBHM_NS_LOOKUP_QUERY_ENTRY     pPquery         = (PBBHM_NS_LOOKUP_QUERY_ENTRY)hPquery;
    
    AnscAcquireLock    (&pMyObject->PqueryTableLock);
    if (!(AnscSListPopEntryByLink(&pMyObject->PqueryTable, &pPquery->Linkage)))
    {
        AnscReleaseLock    (&pMyObject->PqueryTableLock);
        return ANSC_STATUS_FAILURE;
    }
    AnscReleaseLock    (&pMyObject->PqueryTableLock);

    BbhmDiagnsFreePquery(pPquery);

    return  ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsDelAllPqueries
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to delete all pending queries.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsDelAllPqueries
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject       = (PBBHM_DIAG_NS_LOOKUP_OBJECT  )hThisObject;
    PBBHM_NS_LOOKUP_QUERY_ENTRY     pPquery         = NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry     = NULL;

    AnscAcquireLock(&pMyObject->PqueryTableLock);

    pSLinkEntry = AnscSListPopEntry(&pMyObject->PqueryTable);

    while ( pSLinkEntry )
    {
        pPquery     = ACCESS_BBHM_NS_LOOKUP_QUERY_ENTRY(pSLinkEntry);
        pSLinkEntry = AnscSListPopEntry(&pMyObject->PqueryTable);
        BbhmDiagnsFreePquery(pPquery);
    }


    AnscReleaseLock(&pMyObject->PqueryTableLock);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsSetStopTime
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hQuery,
                ANSC_HANDLE                 hDnsHeader
                ULONG                       StopTime
            );

    description:

        This function is called to close this object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hQuery
                Handle of query object associated.

                ANSC_HANDLE                 hDnsHeader
                Handle of the dns packet header.

                ULONG                       StopTime
                Time when query stopped.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsSetStopTime
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hQuery,
        ANSC_HANDLE                 hDnsHeader,
        ULONG                       StopTime
    )
{
    ANSC_STATUS                     returnStatus            = ANSC_STATUS_FAILURE;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject               = (PBBHM_DIAG_NS_LOOKUP_OBJECT  )hThisObject;
    PBBHM_NS_LOOKUP_QUERY_ENTRY     pQuery                  = (PBBHM_NS_LOOKUP_QUERY_ENTRY  )hQuery;
    PSINGLE_LINK_ENTRY              pSLinkEntry             = NULL;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty               = (PBBHM_NS_LOOKUP_PROPERTY     )&pMyObject->Property;
    PDSLH_NSLOOKUP_INFO             pDiagInfo               = (PDSLH_NSLOOKUP_INFO          )pMyObject->hDslhDiagInfo;
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pEchoEntry              = NULL;
    PDNS_HEADER                     pDnsHeader              = (PDNS_HEADER)hDnsHeader;
    char*                           pAnSection              = NULL;
    ULONG                           i                       = 0;
    ULONG                           ulIpCount               = 0;
    ULONG                           AnCount                 = AnscDnsGetAnCount(pDnsHeader);
    USHORT                          usDnsRrType             = (USHORT)DNS_RR_TYPE_A;
    USHORT                          usDnsRrClass            = (USHORT)DNS_RR_CLASS_IN;
    char*                           pAnEntry                = NULL;
    //ULONG                           RdLen;
    char                            addr[INET6_ADDRSTRLEN]  = {0};
    char*                           p                       = NULL;

    CcspTraceInfo(("!!! In BbhmDiagnsSetStopTime !!!\n"));

    AnscAcquireLock(&pMyObject->EchoTableLock);
    pSLinkEntry = AnscSListGetFirstEntry(&pMyObject->EchoTable);

    while ( pSLinkEntry )
    {
        pEchoEntry = (PBBHM_NS_LOOKUP_ECHO_ENTRY)ACCESS_BBHM_NS_LOOKUP_ECHO_ENTRY(pSLinkEntry);
        pSLinkEntry = AnscSListGetNextEntry(pSLinkEntry);

        if ( pEchoEntry->QueryId == pQuery->QueryId )
        {
            if ( (StopTime - pEchoEntry->StartTime <= pProperty->TimeOut) && (pEchoEntry->StopTime == 0) )
            {
                returnStatus                 = ANSC_STATUS_SUCCESS;
                pProperty->NumDnsSuccess++;
                pEchoEntry->StopTime         = StopTime;
                pEchoEntry->ResponsTime      = StopTime - pEchoEntry->StartTime;
                pEchoEntry->Status           = BBHM_NS_LOOKUP_STATUS_Success;
                pEchoEntry->AnswerType       = AnscDnsIsAuthoritativeAnswer(pDnsHeader) ? BBHM_NS_LOOKUP_RESULT_Authoritative : BBHM_NS_LOOKUP_RESULT_NonAuthoritative;
                pEchoEntry->HostNameReturned = AnscCloneString(pDiagInfo->HostName);
                AnscDnsGetAnSection(pDnsHeader, pAnSection);

                pEchoEntry->IPAddresses      = AnscAllocateMemory(NS_LOOKUP_ENTRY_MAX_IPADDRESS * (INET6_ADDRSTRLEN + 1));

                if ( !pEchoEntry->IPAddresses )
                {
	            AnscReleaseLock(&pMyObject->EchoTableLock); //CID-135254 - Missing unlock
                    return ANSC_STATUS_RESOURCES;
                }

                //if dns server returned more than one answer, the first one should be CNAME as HostNameReturned in tr157,
                //or there will be no host name returned.

                for ( i = 0; i < AnCount; i++ )
                {
                    AnscDnsArSectionGetEntry (pDnsHeader, pAnSection, i, pAnEntry);
                    //AnscDnsRrEntryGetRdLength(pDnsHeader, pAnEntry, RdLen);
                    AnscDnsRrEntryGetType    (pDnsHeader, pAnEntry, usDnsRrType);
                    AnscDnsRrEntryGetClass   (pDnsHeader, pAnEntry, usDnsRrClass);

                    if ( (usDnsRrClass == DNS_RR_CLASS_IN) && (usDnsRrType == DNS_RR_TYPE_A || usDnsRrType == DNS_RR_TYPE_AAAA) )
                    {
                        switch ( usDnsRrType )
                        {
                            case    DNS_RR_TYPE_A:

                                AnscDnsRrEntryGetRdata(pDnsHeader, pAnEntry, p);
                                inet_ntop(AF_INET, p, addr, INET_ADDRSTRLEN);

                                break;

                            case    DNS_RR_TYPE_AAAA:

                                AnscDnsRrEntryGetRdata(pDnsHeader, pAnEntry, p);
                                inet_ntop(AF_INET6, p, addr, INET6_ADDRSTRLEN);

                                break;

                        }

                        /* Comma-separated list(up to 10 items) of IPAddresses */
                        if ( ulIpCount != 0 )
                        {
                            AnscCatString (pEchoEntry->IPAddresses, ",");
                        }

                        AnscCatString(pEchoEntry->IPAddresses, addr);
                        ulIpCount++;

                        if ( ulIpCount == NS_LOOKUP_ENTRY_MAX_IPADDRESS )
                        {
                            break;
                        }

                    }
                }
/*
                ULONG                           k                       = 0;
                INT                             tmp;
                ULONG                           j                       = 0;
    
                for(i = 0, j = 0; i < AnCount; i++)
                {
                    AnscDnsArSectionGetEntry (pDnsHeader, pAnSection, i, pAnEntry);
                    AnscDnsRrEntryGetRdLength(pDnsHeader, pAnEntry, RdLen);
                    AnscDnsRrEntryGetType    (pDnsHeader, pAnEntry, usDnsRrType);
                    AnscDnsRrEntryGetClass   (pDnsHeader, pAnEntry, usDnsRrClass);
                    if ( (usDnsRrClass == DNS_RR_CLASS_IN)  && (usDnsRrType == DNS_RR_TYPE_A) 
                         && (RdLen == 4) )
                    {
                        j += RdLen;
                    }
                }

                pEchoEntry->IPAddresses = AnscAllocateMemory(j * 4);
                if ( !pEchoEntry->IPAddresses )
                {
                    return ANSC_STATUS_RESOURCES;
                }

                for(j = 0, k = 0; j < AnCount; j++)
                {
                    AnscDnsArSectionGetEntry (pDnsHeader, pAnSection, j, pAnEntry);
                    AnscDnsRrEntryGetRdLength(pDnsHeader, pAnEntry, RdLen);
                    AnscDnsRrEntryGetType    (pDnsHeader, pAnEntry, usDnsRrType);

                    switch ( usDnsRrType )
                    {
                        case    DNS_RR_TYPE_A :

                            AnscDnsRrEntryGetClass(pDnsHeader, pAnEntry, usDnsRrClass);
                            if ( usDnsRrClass != DNS_RR_CLASS_IN  || RdLen != 4 )
                            {
                                break;
                            }

                            AnscDnsRrEntryGetRdAddr(pDnsHeader, pAnEntry, qresult_addr.Dot);
                            
                            tmp = qresult_addr.Dot[0] & 0xFF;
                            _ansc_itoa(tmp, &pEchoEntry->IPAddresses[k], 10);
                            k = AnscSizeOfString(pEchoEntry->IPAddresses);
                            pEchoEntry->IPAddresses[k++] = '.';
                            tmp = qresult_addr.Dot[1] & 0xFF;
                            _ansc_itoa(tmp, &pEchoEntry->IPAddresses[k], 10);
                            k = AnscSizeOfString(pEchoEntry->IPAddresses);
                            pEchoEntry->IPAddresses[k++] = '.';
                            tmp = qresult_addr.Dot[2] & 0xFF;
                            _ansc_itoa(tmp, &pEchoEntry->IPAddresses[k], 10);
                            k = AnscSizeOfString(pEchoEntry->IPAddresses);
                            pEchoEntry->IPAddresses[k++] = '.';
                            tmp = qresult_addr.Dot[3] & 0xFF;
                            _ansc_itoa(tmp, &pEchoEntry->IPAddresses[k], 10);
                            k = AnscSizeOfString(pEchoEntry->IPAddresses);
                            pEchoEntry->IPAddresses[k++] = ',';
                            break;

                        default:
                            break;
                    }
                }
                pEchoEntry->IPAddresses[k-1] = '\0';
                */
            }
            else
            {
                returnStatus                = ANSC_STATUS_SUCCESS;
                pEchoEntry->StopTime        = StopTime;
                pEchoEntry->Status          = BBHM_NS_LOOKUP_STATUS_Error_Timeout;
                pEchoEntry->AnswerType      = BBHM_NS_LOOKUP_RESULT_None;
                pEchoEntry->HostNameReturned= NULL;
                pEchoEntry->ResponsTime     = StopTime - pEchoEntry->StartTime;
                pEchoEntry->IPAddresses     = NULL;
                pProperty->Status           = BBHM_NS_LOOKUP_STATUS_TIMEOUT;
            }
            pMyObject->DelPquery(pMyObject, pQuery);
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
        BbhmDiagnsClose
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
BbhmDiagnsClose
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink       = (PBBHM_NS_LOOKUP_XSINK_OBJECT  )pMyObject->hXsinkObject;
    PDSLH_NSLOOKUP_INFO             pDiagInfo    = (PDSLH_NSLOOKUP_INFO           )pMyObject->hDslhDiagInfo;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pEchoEntry   = NULL;
    PBBHM_NS_LOOKUP_QUERY_ENTRY     pQuery       = NULL;
    ULONG                           i;

    if ( !pMyObject->bActive )
    {
        return  ANSC_STATUS_SUCCESS;
    }

    if ( pXsink )
    {
        pXsink->Detach((ANSC_HANDLE)pXsink);
        pXsink->Remove((ANSC_HANDLE)pXsink);
        pMyObject->hXsinkObject = NULL;
    }

    if ( pDiagInfo )
    {
        pEchoEntry = (PBBHM_NS_LOOKUP_ECHO_ENTRY)pDiagInfo->hDiaginfo;
        if ( pEchoEntry )
        {
            for(i = 0; i < pDiagInfo->ResultNumberOfEntries; i++)
            {
                AnscFreeMemory(pEchoEntry[i].HostNameReturned);
                AnscFreeMemory(pEchoEntry[i].IPAddresses);
            }
            AnscFreeMemory(pEchoEntry);
            pEchoEntry  = NULL;
        }
        AnscFreeMemory(pDiagInfo);
        pDiagInfo = NULL;
    }

    AnscAcquireLock(&pMyObject->EchoTableLock);

    pSLinkEntry = AnscSListPopEntry(&pMyObject->EchoTable);

    while ( pSLinkEntry )
    {
        pEchoEntry  = ACCESS_BBHM_NS_LOOKUP_ECHO_ENTRY(pSLinkEntry);
        pSLinkEntry = AnscSListPopEntry(&pMyObject->EchoTable);

        AnscFreeMemory(pEchoEntry->HostNameReturned);
        AnscFreeMemory(pEchoEntry->IPAddresses);
        AnscFreeMemory(pEchoEntry);
        pEchoEntry = NULL;
    }

    AnscReleaseLock(&pMyObject->EchoTableLock);

    AnscAcquireLock(&pMyObject->PqueryTableLock);
    pSLinkEntry = AnscSListPopEntry(&pMyObject->PqueryTable);

    while ( pSLinkEntry )
    {
        pQuery  = ACCESS_BBHM_NS_LOOKUP_QUERY_ENTRY(pSLinkEntry);
        pSLinkEntry = AnscSListPopEntry(&pMyObject->PqueryTable);

        AnscFreeMemory(pQuery);
    }

    AnscReleaseLock(&pMyObject->PqueryTableLock);

    pMyObject->bActive = FALSE;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsCalculateResult
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       Num
            );

    description:

        This function is called to calculate diag result.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ULONG                       Num
                Number of diag result.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsCalculateResult
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       Num
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PDSLH_NSLOOKUP_INFO             pDslhDiagInfo= (PDSLH_NSLOOKUP_INFO           )pMyObject->hDslhDiagInfo;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pEchoEntry   = NULL;
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pDiagnsInfo  = (PBBHM_NS_LOOKUP_ECHO_ENTRY    )pDslhDiagInfo->hDiaginfo;
    ULONG                           i            = 0;

    if ( pDiagnsInfo )
    {
        for(i = 0; i < pDslhDiagInfo->ResultNumberOfEntries; i++)
        {
            AnscFreeMemory(pDiagnsInfo[i].HostNameReturned);
            AnscFreeMemory(pDiagnsInfo[i].IPAddresses);
        }
        AnscFreeMemory(pDiagnsInfo);
        pDiagnsInfo = NULL;
    }

    pDiagnsInfo = AnscAllocateMemory(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY) * Num);

    if ( !pDiagnsInfo )
    {
        return ANSC_STATUS_RESOURCES;
    }
    else
    {
        pDslhDiagInfo->hDiaginfo = pDiagnsInfo;
    }

    pMyObject->DelAllPqueries(pMyObject);

    AnscAcquireLock(&pMyObject->EchoTableLock);
    pSLinkEntry = AnscSListPopEntry(&pMyObject->EchoTable);

    while ( pSLinkEntry )
    {
        pEchoEntry                          = ACCESS_BBHM_NS_LOOKUP_ECHO_ENTRY(pSLinkEntry);
        pSLinkEntry                         = AnscSListPopEntry(&pMyObject->EchoTable);

        pDiagnsInfo[i].Status               = pEchoEntry->Status;
        pDiagnsInfo[i].AnswerType           = pEchoEntry->AnswerType;
        pDiagnsInfo[i].ResponsTime          = pEchoEntry->ResponsTime;
        pDiagnsInfo[i].HostNameReturned     = AnscCloneString(pEchoEntry->HostNameReturned);
        pDiagnsInfo[i].IPAddresses          = AnscCloneString(pEchoEntry->IPAddresses);
        pDiagnsInfo[i++].DNSServerIPName    = AnscCloneString(pEchoEntry->DNSServerIPName);

        AnscFreeMemory(pEchoEntry->HostNameReturned);
        pEchoEntry->HostNameReturned = NULL;
        CcspTraceInfo(("!!! Ready to free pEchoEntry->IPAddresses !!!\n"));
        AnscFreeMemory(pEchoEntry->IPAddresses);
        pEchoEntry->IPAddresses = NULL;
        AnscFreeMemory(pEchoEntry->DNSServerIPName);
        pEchoEntry->DNSServerIPName = NULL;
        AnscFreeMemory(pEchoEntry);
        pEchoEntry = NULL;
    }

    AnscReleaseLock(&pMyObject->EchoTableLock);

    return  returnStatus;
}

