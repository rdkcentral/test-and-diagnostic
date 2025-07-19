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

    module:     bbhm_diagns_states.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced state-access functions
        of the Bbhm NSLookup Diagnostic Object.

        *   BbhmDiagnsReset
        *   BbhmDiagnsSetControl
        *   BbhmDiagnsGetTimeOut
        *   BbhmDiagnsSetTimeOut
        *   BbhmDiagnsGetSrcIp
        *   BbhmDiagnsSetSrcIp
        *   BbhmDiagnsResetPropertyCounter
        *   BbhmDiagnsResetProperty
        *   BbhmDiagnsSetStatus
        *   BbhmDiagnsGetDstIp
        *   BbhmDiagnsSetDstIp
        *   BbhmDiagnsCopyDiagParams
        *   BbhmDiagnsGetNumPkts
        *   BbhmDiagnsSetNumPkts
        *   BbhmDiagnsGetPktsSent
        *   BbhmDiagnsSetPktsSent
        *   BbhmDiagnsGetStatus
        *   BbhmDiagnsSetDiagParams

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
        BbhmDiagnsReset
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to reset object states.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsReset
    (
        ANSC_HANDLE                 hThisObject
    )
{
    /*
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT)hThisObject;
    if ( pMyObject->hDslhDiagInfo )
    {
        DslhFreeNSLookupInfo(((PDSLH_NSLOOKUP_INFO)pMyObject->hDslhDiagInfo));
        pMyObject->hDslhDiagInfo = (ANSC_HANDLE)NULL;
    }
    */

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsSetControl
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       ulControl
            );

    description:

        This function is called to set the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ULONG                       ulControl
                This is state value to be set.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsSetControl
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulControl
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    pProperty->Control  = ulControl;

    if ( ulControl == BBHM_NS_LOOKUP_CONTROL_START )
    {
        returnStatus =
            pMyObject->Start((ANSC_HANDLE)pMyObject);
    }
    else if ( ulControl == BBHM_NS_LOOKUP_CONTROL_STOP )
    {
        pMyObject->SetStatus((ANSC_HANDLE)pMyObject, BBHM_NS_LOOKUP_STATUS_STOP);

        returnStatus =
            pMyObject->Stop((ANSC_HANDLE)pMyObject);
    }

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmIDiagnsResetPropertyCounter
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to reset the property.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsResetPropertyCounter
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    pProperty->PktsSent     = 0;
    pProperty->PktsRecv     = 0;
    pProperty->NumDnsSuccess= 0;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsSetStatus
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       ulStatus
            );

    description:

        This function is called to set the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ULONG                       ulStatus
                This is the Status value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsSetStatus
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulStatus
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    pProperty->Status   = ulStatus;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        PUCHAR
        BbhmDiagnsGetDstIp
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Dst IP.

**********************************************************************/

PUCHAR
BbhmDiagnsGetDstIp
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;


    return  pProperty->DstAddrName;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsSetDstIp
            (
                ANSC_HANDLE                 hThisObject,
                PUCHAR                      Dst
            );

    description:

        This function is called to set the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                PUCHAR                      Dst
                This is the IpAddress or name of destination.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsSetDstIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      Dst
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    errno_t rc = -1;
    rc = strcpy_s(pProperty->DstAddrName, sizeof(pProperty->DstAddrName) , Dst);
    ERR_CHK(rc);

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsCopyDiagParams
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDslhDiagInfo
            );

    description:

        This function is called to set the diagnostic parameters. If
        the diagnostic process is ongoing, it will be stopped first.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDslhDiagInfo
                Handle of diaginfo.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsCopyDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{ 
    /*
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT)hThisObject;

    _ansc_memcpy(pMyObject->hDslhDiagInfo, hDslhDiagInfo, sizeof(DSLH_NSLOOKUP_INFO));
    */

    return  ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagnsGetNumPkts
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Number of packets need to be sent.

**********************************************************************/

ULONG
BbhmDiagnsGetNumPkts
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    return  pProperty->NumPkts;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsSetNumPkts
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       ulNumPkts
            );

    description:

        This function is called to set the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ULONG                       ulNumPkts
                This is the NumPkts value.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsSetNumPkts
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulNumPkts
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    pProperty->NumPkts  = ulNumPkts;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagnsGetTimeOut
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Timeout time in Milliseconds.

**********************************************************************/

ULONG
BbhmDiagnsGetTimeOut
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    return  pProperty->TimeOut;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsSetTimeOut
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       ulTimeOut
            );

    description:

        This function is called to set the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ULONG                       ulTimeOut
                This is the TimeOut value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsSetTimeOut
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulTimeOut
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    pProperty->TimeOut  = ulTimeOut;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        PUCHAR
        BbhmDiagnsGetSrcIp
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Src IP.

**********************************************************************/

PUCHAR
BbhmDiagnsGetSrcIp
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    return  pProperty->SrcAddrName;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsSetSrcIp
            (
                ANSC_HANDLE                 hThisObject,
                PUCHAR                      Interface
            );

    description:

        This function is called to set the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                PUCHAR                      Interface
                The interface which sends the packets.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsSetSrcIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      Interface
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;
    errno_t                         rc           = -1;

    rc = strcpy_s(pProperty->SrcAddrName, sizeof(pProperty->SrcAddrName) , Interface);
    ERR_CHK(rc);

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagnsGetPktsSent
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     PktsSent value.

**********************************************************************/

ULONG
BbhmDiagnsGetPktsSent
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    return  pProperty->PktsSent;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsSetPktsSent
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       ulPktsSent
            );

    description:

        This function is called to seet the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ULONG                       ulPktsSent
                This is the PktsSent value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsSetPktsSent
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktsSent
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    pProperty->PktsSent = ulPktsSent;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsResetProperty
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to reset the property.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsResetProperty
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    /*
    pProperty->SrcIp.Value  = 0;
    pProperty->DstIp.Value  = 0;
    */
    AnscZeroMemory(pProperty->SrcAddrName, NS_LOOKUP_MAX_ADDRNAME_LEN);
    AnscZeroMemory(pProperty->DstAddrName, NS_LOOKUP_MAX_ADDRNAME_LEN);
    pProperty->NumPkts      = BBHM_NS_LOOKUP_DEF_NUMBER_PACKETS;
    pProperty->PktSize      = BBHM_NS_LOOKUP_DEF_PACKET_SIZE;
    pProperty->TimeBetween  = BBHM_NS_LOOKUP_DEF_TIME_BETWEEN_IN_MILLISECONDS;
    pProperty->TimeOut      = BBHM_NS_LOOKUP_DEF_TIME_OUT_IN_MILLISECONDS;
    pProperty->Control      = BBHM_NS_LOOKUP_DEF_CONTROL;
    pProperty->Status       = BBHM_NS_LOOKUP_STATUS_NOTRUN;
    pProperty->PktsSent     = 0;
    pProperty->PktsRecv     = 0;
    pProperty->NumDnsSuccess= 0;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagnsGetStatus
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Status value.

**********************************************************************/

ULONG
BbhmDiagnsGetStatus
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PBBHM_NS_LOOKUP_PROPERTY        pProperty    = (PBBHM_NS_LOOKUP_PROPERTY      )&pMyObject->Property;

    return  pProperty->Status;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsSetDiagParams
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDslhDiagInfo
            );

    description:

        This function is called to set the diagnostic parameters. If
        the diagnostic process is ongoing, it will be stopped first.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDslhDiagInfo
                The pointer points to the diagnostic parameters.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsSetDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT   )hThisObject;
    PDSLH_NSLOOKUP_INFO             pDiagInfo    = (PDSLH_NSLOOKUP_INFO           )pMyObject->hDslhDiagInfo;
    PDSLH_NSLOOKUP_INFO             pNewDiagInfo = (PDSLH_NSLOOKUP_INFO           )hDslhDiagInfo;
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pDiagnsEntry = (PBBHM_NS_LOOKUP_ECHO_ENTRY    )NULL;
    ULONG                           i;
    errno_t                         rc           = -1;

    if ( pNewDiagInfo->bForced != TRUE )
    {
        if ( !pMyObject->CheckCanStart((ANSC_HANDLE)pMyObject) )
        {
            AnscTraceFlow(("BbhmDiagnsSetDiagParams -- cannot start diag, last one is probably still ongoing...\n"));

            return  ANSC_STATUS_PENDING;
        }
    }

    AnscAcquireLock(&pMyObject->AccessLock);

    if ( pDiagInfo == NULL )
    {
        pDiagInfo = (PDSLH_NSLOOKUP_INFO)AnscAllocateMemory(sizeof(DSLH_NSLOOKUP_INFO));

        if ( pDiagInfo == NULL )
        {
            AnscTrace("BbhmDiagnsSetDiagParams -- insufficient resources!\n");

            AnscReleaseLock(&pMyObject->AccessLock);

            return  ANSC_STATUS_RESOURCES;
        }
        else
        {
            DslhInitNSLookupInfo(pDiagInfo);
            pMyObject->hDslhDiagInfo = (ANSC_HANDLE)pDiagInfo;
            pDiagInfo->StructSize    = sizeof(DSLH_NSLOOKUP_INFO);
            rc = strcpy_s(pDiagInfo->HostName, sizeof(pDiagInfo->HostName) , pNewDiagInfo->HostName);
            ERR_CHK(rc);
            /*AnscCopyMemory(pDiagInfo->HostName + AnscSizeOfString(pDiagInfo->HostName) + 1,
                           pNewDiagInfo->HostName + AnscSizeOfString(pDiagInfo->HostName) + 1,
                           AnscSizeOfString(pNewDiagInfo->HostName + AnscSizeOfString(pDiagInfo->HostName) + 1));*/
            rc = strcpy_s(pDiagInfo->Interface, sizeof(pDiagInfo->Interface) , pNewDiagInfo->Interface);
            ERR_CHK(rc);
            rc = strcpy_s(pDiagInfo->IfAddr, sizeof(pDiagInfo->IfAddr)   , pNewDiagInfo->IfAddr   );
            ERR_CHK(rc);
            rc = strcpy_s(pDiagInfo->DNSServer,sizeof(pDiagInfo->DNSServer) ,pNewDiagInfo->DNSServer);
            ERR_CHK(rc);
            pDiagInfo->bForced = pNewDiagInfo->bForced;
            pDiagInfo->Timeout = pNewDiagInfo->Timeout;
            pDiagInfo->NumberOfRepetitions = pNewDiagInfo->NumberOfRepetitions;
            pDiagInfo->UpdatedAt = 0;
        }
    }
    else
    {
        pDiagnsEntry = (PBBHM_NS_LOOKUP_ECHO_ENTRY)pDiagInfo->hDiaginfo;

        if ( pDiagnsEntry )
        {
            for(i = 0; i < pDiagInfo->ResultNumberOfEntries; i++)
            {
                AnscFreeMemory(pDiagnsEntry[i].HostNameReturned);
                AnscFreeMemory(pDiagnsEntry[i].IPAddresses);
            }
        }
        AnscFreeMemory(pDiagnsEntry);
        pDiagnsEntry    = NULL;

        DslhInitNSLookupInfo(pDiagInfo);
        pDiagInfo->StructSize    = sizeof(DSLH_NSLOOKUP_INFO);
        rc = strcpy_s(pDiagInfo->HostName, sizeof(pDiagInfo->HostName) , pNewDiagInfo->HostName);
        ERR_CHK(rc);
        /*AnscCopyMemory(pDiagInfo->HostName + AnscSizeOfString(pDiagInfo->HostName) + 1,
                           pNewDiagInfo->HostName + AnscSizeOfString(pDiagInfo->HostName) + 1,
                           AnscSizeOfString(pNewDiagInfo->HostName + AnscSizeOfString(pDiagInfo->HostName) + 1));*/
        rc = strcpy_s(pDiagInfo->Interface, sizeof(pDiagInfo->Interface) , pNewDiagInfo->Interface);
        ERR_CHK(rc);
        rc = strcpy_s(pDiagInfo->IfAddr, sizeof(pDiagInfo->IfAddr) ,   pNewDiagInfo->IfAddr   );
        ERR_CHK(rc);
        rc = strcpy_s(pDiagInfo->DNSServer, sizeof(pDiagInfo->DNSServer) , pNewDiagInfo->DNSServer);
        ERR_CHK(rc);
        pDiagInfo->bForced = pNewDiagInfo->bForced;
        pDiagInfo->Timeout = pNewDiagInfo->Timeout;
        pDiagInfo->NumberOfRepetitions = pNewDiagInfo->NumberOfRepetitions;
        pDiagInfo->UpdatedAt = 0;
    }

    AnscReleaseLock(&pMyObject->AccessLock);

    return  ANSC_STATUS_SUCCESS;
}
