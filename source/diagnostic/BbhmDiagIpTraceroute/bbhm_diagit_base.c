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

    module:     bbhm_diagit_base.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the basic container object functions
        of the Bbhm IpPing Diagnostic Object.

        *   BbhmDiagitCreate
        *   BbhmDiagitRemove
        *   BbhmDiagitEnrollObjects
        *   BbhmDiagitInitialize

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Du Li, Li Shi

    ---------------------------------------------------------------

    revision:

        2007/02/08    initial revision.

**********************************************************************/


#include "bbhm_diagit_global.h"
#include "safec_lib_common.h"

PBBHM_DIAG_IP_TRACEROUTE_OBJECT g_DiagIpTracerouteObj = NULL;

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        BbhmDiagitCreate
            (
                ANSC_HANDLE                 hContainerContext,
                ANSC_HANDLE                 hOwnerContext,
                ANSC_HANDLE                 hAnscReserved
            );

    description:

        This function constructs the Bbhm IpPing Diagnostic Object and
        initializes the member variables and functions.

    argument:   ANSC_HANDLE                 hContainerContext
                This handle is used by the container object to interact
                with the outside world. It could be the real container
                or an target object.

                ANSC_HANDLE                 hOwnerContext
                This handle is passed in by the owner of this object.

                ANSC_HANDLE                 hAnscReserved
                This handle is passed in by the owner of this object.

    return:     newly created container object.

**********************************************************************/

ANSC_HANDLE
BbhmDiagitCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    )
{
    PANSC_COMPONENT_OBJECT          pBaseObject  = NULL;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT)AnscAllocateMemory(sizeof(BBHM_DIAG_IP_TRACEROUTE_OBJECT));

    if ( !pMyObject )
    {
        return  (ANSC_HANDLE)NULL;
    }
    else
    {
        pBaseObject = (PANSC_COMPONENT_OBJECT)pMyObject;
    }

    /*
     * Initialize the common variables and functions for a container object.
     */
    errno_t rc = -1;
    rc = strcpy_s(pBaseObject->Name, sizeof(pBaseObject->Name) , BBHM_DIAG_IP_TRACEROUTE_NAME);
    ERR_CHK(rc);

    pBaseObject->hContainerContext = hContainerContext;
    pBaseObject->hOwnerContext     = hOwnerContext;
    pBaseObject->Oid               = BBHM_DIAG_IP_TRACEROUTE_OID;
    pBaseObject->Initialize        = BbhmDiagitInitialize;

    pBaseObject->Create            = BbhmDiagitCreate;
    pBaseObject->Remove            = BbhmDiagitRemove;
    pBaseObject->EnrollObjects     = BbhmDiagitEnrollObjects;
    pBaseObject->Initialize        = BbhmDiagitInitialize;

    pBaseObject->EnrollObjects((ANSC_HANDLE)pBaseObject);
    pBaseObject->Initialize   ((ANSC_HANDLE)pBaseObject);

    g_DiagIpTracerouteObj = pMyObject;

    return  (ANSC_HANDLE)pMyObject;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function destroys the object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT       pMyObject           = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT    )hThisObject;
    PDSLH_TRACEROUTE_INFO                 pDslhDiagInfo       = (PDSLH_TRACEROUTE_INFO              )pMyObject->hDslhDiagInfo;
    PBBHM_TRACERT_TDO_OBJECT              pStateTimer         = (PBBHM_TRACERT_TDO_OBJECT           )pMyObject->hStateTimer;

    if ( pStateTimer )
    {
        pStateTimer->Remove((ANSC_HANDLE)pStateTimer);
    }

    if ( pMyObject->hSendBuffer )
    {
        AnscFreeMemory(pMyObject->hSendBuffer);

        pMyObject->hSendBuffer = NULL;
    }

    pMyObject->StopDiag((ANSC_HANDLE)pMyObject);

    pMyObject->Close((ANSC_HANDLE)pMyObject);

    pMyObject->Cancel((ANSC_HANDLE)pMyObject);
    pMyObject->Reset((ANSC_HANDLE)pMyObject);

    if ( pDslhDiagInfo )
    {
        DslhFreeTracerouteInfo(((PDSLH_TRACEROUTE_INFO)pDslhDiagInfo));

        pMyObject->hDslhDiagInfo = (ANSC_HANDLE)NULL;
    }

    AnscFreeLock (&pMyObject->EchoTableLock);

    BbhmDiageoRemove((ANSC_HANDLE)pMyObject);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitEnrollObjects
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function enrolls all the objects required by this object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT       pMyObject           = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT)hThisObject;
    PDSLH_TRACEROUTE_INFO                 pDslhDiagInfo       = NULL;
    PANSC_OBJECT_CONTAINER_OBJECT         pContainer          = (PANSC_OBJECT_CONTAINER_OBJECT  )pMyObject->hContainerContext;
    PBBHM_TRACERT_TDO_OBJECT              pStateTimer         = (PBBHM_TRACERT_TDO_OBJECT       )pMyObject->hStateTimer;

    pDslhDiagInfo = AnscAllocateMemory(sizeof(DSLH_TRACEROUTE_INFO));

    if ( !pDslhDiagInfo )
    {
        return ANSC_STATUS_RESOURCES;
    }
    else
    {
        DslhInitTracerouteInfo(pDslhDiagInfo);

        pMyObject->hDslhDiagInfo    = pDslhDiagInfo;
    }

    BbhmDiageoEnrollObjects((ANSC_HANDLE)pMyObject);

    if ( !pMyObject->hSendBuffer )
    {
        pMyObject->hSendBuffer = (PCHAR)AnscAllocateMemory(BBHM_TRACERT_MAX_PACKET_SIZE + sizeof(ICMPV4_HEADER));

        if ( !pMyObject->hSendBuffer )
        {
            return  ANSC_STATUS_RESOURCES;
        }
    }

    if ( !pStateTimer )
    {
        pStateTimer =
            (PBBHM_TRACERT_TDO_OBJECT)BbhmDiagitTdoCreate
                (
                    (ANSC_HANDLE)pContainer,
                    (ANSC_HANDLE)pMyObject,
                    NULL
                );

        if ( !pStateTimer )
        {
            return  ANSC_STATUS_RESOURCES;
        }
        else
        {
            pMyObject->hStateTimer = (ANSC_HANDLE)pStateTimer;
        }

        pStateTimer->SetTimerType((ANSC_HANDLE)pStateTimer, ANSC_TIMER_TYPE_SPORADIC                         );
        pStateTimer->SetInterval ((ANSC_HANDLE)pStateTimer, BBHM_TRACERT_DEF_TIME_BETWEEN_IN_MILLISECONDS    );
        pStateTimer->SetCounter  ((ANSC_HANDLE)pStateTimer, BBHM_TRACERT_DEF_NUMBER_PACKETS                  );
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function first calls the initialization member function
        of the base class object to set the common member fields
        inherited from the base class. It then initializes the member
        fields that are specific to this object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT       pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT)hThisObject;
    ULONG                                 i            = 0;

    /*
     * Until you have to simulate C++ object-oriented programming style with standard C, you don't
     * appreciate all the nice little things come with C++ language and all the dirty works that
     * have been done by the C++ compilers. Member initialization is one of these things. While in
     * C++ you don't have to initialize all the member fields inherited from the base class since
     * the compiler will do it for you, such is not the case with C.
     */
     BbhmDiageoInitialize((ANSC_HANDLE)pMyObject);

    /*
     * Although we have initialized some of the member fields in the "create" member function, we
     * repeat the work here for completeness. While this simulation approach is pretty stupid from
     * a C++/Java programmer perspective, it's the best we can get for universal embedded network
     * programming. Before we develop our own operating system (don't expect that to happen any
     * time soon), this is the way things gonna be.
     */
    pMyObject->Oid                          = BBHM_DIAG_IP_TRACEROUTE_OID;

    pMyObject->bActive                      = FALSE;

    pMyObject->Reset                        = BbhmDiagitReset;

    /* overwrite the virtual functions */
    pMyObject->CopyDiagParams               = BbhmDiagitCopyDiagParams;
    pMyObject->StartDiag                    = BbhmDiagitStartDiag;
    pMyObject->StopDiag                     = BbhmDiagitStopDiag;
    pMyObject->RetrieveResult               = BbhmDiagitRetrieveResult;

    pMyObject->ResetProperty                = BbhmDiagitResetProperty;
    pMyObject->ResetPropertyCounter         = BbhmDiagitResetPropertyCounter;

    pMyObject->GetProperty                  = BbhmDiagitGetProperty;
    pMyObject->SetProperty                  = BbhmDiagitSetProperty;

    pMyObject->Start                        = BbhmDiagitStart;
    pMyObject->SendEcho                     = BbhmDiagitSendEcho;
    pMyObject->Stop                         = BbhmDiagitStop;
    pMyObject->ResolveHost                  = BbhmDiagitResolveHost;
    pMyObject->ResolveHostName              = BbhmDiagitResolveHostName;
    pMyObject->Open                         = BbhmDiagitOpen;
    pMyObject->Close                        = BbhmDiagitClose;
    pMyObject->Expire1                      = BbhmDiagitExpire1;
    pMyObject->Expire2                      = BbhmDiagitExpire2;

    pMyObject->SetStopTime                  = BbhmDiagitSetStopTime;
    pMyObject->AddEchoEntry                 = BbhmDiagitAddEchoEntry;
    pMyObject->CalculateResult              = BbhmDiagitCalculateResult;
    pMyObject->UpdateEntry                  = BbhmDiagitUpdateEntry;
    pMyObject->SetDiagParams                = BbhmDiagitSetDiagParams;

    pMyObject->Accept                       = BbhmDiagitAccept;
    pMyObject->Recv                         = BbhmDiagitRecv;
    pMyObject->Send                         = BbhmDiagitSend;

    pMyObject->GetSrcIpType                 = BbhmDiagitGetSrcIpType;
    pMyObject->SetSrcIpType                 = BbhmDiagitSetSrcIpType;
    pMyObject->GetSrcIp                     = BbhmDiagitGetSrcIp;
    pMyObject->SetSrcIp                     = BbhmDiagitSetSrcIp;
    pMyObject->GetDstIpType                 = BbhmDiagitGetDstIpType;
    pMyObject->SetDstIpType                 = BbhmDiagitSetDstIpType;
    pMyObject->GetDstIp                     = BbhmDiagitGetDstIp;
    pMyObject->SetDstIp                     = BbhmDiagitSetDstIp;
    pMyObject->GetNumPkts                   = BbhmDiagitGetNumPkts;
    pMyObject->SetNumPkts                   = BbhmDiagitSetNumPkts;
    pMyObject->GetPktSize                   = BbhmDiagitGetPktSize;
    pMyObject->SetPktSize                   = BbhmDiagitSetPktSize;
    pMyObject->GetTimeBetween               = BbhmDiagitGetTimeBetween;
    pMyObject->SetTimeBetween               = BbhmDiagitSetTimeBetween;
    pMyObject->GetTimeOut                   = BbhmDiagitGetTimeOut;
    pMyObject->SetTimeOut                   = BbhmDiagitSetTimeOut;
    pMyObject->GetControl                   = BbhmDiagitGetControl;
    pMyObject->SetControl                   = BbhmDiagitSetControl;
    pMyObject->GetStatus                    = BbhmDiagitGetStatus;
    pMyObject->SetStatus                    = BbhmDiagitSetStatus;
    pMyObject->GetPktsSent                  = BbhmDiagitGetPktsSent;
    pMyObject->SetPktsSent                  = BbhmDiagitSetPktsSent;
    pMyObject->GetPktsRecv                  = BbhmDiagitGetPktsRecv;
    pMyObject->SetPktsRecv                  = BbhmDiagitSetPktsRecv;
    pMyObject->GetAvgRTT                    = BbhmDiagitGetAvgRTT;
    pMyObject->SetAvgRTT                    = BbhmDiagitSetAvgRTT;
    pMyObject->GetMaxRTT                    = BbhmDiagitGetMaxRTT;
    pMyObject->SetMaxRTT                    = BbhmDiagitSetMaxRTT;
    pMyObject->GetMinRTT                    = BbhmDiagitGetMinRTT;
    pMyObject->SetMinRTT                    = BbhmDiagitSetMinRTT;
    pMyObject->GetNumIcmpError              = BbhmDiagitGetNumIcmpError;
    pMyObject->SetNumIcmpError              = BbhmDiagitSetNumIcmpError;
    pMyObject->GetIcmpError                 = BbhmDiagitGetIcmpError;
    pMyObject->SetIcmpError                 = BbhmDiagitSetIcmpError;
    pMyObject->GetTtl                       = BbhmDiagitGetTtl;
    pMyObject->SetTtl                       = BbhmDiagitSetTtl;
    pMyObject->SetDiagInfo                  = BbhmDiagitSetDiagInfo;
    pMyObject->GetDiagInfo                  = BbhmDiagitGetDiagInfo;
    pMyObject->SetStateUpdated              = BbhmDiagitSetStateUpdated;
    pMyObject->GetStateUpdated              = BbhmDiagitGetStateUpdated;
    pMyObject->SetDstIpVal                  = BbhmDiagitSetDstIpVal;
    pMyObject->GetDstIpVal                  = BbhmDiagitGetDstIpVal;
    pMyObject->GetDstAddrName               = BbhmDiagitGetDstAddrName;

    pMyObject->Open((ANSC_HANDLE)pMyObject);

    /*
     * We shall initialize the session properties to the default values, which may be changed later
     * via the "configure" member function. If any of the future extensions needs to change the
     * session property, the following code also needs to be changed.
     */
    pMyObject->ResetProperty((ANSC_HANDLE)pMyObject);

    for ( i = 0; i < MAX_ECHO_TABLE_SIZE; i ++ )
    {
        AnscSListInitializeHeader(&pMyObject->EchoTable[i]);
    }

    AnscInitializeLock       (&pMyObject->EchoTableLock);

    return  ANSC_STATUS_SUCCESS;
}
