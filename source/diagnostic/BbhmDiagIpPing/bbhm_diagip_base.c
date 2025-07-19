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

    module:     bbhm_diagip_base.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the basic container object functions
        of the Bbhm IpPing Diagnostic Object.

        *   BbhmDiagipCreate
        *   BbhmDiagipRemove
        *   BbhmDiagipEnrollObjects
        *   BbhmDiagipInitialize

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
#include "safec_lib_common.h"


PBBHM_DIAG_IP_PING_OBJECT g_DiagIpPingObj = NULL;

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        BbhmDiagipCreate
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
BbhmDiagipCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    )
{
    PANSC_COMPONENT_OBJECT          pBaseObject  = NULL;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PBBHM_DIAG_IP_PING_OBJECT)AnscAllocateMemory(sizeof(BBHM_DIAG_IP_PING_OBJECT));

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
    rc = strcpy_s(pBaseObject->Name, sizeof(pBaseObject->Name) , BBHM_DIAG_IP_PING_NAME);
    ERR_CHK(rc);

    pBaseObject->hContainerContext = hContainerContext;
    pBaseObject->hOwnerContext     = hOwnerContext;
    pBaseObject->Oid               = BBHM_DIAG_IP_PING_OID;
    pBaseObject->Create            = BbhmDiagipCreate;
    pBaseObject->Remove            = BbhmDiagipRemove;
    pBaseObject->EnrollObjects     = BbhmDiagipEnrollObjects;
    pBaseObject->Initialize        = BbhmDiagipInitialize;

    pBaseObject->EnrollObjects((ANSC_HANDLE)pBaseObject);
    pBaseObject->Initialize   ((ANSC_HANDLE)pBaseObject);

    g_DiagIpPingObj = pMyObject;

    return  (ANSC_HANDLE)pMyObject;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipRemove
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
BbhmDiagipRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject           = (PBBHM_DIAG_IP_PING_OBJECT    )hThisObject;
    PBBHM_IP_PING_TDO_OBJECT        pStateTimer         = (PBBHM_IP_PING_TDO_OBJECT     )pMyObject->hStateTimer;

    if ( pStateTimer )
    {
        pStateTimer->Remove((ANSC_HANDLE)pStateTimer);
    }

    if ( pMyObject->hSendBuffer )
    {
        AnscFreeMemory(pMyObject->hSendBuffer);
        pMyObject->hSendBuffer = NULL;
    }

    pMyObject->Close((ANSC_HANDLE)pMyObject);

    pMyObject->Cancel((ANSC_HANDLE)pMyObject);
    pMyObject->Reset ((ANSC_HANDLE)pMyObject);

    AnscFreeLock(&pMyObject->EchoTableLock);

    BbhmDiageoRemove((ANSC_HANDLE)pMyObject);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipEnrollObjects
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
BbhmDiagipEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject           = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PDSLH_PING_INFO                 pDslhDiagInfo       = NULL;
    PANSC_OBJECT_CONTAINER_OBJECT   pContainer          = (PANSC_OBJECT_CONTAINER_OBJECT)pMyObject->hContainerContext;
    PBBHM_IP_PING_TDO_OBJECT        pStateTimer         = (PBBHM_IP_PING_TDO_OBJECT )pMyObject->hStateTimer;

    pDslhDiagInfo = AnscAllocateMemory(sizeof(DSLH_PING_INFO));

    if ( !pDslhDiagInfo )
    {
        return ANSC_STATUS_RESOURCES;
    }
    else
    {
        DslhInitPingInfo(pDslhDiagInfo);

        pMyObject->hDslhDiagInfo    = pDslhDiagInfo;
    }

    /* It's not wise to allocate SendBuffer here, since the size is configurable */
/*
    if ( !pMyObject->hSendBuffer )
    {
        pMyObject->hSendBuffer = (PCHAR)AnscAllocateMemory(BBHM_IP_PING_MAX_PACKET_SIZE + sizeof(ICMPV4_HEADER));

        if ( !pMyObject->hSendBuffer )
        {
            return  ANSC_STATUS_RESOURCES;
        }
    }
*/
    if ( !pStateTimer )
    {
        pStateTimer =
            (PBBHM_IP_PING_TDO_OBJECT)BbhmDiagipTdoCreate
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

        pStateTimer->SetTimerType((ANSC_HANDLE)pStateTimer, ANSC_TIMER_TYPE_SPORADIC                     );
        pStateTimer->SetInterval ((ANSC_HANDLE)pStateTimer, BBHM_IP_PING_DEF_TIME_BETWEEN_IN_MILLISECONDS);
        pStateTimer->SetCounter  ((ANSC_HANDLE)pStateTimer, BBHM_IP_PING_DEF_NUMBER_PACKETS      );
    }

    BbhmDiageoEnrollObjects((ANSC_HANDLE)pMyObject);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipInitialize
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
BbhmDiagipInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    ULONG                           i            = 0;

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
    pMyObject->Oid                          = BBHM_DIAG_IP_PING_OID;
    pMyObject->Create                       = BbhmDiagipCreate;
    pMyObject->Remove                       = BbhmDiagipRemove;
    pMyObject->EnrollObjects                = BbhmDiagipEnrollObjects;
    pMyObject->Initialize                   = BbhmDiagipInitialize;

    pMyObject->bActive                      = FALSE;

    pMyObject->Reset                        = BbhmDiagipReset;

    /* overwrite the virtual functions */
    pMyObject->CopyDiagParams               = BbhmDiagipCopyDiagParams;
    pMyObject->StartDiag                    = BbhmDiagipStartDiag;
    pMyObject->StopDiag                     = BbhmDiagipStopDiag;
    pMyObject->RetrieveResult               = BbhmDiagipRetrieveResult;

    pMyObject->ResetProperty                = BbhmDiagipResetProperty;
    pMyObject->ResetPropertyCounter         = BbhmDiagipResetPropertyCounter;

    pMyObject->GetProperty                  = BbhmDiagipGetProperty;
    pMyObject->SetProperty                  = BbhmDiagipSetProperty;

    pMyObject->Start                        = BbhmDiagipStart;
    pMyObject->Stop                         = BbhmDiagipStop;
    pMyObject->Open                         = BbhmDiagipOpen;
    pMyObject->Close                        = BbhmDiagipClose;
    pMyObject->Expire1                      = BbhmDiagipExpire1;
    pMyObject->Expire2                      = BbhmDiagipExpire2;

    pMyObject->SetStopTime                  = BbhmDiagipSetStopTime;
    pMyObject->AddEchoEntry                 = BbhmDiagipAddEchoEntry;
    pMyObject->CalculateResult              = BbhmDiagipCalculateResult;
    pMyObject->SetEnv                       = BbhmDiagipSetEnv;
    pMyObject->SetDiagParams                = BbhmDiagipSetDiagParams;

    pMyObject->Accept                       = BbhmDiagipAccept;
    pMyObject->Recv                         = BbhmDiagipRecv;
    pMyObject->Send                         = BbhmDiagipSend;

    pMyObject->GetSrcIpType                 = BbhmDiagipGetSrcIpType;
    pMyObject->SetSrcIpType                 = BbhmDiagipSetSrcIpType;
    pMyObject->GetSrcIp                     = BbhmDiagipGetSrcIp;
    pMyObject->SetSrcIp                     = BbhmDiagipSetSrcIp;
    pMyObject->GetDstIpType                 = BbhmDiagipGetDstIpType;
    pMyObject->SetDstIpType                 = BbhmDiagipSetDstIpType;
    pMyObject->GetDstIp                     = BbhmDiagipGetDstIp;
    pMyObject->SetDstIp                     = BbhmDiagipSetDstIp;
    pMyObject->GetNumPkts                   = BbhmDiagipGetNumPkts;
    pMyObject->SetNumPkts                   = BbhmDiagipSetNumPkts;
    pMyObject->GetPktSize                   = BbhmDiagipGetPktSize;
    pMyObject->SetPktSize                   = BbhmDiagipSetPktSize;
    pMyObject->GetTimeBetween               = BbhmDiagipGetTimeBetween;
    pMyObject->SetTimeBetween               = BbhmDiagipSetTimeBetween;
    pMyObject->GetTimeOut                   = BbhmDiagipGetTimeOut;
    pMyObject->SetTimeOut                   = BbhmDiagipSetTimeOut;
    pMyObject->GetControl                   = BbhmDiagipGetControl;
    pMyObject->SetControl                   = BbhmDiagipSetControl;
    pMyObject->GetStatus                    = BbhmDiagipGetStatus;
    pMyObject->SetStatus                    = BbhmDiagipSetStatus;
    pMyObject->GetPktsSent                  = BbhmDiagipGetPktsSent;
    pMyObject->SetPktsSent                  = BbhmDiagipSetPktsSent;
    pMyObject->GetPktsRecv                  = BbhmDiagipGetPktsRecv;
    pMyObject->SetPktsRecv                  = BbhmDiagipSetPktsRecv;
    pMyObject->GetAvgRTT                    = BbhmDiagipGetAvgRTT;
    pMyObject->SetAvgRTT                    = BbhmDiagipSetAvgRTT;
    pMyObject->GetMaxRTT                    = BbhmDiagipGetMaxRTT;
    pMyObject->SetMaxRTT                    = BbhmDiagipSetMaxRTT;
    pMyObject->GetMinRTT                    = BbhmDiagipGetMinRTT;
    pMyObject->SetMinRTT                    = BbhmDiagipSetMinRTT;
    pMyObject->GetNumIcmpError              = BbhmDiagipGetNumIcmpError;
    pMyObject->SetNumIcmpError              = BbhmDiagipSetNumIcmpError;
    pMyObject->GetIcmpError                 = BbhmDiagipGetIcmpError;
    pMyObject->SetIcmpError                 = BbhmDiagipSetIcmpError;
    pMyObject->GetNumCalculate              = BbhmDiagipGetNumCalculate;
    pMyObject->SetNumCalculate              = BbhmDiagipSetNumCalculate;
    pMyObject->GetSumRTT                    = BbhmDiagipGetSumRTT;
    pMyObject->SetSumRTT                    = BbhmDiagipSetSumRTT;

    pMyObject->GetMiddleResult              = BbhmDiagipGetMiddleResult;

    pMyObject->ResetProperty((ANSC_HANDLE)pMyObject);

    for ( i = 0; i < MAX_ECHO_TABLE_SIZE; i ++ )
    {
        AnscSListInitializeHeader(&pMyObject->EchoTable[i]);
    }
    AnscSListInitializeHeader(&pMyObject->MiddleResult);

    AnscInitializeLock       (&pMyObject->EchoTableLock);
    AnscInitializeLock       (&pMyObject->MiddleResultLock);

    return  ANSC_STATUS_SUCCESS;
}
