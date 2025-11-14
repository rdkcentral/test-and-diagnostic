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

    module:     bbhm_diagns_base.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the basic container object functions
        of the Bbhm NSLookup Diagnostic Object.

        *   BbhmDiagnsCreate
        *   BbhmDiagnsRemove
        *   BbhmDiagnsEnrollObjects
        *   BbhmDiagnsInitialize

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

PBBHM_DIAG_NS_LOOKUP_OBJECT g_DiagNSLookupObj = NULL;

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        BbhmDiagnsCreate
            (
                ANSC_HANDLE                 hContainerContext,
                ANSC_HANDLE                 hOwnerContext,
                ANSC_HANDLE                 hAnscReserved
            );

    description:

        This function constructs the Bbhm NSLookup Diagnostic Object and
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
BbhmDiagnsCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    )
{
    PANSC_COMPONENT_OBJECT          pBaseObject  = NULL;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject    = NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PBBHM_DIAG_NS_LOOKUP_OBJECT)AnscAllocateMemory(sizeof(BBHM_DIAG_NS_LOOKUP_OBJECT));

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
    rc = strcpy_s(pBaseObject->Name, sizeof(pBaseObject->Name) , BBHM_DIAG_NS_LOOKUP_NAME);
    ERR_CHK(rc);

    pBaseObject->hContainerContext = hContainerContext;
    pBaseObject->hOwnerContext     = hOwnerContext;
    pBaseObject->Oid               = BBHM_DIAG_NS_LOOKUP_OID;

    pBaseObject->Create            = BbhmDiagnsCreate;
    pBaseObject->Remove            = BbhmDiagnsRemove;
    pBaseObject->EnrollObjects     = BbhmDiagnsEnrollObjects;
    pBaseObject->Initialize        = BbhmDiagnsInitialize;

    pBaseObject->EnrollObjects((ANSC_HANDLE)pBaseObject);
    pBaseObject->Initialize   ((ANSC_HANDLE)pBaseObject);

    g_DiagNSLookupObj = pMyObject;

    return  (ANSC_HANDLE)pMyObject;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsRemove
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
BbhmDiagnsRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT       pMyObject           = (PBBHM_DIAG_NS_LOOKUP_OBJECT)hThisObject;
    PBBHM_NS_LOOKUP_TDO_OBJECT        pStateTimer         = (PBBHM_NS_LOOKUP_TDO_OBJECT )pMyObject->hStateTimer;                        
    

    if ( pStateTimer )
    {
        pStateTimer->Remove((ANSC_HANDLE)pStateTimer);
    }

    pMyObject->Close((ANSC_HANDLE)pMyObject);

    if ( pMyObject->hSendBuffer )
    {
        AnscFreeMemory(pMyObject->hSendBuffer);

        pMyObject->hSendBuffer = NULL;
    }

    AnscFreeLock (&pMyObject->EchoTableLock);
    AnscFreeLock (&pMyObject->PqueryTableLock);

     /*CID - 58154 Use after free*/
     /* Removed "cancel and remove calls" as BbhmDiageoRemove() is internally using 
        same calls to free the pMyObject */
    BbhmDiageoRemove((ANSC_HANDLE)pMyObject);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsEnrollObjects
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
BbhmDiagnsEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pMyObject           = (PBBHM_DIAG_NS_LOOKUP_OBJECT  )hThisObject;
    PDSLH_NSLOOKUP_INFO             pDslhDiagInfo       = (PDSLH_NSLOOKUP_INFO          )NULL;
    PBBHM_NS_LOOKUP_TDO_OBJECT      pStateTimer         = (PBBHM_NS_LOOKUP_TDO_OBJECT   )pMyObject->hStateTimer;
    PANSC_OBJECT_CONTAINER_OBJECT   pContainer          = (PANSC_OBJECT_CONTAINER_OBJECT)pMyObject->hContainerContext;

    AnscCoEnrollObjects((ANSC_HANDLE)pMyObject);
    pDslhDiagInfo = AnscAllocateMemory(sizeof(DSLH_NSLOOKUP_INFO));

    if ( !pDslhDiagInfo )
    {
        return ANSC_STATUS_RESOURCES;
    }
    else
    {
        DslhInitNSLookupInfo(pDslhDiagInfo);

        pMyObject->hDslhDiagInfo    = pDslhDiagInfo;
    }

    if ( !pMyObject->hSendBuffer )
    {
        pMyObject->hSendBuffer = (PCHAR)AnscAllocateMemory(BBHM_NS_LOOKUP_DEF_PACKET_SIZE);

        if ( !pMyObject->hSendBuffer )
        {
            return  ANSC_STATUS_RESOURCES;
        }
    }

    if ( !pStateTimer )
    {
        pStateTimer =
            (PBBHM_NS_LOOKUP_TDO_OBJECT)BbhmDiagnsTdoCreate
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

        pStateTimer->SetTimerType((ANSC_HANDLE)pStateTimer, ANSC_TIMER_TYPE_SPORADIC                        );
        pStateTimer->SetInterval ((ANSC_HANDLE)pStateTimer, BBHM_NS_LOOKUP_DEF_TIME_BETWEEN_IN_MILLISECONDS );
        pStateTimer->SetCounter  ((ANSC_HANDLE)pStateTimer, BBHM_NS_LOOKUP_DEF_NUMBER_PACKETS               );
    }

    BbhmDiageoEnrollObjects((ANSC_HANDLE)pMyObject);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsInitialize
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
BbhmDiagnsInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_NS_LOOKUP_OBJECT       pMyObject    = (PBBHM_DIAG_NS_LOOKUP_OBJECT)hThisObject;

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
    pMyObject->Oid                  = BBHM_DIAG_NS_LOOKUP_OID;
    pMyObject->QueryId              = 0; 
    pMyObject->bActive              = FALSE;

    pMyObject->Reset                = BbhmDiagnsReset;
    pMyObject->CopyDiagParams       = BbhmDiagnsCopyDiagParams;

    /* overwrite the virtual functions */
    pMyObject->StartDiag            = BbhmDiagnsStartDiag;
    pMyObject->StopDiag             = BbhmDiagnsStopDiag;
    pMyObject->RetrieveResult       = BbhmDiagnsRetrieveResult;


    pMyObject->ResetProperty        = BbhmDiagnsResetProperty;
    pMyObject->ResetPropertyCounter = BbhmDiagnsResetPropertyCounter;
    pMyObject->Reset                = BbhmDiagnsReset;
                                    
    pMyObject->Start                = BbhmDiagnsStart;
    pMyObject->Stop                 = BbhmDiagnsStop;
    pMyObject->Open                 = BbhmDiagnsOpen;
    pMyObject->Close                = BbhmDiagnsClose;
    pMyObject->Expire1              = BbhmDiagnsExpire1;
    pMyObject->Expire2              = BbhmDiagnsExpire2;
                                    
    pMyObject->SetStopTime          = BbhmDiagnsSetStopTime;
    pMyObject->AddEchoEntry         = BbhmDiagnsAddEchoEntry;
    pMyObject->PopEchoEntry         = BbhmDiagnsPopEchoEntry;

    pMyObject->Recv                 = BbhmDiagnsRecv;
    pMyObject->Send                 = BbhmDiagnsSend;
                                    
    pMyObject->GetSrcIp             = BbhmDiagnsGetSrcIp;       
    pMyObject->SetSrcIp             = BbhmDiagnsSetSrcIp;   
    pMyObject->GetDstIp             = BbhmDiagnsGetDstIp;       
    pMyObject->SetDstIp             = BbhmDiagnsSetDstIp;       
    pMyObject->GetNumPkts           = BbhmDiagnsGetNumPkts;     
    pMyObject->SetNumPkts           = BbhmDiagnsSetNumPkts;         
    pMyObject->GetTimeOut           = BbhmDiagnsGetTimeOut;     
    pMyObject->SetTimeOut           = BbhmDiagnsSetTimeOut;         
    pMyObject->SetControl           = BbhmDiagnsSetControl;             
    pMyObject->SetStatus            = BbhmDiagnsSetStatus;  
    
    pMyObject->AddPquery            = BbhmDiagnsAddPquery;
    pMyObject->GetPqueryById        = BbhmDiagnsGetPqueryById;
    pMyObject->DelPquery            = BbhmDiagnsDelPquery;
    pMyObject->DelAllPqueries       = BbhmDiagnsDelAllPqueries;
    pMyObject->SetDiagParams        = BbhmDiagnsSetDiagParams;
    pMyObject->CalculateResult      = BbhmDiagnsCalculateResult;
    pMyObject->GetStatus            = BbhmDiagnsGetStatus;

    /*
     * We shall initialize the session properties to the default values, which may be changed later
     * via the "configure" member function. If any of the future extensions needs to change the
     * session property, the following code also needs to be changed.
     */
    pMyObject->ResetProperty((ANSC_HANDLE)pMyObject);

    AnscSListInitializeHeader(&pMyObject->EchoTable);
    AnscSListInitializeHeader(&pMyObject->PqueryTable);

    AnscInitializeLock       (&pMyObject->EchoTableLock);
    AnscInitializeLock       (&pMyObject->PqueryTableLock);

    return  ANSC_STATUS_SUCCESS;
}

