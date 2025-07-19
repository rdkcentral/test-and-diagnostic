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

    module:	bbhm_udpecho_base.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the basic container object functions
        of the Bbhm UDP Echo Server Object.

        *   BbhmUdpechoCreate
        *   BbhmUdpechoRemove
        *   BbhmUdpechoEnrollObjects
        *   BbhmUdpechoInitialize

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        06/25/2010    initial revision.

**********************************************************************/


#include "bbhm_udpecho_global.h"
#include "safec_lib_common.h"
PBBHM_UDP_ECHOSRV_OBJECT        g_UdpechoObj = NULL;


/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        BbhmUdpechoCreate
            (
                ANSC_HANDLE                 hContainerContext,
                ANSC_HANDLE                 hOwnerContext,
                ANSC_HANDLE                 hAnscReserved
            );

    description:

        This function constructs the Bbhm UDP Echo Server Object and
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
BbhmUdpechoCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    )
{
    PANSC_COMPONENT_OBJECT          pBaseObject  = NULL;
    PBBHM_UDP_ECHOSRV_OBJECT        pMyObject    = NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PBBHM_UDP_ECHOSRV_OBJECT)AnscAllocateMemory(sizeof(BBHM_UDP_ECHOSRV_OBJECT));

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
    rc = strcpy_s(pBaseObject->Name, sizeof(pBaseObject->Name) , BBHM_DIAG_UDPECHO_SERVER_NAME);
    ERR_CHK(rc);

    pBaseObject->hContainerContext = hContainerContext;
    pBaseObject->hOwnerContext     = hOwnerContext;
    pBaseObject->Oid               = BBHM_DIAG_UDPECHO_SERVER_OID;
    pBaseObject->Create            = BbhmUdpechoCreate;
    pBaseObject->Remove            = BbhmUdpechoRemove;
    pBaseObject->EnrollObjects     = BbhmUdpechoEnrollObjects;
    pBaseObject->Initialize        = BbhmUdpechoInitialize;

    pBaseObject->EnrollObjects((ANSC_HANDLE)pBaseObject);
    pBaseObject->Initialize   ((ANSC_HANDLE)pBaseObject);

    g_UdpechoObj = pMyObject;

    return  (ANSC_HANDLE)pMyObject;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUdpechoRemove
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
BbhmUdpechoRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_UDP_ECHOSRV_OBJECT pMyObject = (PBBHM_UDP_ECHOSRV_OBJECT)hThisObject;

    /* CID - 58154 Use after free */
    /* Removed "cancel and remove calls" as BbhmDiageoRemove() is internally using 
       same calls to free the pMyObject */
    BbhmDiageoRemove((ANSC_HANDLE)pMyObject);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUdpechoEnrollObjects
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
BbhmUdpechoEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_UDP_ECHOSRV_OBJECT        pMyObject    = (PBBHM_UDP_ECHOSRV_OBJECT  )hThisObject;

    AnscCoEnrollObjects((ANSC_HANDLE)pMyObject);
    BbhmDiageoEnrollObjects((ANSC_HANDLE)pMyObject);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUdpechoInitialize
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
BbhmUdpechoInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_UDP_ECHOSRV_OBJECT        pMyObject    = (PBBHM_UDP_ECHOSRV_OBJECT)hThisObject;

    /*
     * Until you have to simulate C++ object-oriented programming style with standard C, you don't
     * appreciate all the nice little things come with C++ language and all the dirty works that
     * have been done by the C++ compilers. Member initialization is one of these things. While in
     * C++ you don't have to initialize all the member fields inherited from the base class since
     * the compiler will do it for you, such is not the case with C.
     */
    AnscCoInitialize((ANSC_HANDLE)pMyObject);

    /*
     * Although we have initialized some of the member fields in the "create" member function, we
     * repeat the work here for completeness. While this simulation approach is pretty stupid from
     * a C++/Java programmer perspective, it's the best we can get for universal embedded network
     * programming. Before we develop our own operating system (don't expect that to happen any
     * time soon), this is the way things gonna be.
     */
    pMyObject->Oid                        = BBHM_DIAG_UDPECHO_SERVER_OID;
    pMyObject->Create                     = BbhmUdpechoCreate;
    pMyObject->Remove                     = BbhmUdpechoRemove;
    pMyObject->EnrollObjects              = BbhmUdpechoEnrollObjects;
    pMyObject->Initialize                 = BbhmUdpechoInitialize;

    /* overwrite the virtual functions */
    pMyObject->StartDiag                  = BbhmUdpechoStartDiag;
    pMyObject->StopDiag                   = BbhmUdpechoStopDiag;
    pMyObject->GetResult                  = BbhmUdpechoGetResult;
    pMyObject->RetrieveResult             = BbhmUdpechoRetrieveResult;
    pMyObject->SetDiagParams              = BbhmUdpechoSetConfig;
    pMyObject->GetConfig                  = BbhmUdpechoGetConfig;   
    
    pMyObject->bActive                    = FALSE;
    pMyObject->bIsServerOn                = FALSE;
    pMyObject->bStopServer                = FALSE;

    pMyObject->Engage                     = BbhmUdpechoEngage;
    pMyObject->Cancel                     = BbhmUdpechoCancel;

    DslhInitUDPEchoConfig((&pMyObject->UDPEchoConfig));

    DslhResetUDPEchoServerStats((&pMyObject->UDPEchoStats));

#ifdef _ANSC_UDP_ECHO_SERVER_PLUS_SUPPORTED_

    pMyObject->UDPEchoConfig.EchoPlusSupported  = TRUE;

#endif

    return  ANSC_STATUS_SUCCESS;
}

