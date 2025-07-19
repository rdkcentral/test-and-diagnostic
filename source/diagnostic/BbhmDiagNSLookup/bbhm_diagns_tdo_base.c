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

    module: bbhm_diagns_tdo_base.c

        For NSLookup Tool,
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the basic container object functions
        of the Poemc Tdo Smo Object.

        *   BbhmDiagnsTdoCreate
        *   BbhmDiagnsTdoRemove
        *   BbhmDiagnsTdoEnrollObjects
        *   BbhmDiagnsTdoInitialize

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Li Shi

    ---------------------------------------------------------------

    revision:

        08/08/09    initial revision.

**********************************************************************/


#include "bbhm_diagns_global.h"
#include "safec_lib_common.h"



/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        BbhmDiagnsTdoCreate
            (
                ANSC_HANDLE                 hContainerContext,
                ANSC_HANDLE                 hOwnerContext,
                ANSC_HANDLE                 hAnscReserved
            );

    description:

        This function constructs the Poemc Timer Object and
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
BbhmDiagnsTdoCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    )
{
    PANSC_COMPONENT_OBJECT          pBaseObject  = NULL;
    PBBHM_NS_LOOKUP_TDO_OBJECT      pMyObject    = NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PBBHM_NS_LOOKUP_TDO_OBJECT)AnscAllocateMemory(sizeof(BBHM_NS_LOOKUP_TDO_OBJECT));

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
    rc = strcpy_s(pBaseObject->Name, sizeof(pBaseObject->Name) , BBHM_NS_LOOKUP_TDO_NAME);
    ERR_CHK(rc);

    pBaseObject->hContainerContext = hContainerContext;
    pBaseObject->hOwnerContext     = hOwnerContext;
    pBaseObject->Oid               = BBHM_NS_LOOKUP_TDO_OID;
    pBaseObject->Create            = BbhmDiagnsTdoCreate;
    pBaseObject->Remove            = BbhmDiagnsTdoRemove;
    pBaseObject->EnrollObjects     = BbhmDiagnsTdoEnrollObjects;
    pBaseObject->Initialize        = BbhmDiagnsTdoInitialize;

    pBaseObject->EnrollObjects((ANSC_HANDLE)pBaseObject);
    pBaseObject->Initialize   ((ANSC_HANDLE)pBaseObject);

    return  (ANSC_HANDLE)pMyObject;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsTdoRemove
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
BbhmDiagnsTdoRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_NS_LOOKUP_TDO_OBJECT      pMyObject    = (PBBHM_NS_LOOKUP_TDO_OBJECT)hThisObject;

    AnscTdoRemove((ANSC_HANDLE)pMyObject);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsTdoEnrollObjects
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
BbhmDiagnsTdoEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_NS_LOOKUP_TDO_OBJECT      pMyObject    = (PBBHM_NS_LOOKUP_TDO_OBJECT)hThisObject;

    AnscTdoEnrollObjects((ANSC_HANDLE)pMyObject);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsTdoInitialize
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
BbhmDiagnsTdoInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_NS_LOOKUP_TDO_OBJECT      pMyObject    = (PBBHM_NS_LOOKUP_TDO_OBJECT)hThisObject;

    /*
     * Until you have to simulate C++ object-oriented programming style with standard C, you don't
     * appreciate all the nice little things come with C++ language and all the dirty works that
     * have been done by the C++ compilers. Member initialization is one of these things. While in
     * C++ you don't have to initialize all the member fields inherited from the base class since
     * the compiler will do it for you, such is not the case with C.
     */
    AnscTdoInitialize((ANSC_HANDLE)pMyObject);

    /*
     * Although we have initialized some of the member fields in the "create" member function, we
     * repeat the work here for completeness. While this simulation approach is pretty stupid from
     * a C++/Java programmer perspective, it's the best we can get for universal embedded network
     * programming. Before we develop our own operating system (don't expect that to happen any
     * time soon), this is the way things gonna be.
     */
    pMyObject->Oid           = BBHM_NS_LOOKUP_TDO_OID;
    pMyObject->Create        = BbhmDiagnsTdoCreate;
    pMyObject->Remove        = BbhmDiagnsTdoRemove;
    pMyObject->EnrollObjects = BbhmDiagnsTdoEnrollObjects;
    pMyObject->Initialize    = BbhmDiagnsTdoInitialize;

    pMyObject->TimerType     = ANSC_TIMER_TYPE_SPORADIC;
    pMyObject->Interval      = BBHM_NS_LOOKUP_DEF_TIME_OUT_IN_MILLISECONDS;
    pMyObject->Counter       = BBHM_NS_LOOKUP_DEF_NUMBER_PACKETS;

    pMyObject->Invoke        = BbhmDiagnsTdoInvoke;
    pMyObject->SetStopTime   = BbhmDiagnsTdoSetStopTime;
    pMyObject->GetStopTime   = BbhmDiagnsTdoGetStopTime;
    pMyObject->SetCounter    = BbhmDiagnsTdoSetCounter;
    pMyObject->GetCounter    = BbhmDiagnsTdoGetCounter;

    return  ANSC_STATUS_SUCCESS;
}

