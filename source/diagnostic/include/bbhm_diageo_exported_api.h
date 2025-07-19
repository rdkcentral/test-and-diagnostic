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

    module: bbhm_diageo_exported_api.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the exported functions provided by the Bbhm Diagnostic Executor
        Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Ding Hua, Li Shi

    ---------------------------------------------------------------

    revision:

        02/08/07    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGEO_EXPORTED_API_
#define  _BBHM_DIAGEO_EXPORTED_API_


/***********************************************************
      FUNCTIONS IMPLEMENTED IN BBHM_DIAGEO_INTERFACE.C
***********************************************************/

ANSC_HANDLE
BbhmCreateDiagnosticExecutor
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );


/***********************************************************
        FUNCTIONS IMPLEMENTED IN BBHM_DIAGEO_BASE.C
***********************************************************/

ANSC_HANDLE
BbhmDiageoCreate
    (
        ANSC_HANDLE                 hContainerContext,
        ANSC_HANDLE                 hOwnerContext,
        ANSC_HANDLE                 hAnscReserved
    );

ANSC_STATUS
BbhmDiageoRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiageoEnrollObjects
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiageoInitialize
    (
        ANSC_HANDLE                 hThisObject
    );


/***********************************************************
     FUNCTIONS IMPLEMENTED IN BBHM_DIAGEO_PROCESS.C
***********************************************************/

BOOLEAN
BbhmDiageoCheckCanStart
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiageoStartDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiageoStopDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDiageoRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    );

/***********************************************************
     FUNCTIONS IMPLEMENTED IN BBHM_DIAGEO_STATES.C
***********************************************************/

ANSC_STATUS
BbhmDiageoSetDiagState
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulDiagState
    );

#endif

