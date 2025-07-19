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

    module: bbhm_download_internal_api.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the internal functions provided by the Bbhm Download Diagnostics 
        Object.

        Bbhm Diagnostics are defined in TR143

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

       Jinghua Xu 

    ---------------------------------------------------------------

    revision:

        06/22/2010    initial revision.

**********************************************************************/


#ifndef  _BBHM_DOWNLOAD_INTERNAL_API_
#define  _BBHM_DOWNLOAD_INTERNAL_API_


/***********************************************************
       FUNCTIONS IMPLEMENTED IN BBHM_DIACO_OPERATION.C
***********************************************************/

ANSC_STATUS
BbhmDownloadEngage
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDownloadCancel
    (
        ANSC_HANDLE                 hThisObject
    );


ANSC_STATUS
BbhmDownloadSetupEnv
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDownloadCloseEnv
    (
        ANSC_HANDLE                 hThisObject
    );

/***********************************************************
         FUNCTIONS IMPLEMENTED IN BBHM_DIACO_ACTION.C
***********************************************************/

ANSC_STATUS
BbhmDownloadStartDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDownloadStopDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_HANDLE
BbhmDownloadGetResult
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDownloadRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_HANDLE
BbhmDownloadGetConfig
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmDownloadSetConfig

    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

ANSC_STATUS
BbhmDownloadSetDiagState

    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulDiagState
    );

#endif

