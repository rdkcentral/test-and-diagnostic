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

    module:	bbhm_udpecho_internal_api.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the internal functions provided by the Bbhm UDP Echo server
        Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        06/22/2010    initial revision.

**********************************************************************/


#ifndef  _BBHM_UDPECHO_INTERNAL_API_
#define  _BBHM_UDPECHO_INTERNAL_API_


/***********************************************************
       FUNCTIONS IMPLEMENTED IN BBHM_UDPECHO_OPERATION.C
***********************************************************/

ANSC_STATUS
BbhmUdpechoEngage
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmUdpechoCancel
    (
        ANSC_HANDLE                 hThisObject
    );


/***********************************************************
         FUNCTIONS IMPLEMENTED IN BBHM_UDPECHO_ACTION.C
***********************************************************/

ANSC_STATUS
BbhmUdpechoStartDiag
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmUdpechoStopDiag
    (
        ANSC_HANDLE                 hThisObject
    );


ANSC_HANDLE
BbhmUdpechoGetResult
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmUdpechoRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    );


ANSC_HANDLE
BbhmUdpechoGetConfig

    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
BbhmUdpechoSetConfig

    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

#endif
