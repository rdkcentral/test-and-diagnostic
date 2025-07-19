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

    module: bbhm_Diagns_xsink_state.c

        For NSLookup Tool,
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced functions of the
        NSLookup Xsink Object.

        *   BbhmDiagnsXsinkGetXsocket
        *   BbhmDiagnsXsinkSetXsocket
        *   BbhmDiagnsXsinkAttach
        *   BbhmDiagnsXsinkDetach
        *   BbhmDiagnsXsinkReset

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


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        BbhmDiagnsXsinkGetXsocket
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function retrieves the state of the object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     state of object.

**********************************************************************/

ANSC_HANDLE
BbhmDiagnsXsinkGetXsocket
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink       = (PBBHM_NS_LOOKUP_XSINK_OBJECT)hThisObject;

    return  pXsink->hXsocketObject;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsXsinkSetXsocket
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hXsocket
            );

    description:

        This function configures the state of the object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hXsocket
                Specifies the state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsXsinkSetXsocket
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hXsocket
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink       = (PBBHM_NS_LOOKUP_XSINK_OBJECT)hThisObject;

    pXsink->hXsocketObject = hXsocket;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsXsinkAttach
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hXsocket
            );

    description:

        This function configures the state of the object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hXsocket
                Specifies the state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsXsinkAttach
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hXsocket
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink       = (PBBHM_NS_LOOKUP_XSINK_OBJECT)hThisObject;

    pXsink->hXsocketObject = hXsocket;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsXsinkDetach
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function configures the state of the object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsXsinkDetach
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink       = (PBBHM_NS_LOOKUP_XSINK_OBJECT)hThisObject;
    PANSC_XSOCKET_OBJECT            pXsocket     = (PANSC_XSOCKET_OBJECT        )pXsink->hXsocketObject;

    if ( pXsocket )
    {
        pXsocket->Close ((ANSC_HANDLE)pXsocket);
        pXsocket->Remove((ANSC_HANDLE)pXsocket);

        pXsink->hXsocketObject = (ANSC_HANDLE)NULL;
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsXsinkReset
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function resets the state of the object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsXsinkReset
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink            = (PBBHM_NS_LOOKUP_XSINK_OBJECT)hThisObject;
    
    pXsink->MaxMessageSize = NS_LOOKUP_XSINK_MAX_MESSAGE_SIZE;
    pXsink->CurMessageSize = 0;
    pXsink->Offset         = 0;

    return  ANSC_STATUS_SUCCESS;
}

