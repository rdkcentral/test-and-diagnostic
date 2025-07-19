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

    module:    bbhm_diagit_sink_states.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced functions of the
        Tracert Sink Object.

        *   BbhmDiagitSinkGetSocket
        *   BbhmDiagitSinkSetSocket
        *   BbhmDiagitSinkAttach
        *   BbhmDiagitSinkDetach
        *   BbhmDiagitSinkReset

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Du Li, Li Shi

    ---------------------------------------------------------------

    revision:

        08/06/09    initial revision.

**********************************************************************/


#include "bbhm_diagit_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        BbhmDiagitSinkGetSocket
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
BbhmDiagitSinkGetSocket
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink        = (PBBHM_TRACERT_SINK_OBJECT)hThisObject;

    return  pSink->hXsocketObject;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSinkSetSocket
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hSocket
            );

    description:

        This function configures the state of the object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hSocket
                Specifies the state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSinkSetSocket
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink        = (PBBHM_TRACERT_SINK_OBJECT)hThisObject;

    pSink->hXsocketObject = hSocket;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSinkAttach
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hSocket
            );

    description:

        This function configures the state of the object.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hSocket
                Specifies the state to be configured.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSinkAttach
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSocket
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink        = (PBBHM_TRACERT_SINK_OBJECT)hThisObject;

    pSink->hXsocketObject = hSocket;

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSinkDetach
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
BbhmDiagitSinkDetach
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink        = (PBBHM_TRACERT_SINK_OBJECT)hThisObject;
    PANSC_XSOCKET_OBJECT            pSocket      = (PANSC_XSOCKET_OBJECT)pSink->hXsocketObject;

    if ( pSocket )
    {
        pSocket->Close ((ANSC_HANDLE)pSocket);
        pSocket->Remove((ANSC_HANDLE)pSocket);

        pSink->hXsocketObject = (ANSC_HANDLE)NULL;
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSinkReset
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
BbhmDiagitSinkReset
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink             = (PBBHM_TRACERT_SINK_OBJECT     )hThisObject;
    
    pSink->MaxMessageSize = BBHM_TRACERT_SINK_MAX_MESSAGE_SIZE;
    pSink->CurMessageSize = 0;
    pSink->Offset         = 0;

    return  ANSC_STATUS_SUCCESS;
}
