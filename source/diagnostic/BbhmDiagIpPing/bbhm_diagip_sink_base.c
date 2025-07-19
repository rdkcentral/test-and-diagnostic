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

    module:    bbhm_diagip_sink_base.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the basic construction and removal
        functions of the BBHM IP Ping Sink Object.

        *   BbhmDiagipSinkCreate
        *   BbhmDiagipSinkRemove

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


#include "bbhm_diagip_global.h"


/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        BbhmDiagipSinkCreate
            (
                ANSC_HANDLE                 hOwnerContext
            );

    description:

        This function constructs the Pptm Sink Object and initializes
        the member variables and functions.

    argument:   ANSC_HANDLE                 hOwnerContext
                This handle is passed in by the owner of this object.

    return:     newly created socket object.

**********************************************************************/

ANSC_HANDLE
BbhmDiagipSinkCreate
    (
        ANSC_HANDLE                 hOwnerContext
    )
{
    PBBHM_IP_PING_SINK_OBJECT       pSink        = NULL;

    pSink = (PBBHM_IP_PING_SINK_OBJECT)AnscAllocateMemory(sizeof(BBHM_IP_PING_SINK_OBJECT));

    if ( !pSink )
    {
        return  (ANSC_HANDLE)NULL;
    }

    pSink->hOwnerContext   = hOwnerContext;
    pSink->hXsocketObject  = (ANSC_HANDLE)NULL;

    pSink->Create          = BbhmDiagipSinkCreate;
    pSink->Remove          = BbhmDiagipSinkRemove;

    pSink->GetXsocket      = BbhmDiagipSinkGetXsocket;
    pSink->SetXsocket      = BbhmDiagipSinkSetXsocket;
    pSink->Attach          = BbhmDiagipSinkAttach;
    pSink->Detach          = BbhmDiagipSinkDetach;

    pSink->GetRecvBuffer   = BbhmDiagipSinkGetRecvBuffer;
    pSink->Accept          = BbhmDiagipSinkAccept;
    pSink->Recv            = BbhmDiagipSinkRecv;
    pSink->Close           = BbhmDiagipSinkClose;
    pSink->Abort           = BbhmDiagipSinkAbort;

    pSink->MaxMessageSize  = BBHM_IP_PING_SINK_MAX_MESSAGE_SIZE;
    pSink->CurMessageSize  = 0;
    pSink->Offset          = 0;

    pSink->Reset           = BbhmDiagipSinkReset;

    return  (ANSC_HANDLE)pSink;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSinkRemove
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
BbhmDiagipSinkRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_IP_PING_SINK_OBJECT       pSink             = (PBBHM_IP_PING_SINK_OBJECT  )hThisObject;
    
    pSink->Reset((ANSC_HANDLE)pSink);

    AnscFreeMemory((ANSC_HANDLE)pSink);

    return  ANSC_STATUS_SUCCESS;
}
