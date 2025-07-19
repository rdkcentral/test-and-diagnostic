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

    module:    bbhm_diagit_sink_base.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the basic construction and removal
        functions of the Tracert Sink Object.

        *   BbhmDiagitSinkCreate
        *   BbhmDiagitSinkRemove

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Du Li, Li Shi

    ---------------------------------------------------------------

    revision:

        10/17/02    initial revision.

**********************************************************************/


#include "bbhm_diagit_global.h"


/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        BbhmDiagitSinkCreate
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
BbhmDiagitSinkCreate
    (
        ANSC_HANDLE                 hOwnerContext
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink        = NULL;

    pSink = (PBBHM_TRACERT_SINK_OBJECT)AnscAllocateMemory(sizeof(BBHM_TRACERT_SINK_OBJECT));

    if ( !pSink )
    {
        return  (ANSC_HANDLE)NULL;
    }

    pSink->hOwnerContext   = hOwnerContext;
    pSink->hXsocketObject   = (ANSC_HANDLE)NULL;

    pSink->Create          = BbhmDiagitSinkCreate;
    pSink->Remove          = BbhmDiagitSinkRemove;

    pSink->GetXsocket      = BbhmDiagitSinkGetSocket;
    pSink->SetXsocket      = BbhmDiagitSinkSetSocket;
    pSink->Attach          = BbhmDiagitSinkAttach;
    pSink->Detach          = BbhmDiagitSinkDetach;

    pSink->GetRecvBuffer   = BbhmDiagitSinkGetRecvBuffer;
    pSink->Accept          = BbhmDiagitSinkAccept;
    pSink->Recv            = BbhmDiagitSinkRecv;
    pSink->Close           = BbhmDiagitSinkClose;
    pSink->Abort           = BbhmDiagitSinkAbort;

    pSink->MaxMessageSize  = BBHM_TRACERT_SINK_MAX_MESSAGE_SIZE;
    pSink->CurMessageSize  = 0;
    pSink->Offset          = 0;

    pSink->Reset           = BbhmDiagitSinkReset;

    return  (ANSC_HANDLE)pSink;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSinkRemove
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
BbhmDiagitSinkRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink             = (PBBHM_TRACERT_SINK_OBJECT     )hThisObject;
    
    pSink->Reset((ANSC_HANDLE)pSink);

    AnscFreeMemory((ANSC_HANDLE)pSink);

    return  ANSC_STATUS_SUCCESS;
}
