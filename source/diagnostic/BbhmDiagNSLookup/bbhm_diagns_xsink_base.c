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

    module: bbhm_diagns_xsink_base.c

        For NSLookup,
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the basic construction and removal
        functions of the BBHM NSLookup Xsink Object.

        *   BbhmDiagnsXsinkCreate
        *   BbhmDiagnsXsinkRemove

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

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        BbhmDiagnsXsinkCreate
            (
                ANSC_HANDLE                 hOwnerContext
            );

    description:

        This function constructs the Pptm Xsink Object and initializes
        the member variables and functions.

    argument:   ANSC_HANDLE                 hOwnerContext
                This handle is passed in by the owner of this object.

    return:     newly created socket object.

**********************************************************************/

ANSC_HANDLE
BbhmDiagnsXsinkCreate
    (
        ANSC_HANDLE                 hOwnerContext
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink       = NULL;

    pXsink = (PBBHM_NS_LOOKUP_XSINK_OBJECT)AnscAllocateMemory(sizeof(BBHM_NS_LOOKUP_XSINK_OBJECT));

    if ( !pXsink )
    {
        return  (ANSC_HANDLE)NULL;
    }

    pXsink->hOwnerContext   = hOwnerContext;
    pXsink->hXsocketObject  = (ANSC_HANDLE)NULL;

    pXsink->Create          = BbhmDiagnsXsinkCreate;
    pXsink->Remove          = BbhmDiagnsXsinkRemove;

    pXsink->GetXsocket      = BbhmDiagnsXsinkGetXsocket;
    pXsink->SetXsocket      = BbhmDiagnsXsinkSetXsocket;
    pXsink->Attach          = BbhmDiagnsXsinkAttach;
    pXsink->Detach          = BbhmDiagnsXsinkDetach;

    pXsink->GetRecvBuffer   = BbhmDiagnsXsinkGetRecvBuffer;
    pXsink->Accept          = BbhmDiagnsXsinkAccept;
    pXsink->Recv            = BbhmDiagnsXsinkRecv;
    pXsink->Close           = BbhmDiagnsXsinkClose;
    pXsink->Abort           = BbhmDiagnsXsinkAbort;

    pXsink->MaxMessageSize  = NS_LOOKUP_XSINK_MAX_MESSAGE_SIZE;
    pXsink->CurMessageSize  = 0;
    pXsink->Offset          = 0;

    pXsink->Reset           = BbhmDiagnsXsinkReset;

    return  (ANSC_HANDLE)pXsink;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsXsinkRemove
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
BbhmDiagnsXsinkRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink            = (PBBHM_NS_LOOKUP_XSINK_OBJECT)hThisObject;
    
    pXsink->Reset((ANSC_HANDLE)pXsink);

    AnscFreeMemory((ANSC_HANDLE)pXsink);

    return  ANSC_STATUS_SUCCESS;
}

