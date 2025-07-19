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

    module:    bbhm_diagit_sink_operation.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced functions of the
        Tracert Sink Object.

        *   BbhmDiagitSinkGetRecvBuffer
        *   BbhmDiagitSinkAccept
        *   BbhmDiagitSinkRecv
        *   BbhmDiagitSinkClose
        *   BbhmDiagitSinkAbort

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

        PVOID
        BbhmDiagitSinkGetRecvBuffer
            (
                ANSC_HANDLE                 hThisObject,
                PANSC_HANDLE                phRecvHandle,
                PULONG                      pulSize
            );

    description:

        This function is called by the receive task to retrieve buffer
        from the socket owner to hold received data.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                PANSC_HANDLE                phRecvHandle
                Specifies a context which is associated with the
                returned buffer.

                PULONG                      pulSize
                This parameter returns the buffer size.

    return:     buffer pointer.

**********************************************************************/

PVOID
BbhmDiagitSinkGetRecvBuffer
    (
        ANSC_HANDLE                 hThisObject,
        PANSC_HANDLE                phRecvHandle,
        PULONG                      pulSize
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink             = (PBBHM_TRACERT_SINK_OBJECT     )hThisObject;
    ULONG                           ulRestSize        = pSink->MaxMessageSize;

    *phRecvHandle = (ANSC_HANDLE)NULL;
    *pulSize      = ulRestSize;

    return  pSink->RecvBuffer;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSinkAccept
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hNewSocket
            );

    description:

        This function notifies the socket owner when network data
        arrives at the socket or socket status has changed.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hNewSocket
                Specifies the socket object we have just created.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSinkAccept
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hNewSocket
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink             = (PBBHM_TRACERT_SINK_OBJECT        )hThisObject;
    PBBHM_TRACERT_SINK_OBJECT       pNewSink          = (PBBHM_TRACERT_SINK_OBJECT        )BbhmDiagitSinkCreate(pSink->hOwnerContext);

    /*RDKB-7452, CID-32932, free unused memory*/
    if(pNewSink)
    {
        BbhmDiagitSinkRemove(pNewSink);
    }

    return  ANSC_STATUS_UNAPPLICABLE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagittSinkRecv
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hRecvHandle,
                PVOID                       buffer,
                ULONG                       ulSize
            );

    description:

        This function notifies the socket owner when network data
        arrives at the socket or socket status has changed.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hRecvHandle
                Specifies the context returned by get_recv_buffer().

                PVOID                       buffer
                Specifies the buffer holding the received data.

                ULONG                       ulSize
                Specifies the size of the data buffer.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSinkRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hRecvHandle,
        PVOID                       buffer,
        ULONG                       ulSize
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink             = (PBBHM_TRACERT_SINK_OBJECT      )hThisObject;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pBbhmDiagit       = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT)pSink->hOwnerContext;
    
    pBbhmDiagit->Recv
            (
                (ANSC_HANDLE)pBbhmDiagit,
                (ANSC_HANDLE)pSink,
                buffer,
                ulSize
            );

    /*AnscTrace("Return from BbhmTracertSinkRecv\n");*/
    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSinkClose
            (
                ANSC_HANDLE                 hThisObject,
                BOOL                        bByPeer
            );

    description:

        This function notifies the socket owner when network data
        arrives at the socket or socket status has changed.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                BOOL                        bByPeer
                Specifies whether the host or the peer closed the
                pingection.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSinkClose
    (
        ANSC_HANDLE                 hThisObject,
        BOOL                        bByPeer
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink             = (PBBHM_TRACERT_SINK_OBJECT     )hThisObject;
    
    pSink->Reset((ANSC_HANDLE)pSink);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSinkAbort
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function notifies the socket owner when critical network
        failure is detected.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSinkAbort
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_TRACERT_SINK_OBJECT       pSink             = (PBBHM_TRACERT_SINK_OBJECT     )hThisObject;
    
    pSink->Reset((ANSC_HANDLE)pSink);

    return  ANSC_STATUS_SUCCESS;
}
