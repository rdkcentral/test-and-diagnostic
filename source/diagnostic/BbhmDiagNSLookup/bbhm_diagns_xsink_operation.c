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

    module: bbhm_diagns_xsink_operation.c

        For NSLookup Tool (PING),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced functions of the
        NSLookup Xsink Object.

        *   BbhmDiagnsXsinkGetRecvBuffer
        *   BbhmDiagnsXsinkAccept
        *   BbhmDiagnsXsinkRecv
        *   BbhmDiagnsXsinkClose
        *   BbhmDiagnsXsinkAbort

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

        PVOID
        BbhmDiagnsXsinkGetRecvBuffer
            (
                ANSC_HANDLE                 hThisObject,
                PANSC_HANDLE                phRecvHandle,
                PULONG                      pulSize
            );

    description:

        This function is called by the receive task to retrieve buffer
        from the Xsocket owner to hold received data.

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
BbhmDiagnsXsinkGetRecvBuffer
    (
        ANSC_HANDLE                 hThisObject,
        PANSC_HANDLE                phRecvHandle,
        PULONG                      pulSize
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink            = (PBBHM_NS_LOOKUP_XSINK_OBJECT)hThisObject;
    ULONG                           ulRestSize        = pXsink->MaxMessageSize;

    *phRecvHandle = (ANSC_HANDLE)NULL;
    *pulSize      = ulRestSize;

    return  pXsink->RecvBuffer;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsXsinkAccept
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hNewXsocket
            );

    description:

        This function notifies the Xsocket owner when network data
        arrives at the socket or Xsocket status has changed.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hNewXsocket
                Specifies the Xsocket object we have just created.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsXsinkAccept
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hNewXsocket
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink            = (PBBHM_NS_LOOKUP_XSINK_OBJECT  )hThisObject;
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pNewXsink         = (PBBHM_NS_LOOKUP_XSINK_OBJECT  )BbhmDiagnsXsinkCreate(pXsink->hOwnerContext);

    /*RDKB-7454, CID-33040, free unused resources*/
    if(pNewXsink)
    {
        BbhmDiagnsXsinkRemove(pNewXsink);
    }

    return  ANSC_STATUS_UNAPPLICABLE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsXsinkRecv
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hRecvHandle,
                PVOID                       buffer,
                ULONG                       ulSize
            );

    description:

        This function notifies the socket owner when network data
        arrives at the Xsocket or Xsocket status has changed.

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
BbhmDiagnsXsinkRecv
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hRecvHandle,
        PVOID                       buffer,
        ULONG                       ulSize
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink            = (PBBHM_NS_LOOKUP_XSINK_OBJECT    )hThisObject;
    PBBHM_DIAG_NS_LOOKUP_OBJECT     pBbhmDiagns       = (PBBHM_DIAG_NS_LOOKUP_OBJECT     )pXsink->hOwnerContext;
    
    pBbhmDiagns->Recv
            (
                (ANSC_HANDLE)pBbhmDiagns,
                (ANSC_HANDLE)pXsink,
                buffer,
                ulSize
            );

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsXsinkClose
            (
                ANSC_HANDLE                 hThisObject,
                BOOL                        bByPeer
            );

    description:

        This function notifies the socket owner when network data
        arrives at the Xsocket or Xsocket status has changed.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                BOOL                        bByPeer
                Specifies whether the host or the peer closed the
                pingection.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsXsinkClose
    (
        ANSC_HANDLE                 hThisObject,
        BOOL                        bByPeer
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink            = (PBBHM_NS_LOOKUP_XSINK_OBJECT)hThisObject;
    
    pXsink->Reset((ANSC_HANDLE)pXsink);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagnsXsinkAbort
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function notifies the Xsocket owner when critical network
        failure is detected.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagnsXsinkAbort
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_NS_LOOKUP_XSINK_OBJECT    pXsink            = (PBBHM_NS_LOOKUP_XSINK_OBJECT    )hThisObject;
    
    pXsink->Reset((ANSC_HANDLE)pXsink);

    return  ANSC_STATUS_SUCCESS;
}

