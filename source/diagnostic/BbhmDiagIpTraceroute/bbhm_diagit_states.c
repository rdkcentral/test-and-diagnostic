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

    module:     bbhm_diagit_states.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced state-access functions
        of the Bbhm IpTraceroute Diagnostic Object.

        *   BbhmDiagitCopyDiagParams
        *   BbhmDiagitReset
        *   BbhmDiagitGetProperty
        *   BbhmDiagitSetProperty
        *   BbhmDiagitGetSrcIpType
        *   BbhmDiagitSetSrcIpType
        *   BbhmDiagitGetDstIpType
        *   BbhmDiagitGetSrcIp
        *   BbhmDiagitSetSrcIp
        *   BbhmDiagitSetDstIp
        *   BbhmDiagitGetDstIp
        *   BbhmDiagitSetDstIp
        *   BbhmDiagitGetNumPkts
        *   BbhmDiagitSetNumPkts
        *   BbhmDiagitGetPktSize
        *   BbhmDiagitSetPktSize
        *   BbhmDiagitGetTimeBetween
        *   BbhmDiagitSetTimeBetween
        *   BbhmDiagitGetTimeOut
        *   BbhmDiagitSetTimeOut
        *   BbhmDiagitGetControl
        *   BbhmDiagitSetControl
        *   BbhmDiagitGetStatus
        *   BbhmDiagitSetStatus
        *   BbhmDiagitGetPktsSent
        *   BbhmDiagitSetPktsSent
        *   BbhmDiagitGetPktsRecv
        *   BbhmDiagitSetPktsRecv
        *   BbhmDiagitGetAvgRTT
        *   BbhmDiagitSetAvgRTT
        *   BbhmDiagitGetMaxRTT
        *   BbhmDiagitSetMaxRTT
        *   BbhmDiagitGetMinRTT
        *   BbhmDiagitSetMinRTT
        *   BbhmDiagitGetNumIcmpError
        *   BbhmDiagitSetNumIcmpError
        *   BbhmDiagitGetIcmpError
        *   BbhmDiagitSetIcmpError
        *   BbhmDiagitResetProperty
        *   BbhmDiagitResetPropertyCounter

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Du Li, Li Shi

    ---------------------------------------------------------------

    revision:

        2009/07/30    initial revision.

**********************************************************************/


#include "bbhm_diagit_global.h"
#include "safec_lib_common.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetDiagParams
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDslhDiagInfo
            );

    description:

        This function is called to set the diagnostic parameters. If
        the diagnostic process is ongoing, it will be stopped first.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitCopyDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT)hThisObject;

    DslhCloneTracerouteInfo(((PDSLH_TRACEROUTE_INFO)pMyObject->hDslhDiagInfo), ((PDSLH_TRACEROUTE_INFO)hDslhDiagInfo));

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitReset
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to reset object states.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitReset
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject     = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT)hThisObject;
    PDSLH_TRACEROUTE_INFO           pDslhDiagInfo = (PDSLH_TRACEROUTE_INFO          )pMyObject->hDslhDiagInfo;

    if ( pDslhDiagInfo )
    {
        AnscZeroMemory((ANSC_HANDLE)pDslhDiagInfo, sizeof(DSLH_TRACEROUTE_INFO));
    }

    return  ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitGetProperty
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hProperty
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                    hProperty
                This handle is the pointer of the property.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitGetProperty
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    *(PBBHM_TRACERT_PROPERTY)hProperty    = *pProperty;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetProperty
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                    hProperty
            );

    description:

        This function is called to set the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ANSC_HANDLE                    hProperty
                This handle is the pointer of the property.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetProperty
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                    hProperty
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    *pProperty    = *(PBBHM_TRACERT_PROPERTY)hProperty;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetSrcIpType
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Src IP Type.

**********************************************************************/

ULONG
BbhmDiagitGetSrcIpType
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->SrcIpType;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetSrcIpType
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulType
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulType
                This is the Type value.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetSrcIpType
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulType
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->SrcIpType    = ulType;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetDstIpType
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Dst IP Type.

**********************************************************************/

ULONG
BbhmDiagitGetDstIpType
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->DstIpType;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetDstIpType
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulType
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulType
                This is the Type value.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetDstIpType
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulType
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->DstIpType    = ulType;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        PUCHAR
        BbhmDiagitGetSrcIp
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Src IP.

**********************************************************************/

PUCHAR
BbhmDiagitGetSrcIp
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->SrcIp.Dot;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetSrcIp
            (
                ANSC_HANDLE                 hThisObject,
                PUCHAR                        IpAddr
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                PUCHAR                        IpAddr
                This is the IpAddress in Dot format.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetSrcIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      IpAddr
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->SrcIp.Value    = AnscReadUlong(IpAddr);

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        PUCHAR
        BbhmDiagitGetDstIp
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Dst IP.

**********************************************************************/

PUCHAR
BbhmDiagitGetDstIp
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->DstIp.Dot;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetDstIp
            (
                ANSC_HANDLE                 hThisObject,
                PUCHAR                      IpAddr
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                PUCHAR                        IpAddr
                This is the IpAddress in Dot format.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetDstIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      IpAddr
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    /*pProperty->DstIp.Value    = AnscReadUlong(IpAddr);*/

    if ( pProperty->pDstAddrName )
    {
        AnscFreeMemory(pProperty->pDstAddrName);
    }

    pProperty->pDstAddrName = AnscCloneString(IpAddr);

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetNumPkts
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Number of packets need to be sent.

**********************************************************************/

ULONG
BbhmDiagitGetNumPkts
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->NumPkts;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetNumPkts
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulNumPkts
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulNumPkts
                This is the NumPkts value.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetNumPkts
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulNumPkts
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->NumPkts    = ulNumPkts;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetPktSize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Packet size.

**********************************************************************/

ULONG
BbhmDiagitGetPktSize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->PktSize;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetPktSize
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       ulPktSize
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulPktSize
                This is the PktSize value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetPktSize
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktSize
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->PktSize    = ulPktSize;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetTimeBetween
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Protocol.

**********************************************************************/

ULONG
BbhmDiagitGetTimeBetween
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->TimeBetween;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetTimeBetween
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulTimeBetween
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulProto
                This is the Protocol value.

    return:     Status of the operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetTimeBetween
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulTimeBetween
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->TimeBetween    = ulTimeBetween;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetTimeOut
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Timeout time in Milliseconds.

**********************************************************************/

ULONG
BbhmDiagitGetTimeOut
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->TimeOut;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetTimeOut
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       ulTimeOut
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulTimeOut
                This is the TimeOut value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetTimeOut
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulTimeOut
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->TimeOut    = ulTimeOut;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetControl
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Control value.

**********************************************************************/

ULONG
BbhmDiagitGetControl
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->Control;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetControl
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       ulControl
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulControl
                This is the Control value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetControl
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulControl
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->Control    = ulControl;

    if ( ulControl == BBHM_TRACERT_CONTROL_START )
    {
        returnStatus =
            pMyObject->Start((ANSC_HANDLE)pMyObject);
    }
    else if ( ulControl == BBHM_TRACERT_CONTROL_ABORT )
    {
        pMyObject->SetStatus((ANSC_HANDLE)pMyObject, BBHM_TRACERT_STATUS_ABORT);

        returnStatus =
            pMyObject->Stop((ANSC_HANDLE)pMyObject);
    }

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetStatus
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Status value.

**********************************************************************/

ULONG
BbhmDiagitGetStatus
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->Status;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetStatus
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulStatus
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulStatus
                This is the Status value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetStatus
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulStatus
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->Status    = ulStatus;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetPktsSent
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     PktsSent value.

**********************************************************************/

ULONG
BbhmDiagitGetPktsSent
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->PktsSent;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetPktsSent
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulPktsSent
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulPktsSent
                This is the PktsSent value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetPktsSent
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktsSent
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->PktsSent    = ulPktsSent;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetPktsRecv
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     PktsRecv value.

**********************************************************************/

ULONG
BbhmDiagitGetPktsRecv
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->PktsRecv;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetPktsRecv
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulPktsRecv
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulPktsRecv
                This is the PktsRecv value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetPktsRecv
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktsRecv
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->PktsRecv    = ulPktsRecv;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetRTT
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     RTT value.

**********************************************************************/

ULONG
BbhmDiagitGetAvgRTT
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->AvgRTT;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetAvgRTT
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulAvgRTT
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulAvgRTT
                This is the RTT value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetAvgRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulAvgRTT
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY           )&pMyObject->Property;

    pProperty->AvgRTT    = ulAvgRTT;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetMaxRTT
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     RTT value.

**********************************************************************/

ULONG
BbhmDiagitGetMaxRTT
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->MaxRTT;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetMaxRTT
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulMaxRTT
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulMaxRTT
                This is the RTT value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetMaxRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulMaxRTT
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->MaxRTT    = ulMaxRTT;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetMinRTT
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     RTT value.

**********************************************************************/

ULONG
BbhmDiagitGetMinRTT
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->MinRTT;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetMinRTT
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulMinRTT
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulMinRTT
                This is the RTT value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetMinRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulMinRTT
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->MinRTT    = ulMinRTT;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetNumIcmpError
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Number of Icmp errors.

**********************************************************************/

ULONG
BbhmDiagitGetNumIcmpError
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->NumIcmpError;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetNumIcmpError
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulNumIcmpError
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulNumIcmpError
                This is the Throughput value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetNumIcmpError
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulNumIcmpError
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->NumIcmpError    = ulNumIcmpError;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetIcmpError
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     The last Icmp errors.

**********************************************************************/

ULONG
BbhmDiagitGetIcmpError
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->IcmpError;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetIcmpError
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulIcmpError
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulIcmpError
                This is the Throughput value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetIcmpError
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulIcmpError
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->IcmpError    = ulIcmpError;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetTtl
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     The last Icmp errors.

**********************************************************************/

ULONG
BbhmDiagitGetTtl
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->Ttl;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetTtl
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       Ttl
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulIcmpError
                This is the Throughput value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetTtl
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       Ttl
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->Ttl    = Ttl;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetDiagInfo
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     The last Icmp errors.

**********************************************************************/

ANSC_HANDLE
BbhmDiagitGetDiagInfo
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    
    return  pMyObject->hDslhDiagInfo;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetDiagInfo
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDslhDiagInfo
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulIcmpError
                This is the Throughput value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetDiagInfo
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    
    pMyObject->hDslhDiagInfo    = hDslhDiagInfo;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        BbhmDiagitGetStateUpdated
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     The last Icmp errors.

**********************************************************************/

BOOL
BbhmDiagitGetStateUpdated
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PDSLH_TRACEROUTE_INFO           pDslhTracertObj = (PDSLH_TRACEROUTE_INFO          )pMyObject->hDslhDiagInfo;

    return  pDslhTracertObj->bRouteUpdated;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetStateUpdated
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDslhDiagInfo
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulIcmpError
                This is the Throughput value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetStateUpdated
    (
        ANSC_HANDLE                 hThisObject,
        BOOL                        StateUpdated
    )
{
    ANSC_STATUS                     returnStatus    = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject       = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PDSLH_TRACEROUTE_INFO           pDslhTracertObj = (PDSLH_TRACEROUTE_INFO             )pMyObject->hDslhDiagInfo;

    pDslhTracertObj->bRouteUpdated    = StateUpdated;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitGetDstIpVal
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     The last Icmp errors.

**********************************************************************/

ULONG
BbhmDiagitGetDstIpVal
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->DstIp.Value;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        char*
        BbhmDiagitGetDstAddrName
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     The last Icmp errors.

**********************************************************************/

char*
BbhmDiagitGetDstAddrName
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    return  pProperty->pDstAddrName;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetDstIpVal
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       IpVal
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulIcmpError
                This is the Throughput value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetDstIpVal
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       IpVal
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->DstIp.Value = IpVal;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitResetProperty
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to reset the property.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitResetProperty
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus    = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject       = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty       = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;
    PDSLH_TRACEROUTE_INFO           pDslhTracertObj = (PDSLH_TRACEROUTE_INFO             )pMyObject->hDslhDiagInfo;
    ULONG                           address         = (ULONG                             )0;
    
    pProperty->SrcIpType    = BBHM_TRACERT_DEF_INET_ADDRESS_TYPE;
    pProperty->SrcIp.Value  = AnscUlongFromHToN(BBHM_TRACERT_DEF_SRC_IP);
    pProperty->DstIpType    = BBHM_TRACERT_DEF_INET_ADDRESS_TYPE;
    pProperty->DstIp.Value  = 0;
    pProperty->NumPkts      = BBHM_TRACERT_DEF_NUMBER_PACKETS;
    pProperty->PktSize      = BBHM_TRACERT_DEF_PACKET_SIZE;
    pProperty->TimeBetween  = BBHM_TRACERT_DEF_TIME_BETWEEN_IN_MILLISECONDS;
    pProperty->TimeOut      = BBHM_TRACERT_DEF_TIME_OUT_IN_MILLISECONDS;
    pProperty->Control      = BBHM_TRACERT_DEF_CONTROL;
    pProperty->Status       = BBHM_TRACERT_DEF_STATUS;
    pProperty->PktsSent     = 0;
    pProperty->PktsRecv     = 0;
    pProperty->BytesSent    = 0;
    pProperty->BytesRecv    = 0;
    pProperty->AvgRTT       = 0;
    pProperty->MaxRTT       = 0;
    pProperty->MinRTT       = 0;
    pProperty->NumIcmpError = 0;
    pProperty->IcmpError    = 0;
    pProperty->Ttl          = 1;
    pProperty->LastHopReached = FALSE;

    if ( pDslhTracertObj )
    {
        address = pMyObject->ResolveHost((ANSC_HANDLE)pMyObject, pDslhTracertObj->Host);

        pProperty->DstIp.Value  = address;

        if ( pProperty->pSrcAddrName )
        {
            AnscFreeMemory(pProperty->pSrcAddrName);
        }

        if ( pProperty->pDstAddrName )
        {
            AnscFreeMemory(pProperty->pDstAddrName);
        }

        pProperty->pDstAddrName = AnscCloneString(pDslhTracertObj->Host);
        pProperty->pSrcAddrName = AnscCloneString(pDslhTracertObj->IfAddrName);
        pProperty->NumPkts      = pDslhTracertObj->NumberOfTries;
        pProperty->PktSize      = pDslhTracertObj->DataBlockSize;

        pProperty->TimeBetween  = pDslhTracertObj->Timeout;
        pProperty->TimeOut      = pDslhTracertObj->Timeout;
    }

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitResetPropertyCounter
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to reset the property.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitResetPropertyCounter
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )hThisObject;
    PBBHM_TRACERT_PROPERTY          pProperty    = (PBBHM_TRACERT_PROPERTY            )&pMyObject->Property;

    pProperty->PktsSent        = 0;
    pProperty->PktsRecv        = 0;
    pProperty->BytesSent       = 0;
    pProperty->BytesRecv       = 0;
    pProperty->AvgRTT          = 0;
    pProperty->MaxRTT          = 0;
    pProperty->MinRTT          = 0;
    pProperty->NumIcmpError    = 0;
    pProperty->IcmpError       = 0;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitSetDiagParams
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDslhDiagInfo
            );

    description:

        This function is called to set the diagnostic parameters. If
        the diagnostic process is ongoing, it will be stopped first.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDslhDiagInfo
                The pointer points to the diagnostic parameters.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitSetDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pMyObject    = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT)hThisObject;
    PDSLH_TRACEROUTE_INFO           pDiagInfo    = (PDSLH_TRACEROUTE_INFO          )pMyObject->hDslhDiagInfo;
    PDSLH_TRACEROUTE_INFO           pNewDiagInfo = (PDSLH_TRACEROUTE_INFO          )hDslhDiagInfo;
    errno_t                         rc           = -1;

    AnscAcquireLock(&pMyObject->AccessLock);

    if ( pDiagInfo == NULL )
    {
        pDiagInfo = (PDSLH_TRACEROUTE_INFO)AnscAllocateMemory(sizeof(DSLH_TRACEROUTE_INFO)); //CID: 56073 -Wrong sizeof argument

        if ( pDiagInfo == NULL )
        {
            AnscTrace("BbhmDiagitSetDiagParams -- insufficient resources!\n");

            AnscReleaseLock(&pMyObject->AccessLock);

            return  ANSC_STATUS_RESOURCES;
        }
        else
        {
            DslhInitTracerouteInfo(pDiagInfo);
            pMyObject->hDslhDiagInfo = (ANSC_HANDLE)pDiagInfo;
            pDiagInfo->StructSize    = sizeof(DSLH_TRACEROUTE_INFO);
            rc = strcpy_s(pDiagInfo->Host, sizeof(pDiagInfo->Host) , pNewDiagInfo->Host);
            ERR_CHK(rc);
            rc = strcpy_s(pDiagInfo->Interface, sizeof(pDiagInfo->Interface) , pNewDiagInfo->Interface);
            ERR_CHK(rc);
            rc = strcpy_s(pDiagInfo->IfAddrName, sizeof(pDiagInfo->IfAddrName) , pNewDiagInfo->IfAddrName);
            ERR_CHK(rc);
            pDiagInfo->DSCP                 = pNewDiagInfo->DSCP;
            pDiagInfo->Timeout              = pNewDiagInfo->Timeout;
            pDiagInfo->MaxHopCount          = pNewDiagInfo->MaxHopCount;
            pDiagInfo->NumberOfTries        = pNewDiagInfo->NumberOfTries;
            pDiagInfo->DataBlockSize        = pNewDiagInfo->DataBlockSize;
            pDiagInfo->UpdatedAt            = 0;
        }
    }
    else
    {
        DslhInitTracerouteInfo(pDiagInfo);
        pDiagInfo->StructSize    = sizeof(DSLH_TRACEROUTE_INFO);
        rc = strcpy_s(pDiagInfo->Host, sizeof(pDiagInfo->Host) , pNewDiagInfo->Host);
        ERR_CHK(rc);
        rc = strcpy_s(pDiagInfo->Interface, sizeof(pDiagInfo->Interface) , pNewDiagInfo->Interface);
        ERR_CHK(rc);
        rc = strcpy_s(pDiagInfo->IfAddrName, sizeof(pDiagInfo->IfAddrName) , pNewDiagInfo->IfAddrName);
        ERR_CHK(rc);
        pDiagInfo->DSCP                 = pNewDiagInfo->DSCP;
        pDiagInfo->Timeout              = pNewDiagInfo->Timeout;
        pDiagInfo->MaxHopCount          = pNewDiagInfo->MaxHopCount;
        pDiagInfo->NumberOfTries        = pNewDiagInfo->NumberOfTries;
        pDiagInfo->DataBlockSize        = pNewDiagInfo->DataBlockSize;
        pDiagInfo->UpdatedAt            = 0;
    }

    AnscReleaseLock(&pMyObject->AccessLock);

    return  ANSC_STATUS_SUCCESS;
}

