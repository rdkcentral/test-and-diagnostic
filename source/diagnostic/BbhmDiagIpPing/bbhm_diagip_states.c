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

    module:     bbhm_diagip_states.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced state-access functions
        of the Bbhm IpPing Diagnostic Object.

        *   BbhmDiagipCopyDiagParams
        *   BbhmDiagipReset
        *   BbhmDiagipGetProperty
        *   BbhmDiagipSetProperty
        *   BbhmDiagipGetSrcIpType
        *   BbhmDiagipSetSrcIpType
        *   BbhmDiagipGetDstIpType
        *   BbhmDiagipGetSrcIp
        *   BbhmDiagipSetSrcIp
        *   BbhmDiagipGetDstIp
        *   BbhmDiagipSetDstIp
        *   BbhmDiagipGetNumPkts
        *   BbhmDiagipSetNumPkts
        *   BbhmDiagipGetPktSize
        *   BbhmDiagipSetPktSize
        *   BbhmDiagipGetTimeBetween
        *   BbhmDiagipSetTimeBetween
        *   BbhmDiagipGetTimeOut
        *   BbhmDiagipSetTimeOut
        *   BbhmDiagipGetControl
        *   BbhmDiagipSetControl
        *   BbhmDiagipGetStatus
        *   BbhmDiagipSetStatus
        *   BbhmDiagipGetPktsSent
        *   BbhmDiagipSetPktsSent
        *   BbhmDiagipGetPktsRecv
        *   BbhmDiagipSetPktsRecv
        *   BbhmDiagipGetAvgRTT
        *   BbhmDiagipSetAvgRTT
        *   BbhmDiagipGetMaxRTT
        *   BbhmDiagipSetMaxRTT
        *   BbhmDiagipGetMinRTT
        *   BbhmDiagipSetMinRTT
        *   BbhmDiagipGetNumIcmpError
        *   BbhmDiagipSetNumIcmpError
        *   BbhmDiagipGetIcmpError
        *   BbhmDiagipSetIcmpError
        *   BbhmDiagipGetNumCalculate
        *   BbhmDiagipSetNumCalculate
        *   BbhmDiagipResetProperty
        *   BbhmDiagipResetPropertyCounter
        *   BbhmDiagipGetMiddleResult
        *   BbhmDiagipSetDiagParams

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Ding Hua, Li Shi

    ---------------------------------------------------------------

    revision:

        2007/02/08    initial revision.

**********************************************************************/


#include "bbhm_diagip_global.h"
#include "safec_lib_common.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetDiagParams
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
BbhmDiagipCopyDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;

    errno_t rc = -1;
    rc = memcpy_s(pMyObject->hDslhDiagInfo, sizeof(pMyObject->hDslhDiagInfo) , hDslhDiagInfo, sizeof(DSLH_PING_INFO));
    ERR_CHK(rc);

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipReset
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
BbhmDiagipReset
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;

    if ( pMyObject->hDslhDiagInfo )
    {
        DslhFreePingInfo(((PDSLH_PING_INFO)pMyObject->hDslhDiagInfo));
        pMyObject->hDslhDiagInfo = (ANSC_HANDLE)NULL;
    }

    return  ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipGetProperty
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                    hProperty
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
BbhmDiagipGetProperty
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    *(PBBHM_IP_PING_PROPERTY)hProperty    = *pProperty;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetProperty
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
BbhmDiagipSetProperty
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                  hProperty
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    *pProperty    = *(PBBHM_IP_PING_PROPERTY)hProperty;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetSrcIpType
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
BbhmDiagipGetSrcIpType
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->SrcIpType;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetSrcIpType
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
BbhmDiagipSetSrcIpType
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulType
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->SrcIpType    = ulType;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetDstIpType
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
BbhmDiagipGetDstIpType
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->DstIpType;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetDstIpType
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
BbhmDiagipSetDstIpType
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulType
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->DstIpType    = ulType;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        PUCHAR
        BbhmDiagipGetSrcIp
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
BbhmDiagipGetSrcIp
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->pSrcAddrName;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetSrcIp
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
BbhmDiagipSetSrcIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      IpAddr
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    /*pProperty->SrcIp.Value    = AnscReadUlong(IpAddr);*/
    pProperty->pSrcAddrName = AnscCloneString(IpAddr);

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        PUCHAR
        BbhmDiagipGetDstIp
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
BbhmDiagipGetDstIp
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->pDstAddrName;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetDstIp
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
BbhmDiagipSetDstIp
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      IpAddr
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY   )&pMyObject->Property;

    /*ansc_hostent*                   pHostent;*/

    /* pProperty->DstIp.Value    = AnscReadUlong(IpAddr); */
    /*pHostent = _ansc_gethostbyname(IpAddr);
    if ( ! pHostent)
    {
        return ANSC_STATUS_FAILURE;
    }*/

    pProperty->pDstAddrName = AnscCloneString(IpAddr);

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetNumPkts
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
BbhmDiagipGetNumPkts
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->NumPkts;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetNumPkts
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
BbhmDiagipSetNumPkts
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulNumPkts
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->NumPkts    = ulNumPkts;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetPktSize
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
BbhmDiagipGetPktSize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->PktSize;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetPktSize
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulPktSize
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
BbhmDiagipSetPktSize
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktSize
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->PktSize    = ulPktSize;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetTimeBetween
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
BbhmDiagipGetTimeBetween
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->TimeBetween;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetTimeBetween
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
BbhmDiagipSetTimeBetween
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulTimeBetween
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->TimeBetween    = ulTimeBetween;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetTimeOut
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
BbhmDiagipGetTimeOut
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->TimeOut;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetTimeOut
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulTimeOut
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
BbhmDiagipSetTimeOut
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulTimeOut
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->TimeOut    = ulTimeOut;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetControl
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
BbhmDiagipGetControl
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->Control;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetControl
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulControl
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
BbhmDiagipSetControl
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulControl
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->Control    = ulControl;

    if ( ulControl == BBHM_IP_PING_CONTROL_START )
    {
        returnStatus =
            pMyObject->Start((ANSC_HANDLE)pMyObject);
    }
    else if ( ulControl == BBHM_IP_PING_CONTROL_STOP )
    {
        pMyObject->SetStatus((ANSC_HANDLE)pMyObject, BBHM_IP_PING_STATUS_STOP);

        returnStatus =
            pMyObject->Stop((ANSC_HANDLE)pMyObject);
    }

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetStatus
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
BbhmDiagipGetStatus
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->Status;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetStatus
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
BbhmDiagipSetStatus
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulStatus
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->Status    = ulStatus;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetPktsSent
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
BbhmDiagipGetPktsSent
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->PktsSent;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetPktsSent
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
BbhmDiagipSetPktsSent
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktsSent
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->PktsSent    = ulPktsSent;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetPktsRecv
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
BbhmDiagipGetPktsRecv
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty     = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->PktsRecv;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetPktsRecv
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
BbhmDiagipSetPktsRecv
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulPktsRecv
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->PktsRecv    = ulPktsRecv;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetAvgRTT
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
BbhmDiagipGetAvgRTT
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->AvgRTT;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetAvgRTT
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
BbhmDiagipSetAvgRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulAvgRTT
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->AvgRTT    = ulAvgRTT;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetMaxRTT
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
BbhmDiagipGetMaxRTT
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->MaxRTT;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetMaxRTT
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
BbhmDiagipSetMaxRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulMaxRTT
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->MaxRTT    = ulMaxRTT;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetMinRTT
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
BbhmDiagipGetMinRTT
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->MinRTT;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetMinRTT
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
BbhmDiagipSetMinRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulMinRTT
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->MinRTT    = ulMinRTT;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetNumIcmpError
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
BbhmDiagipGetNumIcmpError
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->NumIcmpError;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetNumIcmpError
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
BbhmDiagipSetNumIcmpError
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulNumIcmpError
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY)&pMyObject->Property;

    pProperty->NumIcmpError    = ulNumIcmpError;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetIcmpError
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
BbhmDiagipGetIcmpError
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->IcmpError;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetIcmpError
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
BbhmDiagipSetIcmpError
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulIcmpError
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->IcmpError    = ulIcmpError;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetNumCalculate
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
BbhmDiagipGetNumCalculate
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->NumCalculate;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetNumCalculate
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
BbhmDiagipSetNumCalculate
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulNumCalculate
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->NumCalculate    = ulNumCalculate;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipGetSumRTT
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
BbhmDiagipGetSumRTT
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    return  pProperty->SumRTT;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetSumRTT
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
BbhmDiagipSetSumRTT
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulRTT
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->SumRTT = ulRTT;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipResetProperty
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
BbhmDiagipResetProperty
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->SrcIpType      = BBHM_IP_PING_DEF_INET_ADDRESS_TYPE;
    pProperty->SrcIp.Value    = AnscUlongFromHToN(BBHM_IP_PING_DEF_SRC_IP);
    pProperty->DstIpType      = BBHM_IP_PING_DEF_INET_ADDRESS_TYPE;
    pProperty->DstIp.Value    = 0;

    if ( pProperty->pSrcAddrName )
    {
        AnscFreeMemory(pProperty->pSrcAddrName);
        pProperty->pSrcAddrName = NULL;
    }

    if ( pProperty->pDstAddrName )
    {
        AnscFreeMemory(pProperty->pDstAddrName);
        pProperty->pDstAddrName = NULL;
    }

    pProperty->NumPkts        = BBHM_IP_PING_DEF_NUMBER_PACKETS;
    pProperty->PktSize        = BBHM_IP_PING_DEF_PACKET_SIZE;
    pProperty->TimeBetween    = BBHM_IP_PING_DEF_TIME_BETWEEN_IN_MILLISECONDS;
    pProperty->TimeOut        = BBHM_IP_PING_DEF_TIME_OUT_IN_MILLISECONDS;
    pProperty->Control        = BBHM_IP_PING_DEF_CONTROL;
    pProperty->Status         = BBHM_IP_PING_DEF_STATUS;
    pProperty->PktsSent       = 0;
    pProperty->PktsRecv       = 0;
    pProperty->BytesSent      = 0;
    pProperty->BytesRecv      = 0;
    pProperty->AvgRTT         = 0;
    pProperty->MaxRTT         = 0;
    pProperty->MinRTT         = 0;
    pProperty->NumIcmpError   = 0;
    pProperty->IcmpError      = 0;
    pProperty->NumCalculate   = 0;
    pProperty->SumRTT         = 0;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipResetPropertyCounter
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
BbhmDiagipResetPropertyCounter
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;

    pProperty->PktsSent        = 0;
    pProperty->PktsRecv        = 0;
    pProperty->BytesSent       = 0;
    pProperty->BytesRecv       = 0;
    pProperty->AvgRTT          = 0;
    pProperty->MaxRTT          = 0;
    pProperty->MinRTT          = 0;
    pProperty->NumIcmpError    = 0;
    pProperty->IcmpError       = 0;
    pProperty->NumCalculate    = 0;
    pProperty->SumRTT          = 0;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        CHAR*
        BbhmDiagipGetResult
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

CHAR*
BbhmDiagipGetResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT         pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT)hThisObject;
    PBBHM_IP_PING_PROPERTY            pProperty    = (PBBHM_IP_PING_PROPERTY          )&pMyObject->Property;
    PSINGLE_LINK_ENTRY                pSLinkEntry  = NULL;
    PBBHM_IP_PING_ECHO_ENTRY          pEchoEntry   = NULL;
    CHAR*                             pResult      = NULL;
    CHAR*                             ipAddress    = NULL;
    ULONG                             RTT          = 0;
    ULONG                             MaxRTT       = 0;
    ULONG                             MinRTT       = 0;
    ULONG                             NumRTT       = 0;
    ULONG                             AvgRTT       = 0;
    ULONG                             SumRTT       = 0;

    ipAddress = (CHAR*)AnscAllocateMemory(32);
    AnscGetIpAddrString(pProperty->DstIp.Dot, ipAddress);

    AnscAcquireLock(&pMyObject->MiddleResultLock);

    pSLinkEntry = AnscSListPopEntry(&pMyObject->MiddleResult);

    AnscReleaseLock(&pMyObject->MiddleResultLock);
    if ( pSLinkEntry )
    {
        pEchoEntry = (PBBHM_IP_PING_ECHO_ENTRY)ACCESS_BBHM_IP_PING_ECHO_ENTRY(pSLinkEntry);
        pResult = (CHAR*)AnscAllocateMemory(128);
        errno_t rc = -1;
        switch ( pEchoEntry->ICMPType )
        {
        case ICMP_TYPE_ECHO_REPLY:
            RTT = pEchoEntry->StopTime - pEchoEntry->StartTime;
            RTT = RTT > 0 ? RTT : 1;
            MaxRTT = pMyObject->GetMaxRTT((ANSC_HANDLE)pMyObject);
            MinRTT = pMyObject->GetMinRTT((ANSC_HANDLE)pMyObject);
            NumRTT = pMyObject->GetNumCalculate((ANSC_HANDLE)pMyObject);
            AvgRTT = pMyObject->GetAvgRTT((ANSC_HANDLE)pMyObject);
            SumRTT = pMyObject->GetSumRTT((ANSC_HANDLE)pMyObject);
            if ( RTT > MaxRTT )
            {
                MaxRTT = RTT;
            }
            if ( MinRTT == 0 )
            {
                MinRTT = RTT;
            }
            else if ( RTT < MinRTT )
            {
                MinRTT = RTT;
            }
            if ( AvgRTT == 0 )
            {
                AvgRTT = RTT;
            }
            else
            {
                AvgRTT = (SumRTT + RTT) / (NumRTT + 1);
            }
            SumRTT = SumRTT + RTT;
            NumRTT++;
            pMyObject->SetNumCalculate((ANSC_HANDLE)pMyObject, NumRTT);
            pMyObject->SetMaxRTT((ANSC_HANDLE)pMyObject, MaxRTT);
            pMyObject->SetMinRTT((ANSC_HANDLE)pMyObject, MinRTT);
            pMyObject->SetAvgRTT((ANSC_HANDLE)pMyObject, AvgRTT);
            pMyObject->SetSumRTT((ANSC_HANDLE)pMyObject, SumRTT);
            rc = sprintf_s(pResult, 128 ,"Reply from %s: icmp_seq=%d ttl=%d time=%lu ms", ipAddress, pEchoEntry->SeqId, pEchoEntry->TTL, RTT);
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
            break;
        case ICMP_TYPE_DESTINATION_UNREACHABLE:
            rc = strcpy_s(pResult, 128 ,"Destination Unreachable!");
            ERR_CHK(rc);
            break;
        case ICMP_TYPE_SOURCE_QUENCH:
            rc = strcpy_s(pResult, 128 , "Source Quench!");
            ERR_CHK(rc);
            break;
        case ICMP_TYPE_PARAMETER_PROBLEM:
            rc = strcpy_s(pResult, 128 ,"Parameter Problem!");
            ERR_CHK(rc);
            break;
        case ICMP_TYPE_REDIRECT:
            rc = strcpy_s(pResult, 128 , "Redirect!");
            ERR_CHK(rc);
            break;
        default:
            rc = sprintf_s(pResult, 128 , "Error Code %d!", pEchoEntry->ICMPType);
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
        }
        AnscFreeMemory(pEchoEntry);
        pEchoEntry = NULL;
    }

    AnscFreeMemory(ipAddress);
    return pResult;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        CHAR*
        BbhmDiagipGetMiddleResult
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

CHAR*
BbhmDiagipGetMiddleResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT     )hThisObject;
    PBBHM_IP_PING_PROPERTY          pProperty    = (PBBHM_IP_PING_PROPERTY        )&pMyObject->Property;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = NULL;
    PBBHM_IP_PING_ECHO_ENTRY        pEchoEntry   = NULL;
    CHAR*                           pResult      = NULL;
    CHAR*                           ipAddress    = NULL;
    ULONG                           RTT          = 0;
    ULONG                           MaxRTT       = 0;
    ULONG                           MinRTT       = 0;
    ULONG                           NumRTT       = 0;
    ULONG                           AvgRTT       = 0;
    ULONG                           SumRTT       = 0;

    ipAddress = (CHAR*)AnscAllocateMemory(32);
    AnscGetIpAddrString(pProperty->DstIp.Dot, ipAddress);

    AnscAcquireLock(&pMyObject->MiddleResultLock);

    pSLinkEntry = AnscSListPopEntry(&pMyObject->MiddleResult);

    AnscReleaseLock(&pMyObject->MiddleResultLock);
    if ( pSLinkEntry )
    {
        pEchoEntry = (PBBHM_IP_PING_ECHO_ENTRY)ACCESS_BBHM_IP_PING_ECHO_ENTRY(pSLinkEntry);
        pResult = (CHAR*)AnscAllocateMemory(128);
        errno_t rc = -1;
        switch ( pEchoEntry->ICMPType )
        {
        case ICMP_TYPE_ECHO_REPLY:
            RTT = pEchoEntry->StopTime - pEchoEntry->StartTime;
            RTT = RTT > 0 ? RTT : 1;
            MaxRTT = pMyObject->GetMaxRTT((ANSC_HANDLE)pMyObject);
            MinRTT = pMyObject->GetMinRTT((ANSC_HANDLE)pMyObject);
            NumRTT = pMyObject->GetNumCalculate((ANSC_HANDLE)pMyObject);
            AvgRTT = pMyObject->GetAvgRTT((ANSC_HANDLE)pMyObject);
            SumRTT = pMyObject->GetSumRTT((ANSC_HANDLE)pMyObject);
            if ( RTT > MaxRTT )
            {
                MaxRTT = RTT;
            }
            if ( MinRTT == 0 )
            {
                MinRTT = RTT;
            }
            else if ( RTT < MinRTT )
            {
                MinRTT = RTT;
            }
            if ( AvgRTT == 0 )
            {
                AvgRTT = RTT;
            }
            else
            {
                AvgRTT = (SumRTT + RTT) / (NumRTT + 1);
            }
            SumRTT = SumRTT + RTT;
            NumRTT++;
            pMyObject->SetNumCalculate((ANSC_HANDLE)pMyObject, NumRTT);
            pMyObject->SetMaxRTT((ANSC_HANDLE)pMyObject, MaxRTT);
            pMyObject->SetMinRTT((ANSC_HANDLE)pMyObject, MinRTT);
            pMyObject->SetAvgRTT((ANSC_HANDLE)pMyObject, AvgRTT);
            pMyObject->SetSumRTT((ANSC_HANDLE)pMyObject, SumRTT);
            rc = sprintf_s(pResult, 128 , "Reply from %s: icmp_seq=%d ttl=%d time=%lu ms", ipAddress, pEchoEntry->SeqId, pEchoEntry->TTL, RTT);
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
            break;
        case ICMP_TYPE_DESTINATION_UNREACHABLE:
            rc = strcpy_s(pResult, 128 , "Destination Unreachable!");
            ERR_CHK(rc);
            break;
        case ICMP_TYPE_SOURCE_QUENCH:
            rc = strcpy_s(pResult, 128 ,"Source Quench!");
            ERR_CHK(rc);
            break;
        case ICMP_TYPE_PARAMETER_PROBLEM:
            rc = strcpy_s(pResult, 128 , "Parameter Problem!");
            ERR_CHK(rc);
            break;
        case ICMP_TYPE_REDIRECT:
            rc = strcpy_s(pResult, 128 ,"Redirect!");
            ERR_CHK(rc);
            break;
        default:
            rc = sprintf_s(pResult, 128 , "Error Code %d!", pEchoEntry->ICMPType);
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
        }
        AnscFreeMemory(pEchoEntry);
        pEchoEntry = NULL;
    }

    AnscFreeMemory(ipAddress);
    return pResult;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipSetDiagParams
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
BbhmDiagipSetDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pMyObject    = (PBBHM_DIAG_IP_PING_OBJECT     )hThisObject;
    PDSLH_PING_INFO                 pDiagInfo    = (PDSLH_PING_INFO               )pMyObject->hDslhDiagInfo;
    PDSLH_PING_INFO                 pNewDiagInfo = (PDSLH_PING_INFO               )hDslhDiagInfo;
    errno_t                         rc           = -1;

    AnscAcquireLock(&pMyObject->AccessLock);

    if ( pDiagInfo == NULL )
    {
        pDiagInfo = (PDSLH_PING_INFO)AnscAllocateMemory(sizeof(DSLH_PING_INFO));

        if ( pDiagInfo == NULL )
        {
            AnscTrace("BbhmDiagipSetDiagParams -- insufficient resources!\n");

            AnscReleaseLock(&pMyObject->AccessLock);

            return  ANSC_STATUS_RESOURCES;
        }
        else
        {
            DslhInitPingInfo(pDiagInfo);
            pMyObject->hDslhDiagInfo = (ANSC_HANDLE)pDiagInfo;
            pDiagInfo->StructSize    = sizeof(DSLH_PING_INFO);
            rc = strcpy_s(pDiagInfo->Host, sizeof(pDiagInfo->Host) ,pNewDiagInfo->Host);
            ERR_CHK(rc);
            rc = strcpy_s(pDiagInfo->Interface, sizeof(pDiagInfo->Interface) , pNewDiagInfo->Interface);
            ERR_CHK(rc);
            rc = strcpy_s(pDiagInfo->IfAddrName, sizeof(pDiagInfo->IfAddrName) , pNewDiagInfo->IfAddrName);
            ERR_CHK(rc);
            pDiagInfo->DSCP                 = pNewDiagInfo->DSCP;
            pDiagInfo->Timeout              = pNewDiagInfo->Timeout;
            pDiagInfo->NumberOfRepetitions  = pNewDiagInfo->NumberOfRepetitions;
            pDiagInfo->DataBlockSize        = pNewDiagInfo->DataBlockSize;
        }
    }
    else
    {
        DslhInitPingInfo(pDiagInfo);
        pDiagInfo->StructSize    = sizeof(DSLH_PING_INFO);
        rc = strcpy_s(pDiagInfo->Host, sizeof(pDiagInfo->Host) ,pNewDiagInfo->Host);
        ERR_CHK(rc);
        rc = strcpy_s(pDiagInfo->Interface, sizeof(pDiagInfo->Interface) , pNewDiagInfo->Interface);
        ERR_CHK(rc);
        rc = strcpy_s(pDiagInfo->IfAddrName, sizeof(pDiagInfo->IfAddrName), pNewDiagInfo->IfAddrName);
        ERR_CHK(rc);
        pDiagInfo->DSCP                 = pNewDiagInfo->DSCP;
        pDiagInfo->Timeout              = pNewDiagInfo->Timeout;
        pDiagInfo->NumberOfRepetitions  = pNewDiagInfo->NumberOfRepetitions;
        pDiagInfo->DataBlockSize        = pNewDiagInfo->DataBlockSize;
    }

    AnscReleaseLock(&pMyObject->AccessLock);

    return  ANSC_STATUS_SUCCESS;
}

