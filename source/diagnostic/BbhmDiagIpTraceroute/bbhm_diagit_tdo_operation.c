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

    module:    bbhm_diagit_tdo_operation.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced operation functions
        of the Poemc Tdo Smo Object.

        *    BbhmDiagitTdoInvoke
        *    BbhmDiagitGetCounter
        *    BbhmDiagittSetCounter
        *    BbhmDiagitGetStopTime
        *    BbhmDiagitSetStopTime

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

        ANSC_STATUS
        BbhmDiagitTdoInvoke
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is invoked when the timer expires.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitTdoInvoke
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_TRACERT_TDO_OBJECT        pMyObject       = (PBBHM_TRACERT_TDO_OBJECT          )hThisObject;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pTracertObj     = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT   )pMyObject->hOwnerContext;
    PBBHM_TRACERT_PROPERTY          pProperty       = (PBBHM_TRACERT_PROPERTY            )&pTracertObj->Property;
    ULONG                           errorCount      = (ULONG                             )pTracertObj->GetIcmpError((ANSC_HANDLE)pTracertObj);

    CcspTraceInfo(("DiagitTdoInvoke...\n"));

    pTracertObj->SetIcmpError((ANSC_HANDLE)pTracertObj, ++errorCount);

    pTracertObj->UpdateEntry
        (
            (ANSC_HANDLE)pTracertObj,
            pProperty->PktsRecv,
            0,                        /* Hop  IP */
            BBHM_TRACERT_ICMP_TIMEOUT,     /* Stop Time */
            0x0                       /* ICMP code */
        );

    pProperty->PktsRecv ++;

    if ( errorCount >= pTracertObj->GetNumPkts((ANSC_HANDLE)pTracertObj) )
    {
        pTracertObj->Expire2((ANSC_HANDLE)pTracertObj);
    }
    else
    {
        pTracertObj->Expire1((ANSC_HANDLE)pTracertObj);
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitTdoGetStopTime
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     StopTime value.

**********************************************************************/

ULONG
BbhmDiagitTdoGetStopTime
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_TRACERT_TDO_OBJECT        pMyObject       = (PBBHM_TRACERT_TDO_OBJECT          )hThisObject;
    
    return  pMyObject->StopTime;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitCoSetStopTime
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulStopTime
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulStopTime
                This is the Throughput value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitTdoSetStopTime
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulStopTime
    )
{
    ANSC_STATUS                     returnStatus    = ANSC_STATUS_SUCCESS;
    PBBHM_TRACERT_TDO_OBJECT        pMyObject       = (PBBHM_TRACERT_TDO_OBJECT          )hThisObject;
    
    pMyObject->StopTime    = ulStopTime;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagitTdoGetCounter
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     Counter value.

**********************************************************************/

ULONG
BbhmDiagitTdoGetCounter
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_TRACERT_TDO_OBJECT        pMyObject       = (PBBHM_TRACERT_TDO_OBJECT          )hThisObject;
    
    return  pMyObject->Counter;

}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagitCoSetCounter
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                        ulCounter
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                        ulCounter
                This is the Throughput value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagitTdoSetCounter
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                        ulCounter
    )
{
    ANSC_STATUS                     returnStatus    = ANSC_STATUS_SUCCESS;
    PBBHM_TRACERT_TDO_OBJECT        pMyObject       = (PBBHM_TRACERT_TDO_OBJECT          )hThisObject;
    
    pMyObject->Counter    = ulCounter;

    return  returnStatus;
}
