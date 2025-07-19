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

    module:    bbhm_diagip_tdo_operation.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced operation functions
        of the Poemc Tdo Smo Object.

        *   BbhmDiagipTdoInvoke
        *   BbhmDiagipGetCounter
        *   BbhmDiagipSetCounter
        *   BbhmDiagipGetStopTime
        *   BbhmDiagipSetStopTime

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

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipTdoInvoke
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
BbhmDiagipTdoInvoke
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_IP_PING_TDO_OBJECT        pMyObject       = (PBBHM_IP_PING_TDO_OBJECT)hThisObject;
    PBBHM_DIAG_IP_PING_OBJECT       pPing           = (PBBHM_DIAG_IP_PING_OBJECT)pMyObject->hOwnerContext;
    
    if ( pMyObject->Counter > 2 )
    {
        pPing->Expire1((ANSC_HANDLE)pPing);

        pMyObject->Counter--;
        pMyObject->Start((ANSC_HANDLE)pMyObject);
    }
    else if ( pMyObject->Counter == 2 ) 
    {
        pPing->Expire1((ANSC_HANDLE)pPing);
        pMyObject->SetInterval((ANSC_HANDLE)pMyObject, pPing->GetTimeOut((ANSC_HANDLE)pPing));
        pMyObject->Counter--;
        pMyObject->Start((ANSC_HANDLE)pMyObject);
    }
    else
    {
        pPing->Expire2((ANSC_HANDLE)pPing);
    }

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipTdoGetStopTime
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
BbhmDiagipTdoGetStopTime
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_IP_PING_TDO_OBJECT        pMyObject       = (PBBHM_IP_PING_TDO_OBJECT)hThisObject;
    
    return  pMyObject->StopTime;

}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipTdoSetStopTime
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       ulStopTime
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                       ulStopTime
                This is the Throughput value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipTdoSetStopTime
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulStopTime
    )
{
    ANSC_STATUS                     returnStatus    = ANSC_STATUS_SUCCESS;
    PBBHM_IP_PING_TDO_OBJECT        pMyObject       = (PBBHM_IP_PING_TDO_OBJECT)hThisObject;
    
    pMyObject->StopTime    = ulStopTime;

    return  returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiagipTdoGetCounter
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
BbhmDiagipTdoGetCounter
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_IP_PING_TDO_OBJECT        pMyObject       = (PBBHM_IP_PING_TDO_OBJECT)hThisObject;
    
    return  pMyObject->Counter;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiagipCoSetCounter
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                       ulCounter
            );

    description:

        This function is called to retrieve the object state.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.
                ULONG                       ulCounter
                This is the Throughput value.

    return:     Status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiagipTdoSetCounter
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulCounter
    )
{
    ANSC_STATUS                     returnStatus    = ANSC_STATUS_SUCCESS;
    PBBHM_IP_PING_TDO_OBJECT        pMyObject       = (PBBHM_IP_PING_TDO_OBJECT)hThisObject;
    
    pMyObject->Counter    = ulCounter;

    return  returnStatus;
}
