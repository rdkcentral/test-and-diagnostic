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

    module:	bbhm_udpecho_operation.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced operation functions
        of the Bbhm UDP Echo Server Object.

        *   BbhmUdpechoEngage
        *   BbhmUdpechoCancel

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        06/25/2010    initial revision.

**********************************************************************/


#include "bbhm_udpecho_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUdpechoEngage
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to engage the object activity.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmUdpechoEngage
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS            returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_UDP_ECHOSRV_OBJECT  pMyObject = (PBBHM_UDP_ECHOSRV_OBJECT)hThisObject;

    if ( pMyObject->bActive )
    {
        return  ANSC_STATUS_SUCCESS;
    }

    pMyObject->bActive          = TRUE;
    pMyObject->bStopServer      = FALSE;
    pMyObject->bIsServerOn      = FALSE;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUdpechoCancel
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to cancel the object activity.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmUdpechoCancel
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS            returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_UDP_ECHOSRV_OBJECT  pMyObject = (PBBHM_UDP_ECHOSRV_OBJECT)hThisObject;
    ULONG                           i                  = 0;

    pMyObject->StopDiag(pMyObject);

    /* wait until the server is stop successfully */
    while( pMyObject->bIsServerOn && i < 300)
    {
        AnscSleep(500);

        i ++;
    }

    if ( !pMyObject->bActive )
    {
        return  ANSC_STATUS_SUCCESS;
    }

    pMyObject->bActive = FALSE;

    return  returnStatus;
}


