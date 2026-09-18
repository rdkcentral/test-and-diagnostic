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

    module: bbhm_common_internal_api.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This header file contains the prototype definition for all
        the common internal functions provided by the Bbhm Diagnostics 
        Object.

        Bbhm Diagnostics are defined in TR143

    ---------------------------------------------------------------

    environment:

        platform independent

**********************************************************************/

#ifndef  _BBHM_COMMON_INTERNAL_API_
#define  _BBHM_COMMON_INTERNAL_API_

#include "user_time.h"
#include "ssp_global.h"

#define  PAM_COMPONENT_NAME             "eRT.com.cisco.spvtg.ccsp.pam"
#define  PAM_DBUS_PATH                  "/com/cisco/spvtg/ccsp/pam"
#define  INTERFACE_STATS_Tx_BYTES       "Device.IP.Interface.1.Stats.BytesSent"
#define  INTERFACE_STATS_Rx_BYTES       "Device.IP.Interface.1.Stats.BytesReceived"

/***********************************************************
       FUNCTIONS IMPLEMENTED IN BBHM_COMMON_INTERNAL_API.C
***********************************************************/

double
CalculateTimeDifference
    (
        USER_SYSTEM_TIME*  start_time,
        USER_SYSTEM_TIME*  stop_time
    );

ANSC_STATUS
Tad_GetParamValues
    (
        char  *pchComponent,
        char  *pchBus,
        char  *pchParamName,
        ULONG *pulReturnVal
    );

ANSC_STATUS
Tad_GetParamString
    (
        char  *pchComponent,
        char  *pchBus,
        char  *pchParamName,
        char  *pchBuf,
        ULONG  ulBufSize
    );

#endif
