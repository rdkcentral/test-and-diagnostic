/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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


#ifndef  _WANCHK_RBUS_APIS_H
#define  _WANCHK_RBUS_APIS_H


#include "ansc_platform.h"
#include <rbus/rbus.h>
#include <cosa_wanconnectivity_apis.h>

rbusError_t CosaWanCnctvtyChk_RbusInit(VOID);
rbusError_t CosaWanCnctvtyChk_Reg_elements(dml_type_t type);
rbusError_t CosaWanCnctvtyChk_UnReg_elements(dml_type_t type);
ANSC_STATUS CosaWanCnctvtyChk_Intf_Commit (PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO  pIPInterface);
ANSC_STATUS CosaWanCnctvtyChk_URL_Commit (unsigned int InstanceNumber, const char *url);
ANSC_STATUS CosaWanCnctvtyChk_URL_delDBEntry (unsigned int InstanceNumber);

#endif
