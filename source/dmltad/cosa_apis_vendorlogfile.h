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


/**************************************************************************

    module: cosa_apis_vendorlogfile.h

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file defines the apis for objects to support Data Model Library.

    -------------------------------------------------------------------


    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        08/01/2012    initial revision.

**************************************************************************/


#ifndef  _COSA_APIS_VENDORLOGFILE_H
#define  _COSA_APIS_VENDORLOGFILE_H

#include "cosa_apis.h"
#include "plugin_main_apis.h"

#if 0
#include "slap_definitions.h"
#endif

/***********************************************************************

 APIs for Object:

    Device.DeviceInfo.VendorLogFile.{i}.

    *  VendorLogFile_GetEntryCount
    *  VendorLogFile_GetEntry
    *  VendorLogFile_GetParamBoolValue
    *  VendorLogFile_GetParamIntValue
    *  VendorLogFile_GetParamUlongValue
    *  VendorLogFile_GetParamStringValue
    *  VendorLogFile_SetParamBoolValue
    *  VendorLogFile_SetParamIntValue
    *  VendorLogFile_SetParamUlongValue
    *  VendorLogFile_SetParamStringValue
    *  VendorLogFile_Validate
    *  VendorLogFile_Commit
    *  VendorLogFile_Rollback

***********************************************************************/
ULONG
VendorLogFile_GetEntryCount
    (
        ANSC_HANDLE
    );

ANSC_HANDLE
VendorLogFile_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

BOOL
VendorLogFile_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
VendorLogFile_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
VendorLogFile_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
VendorLogFile_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
VendorLogFile_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
VendorLogFile_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
VendorLogFile_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
VendorLogFile_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
VendorLogFile_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
VendorLogFile_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
VendorLogFile_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

#endif
