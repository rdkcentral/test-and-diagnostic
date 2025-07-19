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

    module: cosa_dns_dml.h

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file defines the apis for objects to support Data Model Library.

    -------------------------------------------------------------------


    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/14/2011    initial revision.

**************************************************************************/


#ifndef  _COSA_DNS_DML_H
#define  _COSA_DNS_DML_H


/***********************************************************************

 APIs for Object:

    DNS.Diagnostics.


***********************************************************************/
/***********************************************************************

 APIs for Object:

    DNS.Diagnostics.NSLookupDiagnostics.

    *  NSLookupDiagnostics_GetParamBoolValue
    *  NSLookupDiagnostics_GetParamIntValue
    *  NSLookupDiagnostics_GetParamUlongValue
    *  NSLookupDiagnostics_GetParamStringValue
    *  NSLookupDiagnostics_SetParamBoolValue
    *  NSLookupDiagnostics_SetParamIntValue
    *  NSLookupDiagnostics_SetParamUlongValue
    *  NSLookupDiagnostics_SetParamStringValue
    *  NSLookupDiagnostics_Validate
    *  NSLookupDiagnostics_Commit
    *  NSLookupDiagnostics_Rollback

***********************************************************************/
BOOL
NSLookupDiagnostics_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
NSLookupDiagnostics_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
NSLookupDiagnostics_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
NSLookupDiagnostics_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

BOOL
NSLookupDiagnostics_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

BOOL
NSLookupDiagnostics_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         value
    );

BOOL
NSLookupDiagnostics_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValuepUlong
    );

BOOL
NSLookupDiagnostics_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       strValue
    );

BOOL
NSLookupDiagnostics_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

ULONG
NSLookupDiagnostics_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
NSLookupDiagnostics_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

/***********************************************************************

 APIs for Object:

    DNS.Diagnostics.NSLookupDiagnostics.Result.{i}.

    *  Result_GetEntryCount
    *  Result_GetEntry
    *  Result_IsUpdated
    *  Result_Synchronize
    *  Result_GetParamBoolValue
    *  Result_GetParamIntValue
    *  Result_GetParamUlongValue
    *  Result_GetParamStringValue

***********************************************************************/
ULONG
Result_GetEntryCount
    (
        ANSC_HANDLE
    );

ANSC_HANDLE
Result_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

BOOL
Result_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    );

ULONG
Result_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    );

BOOL
Result_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    );

BOOL
Result_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    );

BOOL
Result_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    );

ULONG
Result_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

#endif
