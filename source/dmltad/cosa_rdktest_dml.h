/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
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

/***********************************************************************

APIs for Object:

    X_RDK_Test.DHCPClientv4Test.

    *  DHCPClientv4Test_GetParamBoolValue
    *  DHCPClientv4Test_SetParamBoolValue
    *  DHCPClientv4Test_GetParamStringValue

***********************************************************************/

BOOL
DHCPClientv4Test_GetParamBoolValue
	(
	    ANSC_HANDLE                 hInsContext,
	    char*                       ParamName,
	    BOOL*                       pBool
	);

BOOL
DHCPClientv4Test_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

ULONG
DHCPClientv4Test_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

/***********************************************************************

    APIs for Object:

    X_RDK_Test.DHCPClientv6Test.

    *  DHCPClientv6Test_GetParamBoolValue
    *  DHCPClientv6Test_SetParamBoolValue
    *  DHCPClientv6Test_GetParamStringValue

***********************************************************************/

BOOL
DHCPClientv6Test_GetParamBoolValue
	(
	    ANSC_HANDLE                 hInsContext,
	    char*                       ParamName,
	    BOOL*                       pBool
	);

BOOL
DHCPClientv6Test_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

ULONG
DHCPClientv6Test_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );
