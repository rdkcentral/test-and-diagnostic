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

    module: cosa_deviceinfo_api.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

        *  CosaDmlDiGetManufacturerOUIPriv
		*  CosaDmlDiGetModelNamePriv
        *  CosaDmlDiGetSerialNumberPriv
        *  CosaDmlDiGetHardwareVersionPriv
    -------------------------------------------------------------------

    environment:

        platform dependent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        05/27/2014    initial revision.

**************************************************************************/

//#include "cosa_deviceinfo_util.h"
#include "cosa_apis.h"
#include "plugin_main_apis.h"

#include <sys/sysinfo.h>

#include "ansc_string_util.h"

//#include <utctx/utctx.h>
//#include <utctx/utctx_api.h>
//#include <utapi.h>
//#include <utapi_util.h>

/*
ANSC_STATUS
CosaDmlDiGetManufacturerOUIPriv
    (
        ANSC_HANDLE                 hContext,
        char*                       pValue,
        ULONG*                      pulSize
    )
{
    *pulSize = 0;

    return ANSC_STATUS_SUCCESS;
}
*/

ANSC_STATUS
CosaDmlDiGetModelNamePriv
    (
        UCHAR*                       pValue
    )
{    
	*pValue = 0;
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDiGetSerialNumberPriv
    (
        ANSC_HANDLE                 hContext,
        char*                       pValue,
        ULONG*                      pulSize
    )
{
    *pulSize = 0;
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaDmlDiGetHardwareVersionPriv
    (
        ANSC_HANDLE                 hContext,
        char*                       pValue,
        ULONG*                      pulSize
    )
{
    *pulSize = 0;
    return ANSC_STATUS_SUCCESS;
}

