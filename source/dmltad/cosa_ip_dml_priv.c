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

    module: cosa_ip_dml.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/17/2011    initial revision.

**************************************************************************/

#include "ansc_platform.h"
#include "cosa_diagnostic_apis.h"
#include "plugin_main_apis.h"
/*#include "cosa_ip_apis.h"*/
#include "cosa_ip_dml.h"
/*#include "cosa_ip_internal.h"*/
#include "safec_lib_common.h"

void
CosaGetInferfaceAddrByNamePriv
	(
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject           = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_PING_INFO                 pDiagPingInfo       = pMyObject->hDiagPingInfo;
    char*                           pAddrName           = NULL;
    errno_t                         rc                  = -1;

    pAddrName = CosaGetInterfaceAddrByName(pDiagPingInfo->Interface);
    rc = strcpy_s(pDiagPingInfo->IfAddrName, sizeof(pDiagPingInfo->IfAddrName), pAddrName);
    ERR_CHK(rc);
    AnscFreeMemory(pAddrName);
}

BOOL
CosaDmlDiagGetRouteHopsNumberPriv
    (
        ANSC_HANDLE                 hInsContext,
        ULONG*                      puLong
    )
{
	*puLong = 0;
	return FALSE;
}
