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


/***********************************************************************

    module: plugin_main_apis.c

        Implement COSA Data Model Library Init and Unload apis.
        This files will hold all data in it.

    ---------------------------------------------------------------

    description:

        This module implements the advanced state-access functions
        of the Dslh Var Record Object.

        *   CosaBackEndManagerCreate
        *   CosaBackEndManagerInitialize
        *   CosaBackEndManagerRemove
    ---------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    ---------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**********************************************************************/

#include "plugin_main_apis.h"
/*
#include "cosa_ethernet_apis.h"
#include "cosa_moca_apis.h"
#include "cosa_time_apis.h"
#include "cosa_userinterface_apis.h"
#include "cosa_nat_apis.h"
#include "cosa_dhcpv4_apis.h"
#include "cosa_users_apis.h"
#include "cosa_wifi_apis.h"
#include "cosa_deviceinfo_apis.h"
#include "cosa_firewall_internal.h"
#include "cosa_x_cisco_com_ddns_internal.h"
#include "cosa_x_cisco_com_security_internal.h"
#include "cosa_ip_apis.h"
#include "cosa_hosts_apis.h"
#include "cosa_routing_apis.h"
#include "cosa_nat_internal.h"
#include "cosa_dhcpv4_internal.h"
#include "cosa_users_internal.h"
#include "cosa_ip_internal.h"
#include "cosa_hosts_internal.h"
#include "cosa_dns_internal.h"
#include "cosa_routing_internal.h"
#include "cosa_deviceinfo_internal.h"
#include "cosa_ethernet_internal.h"
#include "cosa_moca_internal.h"
#include "cosa_time_internal.h"
#include "cosa_userinterface_internal.h"
#include "cosa_ppp_internal.h"
#include "cosa_bridging_internal.h"
#include "cosa_upnp_internal.h"
#include "cosa_interfacestack_internal.h"
*/
#include "cosa_diagnostic_apis.h"
#include "cosa_selfheal_apis.h"
#include "cosa_wanconnectivity_apis.h"

#ifdef WAREHOUSE_DIAGNOSTICS
#include "cosa_warehousediag_apis.h"
#endif

PCOSA_DIAG_PLUGIN_INFO             g_pCosaDiagPluginInfo;
COSAGetParamValueStringProc        g_GetParamValueString;
COSAGetParamValueUlongProc         g_GetParamValueUlong;
COSAValidateHierarchyInterfaceProc g_ValidateInterface;
COSAGetHandleProc                  g_GetRegistryRootFolder;
COSAGetInstanceNumberByIndexProc   g_GetInstanceNumberByIndex;
COSAGetInterfaceByNameProc         g_GetInterfaceByName;
COSAGetHandleProc                  g_GetMessageBusHandle;
COSAGetSubsystemPrefixProc         g_GetSubsystemPrefix;
PCCSP_CCD_INTERFACE                g_pTadCcdIf;
ANSC_HANDLE                        g_MessageBusHandle;

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        CosaBackEndManagerCreate
            (
            );

    description:

        This function constructs cosa datamodel object and return handle.

    argument:

    return:     newly created nat object.

**********************************************************************/

ANSC_HANDLE
CosaBackEndManagerCreate
    (
        VOID
    )
{
    PCOSA_BACKEND_MANAGER_OBJECT    pMyObject    = (PCOSA_BACKEND_MANAGER_OBJECT)NULL;

    /*
        * We create object by first allocating memory for holding the variables and member functions.
        */
    pMyObject = (PCOSA_BACKEND_MANAGER_OBJECT)AnscAllocateMemory(sizeof(COSA_BACKEND_MANAGER_OBJECT));

    if ( !pMyObject )
    {
        return  (ANSC_HANDLE)NULL;
    }

    /*
     * Initialize the common variables and functions for a container object.
     */
    pMyObject->Oid               = COSA_DATAMODEL_BASE_OID;
    pMyObject->Create            = CosaBackEndManagerCreate;
    pMyObject->Remove            = CosaBackEndManagerRemove;
    pMyObject->Initialize        = CosaBackEndManagerInitialize;

    /*pMyObject->Initialize   ((ANSC_HANDLE)pMyObject);*/

    return  (ANSC_HANDLE)pMyObject;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaBackEndManagerInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate cosa manager object and return handle.

    argument:	ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
CosaBackEndManagerInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_BACKEND_MANAGER_OBJECT  pMyObject    = (PCOSA_BACKEND_MANAGER_OBJECT)hThisObject;

#ifdef _COSA_SIM_
        pMyObject->has_moca_slap  = 0;
        pMyObject->has_wifi_slap  = 0;
#endif


    /* Create all object */
    /*pMyObject->hNat           = (ANSC_HANDLE)CosaNatCreate();*/
    pMyObject->hDiag          = (ANSC_HANDLE)CosaDiagCreate();
    pMyObject->hSelfHeal          = (ANSC_HANDLE)CosaSelfHealCreate();
    if (CosaWanCnctvtyChk_Init() != ANSC_STATUS_SUCCESS)
    {
        CcspTraceError(("Wan connectivity check initialization failed\n"));
    }

#ifdef WAREHOUSE_DIAGNOSTICS
    warehousediag_start();
#endif

/*
    pMyObject->hProcStatus    = (ANSC_HANDLE)CosaProcStatusCreate();
   pMyObject->hDeviceInfo    = (ANSC_HANDLE)CosaDeviceInfoCreate();
    pMyObject->hTime          = (ANSC_HANDLE)CosaTimeCreate();
    pMyObject->hUserinterface = (ANSC_HANDLE)CosaUserinterfaceCreate();
    pMyObject->hEthernet      = (ANSC_HANDLE)CosaEthernetCreate();
    pMyObject->hMoCA          = (ANSC_HANDLE)CosaMoCACreate();
    pMyObject->hWifi          = (ANSC_HANDLE)CosaWifiCreate();
    pMyObject->hDhcpv4        = (ANSC_HANDLE)CosaDhcpv4Create();
    pMyObject->hUsers         = (ANSC_HANDLE)CosaUsersCreate();
    pMyObject->hDdns          = (ANSC_HANDLE)CosaDdnsCreate();
    pMyObject->hFirewall      = (ANSC_HANDLE)CosaFirewallCreate();
    pMyObject->hSecurity      = (ANSC_HANDLE)CosaSecurityCreate();
    pMyObject->hIP            = (ANSC_HANDLE)CosaIPCreate();
    pMyObject->hHosts         = (ANSC_HANDLE)CosaHostsCreate();
    pMyObject->hDNS           = (ANSC_HANDLE)CosaDNSCreate();
    pMyObject->hRouting       = (ANSC_HANDLE)CosaRoutingCreate();
    pMyObject->hBridging      = (ANSC_HANDLE)CosaBridgingCreate();
    pMyObject->hUpnp          = (ANSC_HANDLE)CosaUpnpCreate();
    pMyObject->hInterfaceStack = (ANSC_HANDLE)CosaIFStackCreate();
    pMyObject->hPPP           = (ANSC_HANDLE)CosaPPPCreate();
    */

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaBackEndManagerRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function remove cosa manager object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
CosaBackEndManagerRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_BACKEND_MANAGER_OBJECT  pMyObject    = (PCOSA_BACKEND_MANAGER_OBJECT)hThisObject;

    /* Remove all objects */
    /*
    if ( pMyObject->hNat )
    {
        CosaNatRemove((ANSC_HANDLE)pMyObject->hNat);
    }

    if ( pMyObject->hWifi )
    {
        CosaWifiRemove((ANSC_HANDLE)pMyObject->hWifi);
    }
    */

    if ( pMyObject->hDiag )
    {
        CosaDiagRemove((ANSC_HANDLE)pMyObject->hDiag);
    }
/*
    if ( pMyObject->hDeviceInfo )
    {
        CosaDeviceInfoRemove((ANSC_HANDLE)pMyObject->hDeviceInfo);
    }

    if ( pMyObject->hTime )
    {
        CosaTimeRemove((ANSC_HANDLE)pMyObject->hTime);
    }

    if ( pMyObject->hUserinterface )
    {
        CosaUserinterfaceRemove((ANSC_HANDLE)pMyObject->hUserinterface);
    }

    if ( pMyObject->hEthernet )
    {
        CosaEthernetRemove((ANSC_HANDLE)pMyObject->hEthernet);
    }

    if ( pMyObject->hMoCA )
    {
        CosaMoCARemove((ANSC_HANDLE)pMyObject->hMoCA);
    }

    if ( pMyObject->hDhcpv4 )
    {
        CosaDhcpv4Remove((ANSC_HANDLE)pMyObject->hDhcpv4);
    }

    if ( pMyObject->hUsers )
    {
        CosaUsersRemove((ANSC_HANDLE)pMyObject->hUsers);
    }
    if ( pMyObject->hProcStatus )
    {
        COSADmlRemoveProcessInfo((ANSC_HANDLE)pMyObject->hProcStatus);
    }

    if ( pMyObject->hDdns )
    {
        CosaDdnsRemove((ANSC_HANDLE)pMyObject->hDdns);
    }

    if ( pMyObject->hFirewall )
    {
        CosaFirewallRemove((ANSC_HANDLE)pMyObject->hFirewall);
    }

    if ( pMyObject->hSecurity )
    {
        CosaSecurityRemove((ANSC_HANDLE)pMyObject->hSecurity);
    }

    if ( pMyObject->hIP )
    {
        CosaIPRemove((ANSC_HANDLE)pMyObject->hIP);
    }

    if ( pMyObject->hHosts )
    {
        CosaHostsRemove((ANSC_HANDLE)pMyObject->hHosts);
    }

    if ( pMyObject->hDNS )
    {
        CosaDNSRemove((ANSC_HANDLE)pMyObject->hDNS);
    }

    if( pMyObject->hRouting )
    {
        CosaRoutingRemove((ANSC_HANDLE)pMyObject->hRouting);
    }

    if( pMyObject->hBridging )
    {
        CosaBridgingRemove((ANSC_HANDLE)pMyObject->hBridging);
    }

    if ( pMyObject->hUpnp )
    {
        CosaUpnpRemove((ANSC_HANDLE)pMyObject->hUpnp);
    }

    if ( pMyObject->hInterfaceStack )
    {
        CosaIFStackRemove((ANSC_HANDLE)pMyObject->hInterfaceStack);
    }

    if ( pMyObject->hPPP )
    {
        CosaPPPRemove((ANSC_HANDLE)pMyObject->hPPP);
    }
*/
    //CosaWanCnctvtyChkRemove();

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

    return returnStatus;
}
