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

    module: plugin_main.c

        Implement COSA Data Model Library Init and Unload apis.

    ---------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    ---------------------------------------------------------------

    revision:

        01/14/2011    initial revision.

**********************************************************************/

#include "ansc_platform.h"
#include "ansc_load_library.h"
#include "cosa_plugin_api.h"
#include "plugin_main.h"
/*
#include "cosa_deviceinfo_dml.h"
#include "cosa_softwaremodules_dml.h"
#include "cosa_gatewayinfo_dml.h"
#include "cosa_time_dml.h"
#include "cosa_userinterface_dml.h"
#include "cosa_interfacestack_dml.h"
#include "cosa_ethernet_dml.h"
#include "cosa_moca_dml.h"
*/
#include "cosa_ip_dml.h"
/*
#include "cosa_routing_dml.h"
#include "cosa_hosts_dml.h"
*/
#include "cosa_dns_dml.h"
/*
#include "cosa_firewall_dml.h"
#include "cosa_nat_dml.h"
#include "cosa_dhcpv4_dml.h"
#include "cosa_users_dml.h"
#include "cosa_upnp_dml.h"
#include "cosa_bridging_dml.h"
#include "cosa_ppp_dml.h"
#include "cosa_x_cisco_com_ddns_dml.h"
#include "cosa_x_cisco_com_security_dml.h"
#include "cosa_softwaremodules_config.h"
*/
#include "plugin_main_apis.h"
/*
#include "cosa_wifi_internal.h"
#include "cosa_moca_internal.h"
*/
//#include "cosa_apis_deviceinfo.h"
#include "cosa_apis_vendorlogfile.h"

extern ANSC_HANDLE     g_MessageBusHandle_Irep;
extern char            g_SubSysPrefix_Irep[32];

#define THIS_PLUGIN_VERSION                         1

void
COSA_RegisterAdditionalDmApis
    (
    	PCOSA_PLUGIN_INFO               pPlugInfo
    )
{
#if !defined (RESOURCE_OPTIMIZATION)
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_CISCO_COM_ARP_GetParamBoolValue",  X_CISCO_COM_ARP_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_CISCO_COM_ARP_GetParamIntValue",  X_CISCO_COM_ARP_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_CISCO_COM_ARP_GetParamUlongValue",  X_CISCO_COM_ARP_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_CISCO_COM_ARP_GetParamStringValue",  X_CISCO_COM_ARP_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "ARPTable_GetEntryCount",  ARPTable_GetEntryCount);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "ARPTable_GetEntry",  ARPTable_GetEntry);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "ARPTable_IsUpdated",  ARPTable_IsUpdated);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "ARPTable_Synchronize",  ARPTable_Synchronize);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "ARPTable_GetParamBoolValue",  ARPTable_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "ARPTable_GetParamIntValue",  ARPTable_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "ARPTable_GetParamUlongValue",  ARPTable_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "ARPTable_GetParamStringValue",  ARPTable_GetParamStringValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_GetParamBoolValue",  DownloadDiagnostics_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_GetParamIntValue",  DownloadDiagnostics_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_GetParamUlongValue",  DownloadDiagnostics_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_GetParamStringValue",  DownloadDiagnostics_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_SetParamBoolValue",  DownloadDiagnostics_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_SetParamIntValue",  DownloadDiagnostics_SetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_SetParamUlongValue",  DownloadDiagnostics_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_SetParamStringValue",  DownloadDiagnostics_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_Validate",  DownloadDiagnostics_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_Commit",  DownloadDiagnostics_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DownloadDiagnostics_Rollback",  DownloadDiagnostics_Rollback);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_GetParamBoolValue",  UploadDiagnostics_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_GetParamIntValue",  UploadDiagnostics_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_GetParamUlongValue",  UploadDiagnostics_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_GetParamStringValue",  UploadDiagnostics_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_SetParamBoolValue",  UploadDiagnostics_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_SetParamIntValue",  UploadDiagnostics_SetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_SetParamUlongValue",  UploadDiagnostics_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_SetParamStringValue",  UploadDiagnostics_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_Validate",  UploadDiagnostics_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_Commit",  UploadDiagnostics_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UploadDiagnostics_Rollback",  UploadDiagnostics_Rollback);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_GetParamBoolValue",  UDPEchoConfig_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_GetParamIntValue",  UDPEchoConfig_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_GetParamUlongValue",  UDPEchoConfig_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_GetParamStringValue",  UDPEchoConfig_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_SetParamBoolValue",  UDPEchoConfig_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_SetParamIntValue",  UDPEchoConfig_SetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_SetParamUlongValue",  UDPEchoConfig_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_SetParamStringValue",  UDPEchoConfig_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_Validate",  UDPEchoConfig_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_Commit",  UDPEchoConfig_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "UDPEchoConfig_Rollback",  UDPEchoConfig_Rollback);
#endif

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_GetParamBoolValue",  NSLookupDiagnostics_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_GetParamIntValue",  NSLookupDiagnostics_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_GetParamUlongValue",  NSLookupDiagnostics_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_GetParamStringValue",  NSLookupDiagnostics_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_SetParamBoolValue",  NSLookupDiagnostics_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_SetParamIntValue",  NSLookupDiagnostics_SetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_SetParamUlongValue",  NSLookupDiagnostics_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_SetParamStringValue",  NSLookupDiagnostics_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_Validate",  NSLookupDiagnostics_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_Commit",  NSLookupDiagnostics_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "NSLookupDiagnostics_Rollback",  NSLookupDiagnostics_Rollback);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Result_GetEntryCount",  Result_GetEntryCount);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Result_GetEntry",  Result_GetEntry);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Result_IsUpdated",  Result_IsUpdated);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Result_Synchronize",  Result_Synchronize);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Result_GetParamBoolValue",  Result_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Result_GetParamIntValue",  Result_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Result_GetParamUlongValue",  Result_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Result_GetParamStringValue",  Result_GetParamStringValue);
}

