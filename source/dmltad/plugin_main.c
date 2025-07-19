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
#include "diag.h"
#include "safec_lib_common.h"
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

#include "cosa_logbackup_dml.h"
#include "cosa_powermgt_tcxb6_dml.h"
#include "cosa_thermal_dml.h"
#include "cosa_hwst_dml.h"

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
#include "cosa_moca_internal.h"
*/
//#include "cosa_apis_deviceinfo.h"
#include "cosa_apis_vendorlogfile.h"

PCOSA_BACKEND_MANAGER_OBJECT g_pCosaBEManager;
void *                       g_pDslhDmlAgent; 
extern ANSC_HANDLE     g_MessageBusHandle_Irep;
extern char            g_SubSysPrefix_Irep[32];

#define THIS_PLUGIN_VERSION                         1

int ANSC_EXPORT_API
COSA_Init
    (
        ULONG                       uMaxVersionSupported,
        void*                       hCosaPlugInfo         /* PCOSA_PLUGIN_INFO passed in by the caller */
    )
{
    PCOSA_PLUGIN_INFO               pPlugInfo                   = (PCOSA_PLUGIN_INFO                 )hCosaPlugInfo;
    COSAGetParamValueStringProc     pGetStringProc              = (COSAGetParamValueStringProc       )NULL;
    COSAGetParamValueUlongProc      pGetParamValueUlongProc     = (COSAGetParamValueUlongProc        )NULL;
    COSAGetCommonHandleProc         pGetCHProc                  = (COSAGetCommonHandleProc           )NULL;
    COSAValidateHierarchyInterfaceProc
                                    pValInterfaceProc           = (COSAValidateHierarchyInterfaceProc)NULL;
    COSAGetHandleProc               pGetRegistryRootFolder      = (COSAGetHandleProc                 )NULL;
    COSAGetInstanceNumberByIndexProc
                                    pGetInsNumberByIndexProc    = (COSAGetInstanceNumberByIndexProc  )NULL;
    COSAGetInterfaceByNameProc      pGetInterfaceByNameProc     = (COSAGetInterfaceByNameProc        )NULL;

    if ( uMaxVersionSupported < THIS_PLUGIN_VERSION )
    {
      /* this version is not supported */
        return -1;
    }

    pPlugInfo->uPluginVersion       = THIS_PLUGIN_VERSION;
    g_pDslhDmlAgent                 = pPlugInfo->hDmlAgent;

    /* register the back-end apis for the data model */

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
#endif
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_GetParamBoolValue",  IPPing_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_GetParamIntValue",  IPPing_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_GetParamUlongValue",  IPPing_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_GetParamStringValue",  IPPing_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_SetParamBoolValue",  IPPing_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_SetParamIntValue",  IPPing_SetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_SetParamUlongValue",  IPPing_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_SetParamStringValue",  IPPing_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_Validate",  IPPing_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_Commit",  IPPing_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "IPPing_Rollback",  IPPing_Rollback);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_GetParamBoolValue",  TraceRoute_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_GetParamIntValue",  TraceRoute_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_GetParamUlongValue",  TraceRoute_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_GetParamStringValue",  TraceRoute_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_SetParamBoolValue",  TraceRoute_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_SetParamIntValue",  TraceRoute_SetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_SetParamUlongValue",  TraceRoute_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_SetParamStringValue",  TraceRoute_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_Validate",  TraceRoute_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_Commit",  TraceRoute_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "TraceRoute_Rollback",  TraceRoute_Rollback);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RouteHops_GetEntryCount",  RouteHops_GetEntryCount);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RouteHops_GetEntry",  RouteHops_GetEntry);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RouteHops_IsUpdated",  RouteHops_IsUpdated);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RouteHops_Synchronize",  RouteHops_Synchronize);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RouteHops_GetParamBoolValue",  RouteHops_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RouteHops_GetParamIntValue",  RouteHops_GetParamIntValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RouteHops_GetParamUlongValue",  RouteHops_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RouteHops_GetParamStringValue",  RouteHops_GetParamStringValue);
#if !defined (RESOURCE_OPTIMIZATION)
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
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTest_GetParamBoolValue",  SpeedTest_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTest_SetParamBoolValue",  SpeedTest_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTest_Validate",  SpeedTest_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTest_Commit",  SpeedTest_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTest_Rollback",  SpeedTest_Rollback);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTest_GetParamStringValue",  SpeedTest_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTest_SetParamStringValue",  SpeedTest_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTest_GetParamUlongValue",  SpeedTest_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTest_SetParamUlongValue",  SpeedTest_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RDK_SpeedTest_GetParamUlongValue",  RDK_SpeedTest_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RDK_SpeedTest_SetParamUlongValue",  RDK_SpeedTest_SetParamUlongValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTestServer_GetParamBoolValue",  SpeedTestServer_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTestServer_GetParamStringValue",  SpeedTestServer_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SpeedTestServer_SetParamStringValue",  SpeedTestServer_SetParamStringValue);

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

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "LogBackup_GetParamBoolValue",  LogBackup_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "LogBackup_SetParamBoolValue",  LogBackup_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "LogBackup_GetParamUlongValue",  LogBackup_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "LogBackup_SetParamUlongValue",  LogBackup_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "LogBackup_Validate",  LogBackup_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "LogBackup_Commit",  LogBackup_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "LogBackup_Rollback",  LogBackup_Rollback);    
    
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PowerManagement_GetParamBoolValue", PowerManagement_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PowerManagement_SetParamBoolValue",  PowerManagement_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PowerManagement_Validate",  PowerManagement_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PowerManagement_Commit",  PowerManagement_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PowerManagement_Rollback",  PowerManagement_Rollback);    

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Fan_GetParamBoolValue", Fan_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Fan_SetParamBoolValue", Fan_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Fan_GetParamUlongValue", Fan_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Fan_Validate", Fan_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Fan_Commit", Fan_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Fan_Rollback", Fan_Rollback);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "hwHealthTest_GetParamBoolValue", hwHealthTest_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "hwHealthTest_SetParamBoolValue", hwHealthTest_SetParamBoolValue );
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "hwHealthTest_GetParamStringValue", hwHealthTest_GetParamStringValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue", 
                                X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_RDKCENTRAL_COM_RxTxStats_SetParamStringValue", 
                                X_RDKCENTRAL_COM_RxTxStats_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_RDKCENTRAL_COM_RxTxStats_Validate", 
                                X_RDKCENTRAL_COM_RxTxStats_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_RDKCENTRAL_COM_RxTxStats_Commit", 
                                X_RDKCENTRAL_COM_RxTxStats_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_RDKCENTRAL_COM_RxTxStats_Rollback", 
                                X_RDKCENTRAL_COM_RxTxStats_Rollback);

    pGetCHProc = (COSAGetCommonHandleProc)pPlugInfo->AcquireFunction("COSAGetDiagPluginInfo");

    if( pGetCHProc != NULL)
    {
        g_pCosaDiagPluginInfo = pGetCHProc(NULL);
    }
    else
    {
        goto EXIT;
    }

    pGetStringProc = (COSAGetParamValueStringProc)pPlugInfo->AcquireFunction("COSAGetParamValueString");

    if( pGetStringProc != NULL)
    {
        g_GetParamValueString = pGetStringProc;
    }
    else
    {
        goto EXIT;
    }

    pGetParamValueUlongProc = (COSAGetParamValueUlongProc)pPlugInfo->AcquireFunction("COSAGetParamValueUlong");

    if( pGetParamValueUlongProc != NULL)
    {
        g_GetParamValueUlong = pGetParamValueUlongProc;
    }
    else
    {
        goto EXIT;
    }

    pValInterfaceProc = (COSAValidateHierarchyInterfaceProc)pPlugInfo->AcquireFunction("COSAValidateHierarchyInterface");

    if ( pValInterfaceProc )
    {
        g_ValidateInterface = pValInterfaceProc;
    }
    else
    {
        goto EXIT;
    }

#ifdef _SOFTWAREMODULES_SUPPORT_NAF
    CosaSoftwareModulesInit(hCosaPlugInfo);
#endif

    pGetRegistryRootFolder = (COSAGetHandleProc)pPlugInfo->AcquireFunction("COSAGetRegistryRootFolder");

    if ( pGetRegistryRootFolder != NULL )
    {
        g_GetRegistryRootFolder = pGetRegistryRootFolder;
    }
    else
    {
        printf("!!! haha, catcha !!!\n");
        goto EXIT;
    }

    pGetInsNumberByIndexProc = (COSAGetInstanceNumberByIndexProc)pPlugInfo->AcquireFunction("COSAGetInstanceNumberByIndex");

    if ( pGetInsNumberByIndexProc != NULL )
    {
        g_GetInstanceNumberByIndex = pGetInsNumberByIndexProc;
    }
    else
    {
        goto EXIT;
    }

    pGetInterfaceByNameProc = (COSAGetInterfaceByNameProc)pPlugInfo->AcquireFunction("COSAGetInterfaceByName");

    if ( pGetInterfaceByNameProc != NULL )
    {
        g_GetInterfaceByName = pGetInterfaceByNameProc;
    }
    else
    {
        goto EXIT;
    }

    g_pTadCcdIf = g_GetInterfaceByName(g_pDslhDmlAgent, CCSP_CCD_INTERFACE_NAME);

    if ( !g_pTadCcdIf )
    {
        CcspTraceError(("g_pTadCcdIf is NULL !\n"));

        goto EXIT;
    }

    /* Get Message Bus Handle */
    g_GetMessageBusHandle = (COSAGetHandleProc)pPlugInfo->AcquireFunction("COSAGetMessageBusHandle");
    if ( g_GetMessageBusHandle == NULL )
    {
        goto EXIT;
    }

    g_MessageBusHandle = (ANSC_HANDLE)g_GetMessageBusHandle(g_pDslhDmlAgent);
    if ( g_MessageBusHandle == NULL )
    {
        goto EXIT;
    }
    g_MessageBusHandle_Irep = g_MessageBusHandle;

    g_GetSubsystemPrefix = (COSAGetSubsystemPrefixProc)pPlugInfo->AcquireFunction("COSAGetSubsystemPrefix");
    if ( g_GetSubsystemPrefix != NULL )
    {
        char*  tmpSubsystemPrefix;
        errno_t rc = -1;

        if (( tmpSubsystemPrefix = (g_GetSubsystemPrefix(g_pDslhDmlAgent)) ))
        {
            rc = strcpy_s(g_SubSysPrefix_Irep, sizeof(g_SubSysPrefix_Irep), tmpSubsystemPrefix);
            ERR_CHK(rc);
        }
    }

    /* Create backend framework */
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)CosaBackEndManagerCreate();

    if ( g_pCosaBEManager && g_pCosaBEManager->Initialize )
    {
        g_pCosaBEManager->hCosaPluginInfo = pPlugInfo;

        g_pCosaBEManager->Initialize   ((ANSC_HANDLE)g_pCosaBEManager);
    }

    if (diag_init() != DIAG_ERR_OK)
        goto EXIT;

    return  0;

EXIT:

    return -1;

}

#if 0
int ANSC_EXPORT_API
COSA_Async_Init
    (
        ULONG                       uMaxVersionSupported,
        void*                       hCosaPlugInfo         /* PCOSA_PLUGIN_INFO passed in by the caller */
    )
{
    PCOSA_PLUGIN_INFO               pPlugInfo      = (PCOSA_PLUGIN_INFO)hCosaPlugInfo;

#if 0
    if (g_pCosaBEManager)
    {
#ifdef _COSA_SIM_
        COSAGetHandleProc         pProc          = (COSAGetHandleProc       )NULL;
        ULONG                     ulRole         = 0;

        pProc = (COSAGetHandleProc)pPlugInfo->AcquireFunction("COSAGetLPCRole");

        if ( pProc )
        {
            ulRole = (ULONG)(*pProc)();
        }

        /*for simulation, LPC manager to reset Wifi, LPC party to reset Moca*/
        if ( ulRole == LPC_ROLE_MANAGER )
        {
            PCOSA_DATAMODEL_WIFI pWifi = g_pCosaBEManager->hWifi;
            pWifi->Remove(pWifi);
            g_pCosaBEManager->hWifi = (ANSC_HANDLE)CosaWifiCreate();
        }
        else if ( ulRole == LPC_ROLE_PARTY )
        {
            PCOSA_DATAMODEL_MOCA pMoca = g_pCosaBEManager->hMoCA;
            pMoca->Remove(pMoca);
            g_pCosaBEManager->hMoCA = (ANSC_HANDLE)CosaMoCACreate();
        }
#endif

    }
    else
    {
        return -1;
    }

#endif
    return 0;
}

#endif

BOOL ANSC_EXPORT_API
COSA_IsObjSupported
    (
        char*                        pObjName
    )
{
    /* COSA XML file will be generated based on standard TR-xxx data model definition.
     * By default, all the objects are expected to supported in the libraray.
     * Realistically, we will have certain ones cannot be supported at the early stage of development.
     * We can rule them out by return FALSE even if they're defined in COSA XML file.
     */

#if 0

    if (strcmp(pObjName, "InternetGatewayDevice.UserInterface.") == 0)
    {
        /* all the objects/parameters under "UserInterface" will not be populated in Data Model Tree. */
        return FALSE;
    }

#endif

    return TRUE;
}

void ANSC_EXPORT_API
COSA_Unload
    (
        void
    )
{
    ANSC_STATUS                     returnStatus            = ANSC_STATUS_SUCCESS;

    /* unload the memory here */
    diag_term();

    returnStatus  =  CosaBackEndManagerRemove(g_pCosaBEManager);

    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        g_pCosaBEManager = NULL;
    }
    else
    {
        /* print error trace*/
        g_pCosaBEManager = NULL;
    }
}

void ANSC_EXPORT_API
COSA_MemoryCheck
    (
        void
    )
{
    PCOSA_PLUGIN_INFO               pPlugInfo               = (PCOSA_PLUGIN_INFO)g_pCosaBEManager->hCosaPluginInfo;
    
    CosaBackEndManagerRemove(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
    
    COSA_MemoryUsage();
    COSA_MemoryTable();

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)CosaBackEndManagerCreate();

    if ( g_pCosaBEManager && g_pCosaBEManager->Initialize )
    {
        g_pCosaBEManager->hCosaPluginInfo = pPlugInfo;

        g_pCosaBEManager->Initialize   ((ANSC_HANDLE)g_pCosaBEManager);
    }
}

void ANSC_EXPORT_API
COSA_MemoryUsage
    (
        void
    )
{
    /*AnscTraceMemoryUsage();*/
}

void ANSC_EXPORT_API
COSA_MemoryTable
    (
        void
    )
{
    /*AnscTraceMemoryTable();*/
}
