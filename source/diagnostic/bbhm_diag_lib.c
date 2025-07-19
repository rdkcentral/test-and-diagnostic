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
  
    module: bbhm_diag_lib.c

        Implement COSA Data Model Library Init and Unload apis.
 
    ---------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    ---------------------------------------------------------------

    revision:

        12/29/2010    initial revision.

**********************************************************************/

#include "ansc_platform.h"
#include "bbhm_diag_lib.h"
#include "bbhm_diagip_interface.h"
#include "bbhm_diagip_exported_api.h"
#include "bbhm_diagit_interface.h"
#include "bbhm_diagit_exported_api.h"

#include "bbhm_diagns_interface.h"
#include "bbhm_diagns_exported_api.h"
#if !defined (RESOURCE_OPTIMIZATION)
#include "bbhm_download_interface.h"
#include "bbhm_download_exported_api.h"
#include "bbhm_upload_interface.h"
#include "bbhm_upload_exported_api.h"
#include "bbhm_udpecho_interface.h"
#include "bbhm_udpecho_exported_api.h"
#else
#include "dslh_definitions_diagnostics.h"
#endif

#include "ccsp_base_api.h"

extern PBBHM_DIAG_IP_PING_OBJECT       g_DiagIpPingObj;
extern PBBHM_DIAG_IP_TRACEROUTE_OBJECT g_DiagIpTracerouteObj;

extern PBBHM_DIAG_NS_LOOKUP_OBJECT     g_DiagNSLookupObj;
#if !defined (RESOURCE_OPTIMIZATION)
extern PBBHM_DOWNLOAD_DIAG_OBJECT      g_DiagDownloadObj;
extern PBBHM_UPLOAD_DIAG_OBJECT        g_DiagUploadObj;
extern PBBHM_UDP_ECHOSRV_OBJECT        g_UdpechoObj;
#endif

void *                          g_MessageBusHandle = NULL;

COSAGetParamValueStringProc        g_GetParamValueString;
COSANotifyDiagCompleteProc         g_NotifyDiagComplete;

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_Init
    (
        void * hMessageBus
    )
{
    PBBHM_DIAG_IP_PING_OBJECT       pDiagIpPingObj       = (PBBHM_DIAG_IP_PING_OBJECT      )NULL;
    PBBHM_DIAG_IP_TRACEROUTE_OBJECT pDiagIpTracerouteObj = (PBBHM_DIAG_IP_TRACEROUTE_OBJECT)NULL;

    PBBHM_DIAG_NS_LOOKUP_OBJECT     pDiagNSLookupObj     = (PBBHM_DIAG_NS_LOOKUP_OBJECT    )NULL;
#if !defined (RESOURCE_OPTIMIZATION)
    PBBHM_DOWNLOAD_DIAG_OBJECT      pDiagDownloadObj     = (PBBHM_DOWNLOAD_DIAG_OBJECT     )NULL;
    PBBHM_UPLOAD_DIAG_OBJECT        pDiagUploadObj       = (PBBHM_UPLOAD_DIAG_OBJECT       )NULL;
    PBBHM_UDP_ECHOSRV_OBJECT        pUdpechoObj          = (PBBHM_UDP_ECHOSRV_OBJECT       )NULL;
#endif
    
    g_MessageBusHandle = hMessageBus;
    
    pDiagIpPingObj =
        (PBBHM_DIAG_IP_PING_OBJECT)BbhmCreateDiagnosticIpPing
            (
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL
            );

    pDiagIpTracerouteObj =
        (PBBHM_DIAG_IP_TRACEROUTE_OBJECT)BbhmCreateDiagnosticIpTraceroute
            (
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL
            );

    pDiagNSLookupObj =
        (PBBHM_DIAG_NS_LOOKUP_OBJECT)BbhmCreateDiagnosticNSLookup
            (
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL
            );

#if !defined (RESOURCE_OPTIMIZATION)
    pDiagDownloadObj = 
        (PBBHM_DOWNLOAD_DIAG_OBJECT)BbhmCreateDownloadDiag
            (
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL
            );

    pDiagUploadObj = 
        (PBBHM_UPLOAD_DIAG_OBJECT)BbhmCreateUploadDiag
            (
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL
            );
    
    pUdpechoObj = 
        (PBBHM_UDP_ECHOSRV_OBJECT)BbhmCreateUDPEchoServer
            (
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL,
                (ANSC_HANDLE)NULL
            );
#endif

    if ( pDiagIpPingObj )
    {
        pDiagIpPingObj->Engage((ANSC_HANDLE)pDiagIpPingObj);
    }

    if ( pDiagIpTracerouteObj )
    {
        pDiagIpTracerouteObj->Engage((ANSC_HANDLE)pDiagIpTracerouteObj);
    }

    if ( pDiagNSLookupObj )
    {
        pDiagNSLookupObj->Engage((ANSC_HANDLE)pDiagNSLookupObj);
    }

#if !defined (RESOURCE_OPTIMIZATION)
    if ( pDiagDownloadObj )
    {
        pDiagDownloadObj->Engage((ANSC_HANDLE)pDiagDownloadObj);
    }

    if ( pDiagUploadObj )
    {
        pDiagUploadObj->Engage((ANSC_HANDLE)pDiagUploadObj);	
    }

    if ( pUdpechoObj )
    {
        pUdpechoObj->Engage((ANSC_HANDLE)pUdpechoObj);
    }
#endif

    return ANSC_STATUS_SUCCESS;
}

ANSC_HANDLE ANSC_EXPORT_API
COSA_Diag_GetResults
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext
    )
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;

    switch (ulDiagType)
    {
        case DSLH_DIAGNOSTIC_TYPE_Ping:

            if ( !g_DiagIpPingObj )
            {
                return  (ANSC_HANDLE)NULL;
            }
            else
            {
                returnStatus = g_DiagIpPingObj->RetrieveResult((ANSC_HANDLE)g_DiagIpPingObj);

                if ( returnStatus != ANSC_STATUS_SUCCESS )
                {
                    return NULL;
                }

                return  g_DiagIpPingObj->GetResult((ANSC_HANDLE)g_DiagIpPingObj);
            }

            break;

        case DSLH_DIAGNOSTIC_TYPE_Traceroute:

            if ( !g_DiagIpTracerouteObj )
            {
                return  (ANSC_HANDLE)NULL;
            }
            else
            {
                returnStatus = g_DiagIpTracerouteObj->RetrieveResult((ANSC_HANDLE)g_DiagIpTracerouteObj);
                
                if ( returnStatus != ANSC_STATUS_SUCCESS )
                {
                    return NULL;
                }

                return  g_DiagIpTracerouteObj->GetResult((ANSC_HANDLE)g_DiagIpTracerouteObj);
            }

            break;

        case DSLH_DIAGNOSTIC_TYPE_NSLookup:

            if ( !g_DiagNSLookupObj )
            {
                return  (ANSC_HANDLE)NULL;
            }
            else
            {
                returnStatus = g_DiagNSLookupObj->RetrieveResult((ANSC_HANDLE)g_DiagNSLookupObj);

                if ( returnStatus != ANSC_STATUS_SUCCESS )
                {
                    return NULL;
                }

                return  g_DiagNSLookupObj->GetResult((ANSC_HANDLE)g_DiagNSLookupObj);
            }

            break;

#if !defined (RESOURCE_OPTIMIZATION)
        case DSLH_DIAGNOSTIC_TYPE_Download: 

            if ( !g_DiagDownloadObj )
            {
                return  (ANSC_HANDLE)NULL;
            }
            else
            {
                returnStatus = g_DiagDownloadObj->RetrieveResult((ANSC_HANDLE)g_DiagDownloadObj);
                if ( returnStatus != ANSC_STATUS_SUCCESS )
                {
                    return NULL;
                }

                return  g_DiagDownloadObj->GetResult((ANSC_HANDLE)g_DiagDownloadObj);
            }
            break;

        case DSLH_DIAGNOSTIC_TYPE_Upload: 

            if ( !g_DiagUploadObj )
            {
                return  (ANSC_HANDLE)NULL;
            }
            else
            {
                returnStatus = g_DiagUploadObj->RetrieveResult((ANSC_HANDLE)g_DiagUploadObj);
                if ( returnStatus != ANSC_STATUS_SUCCESS )
                {
                    return NULL;
                }

                return  g_DiagUploadObj->GetResult((ANSC_HANDLE)g_DiagUploadObj);
            }            
            break;

        case DSLH_DIAGNOSTIC_TYPE_UdpEcho: 

            if ( !g_UdpechoObj )
            {
                return  (ANSC_HANDLE)NULL;
            }
            else
            {
                returnStatus = g_UdpechoObj->RetrieveResult((ANSC_HANDLE)g_UdpechoObj);
                if ( returnStatus != ANSC_STATUS_SUCCESS )
                {
                    return NULL;
                }

                return  g_UdpechoObj->GetResult((ANSC_HANDLE)g_UdpechoObj);
            }            
            break;            
#endif

    default:

            break;
    }

    return (ANSC_HANDLE)NULL;
}

ANSC_HANDLE ANSC_EXPORT_API
COSA_Diag_GetConfigs
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext
    )
{

#if !defined (RESOURCE_OPTIMIZATION)
    switch (ulDiagType)
    {
        case DSLH_DIAGNOSTIC_TYPE_Download:
            if ( !g_DiagDownloadObj )
            {
                return  (ANSC_HANDLE)NULL;
            }
            else
            {
                return  g_DiagDownloadObj->GetConfig((ANSC_HANDLE)g_DiagDownloadObj);
            }

            break;

        case DSLH_DIAGNOSTIC_TYPE_Upload:
            if ( !g_DiagUploadObj )
            {
                return  (ANSC_HANDLE)NULL;
            }
            else
            {
                return  g_DiagUploadObj->GetConfig((ANSC_HANDLE)g_DiagUploadObj);
            }

            break;

        case DSLH_DIAGNOSTIC_TYPE_UdpEcho:
            if ( !g_UdpechoObj )
            {
                return  (ANSC_HANDLE)NULL;
            }
            else
            {
                return  g_UdpechoObj->GetConfig((ANSC_HANDLE)g_UdpechoObj);
            }  

            break;            

    }
#endif

    return (ANSC_HANDLE)NULL;
}

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_ScheduleDiagnostic
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext,
        ANSC_HANDLE                 hDiagInfo
    )
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;
    PDSLH_PING_INFO                 pPingInfo          = (PDSLH_PING_INFO      )hDiagInfo;
    PDSLH_TRACEROUTE_INFO           pTracerouteInfo    = (PDSLH_TRACEROUTE_INFO)hDiagInfo;

	PDSLH_NSLOOKUP_INFO				pNSLookupInfo	   = (PDSLH_NSLOOKUP_INFO  )hDiagInfo;
#if !defined (RESOURCE_OPTIMIZATION)
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo  = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)hDiagInfo;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo    = (PDSLH_TR143_UPLOAD_DIAG_INFO)hDiagInfo;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo       = (PDSLH_TR143_UDP_ECHO_CONFIG)hDiagInfo;
#endif


    switch (ulDiagType)
    {
        case DSLH_DIAGNOSTIC_TYPE_Ping:

            if ( !g_DiagIpPingObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                if (pPingInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Requested)
                {
                    returnStatus = 
                        g_DiagIpPingObj->SetDiagParams
                            (
                                (ANSC_HANDLE)g_DiagIpPingObj,
                                hDiagInfo
                            );

                    if ( returnStatus == ANSC_STATUS_SUCCESS )
                    {
                        returnStatus = g_DiagIpPingObj->StartDiag((ANSC_HANDLE)g_DiagIpPingObj);
                    }
                }
            }

            break;

        case DSLH_DIAGNOSTIC_TYPE_Traceroute:

            if ( !g_DiagIpTracerouteObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                if ( pTracerouteInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Requested)
                {
                    returnStatus = 
                        g_DiagIpTracerouteObj->SetDiagParams
                            (
                                (ANSC_HANDLE)g_DiagIpTracerouteObj,
                                hDiagInfo
                            );

                    if ( returnStatus == ANSC_STATUS_SUCCESS )
                    {
                        returnStatus = g_DiagIpTracerouteObj->StartDiag((ANSC_HANDLE)g_DiagIpTracerouteObj);
                    }
                }
            }

            break;

	    case DSLH_DIAGNOSTIC_TYPE_NSLookup:

            if ( !g_DiagNSLookupObj )
    	    {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                if (pNSLookupInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Requested)
                {
                    returnStatus = 
            	        g_DiagNSLookupObj->SetDiagParams
            	        (
                                (ANSC_HANDLE)g_DiagNSLookupObj,
                                hDiagInfo
                        );

                    if ( returnStatus == ANSC_STATUS_SUCCESS )
                    {
                        returnStatus = g_DiagNSLookupObj->StartDiag((ANSC_HANDLE)g_DiagNSLookupObj);
                    }

                }
            }

            break;

#if !defined (RESOURCE_OPTIMIZATION)
        case DSLH_DIAGNOSTIC_TYPE_Download:

            if ( !g_DiagDownloadObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                returnStatus = g_DiagDownloadObj->StopDiag((ANSC_HANDLE)g_DiagDownloadObj);

                returnStatus = g_DiagDownloadObj->SetDiagParams
                                (
                                    (ANSC_HANDLE)g_DiagDownloadObj,
                                    hDiagInfo
                                );

                if ( pDownloadInfo->DiagnosticsState == DSLH_TR143_DIAGNOSTIC_Requested )
                {
                    returnStatus = g_DiagDownloadObj->StartDiag((ANSC_HANDLE)g_DiagDownloadObj);
                }
            }
            break;  

        case DSLH_DIAGNOSTIC_TYPE_Upload:

            if ( !g_DiagUploadObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                returnStatus = g_DiagUploadObj->StopDiag((ANSC_HANDLE)g_DiagUploadObj);
                
                returnStatus = g_DiagUploadObj->SetDiagParams
                                (
                                    (ANSC_HANDLE)g_DiagUploadObj,
                                    hDiagInfo
                                );

                if ( pUploadInfo->DiagnosticsState == DSLH_TR143_DIAGNOSTIC_Requested )
                {
                    returnStatus = g_DiagUploadObj->StartDiag((ANSC_HANDLE)g_DiagUploadObj);
                }
            }

            break;

        case DSLH_DIAGNOSTIC_TYPE_UdpEcho:

            if ( !g_UdpechoObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                if ( g_UdpechoObj->bIsServerOn )
                {
                    returnStatus = g_UdpechoObj->StopDiag((ANSC_HANDLE)g_UdpechoObj);
                }

                g_UdpechoObj->SetDiagParams((ANSC_HANDLE)g_UdpechoObj,hDiagInfo);

                if ( pUdpEchoInfo->Enable )
                {
                    returnStatus = g_UdpechoObj->StartDiag((ANSC_HANDLE)g_UdpechoObj);
                }

            }
            break;              
#endif

        default:

            break;
    }

    return  returnStatus;
}

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_SetDiagParams
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext,
        ANSC_HANDLE                 hDiagInfo
    )
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;

    switch (ulDiagType)
    {
        case DSLH_DIAGNOSTIC_TYPE_Ping:

            if ( !g_DiagIpPingObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                returnStatus = 
                    g_DiagIpPingObj->SetDiagParams
                        (
                            (ANSC_HANDLE)g_DiagIpPingObj,
                            hDiagInfo
                        );
            }

            break;

        case DSLH_DIAGNOSTIC_TYPE_Traceroute:

            if ( !g_DiagIpTracerouteObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                returnStatus = 
                    g_DiagIpTracerouteObj->SetDiagParams
                        (
                            (ANSC_HANDLE)g_DiagIpTracerouteObj,
                            hDiagInfo
                        );
            }

            break;

	    case DSLH_DIAGNOSTIC_TYPE_NSLookup:

            if ( !g_DiagNSLookupObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                returnStatus = 
                    g_DiagNSLookupObj->SetDiagParams
                        (
                            (ANSC_HANDLE)g_DiagNSLookupObj,
                            hDiagInfo
                        );
            }

            break;

#if !defined (RESOURCE_OPTIMIZATION)
        case DSLH_DIAGNOSTIC_TYPE_Download:

            if ( !g_DiagDownloadObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                returnStatus = g_DiagDownloadObj->SetDiagParams
                                (
                                    (ANSC_HANDLE)g_DiagDownloadObj,
                                    hDiagInfo
                                );
            }
            break;  

        case DSLH_DIAGNOSTIC_TYPE_Upload:

            if ( !g_DiagUploadObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                returnStatus = g_DiagUploadObj->SetDiagParams
                                (
                                    (ANSC_HANDLE)g_DiagUploadObj,
                                    hDiagInfo
                                );
            }
            break;

        case DSLH_DIAGNOSTIC_TYPE_UdpEcho:

            if ( !g_UdpechoObj)
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                returnStatus = g_UdpechoObj->SetDiagParams
                                (
                                    (ANSC_HANDLE)g_UdpechoObj,
                                    hDiagInfo
                                );
            }
            break;              
#endif

        default:

            break;
    }

    return  returnStatus;
}


ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_SetDiagState
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext,
        ULONG                       ulDiagState
    )
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;

    
    switch (ulDiagType)
        {
            case DSLH_DIAGNOSTIC_TYPE_Ping:
    
                if ( !g_DiagIpPingObj )
                {
                    return  ANSC_STATUS_INTERNAL_ERROR;
                }
                else
                {
                    returnStatus = 
                        g_DiagIpPingObj->SetDiagState
                            (
                                (ANSC_HANDLE)g_DiagIpPingObj,
                                ulDiagState
                            );
                }
    
                break;
    
            case DSLH_DIAGNOSTIC_TYPE_Traceroute:
    
                if ( !g_DiagIpTracerouteObj )
                {
                    return  ANSC_STATUS_INTERNAL_ERROR;
                }
                else
                {
                    returnStatus = 
                        g_DiagIpTracerouteObj->SetDiagState
                            (
                                (ANSC_HANDLE)g_DiagIpTracerouteObj,
                                ulDiagState
                            );
                }
    
                break;
    
            case DSLH_DIAGNOSTIC_TYPE_NSLookup:
    
                if ( !g_DiagNSLookupObj )
                {
                    return  ANSC_STATUS_INTERNAL_ERROR;
                }
                else
                {
                    returnStatus = 
                        g_DiagNSLookupObj->SetDiagState
                            (
                                (ANSC_HANDLE)g_DiagNSLookupObj,
                                ulDiagState
                            );
                }
    
                break;
    
#if !defined (RESOURCE_OPTIMIZATION)
            case DSLH_DIAGNOSTIC_TYPE_Download:
    
                if ( !g_DiagDownloadObj )
                {
                    return  ANSC_STATUS_INTERNAL_ERROR;
                }
                else
                {
                    returnStatus = g_DiagDownloadObj->SetDiagState
                                    (
                                        (ANSC_HANDLE)g_DiagDownloadObj,
                                        ulDiagState
                                    );
                }
                break;  
    
            case DSLH_DIAGNOSTIC_TYPE_Upload:
    
                if ( !g_DiagUploadObj )
                {
                    return  ANSC_STATUS_INTERNAL_ERROR;
                }
                else
                {
                    returnStatus = g_DiagUploadObj->SetDiagState
                                    (
                                        (ANSC_HANDLE)g_DiagUploadObj,
                                        ulDiagState
                                    );
                }
                break;
    
            case DSLH_DIAGNOSTIC_TYPE_UdpEcho:
    
                if ( !g_UdpechoObj)
                {
                    return  ANSC_STATUS_INTERNAL_ERROR;
                }
                else
                {
                    returnStatus = g_UdpechoObj->SetDiagState
                                    (
                                        (ANSC_HANDLE)g_UdpechoObj,
                                        ulDiagState
                                    );
                }
                break;              
#endif
    
            default:
    
                break;
        }
    return returnStatus;
}

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_CancelDiagnostic
    (
        ULONG                       ulDiagType,
        ANSC_HANDLE                 hContext
    )
{

    switch (ulDiagType) 
    {
        case DSLH_DIAGNOSTIC_TYPE_Ping:
	
            if ( !g_DiagIpPingObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                return  g_DiagIpPingObj->StopDiag((ANSC_HANDLE)g_DiagIpPingObj);
            }
            break;

        case DSLH_DIAGNOSTIC_TYPE_Traceroute:
        
            if ( !g_DiagIpTracerouteObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                return  g_DiagIpTracerouteObj->StopDiag((ANSC_HANDLE)g_DiagIpTracerouteObj);
            }
            break;

        case DSLH_DIAGNOSTIC_TYPE_NSLookup:

            if ( !g_DiagNSLookupObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                return  g_DiagNSLookupObj->StopDiag((ANSC_HANDLE)g_DiagNSLookupObj);
            }
            break;

#if !defined (RESOURCE_OPTIMIZATION)
        case DSLH_DIAGNOSTIC_TYPE_Download:

            if ( !g_DiagDownloadObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                return  g_DiagDownloadObj->Cancel((ANSC_HANDLE)g_DiagDownloadObj);
            }
            break;  

        case DSLH_DIAGNOSTIC_TYPE_Upload:

            if ( !g_DiagUploadObj )
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                return  g_DiagUploadObj->Cancel((ANSC_HANDLE)g_DiagUploadObj);
            }
            break;

        case DSLH_DIAGNOSTIC_TYPE_UdpEcho:

            if ( !g_UdpechoObj)
            {
                return  ANSC_STATUS_INTERNAL_ERROR;
            }
            else
            {
                return  g_UdpechoObj->Cancel((ANSC_HANDLE)g_UdpechoObj);
            }
            break;
#endif

        default:

            break;
    }

    return ANSC_STATUS_INTERNAL_ERROR;
}

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_MemoryUsage
    (
        void
    )
{
    /*AnscTraceMemoryUsage();*/

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_MemoryTable
    (
        void
    )
{
    AnscTraceMemoryTable();

    return ANSC_STATUS_SUCCESS;
}

void ANSC_EXPORT_API
COSA_Diag_Unload
    (
        void
    )
{
    if ( g_DiagIpPingObj)
    {
        g_DiagIpPingObj->Cancel((ANSC_HANDLE)g_DiagIpPingObj);
        g_DiagIpPingObj->Remove((ANSC_HANDLE)g_DiagIpPingObj);
    }

    if ( g_DiagIpTracerouteObj)
    {
        g_DiagIpTracerouteObj->Cancel((ANSC_HANDLE)g_DiagIpTracerouteObj);
        g_DiagIpTracerouteObj->Remove((ANSC_HANDLE)g_DiagIpTracerouteObj);
    }

    if ( g_DiagNSLookupObj )
    {
        g_DiagNSLookupObj->Cancel((ANSC_HANDLE)g_DiagNSLookupObj);
        g_DiagNSLookupObj->Remove((ANSC_HANDLE)g_DiagNSLookupObj);
    }

#if !defined (RESOURCE_OPTIMIZATION)
    if ( g_DiagDownloadObj )
    {
        g_DiagDownloadObj->Cancel((ANSC_HANDLE)g_DiagDownloadObj);
        g_DiagDownloadObj->Remove((ANSC_HANDLE)g_DiagDownloadObj);
    }

    if ( g_DiagUploadObj )
    {
        g_DiagUploadObj->Cancel((ANSC_HANDLE)g_DiagUploadObj);
        g_DiagUploadObj->Remove((ANSC_HANDLE)g_DiagUploadObj);
    }

    if ( g_UdpechoObj )
    {
        g_UdpechoObj->Cancel((ANSC_HANDLE)g_UdpechoObj);
        g_UdpechoObj->Remove((ANSC_HANDLE)g_UdpechoObj);
    }
#endif
}


ANSC_STATUS ANSC_EXPORT_API
COSA_Diag_ExportFunc
    (
        ULONG                       uVersion, 
        void*                       hCosaPlugInfo       
    )
{
    PCOSA_PLUGIN_INFO               pPlugInfo       = (PCOSA_PLUGIN_INFO           )hCosaPlugInfo;
    COSAGetParamValueStringProc     pGetStringProc  = (COSAGetParamValueStringProc )NULL;
    COSANotifyDiagCompleteProc      pNotifyDiagProc = (COSANotifyDiagCompleteProc  )NULL;

    pGetStringProc = (COSAGetParamValueStringProc)pPlugInfo->AcquireFunction("COSAGetParamValueString");

    if ( pGetStringProc != NULL)
    { 
        g_GetParamValueString = pGetStringProc;   
    }

    pNotifyDiagProc = (COSANotifyDiagCompleteProc)pPlugInfo->AcquireFunction("COSANotifyDiagComplete");

    if ( pNotifyDiagProc != NULL )
    { 
        g_NotifyDiagComplete = pNotifyDiagProc;   
    }
         
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaSendDiagCompleteSignal
	(
		void
	)
{
	if ( !g_MessageBusHandle )
	{
	    return ANSC_STATUS_FAILURE;
	}

	if ( CcspBaseIf_SenddiagCompleteSignal(g_MessageBusHandle) != CCSP_SUCCESS )
	{
	    return ANSC_STATUS_FAILURE;
	}

	AnscTraceWarning(("CosaSendDiagCompleteSignal -- inform initiator succeeded !\n"));

	return ANSC_STATUS_SUCCESS;
}

