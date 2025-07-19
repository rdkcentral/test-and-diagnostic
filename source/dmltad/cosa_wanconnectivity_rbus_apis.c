/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
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


#include <stdio.h>
#include <ctype.h>
#include "safec_lib_common.h"
#include "cosa_wanconnectivity_rbus_apis.h"
#include "cosa_wanconnectivity_rbus_handler_apis.h"
#include <syscfg/syscfg.h>

extern rbusHandle_t rbus_handle;
extern rbusHandle_t rbus_table_handle;
extern BOOL g_wanconnectivity_check_active;
extern BOOL g_wanconnectivity_check_enable;
extern pthread_mutex_t gIntfAccessMutex;
extern pthread_mutex_t gUrlAccessMutex;
extern SLIST_HEADER    gpUrlList;
extern WANCNCTVTY_CHK_GLOBAL_INTF_INFO *gInterface_List;


extern ANSC_STATUS wancnctvty_chk_start_threads(ULONG InstanceNumber,service_type_t type);
extern ANSC_STATUS wancnctvty_chk_stop_threads(ULONG InstanceNumber,service_type_t type);

rbusDataElement_t WANCHK_Feature_RbusDataElements[] =
{
//RBUS_TABLE
    { "Device.Diagnostics.X_RDK_DNSInternet.Enable", RBUS_ELEMENT_TYPE_EVENT, {WANCNCTVTYCHK_GetHandler, WANCNCTVTYCHK_SetHandler, NULL, NULL, NULL, NULL} }
};

/* Note some of the parameters are of progression scope, commenting for now, while be enabled in
coming sprints for test*/
rbusDataElement_t WANCHK_Feature_Enabled_RbusElements[] =
{
//RBUS_TABLE
    { "Device.Diagnostics.X_RDK_DNSInternet.Active", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetHandler, NULL, NULL, NULL, WANCNCTVTYCHK_SubHandler, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.TestURLNumberOfEntries", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetURLHandler,NULL, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.TestURL.{i}.", RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, WANCNCTVTYCHK_TableAddRowHandler, WANCNCTVTYCHK_TableRemoveRowHandler, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.TestURL.{i}.URL", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetURLHandler, WANCNCTVTYCHK_SetURLHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterfaceNumberOfEntries", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler,NULL, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.", RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.Enable", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.Alias", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.InterfaceName", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.PassiveMonitor", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.PassiveMonitorTimeout", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.ActiveMonitor", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.ActiveMonitorInterval", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.MonitorResult", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, NULL, NULL, NULL,WANCNCTVTYCHK_SubHandler , NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.QueryNow", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.QueryNowResult", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, NULL, NULL, NULL,WANCNCTVTYCHK_SubHandler , NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.QueryTimeout", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.QueryRetry", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.RecordType", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.{i}.ServerType", RBUS_ELEMENT_TYPE_PROPERTY, {WANCNCTVTYCHK_GetIntfHandler, WANCNCTVTYCHK_SetIntfHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDK_DNSInternet.StartConnectivityCheck()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, WANCNCTVTYCHK_StartConnectivityCheck} },
    { "Device.X_RDK_DNSInternet.StopConnectivityCheck()", RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, WANCNCTVTYCHK_StopConnectivityCheck} }
};

/**********************************************************************
    function:
        CosaWanCnctvtyChk_RbusInit
    description:
        This function is called to Init Rbus
    argument:
        VOID
    return:
        RBUS_ERROR_SUCCESS if succeeded;
        RBUS_ERROR_BUS_ERROR if error.
**********************************************************************/
rbusError_t CosaWanCnctvtyChk_RbusInit(VOID)
{
    int rc = RBUS_ERROR_SUCCESS;

    if(RBUS_ENABLED == rbus_checkStatus())
    {
        WANCHK_LOG_INFO("RBUS enabled, Proceed with Wan Connectivity check\n");
    }
    else
    {
        WANCHK_LOG_ERROR("RBUS is NOT ENABLED, Can't Proceed with Wan Connectivity check\n");
        return RBUS_ERROR_BUS_ERROR;
    }

    rc = rbus_open(&rbus_handle, "WanCnctvtyChkEventConsumer");
    if (rc != RBUS_ERROR_SUCCESS)
    {
        WANCHK_LOG_ERROR("rbus initialization failed\n");
        rc = RBUS_ERROR_NOT_INITIALIZED;
        return rc;
    }
    return rc;
}

/**********************************************************************
    function:
        CosaWanCnctvtyChk_Reg_elements
    description:
        This function is called to Init Rbus Elements specific to
        when wan connectivity is enabled
    argument:
        VOID
    return:
        RBUS_ERROR_SUCCESS if succeeded;
        RBUS_ERROR_BUS_ERROR if error.
**********************************************************************/
rbusError_t CosaWanCnctvtyChk_Reg_elements(dml_type_t type)
{
    int rc = RBUS_ERROR_SUCCESS;
    switch(type)
    {
        case FEATURE_DML:
            rc = rbus_regDataElements(rbus_handle, 
                    ARRAY_SZ(WANCHK_Feature_RbusDataElements), WANCHK_Feature_RbusDataElements);
            break;
        case FEATURE_ENABLED_DML:
            rc = rbus_open(&rbus_table_handle, "WanCnctvtyChkTableConsumer");
            if (rc != RBUS_ERROR_SUCCESS)
            {
                WANCHK_LOG_ERROR("rbus initialization failed\n");
                rc = RBUS_ERROR_NOT_INITIALIZED;
                return rc;
            }
            rc = rbus_regDataElements(rbus_table_handle, 
                    ARRAY_SZ(WANCHK_Feature_Enabled_RbusElements), WANCHK_Feature_Enabled_RbusElements);
            break;
        default:
            WANCHK_LOG_WARN("Default/ERROR case");
    }

    if (rc != RBUS_ERROR_SUCCESS)
    {
        WANCHK_LOG_ERROR("rbus register data elements failed");
        return rc;
    }
    return rc;
}

/**********************************************************************
    function:
        CosaWanCnctvtyChk_UnReg_elements
    description:
        This function is called to DeInit Rbus Elements specific to
        when wan connectivity is enabled
    argument:
        VOID
    return:
        RBUS_ERROR_SUCCESS if succeeded;
        RBUS_ERROR_BUS_ERROR if error.
**********************************************************************/
rbusError_t CosaWanCnctvtyChk_UnReg_elements(dml_type_t type)
{
    int rc = RBUS_ERROR_SUCCESS;

    if (type == FEATURE_ENABLED_DML)
    {
        rc = rbus_unregDataElements(rbus_table_handle,
                ARRAY_SZ(WANCHK_Feature_Enabled_RbusElements), WANCHK_Feature_Enabled_RbusElements);
        rbus_close(rbus_table_handle);
    }
    else if (type == FEATURE_DML)
    {
        rc = rbus_unregDataElements(rbus_table_handle,
                ARRAY_SZ(WANCHK_Feature_Enabled_RbusElements), WANCHK_Feature_Enabled_RbusElements);
        rbus_close(rbus_table_handle);
        rc = rbus_unregDataElements(rbus_handle,
                    ARRAY_SZ(WANCHK_Feature_RbusDataElements), WANCHK_Feature_RbusDataElements);
        rbus_close(rbus_table_handle);
    }
    else
        WANCHK_LOG_WARN("Default/ERROR case");

    if (rc != RBUS_ERROR_SUCCESS)
    {
        WANCHK_LOG_ERROR("rbus unregister data elements failed for type %d\n",type);
        return rc;
    }
    return rc;
}

/**********************************************************************
    function:
        CosaWanCnctvtyChk_Intf_Commit
    description:
        This function is to commit the interface configs.
    argument:
        PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO  pIPInterface
    return:
        TRUE if succeeded
        FALSE if failure
**********************************************************************/
ANSC_STATUS CosaWanCnctvtyChk_Intf_Commit (PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO  pIPInterface)
{
    ANSC_STATUS returnStatus                         = ANSC_STATUS_SUCCESS;
    querynow_result_t querynow_result = QUERYNOW_RESULT_UNKNOWN;

    COSA_DML_WANCNCTVTY_CHK_INTF_INFO  CurrentCfg;

    if (pIPInterface->Cfg_bitmask)
    {
        /* check we are currently executing query now, if so ignore the current cfg coming to
        commit, No need of any update to global*/
        if (pIPInterface->Enable && pIPInterface->QueryNow)
        {
            CosaDml_querynow_result_get(pIPInterface->InstanceNumber,&querynow_result);
            if (querynow_result == QUERYNOW_RESULT_BUSY)
            {
                WANCHK_LOG_ERROR("QueryNow Execution is already in progress for Interface %s,Ignoring Current Request\n",
                                                                    pIPInterface->InterfaceName);
                return ANSC_STATUS_FAILURE;
            }
        }

        memset(&CurrentCfg,0,sizeof(COSA_DML_WANCNCTVTY_CHK_INTF_INFO)); 
        CurrentCfg.InstanceNumber = pIPInterface->InstanceNumber;
        returnStatus = CosaDmlGetIntfCfg(&CurrentCfg, FALSE);
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
          WANCHK_LOG_ERROR("%s:Unable to fetch current values from CosaDmlGetIntfCfg",__FUNCTION__);
        }

        if ( (pIPInterface->Cfg_bitmask & INTF_CFG_ACTIVE_ENABLE) || 
                (pIPInterface->Cfg_bitmask & INTF_CFG_QUERYNOW_ENABLE) ||
                  (pIPInterface->Cfg_bitmask & INTF_CFG_PASSIVE_ENABLE) )
        {
            if((CurrentCfg.Enable == FALSE) && ((pIPInterface->QueryNow == TRUE) ||
                                                  (pIPInterface->PassiveMonitor == TRUE) ||
                                                  (pIPInterface->ActiveMonitor == TRUE)) )
            {
                WANCHK_LOG_ERROR("Wan connectivity check for Interface %s not Enabled,Operation not Permitted\n",
                                                                        pIPInterface->InterfaceName);
                return ANSC_STATUS_FAILURE;
            }
        }

        if ( pIPInterface->Cfg_bitmask & INTF_CFG_ACTIVE_INTERVAL)
        {
            WANCHK_LOG_INFO("ActiveMonitorInterval:%ld\n",pIPInterface->ActiveMonitorInterval);
            if (pIPInterface->ActiveMonitorInterval < 1000)
            {
                WANCHK_LOG_ERROR("ActiveMonitor Interval Provided is invalid for interface %s,Operation not Permitted\n",
                                                                    pIPInterface->InterfaceName);
                return ANSC_STATUS_FAILURE;
            } 
        }

        returnStatus = CosaDml_glblintfdb_updateentry(pIPInterface);
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            WANCHK_LOG_ERROR("%s:Unable to update global db entry\n",__FUNCTION__);
            return ANSC_STATUS_FAILURE;
        }
        /* upper case based on interface status*/
        if ( (CurrentCfg.Enable == TRUE) && (pIPInterface->Enable == FALSE))
        {
            /* Interface moving to disable state*/
            WANCHK_LOG_INFO("wanconnectivity_chk Interface status changed %d->%d\n",
                                                        CurrentCfg.Enable,pIPInterface->Enable);
            /* We can only stop passive and active threads, no feasibility for stopping querynow threads
             call stop threads based on the changes*/
            returnStatus = wancnctvty_chk_stop_threads(pIPInterface->InstanceNumber,
                                                            PASSIVE_ACTIVE_MONITOR_THREADS);
            if (returnStatus != ANSC_STATUS_SUCCESS)
            {
                WANCHK_LOG_ERROR("%s:%d Unable to stop threads",__FUNCTION__,__LINE__);
                return ANSC_STATUS_FAILURE;
            }
            return ANSC_STATUS_SUCCESS;
        }
        else if ((CurrentCfg.Enable == FALSE) && (pIPInterface->Enable == TRUE))
        {
                            /* Interface moving to disable state*/
            WANCHK_LOG_INFO("wanconnectivity_chk Interface status changed %d->%d\n",
                                                    CurrentCfg.Enable,pIPInterface->Enable);
            returnStatus = wancnctvty_chk_start_threads(pIPInterface->InstanceNumber,
                                                                                ALL_THREADS);
            if (returnStatus != ANSC_STATUS_SUCCESS)
            {
                WANCHK_LOG_ERROR("%s:%d Unable to start threads",__FUNCTION__,__LINE__);
                return ANSC_STATUS_FAILURE;
            }
            return ANSC_STATUS_SUCCESS; 
        }

        if ( (pIPInterface->Cfg_bitmask & INTF_CFG_QUERY_RETRY) ||
                  (pIPInterface->Cfg_bitmask & INTF_CFG_QUERY_TIMEOUT) )
        {
            WANCHK_LOG_INFO("wanconnectivity_chk config changed\n");
            WANCHK_LOG_INFO("QueryRetry:%ld->%ld,QueryTimeout:%ld->%ld,RecordType:%s->%s,ServerType:%s->%s\n",
                            CurrentCfg.QueryRetry,pIPInterface->QueryRetry,
                            CurrentCfg.QueryTimeout,pIPInterface->QueryTimeout,
                            CurrentCfg.RecordType,pIPInterface->RecordType,
                            CurrentCfg.ServerType,pIPInterface->ServerType);

        }

        /* Give priority to Query Now*/
        // Note we already validated busy status above
        if (pIPInterface->QueryNow)
        {
            returnStatus = wancnctvty_chk_start_threads(pIPInterface->InstanceNumber,
                                                                            QUERYNOW_THREAD);
            if (returnStatus != ANSC_STATUS_SUCCESS)
            {
                WANCHK_LOG_ERROR("%s:%d Unable to start threads",__FUNCTION__,__LINE__);
                return ANSC_STATUS_FAILURE;
            }

        }

        /* Passive Monitor status*/
        if ((CurrentCfg.PassiveMonitor == TRUE) && (pIPInterface->PassiveMonitor == FALSE))
        {
            /* Interface moving to disable state*/
            WANCHK_LOG_INFO("wanconnectivity_chk PassiveMonitor status changed %d->%d\n",
                                    CurrentCfg.PassiveMonitor,pIPInterface->PassiveMonitor);
            returnStatus = wancnctvty_chk_stop_threads(pIPInterface->InstanceNumber,
                                                                    PASSIVE_MONITOR_THREAD);
            if (returnStatus != ANSC_STATUS_SUCCESS)
            {
                WANCHK_LOG_ERROR("%s:%d Unable to stop passive thread",__FUNCTION__,__LINE__);
                return ANSC_STATUS_FAILURE;
            }
        }
        else if (pIPInterface->Cfg_bitmask & INTF_CFG_PASSIVE_TIMEOUT)
        {
            /* Passive monitor config changed, stop passive monitor thread running with old
            config*/
            WANCHK_LOG_INFO("wanconnectivity_chk PassiveMonitor config changed\n");
            WANCHK_LOG_INFO("Timeout:%ld->%ld\n",
                            CurrentCfg.PassiveMonitorTimeout,pIPInterface->PassiveMonitorTimeout);
            returnStatus = wancnctvty_chk_stop_threads(pIPInterface->InstanceNumber,
                                                                    PASSIVE_MONITOR_THREAD);
            if (returnStatus != ANSC_STATUS_SUCCESS)
            {
                WANCHK_LOG_ERROR("%s:%d Unable to stop passive thread",__FUNCTION__,__LINE__);
                return ANSC_STATUS_FAILURE;
            }
        }

        /* Active Monitor status*/
        if ((CurrentCfg.ActiveMonitor == TRUE) && (pIPInterface->ActiveMonitor == FALSE))
        {
                                            /* Interface moving to disable state*/
            WANCHK_LOG_INFO("wanconnectivity_chk ActiveMonitor status changed %d->%d\n",
                                    CurrentCfg.ActiveMonitor,pIPInterface->ActiveMonitor);
            returnStatus = wancnctvty_chk_stop_threads(pIPInterface->InstanceNumber,
                                                                    ACTIVE_MONITOR_THREAD);
            if (returnStatus != ANSC_STATUS_SUCCESS)
            {
                WANCHK_LOG_ERROR("%s:%d Unable to stop active thread",__FUNCTION__,__LINE__);
                return ANSC_STATUS_FAILURE;
            }
        }
        else if ( (pIPInterface->Cfg_bitmask & INTF_CFG_ACTIVE_INTERVAL) ||
                  (pIPInterface->Cfg_bitmask & INTF_CFG_QUERY_RETRY) ||
                  (pIPInterface->Cfg_bitmask & INTF_CFG_QUERY_TIMEOUT) ||
                  (pIPInterface->Cfg_bitmask & INTF_CFG_RECORDTYPE) ||
                  (pIPInterface->Cfg_bitmask & INTF_CFG_SERVERTYPE))
        {
            WANCHK_LOG_INFO("wanconnectivity_chk ActiveMonitor config changed\n");
            WANCHK_LOG_INFO("Interval:%ld->%ld,QueryRetry:%ld->%ld,QueryTimeout:%ld->%ld,RecordType:%s->%s,ServerType:%s->%s\n",
                            CurrentCfg.ActiveMonitorInterval,pIPInterface->ActiveMonitorInterval,
                            CurrentCfg.QueryRetry,pIPInterface->QueryRetry,
                            CurrentCfg.QueryTimeout,pIPInterface->QueryTimeout,
                            CurrentCfg.RecordType,pIPInterface->RecordType,
                            CurrentCfg.ServerType,pIPInterface->ServerType);
            returnStatus = wancnctvty_chk_stop_threads(pIPInterface->InstanceNumber,
                                                                        ACTIVE_MONITOR_THREAD);
            if (returnStatus != ANSC_STATUS_SUCCESS)
            {
                WANCHK_LOG_ERROR("%s:%d Unable to stop threads",__FUNCTION__,__LINE__);
                return ANSC_STATUS_FAILURE;
            }

        }

        /* Sleep 1 second to stop all the running threads */
        sleep(1);

        /* this will start active or passive monitor*/
        returnStatus = wancnctvty_chk_start_threads(pIPInterface->InstanceNumber,
                                                                PASSIVE_ACTIVE_MONITOR_THREADS);
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            WANCHK_LOG_ERROR("%s:%d Unable to start threads",__FUNCTION__,__LINE__);
            return ANSC_STATUS_FAILURE;
        }
    }
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************
    function:
        CosaWanCnctvtyChk_URL_ResetDBEntry
    description:
        This function is to reset the db entry for corresponding entry
    argument:
        PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO  pIPInterface
    return:
        TRUE if succeeded
        FALSE if failure
**********************************************************************/
ANSC_STATUS CosaWanCnctvtyChk_URL_delDBEntry (unsigned int InstanceNumber)
{
    char paramName[BUFLEN_128];
    int url_max_inst = 0;
    errno_t rc = -1;
    PSINGLE_LINK_ENTRY              pSListEntry       = NULL;
    PCOSA_CONTEXT_LINK_OBJECT       pCxtLink          = NULL;

    rc = sprintf_s(paramName,sizeof(paramName),"wanconnectivity_chk_url_%d",InstanceNumber);
    if (rc < EOK)
    {
        ERR_CHK(rc);
    }
    pthread_mutex_lock(&gUrlAccessMutex);
    pSListEntry = AnscSListGetLastEntry(&gpUrlList);
    if (pSListEntry)
    {
        pCxtLink = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSListEntry);
        if (pCxtLink)
        {
            url_max_inst = pCxtLink->InstanceNumber;
        }
    }
    pthread_mutex_unlock(&gUrlAccessMutex);

    syscfg_unset(NULL, paramName);

    /* reset the url max instance number*/
    if (syscfg_set_u_commit(NULL, "wanconnectivity_chk_maxurl_inst", (unsigned) url_max_inst) != 0)
    {
        WANCHK_LOG_WARN("%s: syscfg_set failed for url max inst %d\n", __FUNCTION__, url_max_inst);
    }

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************
    function:
        CosaWanCnctvtyChk_Intf_Commit
    description:
        This function is to commit the interface configs.
    argument:
        PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO  pIPInterface
    return:
        TRUE if succeeded
        FALSE if failure
**********************************************************************/
ANSC_STATUS CosaWanCnctvtyChk_URL_Commit (unsigned int InstanceNumber, const char *url)
{
    errno_t                         rc           = -1;
    char paramName[BUFLEN_128] = {0};
    char Current_URL[MAX_URL_SIZE] = {0};
    BOOL update_syscfg = TRUE;
    int ind = -1;
    char buf[BUFLEN_128] = {0};
    BOOL bFound = FALSE;
    int url_max_inst = 0;
    PSINGLE_LINK_ENTRY              pSListEntry       = NULL;
    PCOSA_CONTEXT_LINK_OBJECT       pCxtLink          = NULL;
    PCOSA_DML_WANCNCTVTY_CHK_URL_INFO pUrlInfo        = NULL;
    ANSC_STATUS returnStatus                          = ANSC_STATUS_SUCCESS;

    rc = sprintf_s(paramName,sizeof(paramName),"wanconnectivity_chk_url_%d",InstanceNumber);
    if (rc < EOK)
    {
        ERR_CHK(rc);
    }

    if ((syscfg_get( NULL, paramName, Current_URL, sizeof(Current_URL)) == 0 ) && (Current_URL[0] != '\0') )
    {
        rc = strcmp_s(url,strlen(url),Current_URL,&ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            /* we don't have an update,No need to update*/
            update_syscfg = FALSE;
            return ANSC_STATUS_SUCCESS;
        }
    }

    if (update_syscfg)
    {
        pthread_mutex_lock(&gUrlAccessMutex);
        pSListEntry           = AnscSListGetFirstEntry(&gpUrlList);
        while( pSListEntry != NULL)
        {
            pCxtLink          = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSListEntry);
            pSListEntry       = AnscSListGetNextEntry(pSListEntry);
            if (pCxtLink && (pCxtLink->InstanceNumber == InstanceNumber))
            {
                bFound = TRUE;
                break;
            }
        }
        if ( bFound == TRUE )
        {
            pUrlInfo = (PCOSA_DML_WANCNCTVTY_CHK_URL_INFO)pCxtLink->hContext;
            rc = strcpy_s(pUrlInfo->URL,MAX_URL_SIZE , url);
            ERR_CHK(rc);
        }
        else
        {
            WANCHK_LOG_ERROR("Global entry for InstanceNumber %d is NULL\n",InstanceNumber);
            pthread_mutex_unlock(&gUrlAccessMutex);
            return ANSC_STATUS_FAILURE;
        }
        pthread_mutex_unlock(&gUrlAccessMutex);
        if (syscfg_set(NULL, paramName, url) != 0)
        {
            WANCHK_LOG_WARN("%s: syscfg_set failed for %s\n", __FUNCTION__,pUrlInfo->URL);
            /* revert to Old value*/
            pthread_mutex_lock(&gUrlAccessMutex);
            rc = strcpy_s(pUrlInfo->URL,MAX_URL_SIZE , Current_URL);
            ERR_CHK(rc);
            pthread_mutex_unlock(&gUrlAccessMutex);
            return ANSC_STATUS_FAILURE;
        }

        pthread_mutex_lock(&gUrlAccessMutex);
        pSListEntry = AnscSListGetLastEntry(&gpUrlList);
        if (pSListEntry)
        {
            pCxtLink = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSListEntry);
            if (pCxtLink)
            {
                url_max_inst = pCxtLink->InstanceNumber;
            }
        }
        pthread_mutex_unlock(&gUrlAccessMutex);

        /* increase the url count*/
        rc = sprintf_s(buf,sizeof(buf),"%d",url_max_inst);
        if (rc < EOK)
        {
            ERR_CHK(rc);
        }

        if (syscfg_set(NULL, "wanconnectivity_chk_maxurl_inst", buf) != 0)
        {
            WANCHK_LOG_WARN("%s: syscfg_set failed for url count %s\n", __FUNCTION__,
                                                                            url);
        }

        if (syscfg_commit() != 0)
        {
           WANCHK_LOG_WARN("%s: syscfg commit failed for %s\n", __FUNCTION__,url);
           pthread_mutex_lock(&gUrlAccessMutex);
           rc = strcpy_s(pUrlInfo->URL,MAX_URL_SIZE , Current_URL);
           ERR_CHK(rc);
           pthread_mutex_unlock(&gUrlAccessMutex);
           return ANSC_STATUS_FAILURE;
        }

        unsigned int Instance = 1;
        WANCHK_LOG_INFO("%s: URL list updated,Restarting threads\n",__FUNCTION__);
        /* In progress QueryNow we can't do anything,restart active monitor if running*/
        PWANCNCTVTY_CHK_GLOBAL_INTF_INFO interface_list = gInterface_List;
        while (interface_list != NULL) {
          pthread_mutex_lock(&gIntfAccessMutex);
          Instance = interface_list->IPInterface.InstanceNumber;
          interface_list = interface_list->next;
          pthread_mutex_unlock(&gIntfAccessMutex);

          returnStatus = wancnctvty_chk_stop_threads(Instance,ACTIVE_MONITOR_THREAD);
          if (returnStatus != ANSC_STATUS_SUCCESS)
          {
              WANCHK_LOG_ERROR("%s:%d Unable to stop threads",__FUNCTION__,__LINE__);
              return ANSC_STATUS_FAILURE;
          }

          /* this will start active*/
          returnStatus = wancnctvty_chk_start_threads(Instance,ACTIVE_MONITOR_THREAD);
          if (returnStatus != ANSC_STATUS_SUCCESS)
          {
              WANCHK_LOG_ERROR("%s:%d Unable to start threads",__FUNCTION__,__LINE__);
              return ANSC_STATUS_FAILURE;
          }
        }
    }

    return ANSC_STATUS_SUCCESS;
}

