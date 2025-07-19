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

#include "plugin_main_apis.h"
#include "safec_lib_common.h"
#include "cosa_wanconnectivity_apis.h"
#include <rbus/rbus.h>
#include <syscfg/syscfg.h>
#include "secure_wrapper.h"


#ifdef GATEWAY_FAILOVER_SUPPORTED
static void eventReceiveHandler(
    rbusHandle_t handle,
    rbusEvent_t const* event,
    rbusEventSubscription_t* subscription);
#endif

rbusHandle_t rbus_handle  = NULL;
/* For registering and unregistering at run time, based on feature status, couldn't
able to do properly with single handle, introducing other handles, with single
handle, without rbus_close could see parameters still exists with rbus_unRegDataElements*/
rbusHandle_t rbus_table_handle  = NULL;
BOOL g_wanconnectivity_check_active = FALSE;
BOOL g_wanconnectivity_check_enable = TRUE;
BOOL g_wanconnectivity_check_start = FALSE;
SLIST_HEADER                  gpUrlList;
ULONG                         gulUrlNextInsNum = 1;
ULONG                         gIntfCount = 0;
USHORT                        g_last_sent_actv_txn_id_A;
USHORT                        g_last_sent_actv_txn_id_AAAA;
USHORT                        g_last_sent_actv_txn_id_A_bkp;
USHORT                        g_last_sent_actv_txn_id_AAAA_bkp;
int sysevent_fd_wanchk;
token_t sysevent_token_wanchk;
WANCNCTVTY_CHK_GLOBAL_INTF_INFO *gInterface_List = NULL;
pthread_mutex_t gIntfAccessMutex;
pthread_mutex_t gUrlAccessMutex;
pthread_mutex_t gDnsTxnIdAccessMutex;
pthread_mutex_t gDnsTxnIdBkpAccessMutex;

#ifdef GATEWAY_FAILOVER_SUPPORTED
const char* sub_activegwevent_param[] = {ACTIVE_GATEWAY_DML};
#endif

extern rbusError_t CosaWanCnctvtyChk_RbusInit(VOID);
extern rbusError_t CosaWanCnctvtyChk_Reg_elements(dml_type_t type);
extern rbusError_t CosaWanCnctvtyChk_UnReg_elements(dml_type_t type);
extern ANSC_STATUS wancnctvty_chk_start_threads(ULONG InstanceNumber,service_type_t type);
extern ANSC_STATUS wancnctvty_chk_stop_threads(ULONG InstanceNumber,service_type_t type);
extern ANSC_STATUS wancnctvty_chk_monitor_result_update(ULONG InstanceNumber,monitor_result_t result);
BOOL CosaWanCnctvtyChk_IsPrimary_Configured();

/*********************************************************************************
 * Function to process the feature enable flag change
   1. disabled -> enabled
      * set active status based on current HOST status
      * if host is active and primary, populate interface table
      *passive monitor config is enabled, start passive dns sniffer
      *continous query is enabled, start continous query thread
      *Note continous query result will supersede the passive
       monitor result
    * To Do check do we need passive monitor when continous query is
      enabled
      * if host is not active, set active status as false and exit
   2. Enabled -> disabled
      * stop passive monitor thread and free resources
      * stop continous query thread if running
      * update result object accordingly

*NOTE we are in the context of dmcli so make sure to run the actions in background
as thread and detachable
***********************************************************************************/ 

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaWanCnctvtyChkInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate wan connectivity check object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS CosaWanCnctvtyChk_Init (VOID)
{
    int rc = RBUS_ERROR_SUCCESS;

    sysevent_fd_wanchk = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT,
                      SE_VERSION, "wan_connectivity_check", &sysevent_token_wanchk);
    if (sysevent_fd_wanchk < 0)
    {
        WANCHK_LOG_ERROR("%s: sysevent int failed \n", __FUNCTION__);
        return ANSC_STATUS_FAILURE;
    }

    /* Rbus init*/
    rc = CosaWanCnctvtyChk_RbusInit();
    if(rc)
    {
        WANCHK_LOG_ERROR("RbusInit failure, reason = %d", rc);
        return ANSC_STATUS_FAILURE;
    }

    rc = CosaWanCnctvtyChk_Reg_elements(FEATURE_DML);
    if(rc)
    {
        WANCHK_LOG_ERROR("RbusDML feature Reg failure, reason = %d", rc);
        return ANSC_STATUS_FAILURE;
    }

    /* Initialize url list access mutex */
    pthread_mutexattr_t     mutex_attr_url;
    pthread_mutexattr_init(&mutex_attr_url);
    pthread_mutexattr_settype(&mutex_attr_url, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(gUrlAccessMutex), &(mutex_attr_url));
    pthread_mutexattr_destroy(&mutex_attr_url);

    /* Initialize interface list access mutex */
    pthread_mutexattr_t     mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(gIntfAccessMutex), &(mutex_attr));
    pthread_mutexattr_destroy(&mutex_attr);

    /* Initialize DNS txn id primary interface access mutex */
    pthread_mutexattr_t     mutex_attr_txn;
    pthread_mutexattr_init(&mutex_attr_txn);
    pthread_mutexattr_settype(&mutex_attr_txn, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(gDnsTxnIdAccessMutex), &(mutex_attr_txn));
    pthread_mutexattr_destroy(&mutex_attr_txn);

    /* Initialize DNS txn id backup interface access mutex */
    pthread_mutexattr_t     mutex_attr_txn_bkp;
    pthread_mutexattr_init(&mutex_attr_txn_bkp);
    pthread_mutexattr_settype(&mutex_attr_txn_bkp, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(gDnsTxnIdBkpAccessMutex), &(mutex_attr_txn_bkp));
    pthread_mutexattr_destroy(&mutex_attr_txn_bkp);

    pthread_mutex_lock(&gUrlAccessMutex);
    g_wanconnectivity_check_enable = TRUE;
    g_wanconnectivity_check_active = FALSE;
    AnscSListInitializeHeader(&gpUrlList);
    gulUrlNextInsNum          = 1;
    pthread_mutex_unlock(&gUrlAccessMutex);

    WANCHK_LOG_INFO("%s: Wan Connectivty Check Enable : %s\n", __FUNCTION__,
                            (g_wanconnectivity_check_enable == TRUE) ? "true" : "false");

    if (g_wanconnectivity_check_enable == TRUE)
    {
        rc = CosaWanCnctvtyChk_Reg_elements(FEATURE_ENABLED_DML);
        if(rc)
        {
            WANCHK_LOG_ERROR("RbusDML Enabled Reg failure, reason = %d", rc);
            return ANSC_STATUS_FAILURE;
        }

        g_wanconnectivity_check_active    = CosaWanCnctvtyChk_GetActive_Status();
        if (g_wanconnectivity_check_active == TRUE) {
            if (CosaWanCnctvtyChk_Init_URLTable () != ANSC_STATUS_SUCCESS)
            {
                WANCHK_LOG_ERROR("%s: URL Table Init failed\n",__FUNCTION__);
            }
        }
        CosaWanCnctvtyChk_SubscribeActiveGW();
    }

    return ANSC_STATUS_SUCCESS;
}

/* CosaWanCnctvtyChk_Init_URLTable

fetch the URL entries from the db, if we don't have any, make the default URL as
"www.google.com" proposed by architecture*/

ANSC_STATUS CosaWanCnctvtyChk_Init_URLTable (VOID)
{
    PCOSA_CONTEXT_LINK_OBJECT       pCosaContext    = (PCOSA_CONTEXT_LINK_OBJECT)NULL;
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_DML_WANCNCTVTY_CHK_URL_INFO pUrlInfo      = (PCOSA_DML_WANCNCTVTY_CHK_URL_INFO)NULL;
    errno_t rc = -1;
    int index = -1;
    int total_url_entries = 0;
    char buf[BUFLEN_8] = {0};
    BOOL use_default_url = FALSE;
    char *default_url = DEFAULT_URL;
    char paramName[BUFLEN_128] = {0};
    char URL_buf[MAX_URL_SIZE] = {0};
    int rbus_ret = RBUS_ERROR_SUCCESS;

    if (syscfg_get(NULL, "wanconnectivity_chk_maxurl_inst", buf, sizeof(buf)) == 0 && buf[0] != '\0')
    {
        total_url_entries = atoi(buf);
        WANCHK_LOG_INFO("%s: Wan Connectivty Check max url instance : %d\n", __FUNCTION__,
                                                                    total_url_entries);
    }
    else
    {
        total_url_entries = DEFAULT_URL_COUNT;
        use_default_url  = TRUE;
    }
    for (index=0; index < total_url_entries;index++)
    {
        if ( !pUrlInfo)
        {
            pUrlInfo = (PCOSA_DML_WANCNCTVTY_CHK_URL_INFO)
                                        AnscAllocateMemory(sizeof(COSA_DML_WANCNCTVTY_CHK_URL_INFO));
        }
        if ( !pUrlInfo)
        {
           return ANSC_STATUS_RESOURCES;
        }

        rc = sprintf_s(paramName,sizeof(paramName),"wanconnectivity_chk_url_%d",(index+1));
        if (rc < EOK)
        {
            ERR_CHK(rc);
        }

        if (syscfg_get(NULL, paramName, URL_buf, sizeof(URL_buf)) == 0 && URL_buf[0] != '\0')
        {
            rc = strcpy_s(pUrlInfo->URL,MAX_URL_SIZE , URL_buf);
            ERR_CHK(rc);
        }
        else if (use_default_url)
        {
            rc = strcpy_s(pUrlInfo->URL,MAX_URL_SIZE , default_url);
            ERR_CHK(rc);
        }
        else
        {
            /* A corner case,if we delete a row in this order, having rows 1,2,3 delete row 2.
            skip if we have empty entry, skip for now*/
            WANCHK_LOG_ERROR("URL entry is empty in DB for instance:%d\n",(index+1));
            pthread_mutex_lock(&gUrlAccessMutex);
            gulUrlNextInsNum++;
            pthread_mutex_unlock(&gUrlAccessMutex);
            continue;
        }

        pCosaContext = (PCOSA_CONTEXT_LINK_OBJECT)AnscAllocateMemory(sizeof(COSA_CONTEXT_LINK_OBJECT));

       if ( !pCosaContext )
       {
          returnStatus = ANSC_STATUS_RESOURCES;
          goto  EXIT;
       }

       pthread_mutex_lock(&gUrlAccessMutex);
       pCosaContext->InstanceNumber =  gulUrlNextInsNum;
       pUrlInfo->InstanceNumber = gulUrlNextInsNum; 
       gulUrlNextInsNum++;
       if (gulUrlNextInsNum == 0)
            gulUrlNextInsNum = 1;

       pCosaContext->hContext      = (ANSC_HANDLE)AnscAllocateMemory(sizeof(COSA_DML_WANCNCTVTY_CHK_URL_INFO));
       memcpy(pCosaContext->hContext, (ANSC_HANDLE)pUrlInfo, sizeof(COSA_DML_WANCNCTVTY_CHK_URL_INFO));
       pCosaContext->hParentTable  = NULL;
       pCosaContext->bNew          = TRUE;

       CosaSListPushEntryByInsNum(&gpUrlList, pCosaContext);
       rc = rbusTable_registerRow(rbus_table_handle,WANCHK_TEST_URL_TABLE ,pUrlInfo->InstanceNumber,
                                                                                            NULL);
       if(rbus_ret != RBUS_ERROR_SUCCESS)
       {
            WANCHK_LOG_ERROR("\n%s %d - URL Table (%s) Add failed, Error=%d \n", 
                                            __FUNCTION__, __LINE__,WANCHK_TEST_URL_TABLE,rbus_ret);
            pthread_mutex_unlock(&gUrlAccessMutex);
            returnStatus = ANSC_STATUS_FAILURE;
            goto EXIT;
       }
       else
       {
            WANCHK_LOG_INFO("\n%s %d - URL Table (%s) Added Successfully\n",
                                                __FUNCTION__, __LINE__, WANCHK_TEST_URL_TABLE );
       }
       pthread_mutex_unlock(&gUrlAccessMutex);
       AnscFreeMemory(pUrlInfo);
       pUrlInfo = (PCOSA_DML_WANCNCTVTY_CHK_URL_INFO)NULL;
    }
EXIT:
    if (pUrlInfo)
       AnscFreeMemory(pUrlInfo);
    return returnStatus;
}

/* CosaWanCnctvtyChk_Init_Intf

Initialize interface table and fetch the corresponding value from DB or assign to defaults*/

ANSC_STATUS CosaWanCnctvtyChk_Init_Intf (char* if_name, char* alias,
                                         char* IPv4_nameserver_list, char* IPv6_nameserver_list, 
                                         int IPv4DnsServerCount, int IPv6DnsServerCount,
                                         char* IPv4_Gateway, char* IPv6_Gateway)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    COSA_DML_WANCNCTVTY_CHK_INTF_INFO IPInterface;
    int rc = RBUS_ERROR_SUCCESS;

    memset(&IPInterface,0,sizeof(COSA_DML_WANCNCTVTY_CHK_INTF_INFO));

    pthread_mutex_lock(&gIntfAccessMutex);
    gIntfCount++;
    IPInterface.InstanceNumber = gIntfCount;
    pthread_mutex_unlock(&gIntfAccessMutex);

    rc = strcpy_s(IPInterface.InterfaceName, MAX_INTF_NAME_SIZE , if_name);
    ERR_CHK(rc);

    rc = strcpy_s(IPInterface.Alias, MAX_INTF_NAME_SIZE , alias);
    ERR_CHK(rc);

    rc = strcpy_s(IPInterface.IPv4Gateway, IPv4_STR_LEN, IPv4_Gateway);
    ERR_CHK(rc);

    rc = strcpy_s(IPInterface.IPv6Gateway, IPv6_STR_LEN , IPv6_Gateway);
    ERR_CHK(rc);

    if (CosaWanCnctvtyChk_IfGetEntry(&IPInterface) != ANSC_STATUS_SUCCESS)
    {
        WANCHK_LOG_ERROR("Unable to get interface config for instance %ld\n",
                                                                        IPInterface.InstanceNumber);
        return ANSC_STATUS_FAILURE;
    }
    if (CosaWanCnctvtyChk_DNS_UpdateEntry(if_name, alias, IPv4_nameserver_list,
                                          IPv6_nameserver_list, IPv4DnsServerCount,
                                          IPv6DnsServerCount) != ANSC_STATUS_SUCCESS)
    {
        WANCHK_LOG_ERROR("%s: DNS Update failed for interface: %s, alias: %s\n", __FUNCTION__, if_name, alias);
    }

    rc = rbusTable_registerRow(rbus_table_handle,WANCHK_INTF_TABLE,IPInterface.InstanceNumber,
                                                                                IPInterface.Alias);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        WANCHK_LOG_ERROR("%s %d - Interface(%ld) Table (%s) Registration failed, Error=%d \n", 
                                                __FUNCTION__, __LINE__,IPInterface.InstanceNumber,
                                                WANCHK_INTF_TABLE,rc);
        return ANSC_STATUS_FAILURE;
    }
    else
    {
         WANCHK_LOG_INFO("%s %d - Interface(%ld) Table (%s) Registration Successfully, AliasName(%s)\n",
                                                __FUNCTION__, __LINE__,IPInterface.InstanceNumber, 
                                                WANCHK_INTF_TABLE, IPInterface.Alias);
    }

    pthread_mutex_lock(&gIntfAccessMutex);
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = get_InterfaceList(IPInterface.InstanceNumber);
    gIntfInfo->IPInterface.Configured = TRUE;
    pthread_mutex_unlock(&gIntfAccessMutex);

    if (returnStatus == ANSC_STATUS_SUCCESS)
    {
        returnStatus = wancnctvty_chk_start_threads(IPInterface.InstanceNumber,ALL_THREADS);
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            WANCHK_LOG_ERROR("%s:%d Unable to start threads\n",__FUNCTION__,__LINE__);
            return ANSC_STATUS_FAILURE;
        }
    }
    CosaWanCnctvtyChk_Interface_dump(IPInterface.InstanceNumber);
    return returnStatus;
}

ANSC_STATUS CosaWanCnctvtyChk_IfGetEntry(PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO pIPInterface)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    /* Get stored config Values or use default values since we are in initialization*/
    CosaDmlGetIntfCfg(pIPInterface,TRUE);

    pIPInterface->MonitorResult         = MONITOR_RESULT_UNKNOWN;
    pIPInterface->QueryNow              = FALSE;
    pIPInterface->QueryNowResult        = QUERYNOW_RESULT_UNKNOWN;
    pIPInterface->Cfg_bitmask           = INTF_CFG_ALL;
    returnStatus = CosaDml_glblintfdb_updateentry(pIPInterface);
    if (returnStatus != ANSC_STATUS_SUCCESS)
    {
        WANCHK_LOG_ERROR("%s:Unable to update global db entry\n",__FUNCTION__);
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     self

    prototype:

        BOOL
        CosaWanCnctvtyChk_GetActive_Status
        (
         );

    description:

        This function will check whether host is active or not.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     operation status.

**********************************************************************/
BOOL CosaWanCnctvtyChk_GetActive_Status(void)
{

#ifdef GATEWAY_FAILOVER_SUPPORTED
   ANSC_STATUS ret = ANSC_STATUS_SUCCESS;
   char Value[128] = {0};
   errno_t      rc = -1;
   int ind         = -1;

   ret = WanCnctvtyChk_GetParameterValue(ACTIVE_GATEWAY_DML,Value);

   if (ret == ANSC_STATUS_SUCCESS)
   {
       if (Value[0] != '\0')
       {
           WANCHK_LOG_INFO("%s: Active Gateway Status : %s\n", __FUNCTION__,Value);
           rc = strcmp_s( "true",strlen("true"),Value, &ind);
           ERR_CHK(rc);
           if((!ind) && (rc == EOK))
           {
             return TRUE;
           }
       }
   }
   return FALSE;
#else
   return TRUE;
#endif

}

ANSC_STATUS CosaWanCnctvtyChk_SubscribeActiveGW(void)
{
#ifdef GATEWAY_FAILOVER_SUPPORTED
    int ret = RBUS_ERROR_SUCCESS;
    int iter=0;
    for(iter=0;iter<ARRAY_SZ(sub_activegwevent_param);iter++)
    {
       ret = rbusEvent_Subscribe(rbus_handle, sub_activegwevent_param[iter], eventReceiveHandler, NULL, 0);
       if(ret != RBUS_ERROR_SUCCESS)
       {
           WANCHK_LOG_ERROR("WanCnctvtyChkEventConsumer: rbusEvent_Subscribe failed for %s ret: %d\n",
                                                            sub_activegwevent_param[iter],ret);
           return ANSC_STATUS_FAILURE;
       }
    }
#endif
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS CosaWanCnctvtyChk_UnSubscribeActiveGW(void)
{
#ifdef GATEWAY_FAILOVER_SUPPORTED
    int ret = RBUS_ERROR_SUCCESS;
    int iter=0;
    for(iter=0;iter<ARRAY_SZ(sub_activegwevent_param);iter++)
    {
       ret = rbusEvent_Unsubscribe(rbus_handle, sub_activegwevent_param[iter]);
       if(ret != RBUS_ERROR_SUCCESS)
       {
           WANCHK_LOG_ERROR("WanCnctvtyChkEventConsumer: rbusEvent_Unsubscribe failed for %s ret: %d\n",
                                                            sub_activegwevent_param[iter],ret);
           return ANSC_STATUS_FAILURE;
       }
    }
#endif
    return ANSC_STATUS_SUCCESS;
}

#ifdef GATEWAY_FAILOVER_SUPPORTED
static void eventReceiveHandler(
    rbusHandle_t handle,
    rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;

    const char* eventName = event->name;
    rbusValue_t valBuff;
    BOOL New_Actv_Status = FALSE;
    valBuff = rbusObject_GetValue(event->data, NULL );
    if(!valBuff)
    {
        WANCHK_LOG_WARN("WanCnctvtyChkEventConsumer : FAILED, value is NULL\n");
    }
    else
    {
        if (strcmp(eventName,ACTIVE_GATEWAY_DML) == 0)
        {
           New_Actv_Status = rbusValue_GetBoolean(valBuff);
           WANCHK_LOG_WARN("WanCnctvtyChkEventConsumer : New value of ActiveGateway is = %d\n",
                                                                                New_Actv_Status);
           handle_actv_status_event (New_Actv_Status);
        }
    }
}
#endif

void handle_actv_status_event (BOOL new_status)
{
    if (g_wanconnectivity_check_active != new_status)
    {
       WANCHK_LOG_INFO("%s : New value of ActiveGateway is = %d\n",__FUNCTION__,new_status);
       if (new_status)
       {
          /* we are already in disabled state, no need to free any memory*/
          g_wanconnectivity_check_active = TRUE;
       }
       else
       {
        /* we are moving to disabled state, bring down all interfaces*/
        WANCHK_LOG_INFO("%s: Active Gateway is DOWN. Stopping Wan Connectivity Check on all interfaces\n", __FUNCTION__);
        g_wanconnectivity_check_active = FALSE;
        ULONG instNum = -1;
        PWANCNCTVTY_CHK_GLOBAL_INTF_INFO interface_list = gInterface_List;
        while (interface_list != NULL) {
          pthread_mutex_lock(&gIntfAccessMutex);
          instNum = interface_list->IPInterface.InstanceNumber;
          interface_list = interface_list->next;
          pthread_mutex_unlock(&gIntfAccessMutex);

          CosaWanCnctvtyChk_Remove_Intf(instNum);
        }
        // CosaWanCnctvtyChk_UnReg_elements(FEATURE_ENABLED_DML);
       }
    }
}

ANSC_STATUS CosaWanCnctvtyChk_Remove_Intf (ULONG IntfIndex)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    pthread_mutex_lock(&gIntfAccessMutex);
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = get_InterfaceList(IntfIndex);
    gIntfInfo->IPInterface.Enable = FALSE;

    //Reset MonitorResult during Stop Test
    wancnctvty_chk_monitor_result_update(IntfIndex, MONITOR_RESULT_UNKNOWN);

    if (gIntfInfo->IPInterface.Configured == FALSE)
    {
        WANCHK_LOG_INFO("Unconfigured Interface,No need of removal\n");
        pthread_mutex_unlock(&gIntfAccessMutex);
        return ANSC_STATUS_SUCCESS;
    }
    pthread_mutex_unlock(&gIntfAccessMutex);

    returnStatus = wancnctvty_chk_stop_threads(IntfIndex,ALL_THREADS);
    if (returnStatus != ANSC_STATUS_SUCCESS)
    {
        WANCHK_LOG_ERROR("%s:%d Unable to stop threads\n",__FUNCTION__,__LINE__);
        return ANSC_STATUS_FAILURE;
    }

    return returnStatus;
}

ANSC_STATUS CosaDmlGetIntfCfg(PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO pIPInterface,BOOL use_default)
{
    errno_t rc = -1;    

    /* set to defaults , override if config exists*/
    if (use_default)
    {
        pIPInterface->Enable  = DEF_INTF_ENABLE;

        pIPInterface->ActiveMonitor = DEF_ACTIVE_MONITOR_PRIMARY_ENABLE;
        pIPInterface->PassiveMonitor = DEF_PASSIVE_MONITOR_PRIMARY_ENABLE;

        pIPInterface->PassiveMonitorTimeout = DEF_PASSIVE_MONITOR_TIMEOUT;
        pIPInterface->ActiveMonitorInterval = DEF_ACTIVE_MONITOR_INTERVAL;
        pIPInterface->QueryTimeout = DEF_QUERY_TIMEOUT;
        pIPInterface->QueryRetry = DEF_QUERY_RETRY;
        rc = strcpy_s(pIPInterface->RecordType,MAX_RECORD_TYPE_SIZE , DEF_QUERY_RECORDTYPE);
        ERR_CHK(rc);
        rc = strcpy_s(pIPInterface->ServerType,MAX_SERVER_TYPE_SIZE , DEF_QUERY_SERVERTYPE);
        ERR_CHK(rc);
    }
    else {
        pthread_mutex_lock(&gIntfAccessMutex);
        PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = get_InterfaceList(pIPInterface->InstanceNumber);
        if (gIntfInfo == NULL) {
            WANCHK_LOG_DBG("%s: No interface with InstanceNumber: %d", __FUNCTION__, pIPInterface->InstanceNumber);
            pthread_mutex_unlock(&gIntfAccessMutex);
            return ANSC_STATUS_FAILURE;
        }
        pIPInterface->Enable = gIntfInfo->IPInterface.Enable;
        pIPInterface->ActiveMonitor = gIntfInfo->IPInterface.ActiveMonitor;
        pIPInterface->PassiveMonitor = gIntfInfo->IPInterface.PassiveMonitor;
        pIPInterface->PassiveMonitorTimeout = gIntfInfo->IPInterface.PassiveMonitorTimeout;
        pIPInterface->ActiveMonitorInterval = gIntfInfo->IPInterface.ActiveMonitorInterval;
        pIPInterface->QueryNow = gIntfInfo->IPInterface.QueryNow;
        pIPInterface->QueryTimeout = gIntfInfo->IPInterface.QueryTimeout;
        pIPInterface->QueryRetry = gIntfInfo->IPInterface.QueryRetry;
        rc = strcpy_s(pIPInterface->RecordType, MAX_RECORD_TYPE_SIZE , gIntfInfo->IPInterface.RecordType);
        ERR_CHK(rc);
        rc = strcpy_s(pIPInterface->ServerType, MAX_SERVER_TYPE_SIZE , gIntfInfo->IPInterface.ServerType);
        ERR_CHK(rc);
        pthread_mutex_unlock(&gIntfAccessMutex);
    }
    return ANSC_STATUS_SUCCESS;

}

ANSC_STATUS CosaDml_glblintfdb_delentry(ULONG InstanceNumber)
{
    pthread_mutex_lock(&gIntfAccessMutex);
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = get_InterfaceList(InstanceNumber);
    if (gIntfInfo &&  gIntfInfo->IPInterface.Configured)
    {
        if (gIntfInfo->IPv4DnsServerList)
        {
            free(gIntfInfo->IPv4DnsServerList);
            gIntfInfo->IPv4DnsServerList = NULL;
        }
        if (gIntfInfo->IPv6DnsServerList)
        {
            free(gIntfInfo->IPv6DnsServerList);
            gIntfInfo->IPv6DnsServerList = NULL;
        }
        memset(gIntfInfo, 0, sizeof(WANCNCTVTY_CHK_GLOBAL_INTF_INFO));
    }
    pthread_mutex_unlock(&gIntfAccessMutex);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS CosaDml_glblintfdb_updateentry(PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO pIPInterface)
{
    if (!pIPInterface)
    {
        WANCHK_LOG_ERROR("%s:%d Interface data is NULL",__FUNCTION__,__LINE__);
        return ANSC_STATUS_FAILURE;
    }

    uint32_t bitmask = pIPInterface->Cfg_bitmask;

    pthread_mutex_lock(&gIntfAccessMutex);
    ULONG InstanceNumber = pIPInterface->InstanceNumber;
    errno_t rc = -1;
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = create_InterfaceList(InstanceNumber);
    gIntfInfo->IPInterface.InstanceNumber = pIPInterface->InstanceNumber;
    if (bitmask & INTF_CFG_ENABLE)
    {
        gIntfInfo->IPInterface.Enable = pIPInterface->Enable;
    }
    memset(gIntfInfo->IPInterface.Alias,0,MAX_INTF_NAME_SIZE);
    rc = strcpy_s(gIntfInfo->IPInterface.Alias,MAX_INTF_NAME_SIZE , pIPInterface->Alias);
    ERR_CHK(rc);
    memset(gIntfInfo->IPInterface.InterfaceName,0,MAX_INTF_NAME_SIZE);
    rc = strcpy_s(gIntfInfo->IPInterface.InterfaceName,MAX_INTF_NAME_SIZE ,
                                                            pIPInterface->InterfaceName);
    ERR_CHK(rc);
    memset(gIntfInfo->IPInterface.IPv4Gateway, 0, IPv4_STR_LEN);
    rc = strcpy_s(gIntfInfo->IPInterface.IPv4Gateway, IPv4_STR_LEN, pIPInterface->IPv4Gateway);
    ERR_CHK(rc);
    memset(gIntfInfo->IPInterface.IPv6Gateway, 0, IPv6_STR_LEN);
    rc = strcpy_s(gIntfInfo->IPInterface.IPv6Gateway, IPv6_STR_LEN, pIPInterface->IPv6Gateway);
    ERR_CHK(rc);
    if (bitmask & INTF_CFG_PASSIVE_ENABLE)
    {
        gIntfInfo->IPInterface.PassiveMonitor = pIPInterface->PassiveMonitor;
    }

    if (bitmask & INTF_CFG_PASSIVE_TIMEOUT)
    {    
        gIntfInfo->IPInterface.PassiveMonitorTimeout = pIPInterface->PassiveMonitorTimeout;
    }
    if (bitmask & INTF_CFG_ACTIVE_ENABLE)
    {
        gIntfInfo->IPInterface.ActiveMonitor = pIPInterface->ActiveMonitor;
    }
    if (bitmask & INTF_CFG_ACTIVE_INTERVAL)
    {
        gIntfInfo->IPInterface.ActiveMonitorInterval = pIPInterface->ActiveMonitorInterval;
    }
    if (bitmask & INTF_CFG_QUERYNOW_ENABLE)
    {
        gIntfInfo->IPInterface.QueryNow = pIPInterface->QueryNow;
    }
    if (bitmask & INTF_CFG_QUERY_TIMEOUT)
    {
        gIntfInfo->IPInterface.QueryTimeout = pIPInterface->QueryTimeout;
    }
    if (bitmask & INTF_CFG_QUERY_RETRY)
    {
        gIntfInfo->IPInterface.QueryRetry = pIPInterface->QueryRetry;
    }
    if (bitmask & INTF_CFG_RECORDTYPE)
    {
        memset(gIntfInfo->IPInterface.RecordType,0,MAX_RECORD_TYPE_SIZE);
        rc = strcpy_s(gIntfInfo->IPInterface.RecordType,MAX_RECORD_TYPE_SIZE ,
                                                                    pIPInterface->RecordType);
        ERR_CHK(rc);
    }
    if (bitmask & INTF_CFG_SERVERTYPE)
    {
        memset(gIntfInfo->IPInterface.ServerType,0,MAX_SERVER_TYPE_SIZE);
        rc = strcpy_s(gIntfInfo->IPInterface.ServerType,MAX_SERVER_TYPE_SIZE ,
                                                                    pIPInterface->ServerType);
        ERR_CHK(rc);
    }
    pthread_mutex_unlock(&gIntfAccessMutex);
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS CosaDml_glblintfdb_update_dnsentry(char *InterfaceName, unsigned int IPv4DnsServerCount,
                                                unsigned int IPv6DnsServerCount,
                                                PCOSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO pIPv4DnsSrvInfo,
                                                PCOSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO pIPv6DnsSrvInfo)
{
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = NULL;
    if (!InterfaceName)
    {
        WANCHK_LOG_ERROR("%s:InterfaceName is NULL,Unable to update\n",__FUNCTION__);
        return ANSC_STATUS_FAILURE;
    }

    ULONG InstanceNumber = GetInstanceNo_FromName(InterfaceName);
    if (InstanceNumber == -1)
    {
        WANCHK_LOG_ERROR("%s:Unable to Find Matching Index for Interface %s\n",__FUNCTION__,InterfaceName);
        return ANSC_STATUS_FAILURE;
    }
    pthread_mutex_lock(&gIntfAccessMutex);
    gIntfInfo = get_InterfaceList(InstanceNumber);
    uint32_t Old_IPv4DnsServerCount = gIntfInfo->IPv4DnsServerCount;
    uint32_t Old_IPv6DnsServerCount = gIntfInfo->IPv6DnsServerCount;

    if (gIntfInfo->IPv4DnsServerCount && gIntfInfo->IPv4DnsServerList)
    {
        WANCHK_LOG_INFO("Free the older IPv4 dns server list\n");
        free(gIntfInfo->IPv4DnsServerList);
        gIntfInfo->IPv4DnsServerList = NULL;
        gIntfInfo->IPv4DnsServerCount = 0;
    }
    if (gIntfInfo->IPv6DnsServerCount && gIntfInfo->IPv6DnsServerList)
    {
        WANCHK_LOG_INFO("Free the older IPv6 dns server list\n");
        free(gIntfInfo->IPv6DnsServerList);
        gIntfInfo->IPv6DnsServerList = NULL;
        gIntfInfo->IPv6DnsServerCount = 0;
    }

    if (IPv4DnsServerCount)
    {
        gIntfInfo->IPv4DnsServerList = pIPv4DnsSrvInfo;
        gIntfInfo->IPv4DnsServerCount = IPv4DnsServerCount;
        WANCHK_LOG_INFO ("Updated IPv4DnsServerCount:%d->%d for interface %s\n",Old_IPv4DnsServerCount,
                                            IPv4DnsServerCount, gIntfInfo->IPInterface.InterfaceName);
    }
    if (IPv6DnsServerCount)
    {
        gIntfInfo->IPv6DnsServerList = pIPv6DnsSrvInfo;
        gIntfInfo->IPv6DnsServerCount = IPv6DnsServerCount;
        WANCHK_LOG_INFO ("Updated IPv6DnsServerCount:%d->%d for interface %s\n",Old_IPv6DnsServerCount,
                                            IPv6DnsServerCount, gIntfInfo->IPInterface.InterfaceName);
    }
    pthread_mutex_unlock(&gIntfAccessMutex);
    return ANSC_STATUS_SUCCESS;
}

ULONG GetInstanceNo_FromName(char *InterfaceName)
{
    int ind = -1;
    errno_t rc = -1;
    ULONG InstanceNumber = -1;
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = NULL;

    pthread_mutex_lock(&gIntfAccessMutex);
    gIntfInfo = gInterface_List;
    while (gIntfInfo != NULL) {
        rc = strcmp_s(InterfaceName,strlen(InterfaceName),gIntfInfo->IPInterface.InterfaceName, &ind);
        ERR_CHK(rc);
        if((!ind) && (rc == EOK)) {
            InstanceNumber = gIntfInfo->IPInterface.InstanceNumber;
            WANCHK_LOG_INFO("%s: Found InstanceNumber %d with InterfaceName: %s\n", __FUNCTION__, InstanceNumber, InterfaceName);
            pthread_mutex_unlock(&gIntfAccessMutex);
            return InstanceNumber;
        }
        gIntfInfo = gIntfInfo->next;
    }
    pthread_mutex_unlock(&gIntfAccessMutex);
    WANCHK_LOG_INFO("%s: No Interface with InterfaceName: %s\n", __FUNCTION__, InterfaceName);
    return -1;
}

ANSC_STATUS CosaDml_querynow_result_get(ULONG InstanceNumber,querynow_result_t *result)
{
    pthread_mutex_lock(&gIntfAccessMutex);
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = get_InterfaceList(InstanceNumber);
    *result = gIntfInfo->IPInterface.QueryNowResult;
    pthread_mutex_unlock(&gIntfAccessMutex);
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS CosaDml_monitor_result_get(ULONG InstanceNumber,monitor_result_t *result)
{
    pthread_mutex_lock(&gIntfAccessMutex);
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = get_InterfaceList(InstanceNumber);
    *result = gIntfInfo->IPInterface.MonitorResult;
    pthread_mutex_unlock(&gIntfAccessMutex);
    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS CosaWanCnctvtyChk_Urllist_dump (VOID)
{
    ANSC_STATUS returnStatus                          = ANSC_STATUS_SUCCESS;
    PSINGLE_LINK_ENTRY              pSListEntry       = NULL;
    PCOSA_CONTEXT_LINK_OBJECT       pCxtLink          = NULL;
    PCOSA_DML_WANCNCTVTY_CHK_URL_INFO pUrlInfo        = NULL;

    WANCHK_LOG_INFO("%s Dumping URL List\n",__FUNCTION__);

    pthread_mutex_lock(&gUrlAccessMutex);
    pSListEntry           = AnscSListGetFirstEntry(&gpUrlList);
    while( pSListEntry != NULL)
    {
        pCxtLink          = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSListEntry);
        pSListEntry       = AnscSListGetNextEntry(pSListEntry);
        pUrlInfo = (PCOSA_DML_WANCNCTVTY_CHK_URL_INFO)pCxtLink->hContext;
        if (pUrlInfo)
        {
            WANCHK_LOG_INFO("Found Instance Number %ld URL %s\n",
                                                    pCxtLink->InstanceNumber,
                                                    pUrlInfo->URL);
        }
    }
    pthread_mutex_unlock(&gUrlAccessMutex);
    return returnStatus;
}

ANSC_STATUS CosaWanCnctvtyChk_Interface_dump (ULONG InstanceNumber)
{
    pthread_mutex_lock(&gIntfAccessMutex);
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = get_InterfaceList(InstanceNumber);

    WANCHK_LOG_INFO("*******************Interface Config for Instance %ld************************\n",InstanceNumber);
    WANCHK_LOG_INFO("Enable                     : %s\n",gIntfInfo->IPInterface.Enable ? "true" : "false");
    WANCHK_LOG_INFO("Alias                      : %s\n",gIntfInfo->IPInterface.Alias);
    WANCHK_LOG_INFO("InterfaceName              : %s\n",gIntfInfo->IPInterface.InterfaceName);
    WANCHK_LOG_INFO("PassiveMonitor             : %s\n",gIntfInfo->IPInterface.PassiveMonitor ? "true" : "false");
    WANCHK_LOG_INFO("PassiveMonitor Timeout     : %ld\n",gIntfInfo->IPInterface.PassiveMonitorTimeout);
    WANCHK_LOG_INFO("ActiveMonitor              : %s\n",gIntfInfo->IPInterface.ActiveMonitor ? "true" : "false");
    WANCHK_LOG_INFO("ActiveMonitorInterval      : %ld\n",gIntfInfo->IPInterface.ActiveMonitorInterval);
    WANCHK_LOG_INFO("MonitorResult              : %ld\n",gIntfInfo->IPInterface.MonitorResult);
    WANCHK_LOG_INFO("QueryNow                   : %s\n",gIntfInfo->IPInterface.QueryNow ? "true" : "false");
    WANCHK_LOG_INFO("QueryNowResult             : %ld\n",gIntfInfo->IPInterface.QueryNowResult);
    WANCHK_LOG_INFO("QueryTimeout               : %ld\n",gIntfInfo->IPInterface.QueryTimeout);
    WANCHK_LOG_INFO("QueryRetry                 : %ld\n",gIntfInfo->IPInterface.QueryRetry);
    WANCHK_LOG_INFO("RecordType                 : %s\n",gIntfInfo->IPInterface.RecordType);
    WANCHK_LOG_INFO("ServerType                 : %s\n",gIntfInfo->IPInterface.ServerType);
    WANCHK_LOG_INFO ("IPv4DnsServerCount         : %d\n",gIntfInfo->IPv4DnsServerCount);
    WANCHK_LOG_INFO ("IPv6DnsServerCount         : %d\n",gIntfInfo->IPv6DnsServerCount);
    WANCHK_LOG_INFO ("QueryNowSubCount           : %d\n",gIntfInfo->IPInterface.QueryNowResult_SubsCount);
    WANCHK_LOG_INFO ("Conf updated               : %d\n",gIntfInfo->IPInterface.Configured);
    if (strlen(gIntfInfo->IPInterface.IPv4Gateway)) {
        WANCHK_LOG_INFO("IPv4 Gateway               : %s\n",gIntfInfo->IPInterface.IPv4Gateway);
    }
    if (strlen(gIntfInfo->IPInterface.IPv6Gateway)) {
        WANCHK_LOG_INFO("IPv6 Gateway               : %s\n",gIntfInfo->IPInterface.IPv6Gateway);
    }

    for (int i=0;i < gIntfInfo->IPv4DnsServerCount;i++)
    {
        WANCHK_LOG_INFO("IPv4 DNS_ENTRY_%d          : %s\n",(i+1),gIntfInfo->IPv4DnsServerList[i].IPv4Address);
    }
    for (int i=0;i < gIntfInfo->IPv6DnsServerCount;i++)
    {
        WANCHK_LOG_INFO("IPv6 DNS_ENTRY_%d          : %s\n",(i+1),gIntfInfo->IPv6DnsServerList[i].IPv6Address);
    }
    pthread_mutex_unlock(&gIntfAccessMutex);
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************
    function:
        is_valid_interface
    description:
        Checks whether the interface is valid or not
    argument:
        const char *if_name
    return:
        ANSC_STATUS
**********************************************************************/
ANSC_STATUS is_valid_interface(const char *if_name)
{
    char file_name[64] = {0};
    errno_t rc;

    rc = sprintf_s(file_name, sizeof(file_name), "/sys/class/net/%s", if_name);
    ERR_CHK(rc);
    if (rc < EOK)
        return ANSC_STATUS_FAILURE;

    if (0 == access(file_name, F_OK)) {
        return ANSC_STATUS_SUCCESS;
    }

    return ANSC_STATUS_FAILURE;
}

/**********************************************************************
    function:
        is_valid_aliasName
    description:
        Checks whether the alias is valid or not
    argument:
        const char *alias
    return:
        ANSC_STATUS
**********************************************************************/
ANSC_STATUS is_valid_aliasName(const char *alias)
{
   char buf[BUFLEN_128] = {0};
   int ret = 0;

   ret = WanCnctvtyChk_GetParameterValue(ALIAS_CHECK_DML, buf);

   if (ret == ANSC_STATUS_SUCCESS) {
       if (strlen(buf)) {
           WANCHK_LOG_INFO("Available Alias : %s, Alias Passed: %s\n", buf, alias);
           if (strstr(buf, alias)) {
               return ANSC_STATUS_SUCCESS;
           }
       }
   }

   return ANSC_STATUS_FAILURE;
}

/**********************************************************************
    function:
       validate_DNS_nameservers
    description:
       This function will validate the DNS nameservers
    argument:
       char* IPv4_nameserver_list
       char* IPv6_nameserver_list
       int* DnsServerCount
    return:
       ANSC_STATUS
 **********************************************************************/
ANSC_STATUS validate_DNS_nameservers (char* IPv4_nameserver_list, char* IPv6_nameserver_list, 
                                      int* IPv4DnsServerCount, int* IPv6DnsServerCount)
{
    struct in_addr ipv4;
    struct in6_addr ipv6;

    WANCHK_LOG_INFO("%s: Validating DNS Nameservers\n", __FUNCTION__);

    if (IPv4_nameserver_list != NULL) {
        char* ipv4_list = strdup(IPv4_nameserver_list);
        char *ipv4_nameserver = strtok(ipv4_list, ",");
        while (ipv4_nameserver != NULL) {
            if (inet_pton(AF_INET, ipv4_nameserver, &ipv4) != 1) {
                WANCHK_LOG_ERROR("Invalid IPv4 DNS server address: %s \n", ipv4_nameserver);
                free(ipv4_list);
                return ANSC_STATUS_FAILURE;
            }
            (*IPv4DnsServerCount)++;
            ipv4_nameserver = strtok(NULL, ",");
        }
        free(ipv4_list);
    }

    if (IPv6_nameserver_list != NULL) {
        char* ipv6_list = strdup(IPv6_nameserver_list);
        char *ipv6_nameserver = strtok(ipv6_list, ",");
        while (ipv6_nameserver != NULL) {
            if (inet_pton(AF_INET6, ipv6_nameserver, &ipv6) != 1) {
                WANCHK_LOG_ERROR("Invalid IPv6 DNS server address: %s \n", ipv6_nameserver);
                free(ipv6_list);
                return ANSC_STATUS_FAILURE;
            }
            (*IPv6DnsServerCount)++;
            ipv6_nameserver = strtok(NULL, ",");
        }
        free(ipv6_list);
    }

    if ( (IPv4_nameserver_list == NULL) || ((*IPv4DnsServerCount) == 0) ) {
        WANCHK_LOG_WARN("IPv4 DNS Servers are not provided\n");
    }

    if ( (IPv6_nameserver_list == NULL) || ((*IPv6DnsServerCount) == 0) ) {
        WANCHK_LOG_WARN("IPv6 DNS Servers are not provided\n");
    }

    if ((*IPv4DnsServerCount) > 4 || (*IPv6DnsServerCount) > 4) {
        WANCHK_LOG_ERROR("Maximum of only 4 IPv4/v6 DNS servers can be provided\n");
        return ANSC_STATUS_FAILURE;
    }

    return ANSC_STATUS_SUCCESS;
}

/*************************************************************************
    function:
        get_InterfaceList
    description:
        This function will retrieve interface list with given InstanceNumber
    argument:
        ULONG InstanceNumber
    return:
        PWANCNCTVTY_CHK_GLOBAL_INTF_INFO
    note:
        Caller of this function should hold lock for "gIntfAccessMutex"
*************************************************************************/
PWANCNCTVTY_CHK_GLOBAL_INTF_INFO get_InterfaceList (ULONG InstanceNumber) {
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO interface_list = gInterface_List;
    while (interface_list != NULL) {
           if (interface_list->IPInterface.InstanceNumber == InstanceNumber) {
               return interface_list;
           }
           interface_list = interface_list -> next;
    }

    WANCHK_LOG_ERROR("%s: No interface_list with InstanceNumber %ld\n", __FUNCTION__, InstanceNumber);
    return interface_list;
}

/*************************************************************************
    function:
        get_InterfaceFromAlias
    description:
        This function will retrieve interface list with given Alias
    argument:
        char* Alias
    return:
        PWANCNCTVTY_CHK_GLOBAL_INTF_INFO
    note:
        Caller of this function should hold lock for "gIntfAccessMutex"
*************************************************************************/
PWANCNCTVTY_CHK_GLOBAL_INTF_INFO get_InterfaceFromAlias (char* Alias) {
    int ind = -1;
    errno_t rc = -1;
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO interface_list = gInterface_List;
    while (interface_list != NULL) {
           rc = strcmp_s(Alias,strlen(Alias),interface_list->IPInterface.Alias, &ind);
           ERR_CHK(rc);
           if ((!ind) && (rc == EOK)) {
               WANCHK_LOG_DBG("%s: InstNum: %d, Alias: %s\n", __FUNCTION__, interface_list->IPInterface.InstanceNumber, Alias);
               return interface_list;
           }
           interface_list = interface_list -> next;
    }

    WANCHK_LOG_WARN("%s: No interface_list with Alias %s\n", __FUNCTION__, Alias);
    return interface_list;
}

/*************************************************************************
    function:
        create_InterfaceList
    description:
        This function will create/add new node to gInterface_List with
	given InstanceNumber
    argument:
        ULONG InstanceNumber
    return:
        PWANCNCTVTY_CHK_GLOBAL_INTF_INFO
    note:
        Caller of this function should hold lock for "gIntfAccessMutex"
*************************************************************************/
PWANCNCTVTY_CHK_GLOBAL_INTF_INFO create_InterfaceList (ULONG InstanceNumber) {
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO interface_list = get_InterfaceList(InstanceNumber);
    if (interface_list != NULL) {
        WANCHK_LOG_INFO("%s: Found interface with InstanceNumber %ld\n", __FUNCTION__, InstanceNumber);
        return interface_list;
    }
    if (gInterface_List == NULL) {
        gInterface_List = (WANCNCTVTY_CHK_GLOBAL_INTF_INFO*) malloc(sizeof(WANCNCTVTY_CHK_GLOBAL_INTF_INFO));
        if (!gInterface_List) {
            WANCHK_LOG_ERROR("%s:%d Unable to allocate memory\n",__FUNCTION__, __LINE__);
            return NULL;
        }
        memset(gInterface_List, 0, sizeof(WANCNCTVTY_CHK_GLOBAL_INTF_INFO));
        WANCHK_LOG_DBG("%s: Creating first element of gInterface_List with InstanceNumber %ld\n", __FUNCTION__, InstanceNumber);
        return gInterface_List;
    } else {
        interface_list = gInterface_List;
        while (interface_list->next != NULL) {
             interface_list = interface_list->next;
        }
        interface_list->next = (WANCNCTVTY_CHK_GLOBAL_INTF_INFO*) malloc(sizeof(WANCNCTVTY_CHK_GLOBAL_INTF_INFO));
        if (!interface_list->next) {
            WANCHK_LOG_ERROR("%s:%d Unable to allocate memory\n",__FUNCTION__, __LINE__);
            return NULL;
        }
        memset(interface_list->next, 0, sizeof(WANCNCTVTY_CHK_GLOBAL_INTF_INFO));
        WANCHK_LOG_DBG("%s: Adding new element in gInterface_List with InstanceNumber %ld\n", __FUNCTION__, InstanceNumber);
        return interface_list->next;
    }
    return NULL;
}

BOOL check_for_change_in_dns(char* alias, char* IPv4_nameserver_list, char* IPv6_nameserver_list, 
                             int newIPv4DnsCount, int newIPv6DnsCount) {
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = NULL;
    int dns_idx = 0;
    pthread_mutex_lock(&gIntfAccessMutex);
    gIntfInfo = get_InterfaceFromAlias(alias);

    if (gIntfInfo == NULL) {
        WANCHK_LOG_INFO("%s: No interface with Alias\n", __FUNCTION__ );
        pthread_mutex_unlock(&gIntfAccessMutex);
        return FALSE;
    }

    if ((gIntfInfo->IPv4DnsServerCount != newIPv4DnsCount) ||
        (gIntfInfo->IPv6DnsServerCount != newIPv6DnsCount)) {
        WANCHK_LOG_INFO("%s: DNS server count changed. Update DNS Server List\n", __FUNCTION__ );
        pthread_mutex_unlock(&gIntfAccessMutex);
        return TRUE;
    }

    if (IPv4_nameserver_list != NULL) {
        char* ipv4_list = strdup(IPv4_nameserver_list);
        char *ipv4_nameserver = strtok(ipv4_list, ",");
        while (ipv4_nameserver != NULL) {
            if (strcmp(ipv4_nameserver, gIntfInfo->IPv4DnsServerList[dns_idx].IPv4Address) != 0) {
                WANCHK_LOG_INFO("%s: ipv4 address changed. Update DNS list\n", __FUNCTION__);
                pthread_mutex_unlock(&gIntfAccessMutex);
                free(ipv4_list);
                return TRUE;
            }
            dns_idx++;
            ipv4_nameserver = strtok(NULL, ",");
        }
        free(ipv4_list);
    }

    dns_idx = 0;
    if (IPv6_nameserver_list != NULL) {
        char* ipv6_list = strdup(IPv6_nameserver_list);
        char *ipv6_nameserver = strtok(ipv6_list, ",");
        while (ipv6_nameserver != NULL) {
            if (strcmp(ipv6_nameserver, gIntfInfo->IPv6DnsServerList[dns_idx].IPv6Address) != 0) {
                WANCHK_LOG_INFO("%s: ipv6 address changed. Update DNS list\n", __FUNCTION__);
                pthread_mutex_unlock(&gIntfAccessMutex);
                free(ipv6_list);
                return TRUE;
            }
            dns_idx++;
            ipv6_nameserver = strtok(NULL, ",");
        }
        free(ipv6_list);
    }
    pthread_mutex_unlock(&gIntfAccessMutex);
    return FALSE;
}

ANSC_STATUS CosaWanCnctvtyChk_DNS_UpdateEntry(char *InterfaceName, char* alias, char *IPv4_nameserver_list,
                                              char *IPv6_nameserver_list, int IPv4DnsServerCount, int IPv6DnsServerCount) {
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    unsigned int dns_idx = 0;
    errno_t rc = -1;
    PCOSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO pIPv4DnsSrvInfo = (PCOSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO) NULL;
    PCOSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO pIPv6DnsSrvInfo = (PCOSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO) NULL;

    WANCHK_LOG_INFO("Updating DNS for Interface: %s, Alias: %s\n", InterfaceName, alias);

    // Allocate memory for pIPv4DnsSrvInfo and pIPv6DnsSrvInfo
    pIPv4DnsSrvInfo = (PCOSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO) malloc(IPv4DnsServerCount * sizeof(COSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO));
    if (pIPv4DnsSrvInfo == NULL) {
        WANCHK_LOG_ERROR("%s:%d Unable to allocate memory\n",__FUNCTION__,__LINE__);
        return ANSC_STATUS_FAILURE;
    }
    memset(pIPv4DnsSrvInfo, 0, IPv4DnsServerCount * sizeof(COSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO));

    pIPv6DnsSrvInfo = (PCOSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO) malloc(IPv6DnsServerCount * sizeof(COSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO));
    if (pIPv6DnsSrvInfo == NULL) {
        WANCHK_LOG_ERROR("%s:%d Unable to allocate memory\n",__FUNCTION__,__LINE__);
        AnscFreeMemory(pIPv4DnsSrvInfo);
        pIPv4DnsSrvInfo = NULL;
        return ANSC_STATUS_FAILURE;
    }
    memset(pIPv6DnsSrvInfo, 0, IPv6DnsServerCount * sizeof(COSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO));

    // Copying v4 and v6 nameservers to pIPv4DnsSrvInfo and pIPv6DnsSrvInfo
    if (IPv4_nameserver_list != NULL) {
        char* ipv4_list = strdup(IPv4_nameserver_list);
        char *ipv4_nameserver = strtok(ipv4_list, ",");
        while (ipv4_nameserver != NULL) {
            pIPv4DnsSrvInfo[dns_idx].dns_type = DNS_SRV_IPV4;
            memset(pIPv4DnsSrvInfo[dns_idx].IPv4Address, 0, IPv4_STR_LEN);
            rc = strcpy_s(pIPv4DnsSrvInfo[dns_idx].IPv4Address, IPv4_STR_LEN, ipv4_nameserver);
            ERR_CHK(rc);
            dns_idx++;
            ipv4_nameserver = strtok(NULL, ",");
        }
        free(ipv4_list);
    }

    dns_idx = 0;
    if (IPv6_nameserver_list != NULL) {
        char* ipv6_list = strdup(IPv6_nameserver_list);
        char *ipv6_nameserver = strtok(ipv6_list, ",");
        while (ipv6_nameserver != NULL) {
            pIPv6DnsSrvInfo[dns_idx].dns_type = DNS_SRV_IPV6;
            memset(pIPv6DnsSrvInfo[dns_idx].IPv6Address, 0, IPv6_STR_LEN);
            rc = strcpy_s(pIPv6DnsSrvInfo[dns_idx].IPv6Address, IPv6_STR_LEN, ipv6_nameserver);
            ERR_CHK(rc);
            dns_idx++;
            ipv6_nameserver = strtok(NULL, ",");
        }
        free(ipv6_list);
    } 

    //Update DNS list to global DB
    returnStatus = CosaDml_glblintfdb_update_dnsentry(InterfaceName, IPv4DnsServerCount, IPv6DnsServerCount,
                                                      pIPv4DnsSrvInfo, pIPv6DnsSrvInfo);
    if (returnStatus != ANSC_STATUS_SUCCESS)
    {
       WANCHK_LOG_WARN("%s:%d Unable to update global db dns entry\n", __FUNCTION__, __LINE__);
    }

    if (returnStatus!= ANSC_STATUS_SUCCESS && pIPv4DnsSrvInfo)
    {
       AnscFreeMemory(pIPv4DnsSrvInfo);
       pIPv4DnsSrvInfo = NULL;
    }
    if (returnStatus!= ANSC_STATUS_SUCCESS && pIPv6DnsSrvInfo)
    {
       AnscFreeMemory(pIPv6DnsSrvInfo);
       pIPv6DnsSrvInfo = NULL;
    }

    return returnStatus;
}
