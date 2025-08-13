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


#include "safec_lib_common.h"
#include "cosa_wanconnectivity_rbus_apis.h"
#include "cosa_wanconnectivity_rbus_handler_apis.h"
#include "msgpack.h"
#include "ansc_platform.h"
#include "webconfig_framework.h"
#include <syscfg/syscfg.h>
#define WANCHK_WEBCONFIG_SUBDOC_NAME "startconnectivity"
#define SUBDOC_COUNT 1


extern rbusHandle_t rbus_handle;
extern rbusHandle_t rbus_table_handle;
extern BOOL g_wanconnectivity_check_active;
extern BOOL g_wanconnectivity_check_enable;
extern BOOL g_wanconnectivity_check_start;
extern pthread_mutex_t gIntfAccessMutex;
extern pthread_mutex_t gUrlAccessMutex;
extern ULONG   gulUrlNextInsNum;
extern ULONG   gIntfCount;
extern SLIST_HEADER    gpUrlList;
extern WANCNCTVTY_CHK_GLOBAL_INTF_INFO *gInterface_List;
extern ANSC_STATUS wancnctvty_chk_start_threads(ULONG InstanceNumber,service_type_t type);
extern ANSC_STATUS wancnctvty_chk_stop_threads(ULONG InstanceNumber,service_type_t type);
extern PWANCNCTVTY_CHK_GLOBAL_INTF_INFO get_InterfaceFromAlias(char *Alias);


typedef struct _wanchkparam_t
{
    char *linux_interface_name;
    char *alias;
    char *IPv4_DNS_Servers;
    char *IPv6_DNS_Servers;
    char *IPv4_Gateway;
    char *IPv6_Gateway;
} wanchkparam_t;

typedef struct _wanchkdoc_t
{
    char *subdoc_name;
    uint32_t version;
    uint32_t transaction_id;
    wanchkparam_t *param;
} wanchkdoc_t;

/**********************************************************************
    function:
        WANCNCTVTYCHK_GetHandler
    description:
        This Handler function is to get Value from the table
    argument:
        rbusHandle_t   handle
        rbusProperty_t   property
        rbusGetHandlerOptions_t opts
    return:
        rbusError_t
**********************************************************************/
rbusError_t WANCNCTVTYCHK_GetHandler(rbusHandle_t handle, rbusProperty_t property,
                                                        rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    rbusValue_t value;
    char const* name;
    rbusValue_Init(&value);
    name = rbusProperty_GetName(property);

    WANCHK_LOG_DBG("Get Request for %s\n",name);

    if(strcmp(name, "Device.Diagnostics.X_RDK_DNSInternet.Enable") == 0)
    {
        rbusValue_SetBoolean(value, (g_wanconnectivity_check_enable == TRUE) ? true : false);
    }
    else if(strcmp(name, "Device.Diagnostics.X_RDK_DNSInternet.Active") == 0)
    {
        if (g_wanconnectivity_check_enable == TRUE)
        {
            rbusValue_SetBoolean(value, (g_wanconnectivity_check_active == TRUE) ? true : false);
        }
    }
    else
    {
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;

}

/**********************************************************************
    function:
        WANCNCTVTYCHK_GetHandler
    description:
        This Handler function is to get Value from the table
    argument:
        rbusHandle_t   handle
        rbusProperty_t   property
        rbusGetHandlerOptions_t opts
    return:
        rbusError_t
**********************************************************************/
rbusError_t WANCNCTVTYCHK_GetURLHandler(rbusHandle_t handle, rbusProperty_t property,
                                                        rbusGetHandlerOptions_t* opts)
{
    char const* name;
    int ret = 0;
    errno_t rc = -1;
    unsigned int instNum =0;
    char Param[BUFLEN_128] = {0};
    rbusValue_t value;
    BOOL bFound = FALSE;

    rbusValue_Init(&value);

    name = rbusProperty_GetName(property);

    WANCHK_LOG_DBG("get handler with names %s\n",name);
    if (strstr(name,"Device.Diagnostics.X_RDK_DNSInternet.TestURL."))
    {
        ret = sscanf(name, "Device.Diagnostics.X_RDK_DNSInternet.TestURL.%d.%127s", &instNum,
                                                                                   Param);
        if ((ret == 2) && (instNum > 0) && (strcmp(Param, "URL") == 0))
        {
            PSINGLE_LINK_ENTRY              pSListEntry       = NULL;
            PCOSA_CONTEXT_LINK_OBJECT       pCxtLink          = NULL;
            PCOSA_DML_WANCNCTVTY_CHK_URL_INFO pUrlInfo        = NULL;

            pthread_mutex_lock(&gUrlAccessMutex);
            pSListEntry           = AnscSListGetFirstEntry(&gpUrlList);
            while( pSListEntry != NULL)
            {
                pCxtLink          = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSListEntry);
                pSListEntry       = AnscSListGetNextEntry(pSListEntry);
                if (pCxtLink && (pCxtLink->InstanceNumber == instNum))
                {
                    bFound = TRUE;
                    break;
                }
            }
            if ( bFound == TRUE)
            {
                pUrlInfo = (PCOSA_DML_WANCNCTVTY_CHK_URL_INFO)pCxtLink->hContext;
                rbusValue_SetString(value, pUrlInfo->URL);
                ERR_CHK(rc);
            }
            else
            {
                WANCHK_LOG_INFO("Couldn't find corresponding URL entry for InstanceNumber %d\n",
                                                                                        instNum);
                pthread_mutex_unlock(&gUrlAccessMutex);
                rbusValue_Release(value); 
                return RBUS_ERROR_BUS_ERROR;
            }
            pthread_mutex_unlock(&gUrlAccessMutex);
        }
        else
        {
            rbusValue_Release(value);
            return RBUS_ERROR_INVALID_INPUT;
        }
    }
    else if (strcmp(name, "Device.Diagnostics.X_RDK_DNSInternet.TestURLNumberOfEntries") == 0)
    {
        int total_url_entries = 0;
        pthread_mutex_lock(&gUrlAccessMutex);
        total_url_entries     = AnscSListQueryDepth(&gpUrlList);
        pthread_mutex_unlock(&gUrlAccessMutex);

        rbusValue_SetUInt32(value, total_url_entries);
    }
    else
    {
        rbusValue_Release(value);
        return RBUS_ERROR_INVALID_INPUT;
    }
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return RBUS_ERROR_SUCCESS;
}
/**********************************************************************
    function:
        WANCNCTVTYCHK_GetIntfHandler
    description:
        This Handler function is to get Value from the table
    argument:
        rbusHandle_t   handle
        rbusProperty_t   property
        rbusGetHandlerOptions_t opts
    return:
        rbusError_t
**********************************************************************/
rbusError_t WANCNCTVTYCHK_GetIntfHandler(rbusHandle_t handle, rbusProperty_t property,
                                                        rbusGetHandlerOptions_t* opts)
{
    char const* name;
    int aliasRet = 0, instRet = 0;
    unsigned int instNum = 0;
    char Param[BUFLEN_128] = {0};
    char alias[BUFLEN_128] = {0};
    rbusValue_t value;
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = NULL;

    rbusValue_Init(&value);

    name = rbusProperty_GetName(property);
    WANCHK_LOG_DBG("Inside get handler with names %s\n",name);
    if(strstr(name,"Device.Diagnostics.X_RDK_DNSInternet.WANInterface."))
    {
        pthread_mutex_lock(&gIntfAccessMutex);
        aliasRet = sscanf(name, "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.[%[^]]].%127s", alias, Param);
        if (aliasRet == 2) {
            WANCHK_LOG_DBG("%s: Name:%s, alias: %s, ret: %d\n", __FUNCTION__, name, alias, aliasRet);
            gIntfInfo = get_InterfaceFromAlias(alias);
        }

        instRet = sscanf(name, "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.%d.%127s", &instNum, Param);
        if (instRet == 2) {
            WANCHK_LOG_DBG("%s: Name:%s, instNum: %d, ret: %d\n", __FUNCTION__, name, instNum, instRet);
            gIntfInfo = get_InterfaceList(instNum);
        }

        if (gIntfInfo)
        {
            if (strcmp(Param, "Enable") == 0)
            {
                rbusValue_SetBoolean(value, gIntfInfo->IPInterface.Enable);
            }
            else if (strcmp(Param, "PassiveMonitor") == 0)
            {
               rbusValue_SetBoolean(value, gIntfInfo->IPInterface.PassiveMonitor);
            }
            else if (strcmp(Param, "ActiveMonitor") == 0)
            {
               rbusValue_SetBoolean(value, gIntfInfo->IPInterface.ActiveMonitor);
            }
            else if (strcmp(Param, "QueryNow") == 0)
            {
               rbusValue_SetBoolean(value, gIntfInfo->IPInterface.QueryNow);
            }
            else if (strcmp(Param, "PassiveMonitorTimeout") == 0)
            {
                rbusValue_SetUInt32(value, gIntfInfo->IPInterface.PassiveMonitorTimeout);
            }
            else if (strcmp(Param, "ActiveMonitorInterval") == 0)
            {
                rbusValue_SetUInt32(value, gIntfInfo->IPInterface.ActiveMonitorInterval);
            }
            else if (strcmp(Param, "MonitorResult") == 0)
            {
                rbusValue_SetUInt32(value, gIntfInfo->IPInterface.MonitorResult);
            }
            else if (strcmp(Param, "QueryNowResult") == 0)
            {
                rbusValue_SetUInt32(value, gIntfInfo->IPInterface.QueryNowResult);
            }
            else if (strcmp(Param, "QueryTimeout") == 0)
            {
                rbusValue_SetUInt32(value, gIntfInfo->IPInterface.QueryTimeout);
            }
            else if (strcmp(Param, "QueryRetry") == 0)
            {
                rbusValue_SetUInt32(value, gIntfInfo->IPInterface.QueryRetry);
            }
            else if (strcmp(Param, "Alias") == 0)
            {
                rbusValue_SetString(value, gIntfInfo->IPInterface.Alias);
            }
            else if (strcmp(Param, "InterfaceName") == 0)
            {
                rbusValue_SetString(value, gIntfInfo->IPInterface.InterfaceName);
            }
            else if (strcmp(Param, "RecordType") == 0)
            {
                rbusValue_SetString(value, gIntfInfo->IPInterface.RecordType);
            }
            else if (strcmp(Param, "ServerType") == 0)
            {
                rbusValue_SetString(value, gIntfInfo->IPInterface.ServerType);
            }
            else
            {
                pthread_mutex_unlock(&gIntfAccessMutex);
                rbusValue_Release(value);
                return RBUS_ERROR_INVALID_INPUT;

            }
            pthread_mutex_unlock(&gIntfAccessMutex);
        }
        else
        {
            rbusValue_Release(value);
            pthread_mutex_unlock(&gIntfAccessMutex);
            return RBUS_ERROR_INVALID_INPUT;
        }
    }
    else if (strcmp(name, "Device.Diagnostics.X_RDK_DNSInternet.WANInterfaceNumberOfEntries") == 0)
    {
        ULONG total_intf_entries = 0;
        pthread_mutex_lock(&gIntfAccessMutex);
        total_intf_entries     = gIntfCount;
        pthread_mutex_unlock(&gIntfAccessMutex);

        rbusValue_SetUInt32(value, total_intf_entries);
    }
    else
    {
        return RBUS_ERROR_INVALID_INPUT;
    }
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        WTC_TableUlongSetHandler
    description:
        This Handler function is to set Ulong Value to the table
    argument:
        rbusHandle_t                handle
        rbusProperty_t              property
        rbusGetHandlerOptions_t     opts
    return:
        rbusError_t
**********************************************************************/
rbusError_t WANCNCTVTYCHK_SetHandler(rbusHandle_t handle, rbusProperty_t prop,
                                                            rbusSetHandlerOptions_t* opts)
{
    (void)opts;
    int rc = RBUS_ERROR_SUCCESS;
    int index = 1;
    BOOL newValue;
    char const* name = rbusProperty_GetName(prop);
    rbusValue_t value = rbusProperty_GetValue(prop);
    rbusValueType_t type = rbusValue_GetType(value);

    if(strcmp(name, "Device.Diagnostics.X_RDK_DNSInternet.Enable") == 0)
    {
        if (type != RBUS_BOOLEAN)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        newValue = rbusValue_GetBoolean(value);

        if (newValue != g_wanconnectivity_check_enable) {
            g_wanconnectivity_check_enable = newValue;
            if (g_wanconnectivity_check_enable == FALSE) {
                rc = CosaWanCnctvtyChk_UnReg_elements(FEATURE_ENABLED_DML);
                if(rc)
                {
                    WANCHK_LOG_ERROR("RbusDML Enabled UnReg failure, reason = %d", rc);
                    return RBUS_ERROR_BUS_ERROR;
                }
                while(index <= gIntfCount) {
                    CosaWanCnctvtyChk_Remove_Intf(index);
                    CosaDml_glblintfdb_delentry(index);
                    index++;
                }
                gIntfCount = 0;
            }
            else {
                rc = CosaWanCnctvtyChk_Reg_elements(FEATURE_ENABLED_DML);
                if(rc)
                {
                   WANCHK_LOG_ERROR("RbusDML Enabled Reg failure, reason = %d", rc);
                   return RBUS_ERROR_BUS_ERROR;
                }
            }
        }
    }
    else
    {
        return RBUS_ERROR_INVALID_INPUT;
    }
    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        WANCNCTVTYCHK_SetURLHandler
    description:
        This Handler function is to set Ulong Value to the table
    argument:
        rbusHandle_t                handle
        rbusProperty_t              property
        rbusGetHandlerOptions_t     opts
    return:
        rbusError_t
**********************************************************************/
rbusError_t WANCNCTVTYCHK_SetURLHandler(rbusHandle_t handle, rbusProperty_t prop,
                                                        rbusSetHandlerOptions_t* opts)
{
    (void)opts;
    unsigned int instNum = 0;
    char Param[BUFLEN_128] ={0};
    char const* name = rbusProperty_GetName(prop);
    rbusValue_t value = rbusProperty_GetValue(prop);
    rbusValueType_t type = rbusValue_GetType(value);
    int ret = 0;

    if (strstr(name,"Device.Diagnostics.X_RDK_DNSInternet.TestURL."))
    {
        ret = sscanf(name, "Device.Diagnostics.X_RDK_DNSInternet.TestURL.%d.%127s", &instNum,
                                                                                    Param);
        if ((ret == 2) && (instNum > 0) && (strcmp(Param, "URL") == 0))
        {
            WANCHK_LOG_DBG("PropName = %s, param = %s, instnum = %d, ret = %d\n",
                               name, Param, instNum, ret);
            const char *URL = rbusValue_GetString(value, NULL);
            if (type != RBUS_STRING || URL == NULL || strlen(URL) <= 0)
            {
                return RBUS_ERROR_INVALID_INPUT;
            }
            if (CosaWanCnctvtyChk_URL_Commit(instNum,URL) != ANSC_STATUS_SUCCESS)
            {
                WANCHK_LOG_ERROR("%s: Interface commit failed\n",__FUNCTION__);
                return RBUS_ERROR_BUS_ERROR;
            }
        }
        else
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
    }
    else
    {
        return RBUS_ERROR_INVALID_INPUT;
    }
    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        WANCNCTVTYCHK_SetIntfHandler
    description:
        This Handler function is to set Ulong Value to the table
    argument:
        rbusHandle_t                handle
        rbusProperty_t              property
        rbusGetHandlerOptions_t     opts
    return:
        rbusError_t
**********************************************************************/
rbusError_t WANCNCTVTYCHK_SetIntfHandler(rbusHandle_t handle, rbusProperty_t prop,
                                                        rbusSetHandlerOptions_t* opts)
{
    (void)opts;
    unsigned int instNum = 0;
    char Param[BUFLEN_128] ={0};
    char alias[BUFLEN_128] ={0};
    char const* name = rbusProperty_GetName(prop);
    rbusValue_t value = rbusProperty_GetValue(prop);
    rbusValueType_t type = rbusValue_GetType(value);
    errno_t rc = -1;
    int aliasRet = 0, instRet = 0;
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = NULL;

    if(strstr(name,"Device.Diagnostics.X_RDK_DNSInternet.WANInterface."))
    {
        pthread_mutex_lock(&gIntfAccessMutex);
        aliasRet = sscanf(name, "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.[%[^]]].%127s", alias, Param);
        if (aliasRet == 2) {
            WANCHK_LOG_DBG("%s: Name:%s, alias: %s, ret: %d\n", __FUNCTION__, name, alias, aliasRet);
            gIntfInfo = get_InterfaceFromAlias(alias);
        }

        instRet = sscanf(name, "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.%d.%127s", &instNum, Param);
        if (instRet == 2) {
            WANCHK_LOG_DBG("%s: Name:%s, instNum: %d, ret: %d\n", __FUNCTION__, name, instNum, instRet);
            gIntfInfo = get_InterfaceList(instNum);
        }

        if (gIntfInfo)
        {
            COSA_DML_WANCNCTVTY_CHK_INTF_INFO IPInterface;
            memset(&IPInterface,0,sizeof(COSA_DML_WANCNCTVTY_CHK_INTF_INFO));
            IPInterface = gIntfInfo->IPInterface;
            pthread_mutex_unlock(&gIntfAccessMutex);

            IPInterface.Cfg_bitmask = 0;

            if (type == RBUS_BOOLEAN)
            {
                if (strcmp(Param, "Enable") == 0)
                {
                    BOOL enable_status = rbusValue_GetBoolean(value);
                    if (IPInterface.Enable != enable_status)
                    {
                        IPInterface.Enable = enable_status;
                        IPInterface.Cfg_bitmask |= INTF_CFG_ENABLE;
                    }
                }
                if (strcmp(Param, "PassiveMonitor") == 0)
                {
                    BOOL enable_status = rbusValue_GetBoolean(value);
                    if (IPInterface.PassiveMonitor != enable_status)
                    {
                        IPInterface.PassiveMonitor = enable_status;
                        IPInterface.Cfg_bitmask |= INTF_CFG_PASSIVE_ENABLE;
                    }
                }

                if (strcmp(Param, "ActiveMonitor") == 0)
                {
                    BOOL enable_status = rbusValue_GetBoolean(value);
                    if (IPInterface.ActiveMonitor != enable_status)
                    {
                        IPInterface.ActiveMonitor = enable_status;
                        IPInterface.Cfg_bitmask |= INTF_CFG_ACTIVE_ENABLE;
                    }
                }
                if (strcmp(Param, "QueryNow") == 0)
                {
                    IPInterface.QueryNow = rbusValue_GetBoolean(value);
                    IPInterface.Cfg_bitmask |= INTF_CFG_QUERYNOW_ENABLE;
                }
            }
            if (type == RBUS_UINT32)
            {
                if (strcmp(Param, "PassiveMonitorTimeout") == 0)
                {
                    uint32_t input = rbusValue_GetUInt32(value);
                    if (input < 11000)
                    {
                        WANCHK_LOG_ERROR("%s: PassiveMonitorTimeout not valid. Value should be greater than 11 seconds\n", __FUNCTION__);
                        return RBUS_ERROR_INVALID_INPUT;
                    }
                    if (IPInterface.PassiveMonitorTimeout != input)
                    {
                        IPInterface.PassiveMonitorTimeout =  input;
                        IPInterface.Cfg_bitmask |= INTF_CFG_PASSIVE_TIMEOUT;
                    }
                }
                
                if (strcmp(Param, "ActiveMonitorInterval") == 0)
                {
                    uint32_t input = rbusValue_GetUInt32(value);
                    if (input < 11000)
                    {
                        WANCHK_LOG_ERROR("%s: ActiveMonitorInterval not valid. Value should be greater than 11 seconds\n", __FUNCTION__);
                        return RBUS_ERROR_INVALID_INPUT;
                    }
                    if (IPInterface.ActiveMonitorInterval != input)
                    {
                        IPInterface.ActiveMonitorInterval =  input;
                        IPInterface.Cfg_bitmask |= INTF_CFG_ACTIVE_INTERVAL;
                    }
                }
                
                if (strcmp(Param, "QueryTimeout") == 0)
                {
                    uint32_t input = rbusValue_GetUInt32(value);
                    if (IPInterface.QueryTimeout != input)
                    {
                        IPInterface.QueryTimeout =  input;
                        IPInterface.Cfg_bitmask |= INTF_CFG_QUERY_TIMEOUT;
                    }
                }
                
                if (strcmp(Param, "QueryRetry") == 0)
                {
                    uint32_t input = rbusValue_GetUInt32(value);
                    if (IPInterface.QueryRetry != input)
                    {
                        IPInterface.QueryRetry =  input;
                        IPInterface.Cfg_bitmask |= INTF_CFG_QUERY_RETRY;
                    }
                }
            }
            if (type == RBUS_STRING)
            {
                if (strcmp(Param, "RecordType") == 0)
                {
                    const char *record_type = rbusValue_GetString(value, NULL);
                    if (type != RBUS_STRING || record_type == NULL || strlen(record_type) <= 0 ||
                        strlen(record_type) > 6 ||
                            (strcmp(record_type, "A") &&
                             strcmp(record_type, "AAAA") &&
                             strcmp(record_type, "A+AAAA") &&
                             strcmp(record_type, "A*AAAA")
                            )
                       )
                    {
                        WANCHK_LOG_ERROR("%s: RecordType not valid\n", __FUNCTION__);
                        return RBUS_ERROR_INVALID_INPUT;
                    }
                    if (strcmp(IPInterface.RecordType,record_type))
                    {
                        memset(IPInterface.RecordType,0,MAX_RECORD_TYPE_SIZE);
                        rc = strcpy_s(IPInterface.RecordType,MAX_RECORD_TYPE_SIZE ,record_type);
                        ERR_CHK(rc);
                        IPInterface.Cfg_bitmask |= INTF_CFG_RECORDTYPE;
                    }
                }

                if (strcmp(Param, "ServerType") == 0)
                {
                    const char *server_type = rbusValue_GetString(value, NULL);
                    if (type != RBUS_STRING || server_type == NULL || strlen(server_type) <= 0 ||
                        strlen(server_type) > 9 ||
                            (strcmp(server_type, "IPv4") &&
                             strcmp(server_type, "IPv6") &&
                             strcmp(server_type, "IPv4+IPv6") &&
                             strcmp(server_type, "IPv4*IPv6")
                            )
                       )
                    {
                        WANCHK_LOG_ERROR("%s: ServerType not valid\n", __FUNCTION__);
                        return RBUS_ERROR_INVALID_INPUT;
                    }
                    if (strcmp(IPInterface.ServerType,server_type))
                    {
                        memset(IPInterface.ServerType,0,MAX_SERVER_TYPE_SIZE);
                        rc = strcpy_s(IPInterface.ServerType,MAX_SERVER_TYPE_SIZE ,server_type);
                        ERR_CHK(rc);
                        IPInterface.Cfg_bitmask |= INTF_CFG_SERVERTYPE;
                    }
                }
            }

            if (IPInterface.Cfg_bitmask)
            {
                if (CosaWanCnctvtyChk_Intf_Commit(&IPInterface) != ANSC_STATUS_SUCCESS)
                {
                    WANCHK_LOG_ERROR("%s: Interface commit failed\n",__FUNCTION__);
                    return RBUS_ERROR_INVALID_INPUT;
                }
            }
        }
        else
        {
            WANCHK_LOG_ERROR("%s:%d Invalid Input\n",__FUNCTION__,__LINE__);
            pthread_mutex_unlock(&gIntfAccessMutex);
            return RBUS_ERROR_INVALID_INPUT;
        }
    }
    else
    {
        WANCHK_LOG_ERROR("%s:%d Invalid Input\n",__FUNCTION__,__LINE__);
        return RBUS_ERROR_INVALID_INPUT;
    }
    return RBUS_ERROR_SUCCESS;
}


/**********************************************************************
    function:
       WANCNCTVTYCHK_SubHandler
    description:
        This is an Event Handler for Ulong parameters in the table
    argument:
        rbusHandle_t             handle
        rbusEventSubAction_t     action
        const char*              eventName
        rbusFilter_t             filter
        int32_t                  interval
        bool                     autoPublish
    return:
        rbusError_t
**********************************************************************/

rbusError_t WANCNCTVTYCHK_SubHandler(rbusHandle_t handle, rbusEventSubAction_t action,
                                          const char *eventName, rbusFilter_t filter,
                                          int32_t interval, bool *autoPublish)
{
    *autoPublish = FALSE;
    char *subscribe_action = NULL;
    unsigned int instNum = 0;
    char Param[BUFLEN_128] ={0};
    char alias[BUFLEN_128] = {0};
    int aliasRet = 0, instRet = 0;
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = NULL;

    subscribe_action = action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe";
    WANCHK_LOG_INFO("%s %d - Got Request %s for Event %s\n", __FUNCTION__, __LINE__,
                                                        subscribe_action,eventName);
    if(strstr(eventName,"Device.Diagnostics.X_RDK_DNSInternet.WANInterface."))
    {
        pthread_mutex_lock(&gIntfAccessMutex);
        aliasRet = sscanf(eventName, "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.[%[^]]].%127s", alias, Param);
        if (aliasRet == 2) {
            WANCHK_LOG_DBG("%s: Name:%s, alias: %s, Param: %s\n", __FUNCTION__, eventName, alias, Param);
            gIntfInfo = get_InterfaceFromAlias(alias);
        }

        instRet = sscanf(eventName, "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.%d.%127s", &instNum, Param);
        if (instRet == 2) {
            WANCHK_LOG_DBG("%s: Name:%s, instNum: %d, Param: %s\n", __FUNCTION__, eventName, instNum, Param);
            gIntfInfo = get_InterfaceList(instNum);
        }

        if (gIntfInfo)
        {
            if (strcmp(Param, "MonitorResult") == 0)
            {
                if (action == RBUS_EVENT_ACTION_SUBSCRIBE ) {
                        gIntfInfo->IPInterface.MonitorResult_SubsCount++;
                } else {
                    if (gIntfInfo->IPInterface.MonitorResult_SubsCount)
                        gIntfInfo->IPInterface.MonitorResult_SubsCount--;
                }
            }
            else if (strcmp(Param, "QueryNowResult") == 0)
            {
                if (action == RBUS_EVENT_ACTION_SUBSCRIBE ) {
                        gIntfInfo->IPInterface.QueryNowResult_SubsCount++;
                } else {
                    if (gIntfInfo->IPInterface.QueryNowResult_SubsCount)
                        gIntfInfo->IPInterface.QueryNowResult_SubsCount--;
                }
            }
            pthread_mutex_unlock(&gIntfAccessMutex);
        }
        else
        {
            WANCHK_LOG_ERROR("%s:%d Invalid Input\n",__FUNCTION__,__LINE__);
            pthread_mutex_unlock(&gIntfAccessMutex);
            return RBUS_ERROR_INVALID_INPUT;
        }
    }
    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        sendUlongUpdateEvent
    description:
        This is an Event Handler for Ulong parameters in the table
    argument:
        rbusHandle_t             handle
        rbusEventSubAction_t     action
        const char*              eventName
        rbusFilter_t             filter
        int32_t                  interval
        bool                     autoPublish
    return:
        rbusError_t
**********************************************************************/
rbusError_t WANCNCTVTYCHK_PublishEvent(char* event_name , uint32_t eventNewData, uint32_t eventOldData)
{
    rbusEvent_t event;
    rbusObject_t data;
    rbusValue_t value;
    rbusValue_t oldVal;
    rbusValue_t byVal;
    rbusError_t ret = RBUS_ERROR_SUCCESS;

    WANCHK_LOG_INFO("Publishing event:%s | oldValue:%d, newValue:%d\n", event_name, eventOldData, eventNewData);
    //initialize and set previous value for the event
    rbusValue_Init(&oldVal);
    rbusValue_SetUInt32(oldVal, eventOldData);
    //initialize and set new value for the event
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, eventNewData);
    //initialize and set responsible component name for value change
    rbusValue_Init(&byVal);
    rbusValue_SetString(byVal, "WanCnctvtyChkTableConsumer");
    //initialize and set rbusObject with desired values
    rbusObject_Init(&data, NULL);
    rbusObject_SetValue(data, "value", value);
    rbusObject_SetValue(data, "oldValue", oldVal);
    rbusObject_SetValue(data, "by", byVal);
    //set data to be transferred
    event.name = event_name;
    event.data = data;
    event.type = RBUS_EVENT_VALUE_CHANGED;
    //publish the event
    ret = rbusEvent_Publish(rbus_table_handle, &event);
    if(ret != RBUS_ERROR_SUCCESS) {
            WANCHK_LOG_WARN("rbusEvent_Publish for %s failed: %d\n", event_name, ret);
    }
    //release all initialized rbusValue objects
    rbusValue_Release(value);
    rbusValue_Release(oldVal);
    rbusValue_Release(byVal);
    rbusObject_Release(data);
    return ret;
}

/**********************************************************************
    function:
        WTC_TableAddRowHandler
    description:
        Handler function to Add rows
    argument:
        rbusHandle_t   handle
        char const*    tableName
        char const*    aliasName
        uint32_t*      instNum
    return:
        rbusError_t
**********************************************************************/

rbusError_t WANCNCTVTYCHK_TableAddRowHandler(rbusHandle_t handle, char const* tableName,
                                   char const* aliasName, uint32_t* instNum)
{
    (void)handle;
    (void)aliasName;
    PCOSA_CONTEXT_LINK_OBJECT          pSubCosaContext  = (PCOSA_CONTEXT_LINK_OBJECT)NULL;
    PCOSA_DML_WANCNCTVTY_CHK_URL_INFO  pUrlEntry     = (PCOSA_DML_WANCNCTVTY_CHK_URL_INFO)NULL;

    pUrlEntry = (PCOSA_DML_WANCNCTVTY_CHK_URL_INFO)AnscAllocateMemory(sizeof
                                                                (COSA_DML_WANCNCTVTY_CHK_URL_INFO));
    if ( !pUrlEntry)
    {
        WANCHK_LOG_WARN("%s resource allocation failed\n",__FUNCTION__);
        return RBUS_ERROR_BUS_ERROR;
    }

    pSubCosaContext = (PCOSA_CONTEXT_LINK_OBJECT)AnscAllocateMemory(sizeof(COSA_CONTEXT_LINK_OBJECT));
    if ( !pSubCosaContext)
    {
        goto EXIT;
    }

    pthread_mutex_lock(&gUrlAccessMutex);
    pSubCosaContext->InstanceNumber =  gulUrlNextInsNum;
    pUrlEntry->InstanceNumber = gulUrlNextInsNum; 
    gulUrlNextInsNum++;
    if (gulUrlNextInsNum == 0)
        gulUrlNextInsNum = 1;

    /* now we have this link content */
    pSubCosaContext->hContext = (ANSC_HANDLE)pUrlEntry;
    pSubCosaContext->hParentTable     = NULL;
    pSubCosaContext->bNew             = TRUE;

    CosaSListPushEntryByInsNum(&gpUrlList, (PCOSA_CONTEXT_LINK_OBJECT)pSubCosaContext);
    *instNum = pUrlEntry->InstanceNumber;
    pthread_mutex_unlock(&gUrlAccessMutex);
    WANCHK_LOG_INFO("Added TableName = %s, InstNum = %d\n", tableName, *instNum);
    return RBUS_ERROR_SUCCESS;
EXIT:
    AnscFreeMemory(pUrlEntry);
    return RBUS_ERROR_BUS_ERROR;
}

/**********************************************************************
    function:
        WTC_TableRemoveRowHandler
    description:
        Handler function to Remove rows
    argument:
        rbusHandle_t   handle
        char const*    rowName
    return:
        rbusError_t
**********************************************************************/

rbusError_t WANCNCTVTYCHK_TableRemoveRowHandler(rbusHandle_t handle, char const* rowName)
{
    (void)handle;
    int instNum = 0;
    BOOL bFound = FALSE;
    PSINGLE_LINK_ENTRY              pSListEntry       = NULL;
    PCOSA_CONTEXT_LINK_OBJECT       pCxtLink          = NULL;
    PCOSA_DML_WANCNCTVTY_CHK_URL_INFO pUrlInfo        = NULL;
    ANSC_STATUS returnStatus                          = ANSC_STATUS_SUCCESS;
    WANCHK_LOG_INFO("RowName = %s\n", rowName);
    if (!rowName)
    {
        WANCHK_LOG_ERROR("RowName is NULL\n");
        return RBUS_ERROR_INVALID_INPUT;
    }
    /* Fetch instance number from Row*/
    int ret = sscanf(rowName, "Device.Diagnostics.X_RDK_DNSInternet.TestURL.%d", &instNum);
    if (ret == 1)
    {
        pthread_mutex_lock(&gUrlAccessMutex);
        pSListEntry           = AnscSListGetFirstEntry(&gpUrlList);
        while( pSListEntry != NULL)
        {
            pCxtLink          = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSListEntry);
            pSListEntry       = AnscSListGetNextEntry(pSListEntry);
            if (pCxtLink && (pCxtLink->InstanceNumber == instNum))
            {
                bFound = TRUE;
                break;
            }
        }
        if ( bFound == TRUE)
        {
            pUrlInfo = (PCOSA_DML_WANCNCTVTY_CHK_URL_INFO)pCxtLink->hContext;
            if ( AnscSListPopEntryByLink((PSLIST_HEADER)&gpUrlList, &pCxtLink->Linkage))
            {
                AnscFreeMemory(pUrlInfo);
                pUrlInfo = NULL;
                AnscFreeMemory(pCxtLink);
                pCxtLink = NULL;
            }
            else
            {
                WANCHK_LOG_ERROR("Unable to remove entry in global DB for %s\n",rowName);
                pthread_mutex_unlock(&gUrlAccessMutex);
                return ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            WANCHK_LOG_ERROR("No entry exists for corresponding Row %s\n",rowName);
            pthread_mutex_unlock(&gUrlAccessMutex);
            return RBUS_ERROR_INVALID_INPUT;
        }
        pthread_mutex_unlock(&gUrlAccessMutex);
    }
    else
    {
        WANCHK_LOG_ERROR("Invalid Input, Unable to remove\n");
        return RBUS_ERROR_INVALID_INPUT;
    }
    CosaWanCnctvtyChk_URL_delDBEntry(instNum);
    WANCHK_LOG_INFO("%s: URL Entry deleted,Restarting threads\n",__FUNCTION__);
    unsigned int Instance = 1;
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

    return RBUS_ERROR_SUCCESS;
}

uint32_t wanchk_webconfig_get_blobversion(char* subdoc)
{
    char subdoc_ver[64] = {0}, buf[72] = {0};
    errno_t rc = -1;

    rc = sprintf_s(buf, sizeof(buf), "%s_version", subdoc);
    if (rc < EOK)
    {
        ERR_CHK(rc);
        return 0;
    }

    if (syscfg_get(NULL, buf, subdoc_ver, sizeof(subdoc_ver)) == 0)
    {
        int version = atoi(subdoc_ver);
        return (uint32_t)version;
    }

    return 0;
}

int wanchk_webconfig_set_blobversion(char* subdoc, uint32_t version)
{
    char subdoc_ver[64] = {0}, buf[72] = {0};
    errno_t rc = -1;

    rc = sprintf_s(subdoc_ver, sizeof(subdoc_ver), "%u", version);
    if (rc < EOK)
           return -1;

    rc = sprintf_s(buf, sizeof(buf), "%s_version", subdoc);
    if (rc < EOK)
    {
        ERR_CHK(rc);
        return -1;
    }

    if (syscfg_set(NULL, buf, subdoc_ver) != 0)
    {
        WANCHK_LOG_ERROR("syscfg_set failed\n");
        return -1;
    }

    if (syscfg_commit() != 0)
    {
        WANCHK_LOG_ERROR("syscfg_commit failed\n");
        return -1;
    }

    return 0;
}

void wanchk_webconfig_init()
{
    errno_t rc = -1;
    char *sub_docs[SUBDOC_COUNT + 1] = {WANCHK_WEBCONFIG_SUBDOC_NAME, (char *)0};

    blobRegInfo *blobData = (blobRegInfo*)AnscAllocateMemory(SUBDOC_COUNT * sizeof(blobRegInfo));
    if (blobData == NULL)
        return;

    rc = memset_s(blobData, SUBDOC_COUNT * sizeof(blobRegInfo), 0, SUBDOC_COUNT * sizeof(blobRegInfo));
    ERR_CHK(rc);

    blobRegInfo *blobDataPointer = blobData;

    for (int i = 0; i < SUBDOC_COUNT; i++)
    {
        rc = strcpy_s(blobDataPointer->subdoc_name, sizeof(blobDataPointer->subdoc_name), sub_docs[i]);
        if (rc != EOK)
        {
            ERR_CHK(rc);
            AnscFreeMemory(blobData);
            return;
        }

        blobDataPointer++;
    }

    getVersion versionGet = wanchk_webconfig_get_blobversion;
    setVersion versionSet = wanchk_webconfig_set_blobversion;

    register_sub_docs(blobData, SUBDOC_COUNT, versionGet, versionSet);
}

pErr wanchk_webconfig_process_request(void *Data)
{
    WANCHK_LOG_INFO("%s: Entering function\n", __FUNCTION__);

    pErr execRetVal = NULL;
    errno_t rc = -1;
    BOOL dns_changed = FALSE;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = NULL;
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    execRetVal = (pErr)AnscAllocateMemory(sizeof(Err));
    if (execRetVal == NULL)
    {
        WANCHK_LOG_ERROR("%s : AnscAllocateMemory failed\n", __FUNCTION__);
        return NULL;
    }

    rc = memset_s(execRetVal, sizeof(Err), 0, sizeof(Err));
    ERR_CHK(rc);

    wanchkdoc_t *wanDoc = (wanchkdoc_t *)Data;
    if (!wanDoc || !wanDoc->param)
    {
        WANCHK_LOG_ERROR("%s: Invalid input blob\n", __FUNCTION__);
        execRetVal->ErrorCode = NULL_BLOB_EXEC_POINTER;
        strncpy(execRetVal->ErrorMsg, "Invalid blob", sizeof(execRetVal->ErrorMsg) - 1);
        return execRetVal;
    }

    char *interface = wanDoc->param->linux_interface_name;
    char *alias = wanDoc->param->alias;
    char *IPv4_nameserver_list = wanDoc->param->IPv4_DNS_Servers;
    char *IPv6_nameserver_list = wanDoc->param->IPv6_DNS_Servers;
    char *IPv4_Gateway = wanDoc->param->IPv4_Gateway;
    char *IPv6_Gateway = wanDoc->param->IPv6_Gateway;

    WANCHK_LOG_INFO("Interface: %s, Alias: %s\n", interface, alias);

    uint32_t IPv4DnsServerCount = 0;
    uint32_t IPv6DnsServerCount = 0;

    if (is_valid_interface(interface) != ANSC_STATUS_SUCCESS) {
        WANCHK_LOG_ERROR("Invalid Interface Name: %s\n", interface);
        execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
        strncpy(execRetVal->ErrorMsg, "Invalid interface", sizeof(execRetVal->ErrorMsg) - 1);
        return execRetVal;
    }

    if (IPv4_nameserver_list == NULL && IPv6_nameserver_list == NULL) {
        WANCHK_LOG_ERROR("DNS Server list missing\n");
        execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
        strncpy(execRetVal->ErrorMsg, "Missing DNS servers", sizeof(execRetVal->ErrorMsg) - 1);
        return execRetVal;
    }

    WANCHK_LOG_INFO("Validating DNS nameservers\n");
    if (validate_DNS_nameservers(IPv4_nameserver_list, IPv6_nameserver_list, &IPv4DnsServerCount, &IPv6DnsServerCount) != ANSC_STATUS_SUCCESS) {
        WANCHK_LOG_ERROR("Invalid DNS Nameserver List\n");
        execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
        strncpy(execRetVal->ErrorMsg, "Invalid DNS list", sizeof(execRetVal->ErrorMsg) - 1);
        return execRetVal;
    }

    if (IPv4_Gateway && strlen(IPv4_Gateway) > 0 && inet_pton(AF_INET, IPv4_Gateway, &ipv4) != 1) {
        WANCHK_LOG_ERROR("Invalid IPv4 Gateway: %s\n", IPv4_Gateway);
        execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
        strncpy(execRetVal->ErrorMsg, "Invalid IPv4 gateway", sizeof(execRetVal->ErrorMsg) - 1);
        return execRetVal;
    }

    if (IPv6_Gateway && strlen(IPv6_Gateway) > 0 && inet_pton(AF_INET6, IPv6_Gateway, &ipv6) != 1) {
        WANCHK_LOG_ERROR("Invalid IPv6 Gateway: %s\n", IPv6_Gateway);
        execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
        strncpy(execRetVal->ErrorMsg, "Invalid IPv6 gateway", sizeof(execRetVal->ErrorMsg) - 1);
        return execRetVal;
    }

    WANCHK_LOG_INFO("Checking for DNS changes\n");
    dns_changed = check_for_change_in_dns(alias, IPv4_nameserver_list, IPv6_nameserver_list, IPv4DnsServerCount, IPv6DnsServerCount);

    pthread_mutex_lock(&gIntfAccessMutex);
    gIntfInfo = get_InterfaceFromAlias(alias);
    if (gIntfInfo && strcmp(interface, gIntfInfo->IPInterface.InterfaceName) == 0 && strcmp(alias, gIntfInfo->IPInterface.Alias) == 0) {
        WANCHK_LOG_INFO("Interface and alias match existing entry\n");

        if (gIntfInfo->IPInterface.Enable == TRUE) {
            WANCHK_LOG_ERROR("Test already running on %s/%s\n", interface, alias);
            pthread_mutex_unlock(&gIntfAccessMutex);
            execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
            strncpy(execRetVal->ErrorMsg, "Test already running", sizeof(execRetVal->ErrorMsg) - 1);
            return execRetVal;
        }

        gIntfInfo->IPInterface.Enable = DEF_INTF_ENABLE;
        gIntfInfo->IPInterface.Configured = TRUE;

        if (IPv4_Gateway) {
            memset(gIntfInfo->IPInterface.IPv4Gateway, 0, IPv4_STR_LEN);
            rc = strcpy_s(gIntfInfo->IPInterface.IPv4Gateway, IPv4_STR_LEN, IPv4_Gateway);
            ERR_CHK(rc);
        }

        if (IPv6_Gateway) {
            memset(gIntfInfo->IPInterface.IPv6Gateway, 0, IPv6_STR_LEN);
            rc = strcpy_s(gIntfInfo->IPInterface.IPv6Gateway, IPv6_STR_LEN, IPv6_Gateway);
            ERR_CHK(rc);
        }

        if (dns_changed) {
            WANCHK_LOG_INFO("DNS has changed, updating entries\n");
            if (CosaWanCnctvtyChk_DNS_UpdateEntry(interface, alias, IPv4_nameserver_list, IPv6_nameserver_list,
                                                  IPv4DnsServerCount, IPv6DnsServerCount) != ANSC_STATUS_SUCCESS)
            {
                WANCHK_LOG_ERROR("DNS update failed\n");
            }
        }

        WANCHK_LOG_INFO("Starting WAN connectivity check threads\n");
        returnStatus = wancnctvty_chk_start_threads(gIntfInfo->IPInterface.InstanceNumber, ALL_THREADS);
        pthread_mutex_unlock(&gIntfAccessMutex);

        if (returnStatus != ANSC_STATUS_SUCCESS) {
            WANCHK_LOG_ERROR("Unable to start threads\n");
            execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
            strncpy(execRetVal->ErrorMsg, "Thread start failed", sizeof(execRetVal->ErrorMsg) - 1);
            return execRetVal;
        }

        execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
        strncpy(execRetVal->ErrorMsg, "WAN connectivity check started", sizeof(execRetVal->ErrorMsg) - 1);
        return execRetVal;
    }

    if (gIntfInfo) {
        WANCHK_LOG_ERROR("Alias already exists: %s\n", alias);
        pthread_mutex_unlock(&gIntfAccessMutex);
        execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
        strncpy(execRetVal->ErrorMsg, "Alias already exists", sizeof(execRetVal->ErrorMsg) - 1);
        return execRetVal;
    }

    pthread_mutex_unlock(&gIntfAccessMutex);

    if (CosaWanCnctvtyChk_GetActive_Status() == TRUE) {
        WANCHK_LOG_INFO("Active gateway detected, initializing interface\n");
        g_wanconnectivity_check_start = TRUE;
        if (CosaWanCnctvtyChk_Init_Intf(interface, alias, IPv4_nameserver_list, IPv6_nameserver_list,
                                        IPv4DnsServerCount, IPv6DnsServerCount, IPv4_Gateway, IPv6_Gateway) != ANSC_STATUS_SUCCESS)
        {
            WANCHK_LOG_ERROR("Interface init failed\n");
            execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
            strncpy(execRetVal->ErrorMsg, "Interface init failed", sizeof(execRetVal->ErrorMsg) - 1);
            return execRetVal;
        }

        execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
        //strncpy(execRetVal->ErrorMsg, "WAN connectivity check started", sizeof(execRetVal->ErrorMsg) - 1);
        return execRetVal;
    }
    else {
        WANCHK_LOG_ERROR("Start from ACTIVE GATEWAY only\n");
        execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
        strncpy(execRetVal->ErrorMsg, "Inactive gateway", sizeof(execRetVal->ErrorMsg) - 1);
        return execRetVal;
    }
}

int wanchk_webconfig_rollback()
{
    WANCHK_LOG_INFO("Entering %s\n", __FUNCTION__);
    CcspTraceWarning(("%s: Rolling back WAN connectivity blob (dummy)\n", __FUNCTION__));
    return 0; // Success
}

void wanchk_webconfig_free_resources(void *arg)
{
    WANCHK_LOG_INFO("Entering %s\n", __FUNCTION__);

    execData *blob_exec_data = (execData*) arg;
    if (blob_exec_data != NULL)
    {
        // Free user_data if allocated
        if (blob_exec_data->user_data != NULL)
        {
            AnscFreeMemory(blob_exec_data->user_data);
            blob_exec_data->user_data = NULL;
        }

        AnscFreeMemory(blob_exec_data);
        blob_exec_data = NULL;
    }
}

/**********************************************************************
    function:
        WANCNCTVTYCHK_StartConnectivityCheck
    description:
        This Handler function is to start wan connectivity check
        with given interface name and alias
    argument:
        rbusHandle_t handle
        char const* methodName
        rbusObject_t inParams
        rbusObject_t outParams
        rbusMethodAsyncHandle_t asyncHandle
    return:
        rbusError_t
**********************************************************************/
rbusError_t WANCNCTVTYCHK_StartConnectivityCheck(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,
                                                        rbusMethodAsyncHandle_t asyncHandle) {
    rbusValue_t value;
    char *interface = NULL;
    char *alias = NULL;
    char *IPv4_nameserver_list = NULL;
    char *IPv6_nameserver_list = NULL;
    char *IPv4_Gateway = NULL;
    char *IPv6_Gateway = NULL;
    uint32_t len = 0;
    uint32_t IPv4DnsServerCount = 0;
    uint32_t IPv6DnsServerCount = 0;
    errno_t  rc = -1;
    BOOL dns_changed;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = NULL;
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    char *subdoc_name = NULL;

    int transaction_id = -1;
    int version = -1;

    char *encoded_blob = NULL;
    char *decodeMsg = NULL;
    ULONG decoded_size = 0;
    msgpack_unpack_return unpack_ret = MSGPACK_UNPACK_SUCCESS;
    execData *execDataWanChk = NULL;

    // Step 1: Get encoded_blob from rbusObject
    len = 0;
    value = rbusObject_GetValue(inParams, "encoded_blob");
    encoded_blob = (char*)rbusValue_GetString(value, &len);

    if (encoded_blob != NULL && strlen(encoded_blob) > 0)
    {
        WANCHK_LOG_INFO("Encoded blob received: %s\n", encoded_blob);

        static BOOL wanchk_initialized = FALSE;
        if (!wanchk_initialized) {
            wanchk_webconfig_init();
            wanchk_initialized = TRUE;
        }

        // Step 2: Decode using AnscBase64Decode
        decodeMsg = (char*)AnscBase64Decode((PUCHAR)encoded_blob, &decoded_size);
        if (decodeMsg == NULL) {
            WANCHK_LOG_ERROR("Failed to decode base64 blob using AnscBase64Decode\n");
            return RBUS_ERROR_INVALID_INPUT;
        }

        // Step 3: Unpack MessagePack
        msgpack_unpacked msg;
        size_t offset = 0;
        msgpack_unpacked_init(&msg);
        unpack_ret = msgpack_unpack_next(&msg, decodeMsg, decoded_size, &offset);

        if (unpack_ret != MSGPACK_UNPACK_SUCCESS || msg.data.type != MSGPACK_OBJECT_MAP) {
            WANCHK_LOG_ERROR("Failed to unpack MessagePack blob\n");
            msgpack_unpacked_destroy(&msg);
            AnscFreeMemory(decodeMsg);
            return RBUS_ERROR_INVALID_INPUT;
        }

        msgpack_object root = msg.data;
        msgpack_object_kv* root_kv = root.via.map.ptr;
        int root_size = root.via.map.size;

        msgpack_object startconnectivity;
        bool found_startconnectivity = false;

        // Step 4: Parse top-level fields and find "startconnectivity"
        for (int i = 0; i < root_size; ++i) {
            const char* key = root_kv[i].key.via.str.ptr;
            msgpack_object val = root_kv[i].val;

            if (strncmp(key, "startconnectivity", root_kv[i].key.via.str.size) == 0 && val.type == MSGPACK_OBJECT_MAP) {
                startconnectivity = val;
                found_startconnectivity = true;
            } else if (strncmp(key, "transaction_id", root_kv[i].key.via.str.size) == 0 && val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                transaction_id = (int)val.via.u64;
            } else if (strncmp(key, "version", root_kv[i].key.via.str.size) == 0 && val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                version = (int)val.via.u64;
            } else if (strncmp(key, "subdoc_name", root_kv[i].key.via.str.size) == 0 && val.type == MSGPACK_OBJECT_STR) {
                subdoc_name = strndup(val.via.str.ptr, val.via.str.size);
            }
        }

        if (!found_startconnectivity) {
            WANCHK_LOG_ERROR("Missing or invalid 'startconnectivity' section\n");
            msgpack_unpacked_destroy(&msg);
            AnscFreeMemory(decodeMsg);
            return RBUS_ERROR_INVALID_INPUT;
        }

        // Step 5: Extract fields from startconnectivity
        msgpack_object_kv* kv = startconnectivity.via.map.ptr;
        int count = startconnectivity.via.map.size;

        for (int i = 0; i < count; ++i) {
            const char* key = kv[i].key.via.str.ptr;
            msgpack_object val = kv[i].val;

            if (strncmp(key, "linux_interface_name", kv[i].key.via.str.size) == 0) {
                interface = strndup(val.via.str.ptr, val.via.str.size);
            } else if (strncmp(key, "alias", kv[i].key.via.str.size) == 0) {
                alias = strndup(val.via.str.ptr, val.via.str.size);
            } else if (strncmp(key, "IPv4_DNS_Servers", kv[i].key.via.str.size) == 0) {
                IPv4_nameserver_list = strndup(val.via.str.ptr, val.via.str.size);
            } else if (strncmp(key, "IPv6_DNS_Servers", kv[i].key.via.str.size) == 0) {
                IPv6_nameserver_list = strndup(val.via.str.ptr, val.via.str.size);
            } else if (strncmp(key, "IPv4_Gateway", kv[i].key.via.str.size) == 0) {
                IPv4_Gateway = strndup(val.via.str.ptr, val.via.str.size);
            } else if (strncmp(key, "IPv6_Gateway", kv[i].key.via.str.size) == 0) {
                IPv6_Gateway = strndup(val.via.str.ptr, val.via.str.size);
            }
        }

        WANCHK_LOG_INFO("Parsed from blob: Interface=%s, Alias=%s, v4DNS=%s, v6DNS=%s, v4GW=%s, v6GW=%s\n",
            interface, alias, IPv4_nameserver_list, IPv6_nameserver_list, IPv4_Gateway, IPv6_Gateway);
        WANCHK_LOG_INFO("Transaction ID: %d, Version: %d, Subdoc: %s\n", transaction_id, version, subdoc_name);

        wanchkdoc_t *wanDoc = (wanchkdoc_t *)AnscAllocateMemory(sizeof(wanchkdoc_t));
        if (wanDoc != NULL) {
            wanDoc->transaction_id = transaction_id;
            wanDoc->version = version;
            wanDoc->subdoc_name = subdoc_name; // already strdup'ed
            wanDoc->param = (wanchkparam_t *)AnscAllocateMemory(sizeof(wanchkparam_t));
            if (wanDoc->param != NULL) {
                wanDoc->param->linux_interface_name = interface;
                wanDoc->param->alias = alias;
                wanDoc->param->IPv4_DNS_Servers = IPv4_nameserver_list;
                wanDoc->param->IPv6_DNS_Servers = IPv6_nameserver_list;
                wanDoc->param->IPv4_Gateway = IPv4_Gateway;
                wanDoc->param->IPv6_Gateway = IPv6_Gateway;
            } else {
                AnscFreeMemory(wanDoc);
                wanDoc = NULL;
            }
        }

        // Step 6: Allocate and populate execData
        execDataWanChk = (execData*)AnscAllocateMemory(sizeof(execData));
        if (execDataWanChk != NULL) {
            rc = memset_s(execDataWanChk, sizeof(execData), 0, sizeof(execData));
            ERR_CHK(rc);

            execDataWanChk->txid = transaction_id;
            execDataWanChk->version = version;
            execDataWanChk->numOfEntries = 1;

            rc = strcpy_s(execDataWanChk->subdoc_name, sizeof(execDataWanChk->subdoc_name), subdoc_name);
            if (rc != EOK) {
                ERR_CHK(rc);
                AnscFreeMemory(execDataWanChk);
                execDataWanChk = NULL;
                AnscFreeMemory(decodeMsg);
                free(subdoc_name);
                return RBUS_ERROR_INVALID_INPUT;
            }

            execDataWanChk->user_data = (void *)wanDoc;
            execDataWanChk->calcTimeout = NULL;
            execDataWanChk->executeBlobRequest = wanchk_webconfig_process_request;
            execDataWanChk->rollbackFunc = wanchk_webconfig_rollback;
            execDataWanChk->freeResources = wanchk_webconfig_free_resources;

            PushBlobRequest(execDataWanChk);
            WANCHK_LOG_INFO("PushBlobRequest complete\n");
        }

        // Cleanup
        msgpack_unpacked_destroy(&msg);
        AnscFreeMemory(decodeMsg);
        if (subdoc_name) free(subdoc_name);
    }
    else
    {
    value = rbusObject_GetValue(inParams, "linux_interface_name");
    interface = (char*)rbusValue_GetString(value, &len);

    len = 0;
    value = rbusObject_GetValue(inParams, "alias");
    alias = (char*)rbusValue_GetString(value, &len);

    len = 0;
    value = rbusObject_GetValue(inParams, "IPv4_DNS_Servers");
    IPv4_nameserver_list = (char*)rbusValue_GetString(value, &len);

    len = 0;
    value = rbusObject_GetValue(inParams, "IPv6_DNS_Servers");
    IPv6_nameserver_list = (char*)rbusValue_GetString(value, &len);

    len = 0;
    value = rbusObject_GetValue(inParams, "IPv4_Gateway");
    IPv4_Gateway = (char*)rbusValue_GetString(value, &len);

    len = 0;
    value = rbusObject_GetValue(inParams, "IPv6_Gateway");
    IPv6_Gateway = (char*)rbusValue_GetString(value, &len);

    WANCHK_LOG_INFO("%s: InterfaceName: %s, Alias: %s, v4_list: %s, v6_list: %s, v4_gateway: %s, v6_gateway: %s\n",
                    __FUNCTION__, interface, alias, IPv4_nameserver_list, IPv6_nameserver_list, IPv4_Gateway, IPv6_Gateway);
    }
    if (is_valid_interface(interface) != ANSC_STATUS_SUCCESS) {
        WANCHK_LOG_ERROR("Invalid Interface Name to Start WAN Connectivity Check\n");
        return RBUS_ERROR_INVALID_INPUT;
    }

    /*
    if (is_valid_aliasName(alias) != ANSC_STATUS_SUCCESS) {
       WANCHK_LOG_ERROR("Invalid Alias Name. Alias Name must be identical to Device.X_RDK_WanManager.InterfaceAvailableStatus\n");
       return RBUS_ERROR_INVALID_INPUT;
    }
    */

    if (IPv4_nameserver_list == NULL && IPv6_nameserver_list == NULL) {
        WANCHK_LOG_ERROR("Provide DNS Server List to Start Wan Connectivity Check for Interface: %s, Alias: %s\n",
                          interface, alias);
        return RBUS_ERROR_INVALID_INPUT;
    }

    if (validate_DNS_nameservers(IPv4_nameserver_list, IPv6_nameserver_list, &IPv4DnsServerCount, &IPv6DnsServerCount) != ANSC_STATUS_SUCCESS) {
        WANCHK_LOG_ERROR("Invalid DNS Nameserver List\n");
        return RBUS_ERROR_INVALID_INPUT;
    }

    if ((IPv4_Gateway != NULL) &&
        (strlen(IPv4_Gateway) > 0 ) &&
        (inet_pton(AF_INET, IPv4_Gateway, &ipv4) != 1)) {
        WANCHK_LOG_ERROR("Invalid IPv4 Gateway address: %s \n", IPv4_Gateway);
        return RBUS_ERROR_INVALID_INPUT;
    }

    if ((IPv6_Gateway != NULL) &&
        (strlen(IPv6_Gateway) > 0) &&
        (inet_pton(AF_INET6, IPv6_Gateway, &ipv6) != 1)) {
        WANCHK_LOG_ERROR("Invalid IPv6 Gateway address: %s \n", IPv6_Gateway);
        return RBUS_ERROR_INVALID_INPUT;
    }

    dns_changed = check_for_change_in_dns(alias, IPv4_nameserver_list, IPv6_nameserver_list, IPv4DnsServerCount, IPv6DnsServerCount);

    pthread_mutex_lock(&gIntfAccessMutex);
    gIntfInfo = get_InterfaceFromAlias(alias);
    if (gIntfInfo && ((strcmp(interface, gIntfInfo->IPInterface.InterfaceName) == 0) && (strcmp(alias, gIntfInfo->IPInterface.Alias) == 0))) {
        //Return Invalid, if start received for already running test
        if (gIntfInfo->IPInterface.Enable == TRUE) {
            WANCHK_LOG_ERROR("Test is already running on Interface %s with Alias %s. To Start again, Stop and Start the test\n", interface, alias);
            pthread_mutex_unlock(&gIntfAccessMutex);
            return RBUS_ERROR_INVALID_INPUT;
        }

        WANCHK_LOG_INFO("Interface %s is already present with Alias %s. Starting Wan Connectivity Check\n", interface, alias);
        gIntfInfo->IPInterface.Enable = DEF_INTF_ENABLE;
        gIntfInfo->IPInterface.Configured = TRUE;

        if (IPv4_Gateway != NULL) {
            memset(gIntfInfo->IPInterface.IPv4Gateway, 0, IPv4_STR_LEN);
            rc = strcpy_s(gIntfInfo->IPInterface.IPv4Gateway, IPv4_STR_LEN, IPv4_Gateway);
            ERR_CHK(rc);
        }

        if (IPv6_Gateway != NULL) {
            memset(gIntfInfo->IPInterface.IPv6Gateway, 0, IPv6_STR_LEN);
            rc = strcpy_s(gIntfInfo->IPInterface.IPv6Gateway, IPv6_STR_LEN, IPv6_Gateway);
            ERR_CHK(rc);
        }

        if (dns_changed == TRUE) {
            WANCHK_LOG_INFO("DNS list changed, Updating DNS nameservers\n");
            if (CosaWanCnctvtyChk_DNS_UpdateEntry(interface, alias, IPv4_nameserver_list, IPv6_nameserver_list,
                                                  IPv4DnsServerCount, IPv6DnsServerCount) != ANSC_STATUS_SUCCESS)
            {
               WANCHK_LOG_ERROR("%s: DNS Update failed for interface: %s, alias: %s\n", __FUNCTION__, interface, alias);
            }
        }

        returnStatus = wancnctvty_chk_start_threads(gIntfInfo->IPInterface.InstanceNumber,ALL_THREADS);
        pthread_mutex_unlock(&gIntfAccessMutex);
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            WANCHK_LOG_ERROR("%s:%d Unable to start threads\n",__FUNCTION__,__LINE__);
            return ANSC_STATUS_FAILURE;
        }
        return RBUS_ERROR_SUCCESS;
    }

    if (gIntfInfo) {
        WANCHK_LOG_ERROR("Interface with Alias: %s is present already. Use Different Alias Name\n", alias);
        pthread_mutex_unlock(&gIntfAccessMutex);
        return RBUS_ERROR_INVALID_INPUT;
    }
    pthread_mutex_unlock(&gIntfAccessMutex);

    g_wanconnectivity_check_active    = CosaWanCnctvtyChk_GetActive_Status();
    if (g_wanconnectivity_check_active == TRUE) {
        /* start wan connectivty check process*/
        g_wanconnectivity_check_start = TRUE;
        if (CosaWanCnctvtyChk_Init_Intf (interface, alias, IPv4_nameserver_list, 
                                         IPv6_nameserver_list, IPv4DnsServerCount,
                                         IPv6DnsServerCount, IPv4_Gateway, IPv6_Gateway) != ANSC_STATUS_SUCCESS)
        {
            WANCHK_LOG_ERROR("%s: Interface Table Init failed for interface: %s, alias: %s\n", __FUNCTION__, interface, alias);
        }
    }
    else {
        WANCHK_LOG_ERROR("Start Wan Connectivity Check from ACTIVE GATEWAY\n");
        return RBUS_ERROR_INVALID_INPUT;
    }

    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        WANCNCTVTYCHK_StopConnectivityCheck
    description:
        This Handler function is to stop wan connectivity check
        with given interface name and alias
    argument:
        rbusHandle_t handle
        char const* methodName
        rbusObject_t inParams
        rbusObject_t outParams
        rbusMethodAsyncHandle_t asyncHandle
    return:
        rbusError_t
**********************************************************************/
rbusError_t WANCNCTVTYCHK_StopConnectivityCheck(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,
                                                       rbusMethodAsyncHandle_t asyncHandle) {

    rbusValue_t value;
    char *interface = NULL;
    char *alias = NULL;
    uint32_t len = 0;
    ULONG InstanceNum = -1;
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo = NULL;

    value = rbusObject_GetValue(inParams, "linux_interface_name");
    interface = (char*)rbusValue_GetString(value, &len);

    len = 0;
    value = rbusObject_GetValue(inParams, "alias");
    alias = (char*)rbusValue_GetString(value, &len); 

    pthread_mutex_lock(&gIntfAccessMutex);
    gIntfInfo = get_InterfaceFromAlias(alias);
    if (gIntfInfo) {
         InstanceNum = gIntfInfo->IPInterface.InstanceNumber;
    }
    pthread_mutex_unlock(&gIntfAccessMutex);

    if (InstanceNum == -1) {
        WANCHK_LOG_ERROR("%s: Invalid Interface/Alias Name\n", __FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    WANCHK_LOG_INFO("Stopping the WAN Connectivity Check for Interface: %s, Alias: %s\n", interface, alias);
    CosaWanCnctvtyChk_Remove_Intf(InstanceNum);

    return RBUS_ERROR_SUCCESS;
}

/**********************************************************************
    function:
        Method_ServiceHandler
    description:
        Handler for managing systemd services via D-Bus
    argument:
        rbusHandle_t handle
        char const* methodName
        rbusObject_t inParams
        rbusObject_t outParams
        rbusMethodAsyncHandle_t asyncHandle
    return:
        rbusError_t
**********************************************************************/
rbusError_t Method_ServiceHandler(rbusHandle_t handle, char const* methodName,
                                  rbusObject_t inParams, rbusObject_t outParams,
                                  rbusMethodAsyncHandle_t asyncHandle) 
{
    (void)handle;
    (void)methodName;

    rbusValue_t value;
    rbusValue_t message, statusCode;
    rbusValue_Init(&message);
    rbusValue_Init(&statusCode);

    const char *service_name = NULL;
    const char *operation = NULL;
    uint32_t len = 0;

    CcspTraceInfo(("******************* ServiceHandler started *******************\n"));

    if (!(value = rbusObject_GetValue(inParams, "service")))
    {
        CcspTraceError(("Missing 'service' parameter\n"));
        rbusValue_SetString(message, "Missing 'service' parameter");
        rbusValue_SetInt32(statusCode, RBUS_ERROR_INVALID_INPUT);
        goto set_response_and_return;
    }
    service_name = rbusValue_GetString(value, &len);

    if (!service_name || strlen(service_name) == 0)
    {
        CcspTraceError(("Service name is Invalid.\n"));
        rbusValue_SetString(message, "Invalid 'service' name");
        rbusValue_SetInt32(statusCode, RBUS_ERROR_INVALID_INPUT);
        goto set_response_and_return;
    }

    if (!(value = rbusObject_GetValue(inParams, "operation")))
    {
        CcspTraceError(("Missing 'operation' parameter\n"));
        rbusValue_SetString(message, "Missing 'operation' parameter");
        rbusValue_SetInt32(statusCode, RBUS_ERROR_INVALID_INPUT);
    }
    operation = rbusValue_GetString(value, &len);

    if (!operation || !len)
    {
        CcspTraceError(("Empty operation\n"));
        rbusValue_SetString(message, "Invalid 'operation' value");
        rbusValue_SetInt32(statusCode, RBUS_ERROR_INVALID_INPUT);
        goto set_response_and_return;
    }

    const char *valid_ops[] = {"start", "stop", "restart", "reload", "enable", "disable", "status"};
    bool valid = false;
    for (size_t i = 0; i < ARRAY_SZ(valid_ops); i++)
    {
        if (strcmp(operation, valid_ops[i]) == 0)
        {
            valid = true;
            break;
        }
    }
    if (!valid)
    {
        CcspTraceError(("Unsupported operation: %s\n", operation));
        rbusValue_SetString(message, "Unsupported operation");
        rbusValue_SetInt32(statusCode, RBUS_ERROR_INVALID_INPUT);
        goto set_response_and_return;
    }

    CcspTraceInfo(("systemd operation '%s' on '%s'\n",  operation ? operation : "NULL", service_name ? service_name : "NULL"));

/* Async handling
    PASYNC_SERVICE_CTXT pContext = malloc(sizeof(ASYNC_SERVICE_CTXT));
    if (!pContext)
    {
        CcspTraceError(("Memory allocation failed\n"));
        return RBUS_ERROR_BUS_ERROR;
    }

    pContext->asyncHandle = asyncHandle;
    strncpy(pContext->service, service_name, sizeof(pContext->service) - 1);
    strncpy(pContext->operation, operation, sizeof(pContext->operation) - 1);
    pContext->service[sizeof(pContext->service) - 1] = '\0';
    pContext->operation[sizeof(pContext->operation) - 1] = '\0';

    pthread_t tid;
    if (pthread_create(&tid, NULL, service_handler_thread, pContext) != 0)
    {
        CcspTraceError(("Thread creation failed\n"));
        free(pContext);
        return RBUS_ERROR_BUS_ERROR;
    }
    pthread_detach(tid);
    return RBUS_ERROR_ASYNC_RESPONSE;
*/

    int exit_code = -1;
    FILE *fp = v_secure_popen("r", "systemctl %s %s", operation, service_name);
    if (fp)
    {
        int status = pclose(fp);
        if (WIFEXITED(status))
            exit_code = WEXITSTATUS(status);
        else
        {
            CcspTraceError(("Script terminated abnormally\n"));
        }
    }
    else
    {
        CcspTraceError(("popen failed\n"));
        rbusValue_SetString(message, "System command execution failed");
        rbusValue_SetInt32(statusCode, RBUS_ERROR_ACCESS_NOT_ALLOWED);
        goto set_response_and_return;
    }

    CcspTraceInfo(("systemctl command exit_code = %d\n", exit_code));

    char msg_buf[256];
    snprintf(msg_buf, sizeof(msg_buf), "Operation: '%s' on Service: '%s' %s.",operation, service_name, (exit_code == 0) ? "Succeeded" : "Failed");
    rbusValue_SetString(message, msg_buf);
    rbusValue_SetInt32(statusCode, exit_code);

set_response_and_return:
    rbusObject_SetValue(outParams, "message", message);
    rbusObject_SetValue(outParams, "statusCode", statusCode);

    int response_ret = rbusValue_GetInt32(statusCode);

    if (message) rbusValue_Release(message);
    if (statusCode) rbusValue_Release(statusCode);

    CcspTraceInfo(("******************* ServiceHandler completed *******************\n"));

    return (response_ret == 0) ? RBUS_ERROR_SUCCESS : response_ret;
}

/**********************************************************************
    function:
        Method_ExecuteScriptHandler
    description:
        RBUS method handler to execute script
    arguments:
        rbusHandle_t handle
        const char* methodName
        rbusObject_t inParams
        rbusObject_t outParams
        rbusMethodAsyncHandle_t asyncHandle
    return:
        rbusError_t
**********************************************************************/
rbusError_t Method_ExecuteScriptHandler(rbusHandle_t handle, const char* methodName,
                                rbusObject_t inParams, rbusObject_t outParams,
                                rbusMethodAsyncHandle_t asyncHandle)
{
    (void)handle;
    (void)methodName;
    (void)asyncHandle;

    rbusValue_t message, statusCode;
    rbusValue_Init(&message);
    rbusValue_Init(&statusCode);
    const char *path = NULL;

    CcspTraceInfo(("Method invoked: %s\n", methodName));

    rbusValue_t val = rbusObject_GetValue(inParams, "path");
    if (!val)
    {
        CcspTraceError(("Missing required parameter: path\n"));
        rbusValue_SetString(message, "Missing 'path' parameter");
        rbusValue_SetInt32(statusCode, RBUS_ERROR_INVALID_INPUT);
        goto set_response_and_return;
    }

    path = rbusValue_GetString(val, NULL);
    if (!path || !*path)
    {
        CcspTraceError(("Empty path parameter\n"));
        rbusValue_SetString(message, "Empty 'path' value");
        rbusValue_SetInt32(statusCode, RBUS_ERROR_INVALID_INPUT);
        goto set_response_and_return;
    }

    char resolved_path[PATH_MAX];
    if (!realpath(path, resolved_path))
    {
        CcspTraceError(("Path resolution failed for '%s'\n", path));
        rbusValue_SetString(message, "Path resolution failed");
        rbusValue_SetInt32(statusCode,
            (errno == EACCES) ? RBUS_ERROR_ACCESS_NOT_ALLOWED : RBUS_ERROR_INVALID_INPUT);
        goto set_response_and_return;
    }

    if (access(resolved_path, X_OK) != 0)
    {
        CcspTraceError(("Execute permission denied for '%s'\n", resolved_path));
        rbusValue_SetString(message, "Execute permission denied");
        rbusValue_SetInt32(statusCode, RBUS_ERROR_ACCESS_NOT_ALLOWED);
        goto set_response_and_return;
    }

    CcspTraceInfo(("Path is valid and executable.\n"));

    /* Commenting out for future async handling

    PASYNC_EXEC_CTXT pContext = (PASYNC_EXEC_CTXT)AnscAllocateMemory(sizeof(ASYNC_EXEC_CTXT));
    if (!pContext)
    {
        CcspTraceError(("Unable to allocate memory for script_exec thread, Abort\n"));
        return RBUS_ERROR_BUS_ERROR;
    }

    pContext->asyncHandle = asyncHandle;
    strncpy(pContext->script_path, resolved_path, PATH_MAX - 1);
    pContext->script_path[PATH_MAX - 1] = '\0';

    CcspTraceInfo(("Calling exec_script_thread\n"));
    pthread_t script_exec_tid;
    if (pthread_create(&script_exec_tid, NULL, exec_script_thread, pContext) != 0)
    {
        CcspTraceError(("Thread creation failed\n"));
        free(pContext);
        return RBUS_ERROR_BUS_ERROR;
    }
    pthread_detach(script_exec_tid);

    */

    int ret = v_secure_system("/bin/sh %s", resolved_path);
    if(ret != 0)
    {
        CcspTraceError(("Failure in executing command via v_secure_system. ret:[%d] \n",ret));
        rbusValue_SetString(message, "Execution failed with v_secure_system");
        rbusValue_SetInt32(statusCode, ret);
    }
    else
    {
        CcspTraceInfo(("Execution Success.\n"));
        rbusValue_SetString(message, "Execution Success");
        rbusValue_SetInt32(statusCode, 0);
    }

set_response_and_return:
    rbusObject_SetValue(outParams, "message", message);
    rbusObject_SetValue(outParams, "statusCode", statusCode);
    int response_ret = rbusValue_GetInt32(statusCode);

    if (message) rbusValue_Release(message);
    if (statusCode) rbusValue_Release(statusCode);

    CcspTraceInfo(("Execution completed (status=%d)\n", response_ret));

    return (response_ret == 0) ? RBUS_ERROR_SUCCESS : response_ret;
}
