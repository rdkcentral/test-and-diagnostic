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

    module: cosa_wanconnectivity_apis.h

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file defines the apis for diagnostic related
        objects to support Data Model Library.

    -------------------------------------------------------------------


    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**************************************************************************/


#ifndef  _COSA_WANCHK_APIS_H
#define  _COSA_WANCHK_APIS_H

#include "cosa_apis.h"
#include "ccsp_base_api.h"
#include <rbus/rbus.h>
#include "sysevent/sysevent.h"
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include "rdk_debug.h"

/* supporting only primary and secondary now*/
#define MAX_INTF_NAME_SIZE 64
#define MAX_URL_SIZE 255
#define MAX_RECORD_TYPE_SIZE 64
#define MAX_SERVER_TYPE_SIZE 64
#define IPv6_STR_LEN 46
#define IPv4_STR_LEN 16
#define MACADDR_SZ 18
#define  ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))

#define ALIAS_CHECK_DML          "Device.X_RDK_WanManager.InterfaceAvailableStatus"
#define ACTIVE_GATEWAY_DML       "Device.X_RDK_GatewayManagement.ActiveGateway"
#define DNS_SRV_COUNT_DML        "Device.DNS.Client.ServerNumberOfEntries"
#define DNS_SRV_TABLE_DML        "Device.DNS.Client.Server."
#define DNS_SRV_ENTRY_DML        "Device.DNS.Client.Server.%d.DNSServer"
#define X_RDK_REMOTE_INVOKE      "Device.X_RDK_Remote.Invoke()"
#define WANCHK_TEST_URL_TABLE    "Device.Diagnostics.X_RDK_DNSInternet.TestURL."
#define WANCHK_TEST_URL_INSTANCE "Device.Diagnostics.X_RDK_DNSInternet.TestURL.%d.TestURL"
#define WANCHK_INTF_TABLE        "Device.Diagnostics.X_RDK_DNSInternet.WANInterface."

// Debug definitions. This will be enabled/disabled via debug.ini
#define WANCHK_LOG_ENTER(fmt...)  RDK_LOG(RDK_LOG_TRACE1,  "LOG.RDK.WANCNCTVTYCHK", fmt)
#define WANCHK_LOG_NOTICE(fmt...) RDK_LOG(RDK_LOG_NOTICE,  "LOG.RDK.WANCNCTVTYCHK", fmt)
#define WANCHK_LOG_RETURN(fmt...) RDK_LOG(RDK_LOG_TRACE1,  "LOG.RDK.WANCNCTVTYCHK", fmt)
#define WANCHK_LOG_ERROR(fmt...)  RDK_LOG(RDK_LOG_ERROR,   "LOG.RDK.WANCNCTVTYCHK", fmt)
#define WANCHK_LOG_WARN(fmt...)   RDK_LOG(RDK_LOG_WARN,    "LOG.RDK.WANCNCTVTYCHK", fmt)
#define WANCHK_LOG_INFO(fmt...)   RDK_LOG(RDK_LOG_INFO,    "LOG.RDK.WANCNCTVTYCHK", fmt)
#define WANCHK_LOG_DBG(fmt...)    RDK_LOG(RDK_LOG_DEBUG,   "LOG.RDK.WANCNCTVTYCHK", fmt)


#define DEFAULT_URL_COUNT 1
#define DEFAULT_URL "www.google.com"

#define BUFLEN_8 8
#define BUFLEN_64 64
#define BUFLEN_128 128
#define BUFLEN_256 256
#define BUFLEN_1024 1024
#define BUFLEN_2048 2048
#define BUFLEN_4096 4096

#define SE_SERVER_WELL_KNOWN_PORT 52367
#define SE_VERSION 1

#define DEF_INTF_ENABLE TRUE
#define DEF_PASSIVE_MONITOR_PRIMARY_ENABLE TRUE
#define DEF_PASSIVE_MONITOR_BACKUP_ENABLE FALSE
#define DEF_PASSIVE_MONITOR_TIMEOUT 12000
#define DEF_ACTIVE_MONITOR_PRIMARY_ENABLE TRUE
#define DEF_ACTIVE_MONITOR_BACKUP_ENABLE FALSE
#define DEF_ACTIVE_MONITOR_INTERVAL 12000
#define DEF_QUERY_TIMEOUT 10000
#define DEF_QUERY_RETRY 1
#define DEF_QUERY_RECORDTYPE "A+AAAA"
#define DEF_QUERY_SERVERTYPE "IPv4+IPv6"

typedef enum _cfg_change_bitmask {
    /* config bit masks*/
    INTF_CFG_ENABLE = (1 << 0),
    INTF_CFG_PASSIVE_ENABLE = (1 << 1),
    INTF_CFG_PASSIVE_TIMEOUT = (1 << 2),
    INTF_CFG_ACTIVE_ENABLE = (1 << 3),
    INTF_CFG_ACTIVE_INTERVAL = (1 << 4),
    INTF_CFG_QUERYNOW_ENABLE = (1 << 5),
    INTF_CFG_QUERY_TIMEOUT = (1 << 6),
    INTF_CFG_QUERY_RETRY = (1 << 7),
    INTF_CFG_RECORDTYPE = (1 << 8),
    INTF_CFG_SERVERTYPE = (1 << 9),
    INTF_CFG_ALL = 0xFFFF,
} cfg_change_bitmask_t;


typedef enum _dns_entry_type {
        DNS_SRV_NONE  = 0,
        DNS_SRV_IPV4  = 1,
        DNS_SRV_IPV6  = 2,
} dns_entrytype_t;

typedef enum _monitor_result {
        MONITOR_RESULT_UNKNOWN  = 0,
        MONITOR_RESULT_CONNECTED  = 1,
        MONITOR_RESULT_DISCONNECTED  = 2,
} monitor_result_t;

typedef enum _querynow_result {
        QUERYNOW_RESULT_UNKNOWN  = 0,
        QUERYNOW_RESULT_CONNECTED  = 1,
        QUERYNOW_RESULT_DISCONNECTED  = 2,
        QUERYNOW_RESULT_BUSY=3,
} querynow_result_t;

typedef enum _IDM_MSG_OPERATION
{
    IDM_SET = 1,
    IDM_GET,
    IDM_SUBS,
    IDM_REQUEST,

}IDM_MSG_OPERATION;

typedef enum _dml_type_t {
        FEATURE_DML  = 1,
        FEATURE_ENABLED_DML  = 2,
} dml_type_t;

typedef struct _idm_invoke_method_Params
{
    IDM_MSG_OPERATION operation;
    char Mac_dest[18];
    char param_name[128];
    char param_value[2048];
    uint timeout;
    enum dataType_e type;
    rbusMethodAsyncHandle_t asyncHandle;
}idm_invoke_method_Params_t;

typedef enum _service_type {
        PASSIVE_MONITOR_THREAD  = 0,
        ACTIVE_MONITOR_THREAD   = 1,
        QUERYNOW_THREAD =2,
        PASSIVE_ACTIVE_MONITOR_THREADS  = 3,
        ALL_THREADS = 4,
} service_type_t;

typedef  struct
_COSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_TABLE
{
    dns_entrytype_t dns_type;
    UCHAR                           IPv4Address[IPv4_STR_LEN];
}
COSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO,  *PCOSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO;

typedef  struct
_COSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_TABLE
{
    dns_entrytype_t dns_type;
    UCHAR                           IPv6Address[IPv6_STR_LEN];
}
COSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO,  *PCOSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO;

typedef  struct
_COSA_DML_WANCNCTVTY_CHK_INTF_TABLE
{
    BOOL                                          Enable;
    UCHAR                                         Alias[MAX_INTF_NAME_SIZE];/* Wan interface primary or backup */
    UCHAR                                         InterfaceName[MAX_INTF_NAME_SIZE];/* Wan interface name */
    BOOL                                          PassiveMonitor;
    ULONG                                         PassiveMonitorTimeout;
    BOOL                                          ActiveMonitor;
    ULONG                                         ActiveMonitorInterval;
    ULONG                                         MonitorResult;
    BOOL                                          QueryNow;
    ULONG                                         QueryNowResult;
    ULONG                                         QueryTimeout;
    ULONG                                         QueryRetry;
    UCHAR                                         RecordType[MAX_RECORD_TYPE_SIZE];
    UCHAR                                         ServerType[MAX_SERVER_TYPE_SIZE];
    ULONG                                         InstanceNumber;
    uint32_t                                      Cfg_bitmask;
    BOOL                                          Configured;
    uint32_t                                      MonitorResult_SubsCount;
    uint32_t                                      QueryNowResult_SubsCount;
    UCHAR                                         IPv4Gateway[IPv4_STR_LEN];
    UCHAR                                         IPv6Gateway[IPv6_STR_LEN];
}
COSA_DML_WANCNCTVTY_CHK_INTF_INFO,  *PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO;

typedef  struct
_COSA_DML_WANCNCTVTY_CHK_URL_TABLE
{
    UCHAR                           URL[MAX_URL_SIZE];
    ULONG                           InstanceNumber;
}
COSA_DML_WANCNCTVTY_CHK_URL_INFO,  *PCOSA_DML_WANCNCTVTY_CHK_URL_INFO;

#define  COSA_DATAMODEL_WANCNCTVTY_CHK_CLASS_CONTENT                                                     \
    BOOL                          Enable;                                                                \
    BOOL                          Active;                                                                \
    SLIST_HEADER                  pUrlList;                                                              \
    ULONG                         ulUrlNextInsNum;                                                       \
    SLIST_HEADER                  pIntfTableList;                                                        \
    ULONG                         ulNextInterfaceInsNum;                                                 \
    /* End of base object class content*/                                                                \

typedef  struct
_COSA_DATAMODEL_WANCNCTVTY_CHK
{
    COSA_DATAMODEL_WANCNCTVTY_CHK_CLASS_CONTENT
}
COSA_DATAMODEL_WANCNCTVTY_CHK,  *PCOSA_DATAMODEL_WANCNCTVTY_CHK;

typedef enum _dns_record_type {
        IPV4_ONLY  = 1,
        IPV6_ONLY  = 2,
        BOTH_IPV4_IPV6    = 3,
        EITHER_IPV4_IPV6  = 4,
        RECORDTYPE_INVALID
} recordtype_t;

typedef enum _dns_server_type {
        SRVR_IPV4_ONLY  = 1,
        SRVR_IPV6_ONLY  = 2,
        SRVR_BOTH_IPV4_IPV6    = 3,
        SRVR_EITHER_IPV4_IPV6  = 4,
        SRVR_TYPE_INVALID
} servertype_t;

typedef  struct
_COSA_DML_WANCNCTVTY_CHK_QUERYNOW_CTXT
{
    ULONG     InstanceNumber;
    BOOL      IsPrimary;
    ULONG     QueryTimeout;
    ULONG     QueryRetry;
    unsigned int IPv4DnsServerCount;
    unsigned int IPv6DnsServerCount;
    unsigned int url_count;
    recordtype_t RecordType;
    servertype_t ServerType;
    UCHAR     InterfaceName[MAX_INTF_NAME_SIZE];
    UCHAR     Alias[MAX_INTF_NAME_SIZE];
    char      **url_list;
    PCOSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO  IPv4DnsServerList;
    PCOSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO  IPv6DnsServerList;
    BOOL      doInfoLogOnce;
    BOOL      QueryInProgress;
    ULONG     ActiveMonitorInterval;
    pthread_t timercb_tid;
    UCHAR     IPv4Gateway[IPv4_STR_LEN];
    UCHAR     IPv6Gateway[IPv6_STR_LEN];
}
COSA_DML_WANCNCTVTY_CHK_QUERYNOW_CTXT_INFO,  *PCOSA_DML_WANCNCTVTY_CHK_QUERYNOW_CTXT_INFO;

typedef  struct
_COSA_DML_WANCNCTVTY_CHK_ACTIVEQUERY_CTXT
{
    BOOL      PassiveMonitor;
    ULONG     ActiveMonitorInterval;
    PCOSA_DML_WANCNCTVTY_CHK_QUERYNOW_CTXT_INFO pQueryCtxt;
}
COSA_DML_WANCNCTVTY_CHK_ACTIVEQUERY_CTXT_INFO,  *PCOSA_DML_WANCNCTVTY_CHK_ACTIVEQUERY_CTXT_INFO;

typedef enum
_COSA_WAN_CNCTVTY_CHK_EVENTS
{
      INTF_PRIMARY = 1,
      INTF_SECONDARY

} COSA_WAN_CNCTVTY_CHK_EVENTS;

typedef  struct
_WANCNCTVTY_CHK_GLOBAL_INTF_INFO
{
    COSA_DML_WANCNCTVTY_CHK_INTF_INFO             IPInterface;
    PCOSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO      IPv4DnsServerList;
    PCOSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO      IPv6DnsServerList;
    unsigned int                                  IPv4DnsServerCount;
    unsigned int                                  IPv6DnsServerCount;
    BOOL                                          Dns_configured;
    pthread_t                                     wancnctvychkpassivethread_tid;
    BOOL                                          PassiveMonitor_Running;
    pthread_t                                     wancnctvychkactivethread_tid;
    BOOL                                          ActiveMonitor_Running;
    pthread_t                                     wancnctvychkquerynowthread_tid;
    BOOL                                          QueryNow_Running;
    struct _WANCNCTVTY_CHK_GLOBAL_INTF_INFO       *next;
}
WANCNCTVTY_CHK_GLOBAL_INTF_INFO,  *PWANCNCTVTY_CHK_GLOBAL_INTF_INFO;
// typedef struct
// _ASYNC_EXEC_CTXT {
//     rbusMethodAsyncHandle_t asyncHandle;
//     char script_path[PATH_MAX];
// } ASYNC_EXEC_CTXT, *PASYNC_EXEC_CTXT;

// typedef struct
// _ASYNC_SERVICE_CTXT {
//     rbusMethodAsyncHandle_t asyncHandle;
//     char service[128];
//     char operation[32];
// } ASYNC_SERVICE_CTXT, *PASYNC_SERVICE_CTXT;


/*************************************
    The actual function declaration
**************************************/

ANSC_STATUS CosaWanCnctvtyChk_Init (VOID);
ANSC_STATUS CosaWanCnctvtyChk_Init_URLTable (VOID);
ANSC_STATUS CosaWanCnctvtyChk_Init_Intf (char* if_name, char* alias, char *IPv4_nameserver_list,
                                         char *IPv6_nameserver_list, int IPv4DnsServerCount,
                                         int IPv6DnsServerCount, char* IPv4_Gateway, char* IPv6_Gateway);
ANSC_STATUS CosaWanCnctvtyChk_IfGetEntry(PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO pIPInterface);
BOOL CosaWanCnctvtyChk_GetActive_Status(void);
ANSC_STATUS CosaWanCnctvtyChk_SubscribeActiveGW(void);
ANSC_STATUS CosaWanCnctvtyChk_UnSubscribeActiveGW(void);
void handle_actv_status_event (BOOL new_status);
ANSC_STATUS CosaWanCnctvtyChk_Remove_Intf (ULONG IntfIndex);
ANSC_STATUS CosaDmlGetIntfCfg(PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO pIPInterface,BOOL use_default);
ANSC_STATUS CosaDml_glblintfdb_delentry(ULONG InstanceNumber);
ANSC_STATUS CosaDml_glblintfdb_updateentry(PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO pIPInterface);
ANSC_STATUS CosaDml_glblintfdb_update_dnsentry(char *InterfaceName,unsigned int IPv4DnsServerCount,
                                               unsigned int IPv6DnsServerCount,
                                               PCOSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO pIPv4DnsSrvInfo,
                                               PCOSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO pIPv6DnsSrvInfo);
ANSC_STATUS CosaDml_querynow_result_get(ULONG InstanceNumber,querynow_result_t *result);
ANSC_STATUS CosaDml_monitor_result_get(ULONG InstanceNumber,monitor_result_t *result);
ANSC_STATUS CosaWanCnctvtyChk_Urllist_dump (VOID);
ANSC_STATUS CosaWanCnctvtyChk_Interface_dump (ULONG InstanceNumber);
ANSC_STATUS is_valid_interface(const char *if_name);
ANSC_STATUS is_valid_aliasName(const char *alias);
ANSC_STATUS validate_DNS_nameservers (char* IPv4_nameserver_list, char* IPv6_nameserver_list, 
                                      int* IPv4DnsServerCount, int* IPv6DnsServerCount);
ANSC_STATUS WanCnctvtyChk_GetParameterValue(  const char *pParamName, char *pReturnVal );
rbusError_t WANCNCTVTYCHK_PublishEvent(char* event_name , uint32_t eventNewData, uint32_t eventOldData);
ULONG GetInstanceNo_FromName(char *InterfaceName);
PWANCNCTVTY_CHK_GLOBAL_INTF_INFO get_InterfaceList (ULONG InstanceNumber);
PWANCNCTVTY_CHK_GLOBAL_INTF_INFO get_InterfaceFromAlias(char *Alias);
PWANCNCTVTY_CHK_GLOBAL_INTF_INFO create_InterfaceList (ULONG InstanceNumber);
BOOL check_for_change_in_dns(char* alias, char* Ipv4_nameserver_list, char* IPv6_nameserver_list, 
                                                       int newIPv4DnsCount, int newIPv6DnsCount);
ANSC_STATUS CosaWanCnctvtyChk_DNS_UpdateEntry(char *InterfaceName, char* alias, char *IPv4_nameserver_list,
                                              char *IPv6_nameserver_list, int IPv4DnsServerCount, int IPv6DnsServerCount);
// void* exec_script_thread(void* arg);
// void* service_handler_thread(void* arg);
#endif
