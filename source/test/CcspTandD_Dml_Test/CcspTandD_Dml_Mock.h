/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2024 RDK Management
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

#include <filesystem>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <experimental/filesystem>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_securewrapper.h>
#include <mocks/mock_usertime.h>
#include <mocks/mock_dslh_dmagnt_exported.h>
#include <mocks/mock_ansc_wrapper_api.h>
#include <mocks/mock_trace.h>
#include <mocks/mock_msgpack.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_ansc_memory.h>
#include <mocks/mock_util.h>
#include <mocks/mock_base_api.h>
#include <mocks/mock_base64.h>
#include <mocks/mock_rbus.h>
#include <mocks/mock_cm_hal.h>
#include <mocks/mock_platform_hal.h>
#include <mocks/mock_cJSON.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_rdklogger.h>
#include <mocks/mock_webconfigframework.h>
#include <mocks/mock_ansc_task.h>
#include <mocks/mock_libev.h>
#include <mocks/mock_resolv.h>
#include <mocks/mock_pcap.h>
#include <mocks/mock_psm.h>
#include <mocks/mock_file_io.h>
#include <mocks/mock_libnet.h>
#include <mocks/mock_messagebus.h>

#define SPEEDTEST_ARG_SIZE 4096
#define SPEEDTEST_AUTH_SIZE 4096
#define SPEEDTEST_VERSION_SIZE 32

extern "C" {
#include "plugin_main_apis.h"
#include "cosa_apis.h"
#include "ccsp_base_api.h"
#include "cosa_dml_api_common.h"
#include "cosa_diagnostic_apis.h"
#include <rbus/rbus.h>
#include "cosa_dml_api_common.h"
#include "cosa_dns_dml.h"
#include "cosa_apis_busutil.h"
#include "cosa_apis_util.h"
#include "cosa_apis_vendorlogfile.h"	
#include "cosa_hwst_dml.h"
#include "cosa_ip_dml.h"
#include "cosa_logbackup_dml.h"
#include "cosa_powermgt_tcxb6_dml.h"
#include "cosa_selfheal_apis.h"
#include "cosa_selfheal_dml.h"
#include "cosa_thermal_dml.h" 
#include "plugin_main.h"
#include "diag.h"
#include "diag_inter.h"
#include "ansc_platform.h"
extern void copy_command_output(FILE *fp, char * buf, int len);
extern ANSC_HANDLE bus_handle;
extern char g_SubSysPrefix_Irep[32];
extern ANSC_HANDLE g_MessageBusHandle_Irep;
extern char g_Subsystem[32];
extern COSAGetParamValueByPathNameProc g_GetParamValueByPathNameProc;

extern char g_argument_speedtest[SPEEDTEST_ARG_SIZE + 1] ;
extern char g_authentication_speedtest[SPEEDTEST_AUTH_SIZE + 1] ;
extern char g_clientversion_speedtest[SPEEDTEST_VERSION_SIZE + 1];

extern BOOL SelfHeal_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                        bValue
    );

extern BOOL SelfHeal_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

extern BOOL
SelfHeal_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );

extern BOOL
SelfHeal_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    );

extern ULONG
SelfHeal_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

extern BOOL
SelfHeal_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    );

extern BOOL
SelfHeal_Validate
   (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

extern ULONG
SelfHeal_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

extern ULONG
SelfHeal_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

extern BOOL ConnectivityTest_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                        bValue
    );

extern BOOL ConnectivityTest_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );

extern BOOL
ResourceMonitor_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );

extern BOOL
ResourceMonitor_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    );

extern BOOL
ResourceMonitor_Validate
   (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    );

extern ULONG
ResourceMonitor_Commit
    (
        ANSC_HANDLE                 hInsContext
    );

extern ULONG
ResourceMonitor_Rollback
    (
        ANSC_HANDLE                 hInsContext
    );

extern ULONG
Fan_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    );

extern ANSC_HANDLE
Fan_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    );

void PopulateParameters();
void check_lte_provisioned(char* lte_wan,char* lte_backup_enable, char* lte_interface_enable, char* ipaddr_family);
}

#define atomic_int volatile int
typedef struct rtRetainable
{
  atomic_int refCount;
} rtRetainable;

typedef struct _rbusBuffer
{
    int             lenAlloc;
    int             posWrite;
    int             posRead;
    uint8_t*        data;
    uint8_t         block1[64];
} *rbusBuffer_t;

struct _rbusValue
{
    rtRetainable retainable;
    union
    {
        bool                    b;
        char                    c;
        unsigned char           u;
        int8_t                  i8;
        uint8_t                 u8;
        int16_t                 i16;
        uint16_t                u16;
        int32_t                 i32;
        uint32_t                u32;
        int64_t                 i64;
        uint64_t                u64;
        float                   f32;
        double                  f64;
        rbusDateTime_t          tv;
        rbusBuffer_t            bytes;
        struct  _rbusProperty*  property;
        struct  _rbusObject*    object;
    } d;
    rbusValueType_t type;
};

#ifdef __cplusplus
extern "C" {
#endif

struct xle_attributes
{
    int devicemode;
    int is_lte_wan_up;
    int iswan_dhcp_client;
    int iswan_dhcp_server;
    int isdhcp_server_running;
    char mesh_wan_status[128];
    int is_ipv6present;
    int is_ipv4present;
    int is_ipv4_wan_route_table;
    int is_ipv6_wan_route_table;
    int is_ipv4_mesh_route_table;
    int is_ipv6_mesh_route_table;
    int is_ipv4_mesh_brWan_link;
    int is_ipv6_mesh_brWan_link;
    int is_default_route;
    int is_mesh_default_route;
    int cellular_restart_count;
};

// Declaration only — actual definition should be in the .c file
extern struct xle_attributes xle_params;

#ifdef __cplusplus
}
#endif

using namespace std;
using namespace testing;
using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::HasSubstr;
using ::testing::SetArrayArgument;
using std::experimental::filesystem::exists;
using ::testing::DoAll;

extern SyscfgMock *g_syscfgMock;
extern SecureWrapperMock *g_securewrapperMock;
extern msgpackMock *g_msgpackMock;
extern UserTimeMock *g_usertimeMock;
extern SafecLibMock *g_safecLibMock;
extern AnscMemoryMock *g_anscMemoryMock;
extern BaseAPIMock *g_baseapiMock;
extern TraceMock *g_traceMock;
extern base64Mock *g_base64Mock;
extern rbusMock *g_rbusMock;
extern CmHalMock *g_cmHALMock;
extern PlatformHalMock *g_platformHALMock;
extern cjsonMock *g_cjsonMock;
extern SyseventMock *g_syseventMock;
extern webconfigFwMock *g_webconfigFwMock;
extern AnscWrapperApiMock * g_anscWrapperApiMock;
extern DslhDmagntExportedMock* g_dslhDmagntExportedMock;
extern rdkloggerMock * g_rdkloggerMock;
extern UtilMock * g_utilMock;
extern AnscTaskMock * g_anscTaskMock;
extern LibevMock * g_libevMock;
extern PsmMock * g_psmMock;
extern PcapMock * g_pcapMock;
extern ResolvMock* g_resolvMock;
extern FileIOMock * g_fileIOMock;
extern LibnetMock * g_libnetMock;
extern MessageBusMock * g_messagebusMock;
