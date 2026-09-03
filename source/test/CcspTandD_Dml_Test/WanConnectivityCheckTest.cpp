/*
* If not stated otherwise in this file or this component's LICENSE
* file the following copyright and licenses apply:
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
#include "CcspTandD_Dml_Mock.h"

extern "C"
{
#include "cosa_wanconnectivity_apis.h"
extern ANSC_STATUS wancnctvty_chk_start_threads(ULONG InstanceNumber,service_type_t type);
extern ANSC_STATUS wancnctvty_chk_stop_threads(ULONG InstanceNumber,service_type_t type);
extern ANSC_STATUS wancnctvty_chk_monitor_result_update(ULONG InstanceNumber,monitor_result_t result);
extern ANSC_STATUS wancnctvty_chk_querynow_result_update(ULONG InstanceNumber,querynow_result_t result);
#include "cosa_wanconnectivity_rbus_handler_apis.h"
#include "cosa_wanconnectivity_rbus_apis.h"
}

extern ANSC_HANDLE bus_handle;
extern char g_SubSysPrefix_Irep[32];
extern ANSC_HANDLE     g_MessageBusHandle_Irep;
extern char g_Subsystem[32]; 
extern COSAGetParamValueByPathNameProc g_GetParamValueByPathNameProc;
FILE *file;

extern ULONG gIntfCount;
extern ULONG gulUrlNextInsNum;
extern BOOL g_wanconnectivity_check_enable;
extern BOOL g_wanconnectivity_check_active;
extern rbusHandle_t rbus_handle;
extern rbusDataElement_t WANCHK_Feature_RbusDataElements[];
extern rbusDataElement_t WANCHK_Feature_Enabled_RbusElements[];
extern PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gInterface_List;
PWANCNCTVTY_CHK_GLOBAL_INTF_INFO intf_info1, intf_info2;
PCOSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO pIPv4DnsServerList;
PCOSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO pIPv6DnsServerList;

class WanConnectivityCheckTest : public ::testing::Test {
    protected:
    void SetUp() override {
        g_rbusMock = new rbusMock();
        g_utilMock = new UtilMock();
        g_fileIOMock = new FileIOMock();
        g_syseventMock = new SyseventMock();
        g_safecLibMock = new SafecLibMock();
        g_syscfgMock = new SyscfgMock();

        //Populating pIPv4DnsServerList
        pIPv4DnsServerList = new COSA_DML_WANCNCTVTY_CHK_IPv4DNSSRV_INFO[2];
        pIPv4DnsServerList[0].dns_type = DNS_SRV_IPV4;
        strcpy((char*)pIPv4DnsServerList[0].IPv4Address, "75.75.75.75");
        pIPv4DnsServerList[1].dns_type = DNS_SRV_IPV4;
        strcpy((char*)pIPv4DnsServerList[1].IPv4Address, "75.75.76.76");

        //Populating pIPv6DnsServerList
        pIPv6DnsServerList = new COSA_DML_WANCNCTVTY_CHK_IPv6DNSSRV_INFO[2];
        pIPv6DnsServerList[0].dns_type = DNS_SRV_IPV6;
        strcpy((char*)pIPv6DnsServerList[0].IPv6Address, "2001:558:feed::1");
        pIPv6DnsServerList[1].dns_type = DNS_SRV_IPV6;
        strcpy((char*)pIPv6DnsServerList[1].IPv6Address, "2001:558:feed::2");

        //Populating gInterface_List to be used by Test fixtures
        intf_info1 = new WANCNCTVTY_CHK_GLOBAL_INTF_INFO();
        intf_info1->IPInterface.Enable = FALSE;
        strcpy((char*)intf_info1->IPInterface.Alias, "DOCSIS");
        strcpy((char*)intf_info1->IPInterface.InterfaceName, "erouter0");
        intf_info1->IPInterface.PassiveMonitor = FALSE;
        intf_info1->IPInterface.PassiveMonitorTimeout = 12000;
        intf_info1->IPInterface.ActiveMonitor = TRUE;
        intf_info1->IPInterface.ActiveMonitorInterval = 12000;
        intf_info1->IPInterface.MonitorResult = 1;
        intf_info1->IPInterface.QueryNow = FALSE;
        intf_info1->IPInterface.QueryNowResult = 1;
        intf_info1->IPInterface.QueryTimeout = 10000;
        intf_info1->IPInterface.QueryRetry = 1;
        strcpy((char*)intf_info1->IPInterface.RecordType, "A+AAAA");
        strcpy((char*)intf_info1->IPInterface.ServerType, "IPv4+IPv6");
        intf_info1->IPInterface.InstanceNumber = 1;
        intf_info1->IPInterface.Cfg_bitmask = 0;
        intf_info1->IPInterface.Configured = FALSE;
        intf_info1->IPInterface.MonitorResult_SubsCount = 1;
        intf_info1->IPInterface.QueryNowResult_SubsCount = 1;
        intf_info1->IPv4DnsServerList = pIPv4DnsServerList;
        intf_info1->IPv6DnsServerList = pIPv6DnsServerList;
        intf_info1->IPv4DnsServerCount = 2;
        intf_info1->IPv6DnsServerCount = 2;
        intf_info1->Dns_configured = FALSE;
        intf_info1->wancnctvychkpassivethread_tid = 1;
        intf_info1->PassiveMonitor_Running = FALSE;
        intf_info1->wancnctvychkactivethread_tid = 1;
        intf_info1->ActiveMonitor_Running = FALSE;
        intf_info1->wancnctvychkquerynowthread_tid = 1;
        intf_info1->QueryNow_Running = FALSE;
        strcpy((char*)intf_info1->IPInterface.IPv4Gateway, "127.0.0.1");
        strcpy((char*)intf_info1->IPInterface.IPv6Gateway, "2001:558:feed::2");

        // Allocate memory for intf_info2 and initialize its members
        intf_info2 = new WANCNCTVTY_CHK_GLOBAL_INTF_INFO();
        intf_info2->IPInterface.Enable = TRUE;
        strcpy((char*)intf_info2->IPInterface.Alias, "REMOTE_LTE");
        strcpy((char*)intf_info2->IPInterface.InterfaceName, "brRWAN");
        intf_info2->IPInterface.PassiveMonitor = TRUE;
        intf_info2->IPInterface.PassiveMonitorTimeout = 12000;
        intf_info2->IPInterface.ActiveMonitor = TRUE;
        intf_info2->IPInterface.ActiveMonitorInterval = 12000;
        intf_info2->IPInterface.MonitorResult = 0;
        intf_info2->IPInterface.QueryNow = FALSE;
        intf_info2->IPInterface.QueryNowResult = 0;
        intf_info2->IPInterface.QueryTimeout = 10000;
        intf_info2->IPInterface.QueryRetry = 1;
        strcpy((char*)intf_info2->IPInterface.RecordType, "A+AAAA");
        strcpy((char*)intf_info2->IPInterface.ServerType, "IPv4+IPv6");
        intf_info2->IPInterface.InstanceNumber = 2;
        intf_info2->IPInterface.Cfg_bitmask = 0;
        intf_info2->IPInterface.Configured = FALSE;
        intf_info2->IPInterface.MonitorResult_SubsCount = 0;
        intf_info2->IPInterface.QueryNowResult_SubsCount = 0;
        intf_info2->IPv4DnsServerList = NULL;
        intf_info2->IPv6DnsServerList = NULL;
        intf_info2->IPv4DnsServerCount = 0;
        intf_info2->IPv6DnsServerCount = 0;
        intf_info2->Dns_configured = FALSE;
        intf_info2->wancnctvychkpassivethread_tid = 1;
        intf_info2->PassiveMonitor_Running = FALSE;
        intf_info2->wancnctvychkactivethread_tid = 1;
        intf_info2->ActiveMonitor_Running = FALSE;
        intf_info2->wancnctvychkquerynowthread_tid = 1;
        intf_info2->QueryNow_Running = FALSE;
        strcpy((char*)intf_info2->IPInterface.IPv4Gateway, "127.0.0.1");
        strcpy((char*)intf_info2->IPInterface.IPv6Gateway, "2001:558:feed::2");

        intf_info1->next = intf_info2;
        intf_info2->next = NULL;

        gInterface_List = intf_info1;
    }
    void TearDown() override {
        delete g_rbusMock;
        delete g_utilMock;
        delete g_fileIOMock;
        delete g_syseventMock;
        delete g_safecLibMock;
        delete g_syscfgMock;
        g_rbusMock = nullptr;
        g_utilMock = nullptr;
        g_fileIOMock = nullptr;
        g_syseventMock = nullptr;
        g_safecLibMock = nullptr;
        g_syscfgMock = nullptr;
    }
};

ACTION_TEMPLATE(SetArgNPointeeTo, HAS_1_TEMPLATE_PARAMS(unsigned, uIndex), AND_2_VALUE_PARAMS(pData, uiDataSize))
{
    memcpy(std::get<uIndex>(args), pData, uiDataSize);
}


TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_Init_FAIL_1) {
    ANSC_STATUS result;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("wan_connectivity_check"), _))
    .Times(1).WillOnce(Return(-1));

    result = CosaWanCnctvtyChk_Init();
    EXPECT_EQ(result, ANSC_STATUS_FAILURE);
}

TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_Init_FAIL_2) {
    ANSC_STATUS result;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("wan_connectivity_check"), _))
    .Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_rbusMock, rbus_checkStatus()).Times(1).WillOnce(Return(RBUS_ENABLED));
    EXPECT_CALL(*g_rbusMock, rbus_open(_, StrEq("WanCnctvtyChkEventConsumer"))).Times(1).WillOnce(Return(RBUS_ERROR_NOT_INITIALIZED));
    result = CosaWanCnctvtyChk_Init();
    EXPECT_EQ(result, ANSC_STATUS_FAILURE);
}

TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_Init_FAIL3) {
    ANSC_STATUS result;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("wan_connectivity_check"), _))
    .Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_rbusMock, rbus_checkStatus()).Times(1).WillOnce(Return(RBUS_ENABLED));
    EXPECT_CALL(*g_rbusMock, rbus_open(_, StrEq("WanCnctvtyChkEventConsumer"))).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbus_regDataElements(_, _, _)).Times(1).WillOnce(Return(RBUS_ERROR_NOT_INITIALIZED));

    result = CosaWanCnctvtyChk_Init();
    EXPECT_EQ(result, ANSC_STATUS_FAILURE);
}

TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_Init_FAIL4) {
    ANSC_STATUS result;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("wan_connectivity_check"), _))
    .Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_rbusMock, rbus_checkStatus()).Times(1).WillOnce(Return(RBUS_ENABLED));
    EXPECT_CALL(*g_rbusMock, rbus_open(_, StrEq("WanCnctvtyChkEventConsumer"))).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbus_regDataElements(_, 1, _)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));

    EXPECT_CALL(*g_rbusMock, rbus_open(_, StrEq("WanCnctvtyChkTableConsumer"))).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbus_regDataElements(_, 22, _)).Times(1).WillOnce(Return(RBUS_ERROR_NOT_INITIALIZED));

    result = CosaWanCnctvtyChk_Init();
    EXPECT_EQ(result, ANSC_STATUS_FAILURE);
}


TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_Init_SUCCESS) {
    ANSC_STATUS result;
    char url_entry[] = "1";
    char mock_url[] = "www.google.com";
    g_wanconnectivity_check_enable = TRUE;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("wan_connectivity_check"), _))
    .Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_rbusMock, rbus_checkStatus()).Times(1).WillOnce(Return(RBUS_ENABLED));
    EXPECT_CALL(*g_rbusMock, rbus_open(_, StrEq("WanCnctvtyChkEventConsumer"))).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbus_regDataElements(_, _, _)).WillRepeatedly(Return(RBUS_ERROR_SUCCESS));

    EXPECT_CALL(*g_rbusMock, rbus_open(_, StrEq("WanCnctvtyChkTableConsumer"))).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, StrEq("wanconnectivity_chk_url_1")))
    .Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_rbusMock, rbusTable_registerRow(_, _, _, _)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));

    result = CosaWanCnctvtyChk_Init();
    EXPECT_EQ(result, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_IfGetEntry_PASS) {
    ANSC_STATUS returnStatus;
    COSA_DML_WANCNCTVTY_CHK_INTF_INFO IPInterface;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    returnStatus = CosaWanCnctvtyChk_IfGetEntry(&IPInterface);
}

TEST_F(WanConnectivityCheckTest, handle_actv_status_event_CASE1) {
    g_wanconnectivity_check_active = FALSE;

    handle_actv_status_event(TRUE);
}

TEST_F(WanConnectivityCheckTest, handle_actv_status_event_CASE2) {
    g_wanconnectivity_check_active = TRUE;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(2);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, _, _)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    handle_actv_status_event(FALSE);
}

TEST_F(WanConnectivityCheckTest, CosaDmlGetIntfCfg_CASE1) {
    ANSC_STATUS returnStatus;
    COSA_DML_WANCNCTVTY_CHK_INTF_INFO IPInterface;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    returnStatus = CosaDmlGetIntfCfg(&IPInterface, TRUE);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, CosaDmlGetIntfCfg_CASE2) {
    ANSC_STATUS returnStatus;
    COSA_DML_WANCNCTVTY_CHK_INTF_INFO IPInterface;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    returnStatus = CosaDmlGetIntfCfg(&IPInterface, FALSE);
    EXPECT_EQ(returnStatus, ANSC_STATUS_FAILURE);
}

TEST_F(WanConnectivityCheckTest, CosaDmlGetIntfCfg_CASE3) {
    ANSC_STATUS returnStatus;
    COSA_DML_WANCNCTVTY_CHK_INTF_INFO IPInterface;
    IPInterface.InstanceNumber = 1;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    returnStatus = CosaDmlGetIntfCfg(&IPInterface, FALSE);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, CosaDml_glblintfdb_delentry) {
    gInterface_List->IPInterface.Configured = TRUE;
    ANSC_STATUS returnStatus;

    returnStatus = CosaDml_glblintfdb_delentry(1);

    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, CosaDml_glblintfdb_updateentry_FAIL) {
    ANSC_STATUS returnStatus;
    PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO pIPInterface = NULL;

    returnStatus = CosaDml_glblintfdb_updateentry(pIPInterface);
    EXPECT_EQ(returnStatus, ANSC_STATUS_FAILURE);
}

TEST_F(WanConnectivityCheckTest, CosaDml_glblintfdb_updateentry_PASS) {
    ANSC_STATUS returnStatus;
    PCOSA_DML_WANCNCTVTY_CHK_INTF_INFO pIPInterface = &(gInterface_List->IPInterface);

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    returnStatus = CosaDml_glblintfdb_updateentry(pIPInterface);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, GetInstanceNo_FromName_PASS) {
    ULONG instance_number;
    char intfName[] = "erouter0";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, StrEq("erouter0"), _, _, _))
    .WillOnce(DoAll(
        testing::SetArgPointee<3>(0),
        Return(EOK)
    ));

    instance_number = GetInstanceNo_FromName(intfName);
    EXPECT_EQ(instance_number, 1);
}

TEST_F(WanConnectivityCheckTest, GetInstanceNo_FromName_FAIL) {
    ULONG instance_number;
    char intfName[] = "eth0";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _)).WillRepeatedly(Return(-1));

    instance_number = GetInstanceNo_FromName(intfName);
    EXPECT_EQ(instance_number, -1);
}

TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_UnSubscribeActiveGW) {
    ANSC_STATUS returnStatus;

    returnStatus = CosaWanCnctvtyChk_UnSubscribeActiveGW();
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, CosaDml_querynow_result_get) {
    ANSC_STATUS returnStatus;
    querynow_result_t result;

    returnStatus = CosaDml_querynow_result_get(1, &result);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
    EXPECT_EQ(result, QUERYNOW_RESULT_CONNECTED);
}

TEST_F(WanConnectivityCheckTest, CosaDml_monitor_result_get) {
    ANSC_STATUS returnStatus;
    monitor_result_t result;

    returnStatus = CosaDml_monitor_result_get(1, &result);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
    EXPECT_EQ(result, MONITOR_RESULT_CONNECTED);
}

TEST_F(WanConnectivityCheckTest, check_for_change_in_dns_PASS1) {
    BOOL result;
    char alias[] = "DOCSIS";
    char IPv4_nameserver_list[] = "75.75.75.75,75.75.76.76";
    char IPv6_nameserver_list[] = "2001:558:feed::1,2001:558:feed::2";
    int newIPv4DnsCount = 2;
    int newIPv6DnsCount = 0;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq(alias), _, StrEq("DOCSIS"), _, _, _))
    .WillOnce(DoAll(
        testing::SetArgPointee<3>(0),
        Return(EOK)
    ));

    result = check_for_change_in_dns(alias, IPv4_nameserver_list, IPv6_nameserver_list, newIPv4DnsCount, newIPv6DnsCount);
    EXPECT_EQ(result, TRUE);
}

TEST_F(WanConnectivityCheckTest, check_for_change_in_dns_PASS2) {
    BOOL result;
    char alias[] = "DOCSIS";
    char IPv4_nameserver_list[] = "8.8.8.8,8.8.8.9";
    char IPv6_nameserver_list[] = "2001:558:feed::1,2001:558:feed::2";
    int newIPv4DnsCount = 2;
    int newIPv6DnsCount = 2;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq(alias), _, StrEq("DOCSIS"), _, _, _))
    .WillOnce(DoAll(
        testing::SetArgPointee<3>(0),
        Return(EOK)
    ));

    result = check_for_change_in_dns(alias, IPv4_nameserver_list, IPv6_nameserver_list, newIPv4DnsCount, newIPv6DnsCount);
    EXPECT_EQ(result, TRUE);
}

TEST_F(WanConnectivityCheckTest, check_for_change_in_dns_PASS3) {
    BOOL result;
    char alias[] = "DOCSIS";
    char IPv4_nameserver_list[] = "75.75.75.75,75.75.76.76";
    char IPv6_nameserver_list[] = "2001:558:feed::11,2001:558:feed::21";
    int newIPv4DnsCount = 2;
    int newIPv6DnsCount = 2;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq(alias), _, StrEq("DOCSIS"), _, _, _))
    .WillOnce(DoAll(
        testing::SetArgPointee<3>(0),
        Return(EOK)
    ));

    result = check_for_change_in_dns(alias, IPv4_nameserver_list, IPv6_nameserver_list, newIPv4DnsCount, newIPv6DnsCount);
    EXPECT_EQ(result, TRUE);
}

TEST_F(WanConnectivityCheckTest, check_for_change_in_dns_FAIL1) {
    BOOL result;
    char alias[] = "DUMMY";
    char IPv4_nameserver_list[] = "75.75.75.75,75.75.76.76";
    char IPv6_nameserver_list[] = "2001:558:feed::1,2001:558:feed::2";
    int newIPv4DnsCount = 2;
    int newIPv6DnsCount = 2;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _)).WillRepeatedly(Return(-1));

    result = check_for_change_in_dns(alias, IPv4_nameserver_list, IPv6_nameserver_list, newIPv4DnsCount, newIPv6DnsCount);
    EXPECT_EQ(result, FALSE);
}

TEST_F(WanConnectivityCheckTest, check_for_change_in_dns_FAIL2) {
    BOOL result;
    char alias[] = "DOCSIS";
    char IPv4_nameserver_list[] = "75.75.75.75,75.75.76.76";
    char IPv6_nameserver_list[] = "2001:558:feed::1,2001:558:feed::2";
    int newIPv4DnsCount = 2;
    int newIPv6DnsCount = 2;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq(alias), _, StrEq("DOCSIS"), _, _, _))
    .WillOnce(DoAll(
        testing::SetArgPointee<3>(0),
        Return(EOK)
    ));

    result = check_for_change_in_dns(alias, IPv4_nameserver_list, IPv6_nameserver_list, newIPv4DnsCount, newIPv6DnsCount);
    EXPECT_EQ(result, FALSE);
}

TEST_F(WanConnectivityCheckTest, is_valid_interface) {
    ANSC_STATUS returnStatus;
    char intfFile[] = "/sys/class/net/erouter0";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::SetArrayArgument<0>(intfFile, intfFile + strlen(intfFile) + 1),
        Return(0)
    ));
    EXPECT_CALL(*g_fileIOMock, access(StrEq("/sys/class/net/erouter0"), _)).Times(1).WillOnce(Return(0));

    returnStatus = is_valid_interface("erouter0");
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, is_valid_aliasName) {
    ANSC_STATUS returnStatus;

    rbus_handle = (rbusHandle_t)malloc(sizeof(rbusHandle_t));

    char paramName[] = "Device.X_RDK_WanManager.InterfaceAvailableStatus";

    char mockAlias[] = "DOCSIS";
    char* mockAliasDynamic = (char*)malloc(strlen(mockAlias) + 1);
    strcpy(mockAliasDynamic, mockAlias);

    // Setup mocks
    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbus_get(_, StrEq(paramName), _)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetType(_)).Times(1).WillOnce(Return(RBUS_STRING));
    EXPECT_CALL(*g_rbusMock, rbusValue_ToString(_, _, _)).Times(1).WillOnce(Return(mockAliasDynamic));  // Use the dynamic string
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    returnStatus = is_valid_aliasName("DOCSIS");

    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);

    free(rbus_handle);
}

TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_Remove_Intf_CASE1) {
    ANSC_STATUS returnStatus;
    int instance_number = 1;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(2);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, _, _)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    returnStatus = CosaWanCnctvtyChk_Remove_Intf(instance_number);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_Remove_Intf_CASE2) {
    ANSC_STATUS returnStatus;
    int instance_number = 1;
    gInterface_List->IPInterface.Configured = FALSE;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(2);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, _, _)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    returnStatus = CosaWanCnctvtyChk_Remove_Intf(instance_number);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_Init_Intf) {
    ANSC_STATUS returnStatus;
    char if_name[] = "erouter0";
    char alias[] = "DOCSIS";
    char IPv4_nameserver_list[] = "75.75.75.75,75.75.76.76";
    char IPv6_nameserver_list[] = "2001:558:feed::1,2001:558:feed::2";
    int IPv4DnsServerCount = 2;
    int IPv6DnsServerCount = 2;
    char IPv4_Gateway[] = "127.0.0.1";
    char IPv6_Gateway[] = "2001:558:feed::2";

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillRepeatedly(DoAll(
            testing::SetArgPointee<3>(0),
            Return(EOK)
        ));

    EXPECT_CALL(*g_rbusMock, rbusTable_registerRow(_, _, _, _)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));

    returnStatus = CosaWanCnctvtyChk_Init_Intf(if_name, alias, IPv4_nameserver_list, IPv6_nameserver_list, IPv4DnsServerCount, IPv6DnsServerCount, IPv4_Gateway, IPv6_Gateway);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, CosaWanCnctvtyChk_Urllist_dump) {
    ANSC_STATUS returnStatus;

    returnStatus = CosaWanCnctvtyChk_Urllist_dump();
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, validate_DNS_nameservers_1) {
    ANSC_STATUS returnStatus;
    char IPv4_nameserver_list[] = "75.75.75.75,75.75.76.76";
    char IPv6_nameserver_list[] = "2001:558:feed::1,2001:558:feed::2";
    int IPv4DnsServerCount = 0;
    int IPv6DnsServerCount = 0;

    returnStatus = validate_DNS_nameservers(IPv4_nameserver_list, IPv6_nameserver_list, &IPv4DnsServerCount, &IPv6DnsServerCount);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
    EXPECT_EQ(IPv4DnsServerCount, 2);
    EXPECT_EQ(IPv6DnsServerCount, 2);
}

TEST_F(WanConnectivityCheckTest, validate_DNS_nameservers_2) {
    ANSC_STATUS returnStatus;
    char *IPv4_nameserver_list = NULL;
    char IPv6_nameserver_list[] = "2001:558:feed::1,2001:558:feed::2";
    int IPv4DnsServerCount = 0;
    int IPv6DnsServerCount = 0;

    returnStatus = validate_DNS_nameservers(IPv4_nameserver_list, IPv6_nameserver_list, &IPv4DnsServerCount, &IPv6DnsServerCount);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
    EXPECT_EQ(IPv6DnsServerCount, 2);
}

TEST_F(WanConnectivityCheckTest, validate_DNS_nameservers_3) {
    ANSC_STATUS returnStatus;
    char IPv4_nameserver_list[] = "75.75.75.75,75.75.76.76";
    char *IPv6_nameserver_list = NULL;
    int IPv4DnsServerCount = 0;
    int IPv6DnsServerCount = 0;

    returnStatus = validate_DNS_nameservers(IPv4_nameserver_list, IPv6_nameserver_list, &IPv4DnsServerCount, &IPv6DnsServerCount);
    EXPECT_EQ(returnStatus, ANSC_STATUS_SUCCESS);
    EXPECT_EQ(IPv4DnsServerCount, 2);
}

TEST_F(WanConnectivityCheckTest, validate_DNS_nameservers_4) {
    ANSC_STATUS returnStatus;
    char IPv4_nameserver_list[] = "75.75.75.75,75.75.76.76,75.75.75.77,8.8.8.8,8.8.4.4";
    char IPv6_nameserver_list[] = "2001:558:feed::1,2001:558:feed::2,2001:558:feed::3,2001:558:feed::4,2001:558:feed::5";
    int IPv4DnsServerCount = 0;
    int IPv6DnsServerCount = 0;

    returnStatus = validate_DNS_nameservers(IPv4_nameserver_list, IPv6_nameserver_list, &IPv4DnsServerCount, &IPv6DnsServerCount);
    EXPECT_EQ(returnStatus, ANSC_STATUS_FAILURE);
    EXPECT_EQ(IPv4DnsServerCount, 5);
    EXPECT_EQ(IPv6DnsServerCount, 5);
}

//cosa_wanconnectivity_rbus_handler_apis.c
TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetHandler_CASE1) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.Enable"));
    EXPECT_CALL(*g_rbusMock, rbusValue_SetBoolean(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetHandler_CASE2) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.Active"));
    EXPECT_CALL(*g_rbusMock, rbusValue_SetBoolean(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetURLHandler_CASE1) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.TestURL.1.URL"));
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetURLHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetURLHandler_CASE2) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.TestURL.4.URL"));

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetURLHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_BUS_ERROR);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetURLHandler_CASE3) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.TestURL.1."));

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetURLHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_INVALID_INPUT);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetURLHandler_CASE4) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.TestURLNumberOfEntries"));
    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetURLHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetURLHandler_CASE5) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("NULL"));

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetURLHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_INVALID_INPUT);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SetHandler_CASE1) {
    g_wanconnectivity_check_enable = TRUE;
    gIntfCount = 1;
    rbusError_t result;
    rbusValue_t value = (rbusValue_t)malloc(sizeof(_rbusValue));

    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.Enable"));
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetValue(_)).Times(1).WillOnce(Return(value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetType(value)).Times(1).WillOnce(Return(RBUS_BOOLEAN));

    EXPECT_CALL(*g_rbusMock, rbusValue_GetBoolean(value)).Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(*g_rbusMock, rbus_unregDataElements(_, _, _)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbus_close(_)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(2);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, _, _)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    result = WANCNCTVTYCHK_SetHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
    free(value);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SetHandler_CASE1_FAIL) {
    g_wanconnectivity_check_enable = TRUE;
    gIntfCount = 1;
    rbusError_t result;
    rbusValue_t value = (rbusValue_t)malloc(sizeof(_rbusValue));

    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.Enable"));
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetValue(_)).Times(1).WillOnce(Return(value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetType(value)).Times(1).WillOnce(Return(RBUS_BOOLEAN));

    EXPECT_CALL(*g_rbusMock, rbusValue_GetBoolean(value)).Times(1).WillOnce(Return(FALSE));

    EXPECT_CALL(*g_rbusMock, rbus_unregDataElements(_, _, _)).Times(1).WillOnce(Return(RBUS_ERROR_BUS_ERROR));
    EXPECT_CALL(*g_rbusMock, rbus_close(_)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));

    result = WANCNCTVTYCHK_SetHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_BUS_ERROR);
    free(value);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SetHandler_CASE2) {
    g_wanconnectivity_check_enable = FALSE;
    rbusError_t result;
    rbusValue_t value = (rbusValue_t)malloc(sizeof(_rbusValue));

    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.Enable"));
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetValue(_)).Times(1).WillOnce(Return(value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetType(value)).Times(1).WillOnce(Return(RBUS_BOOLEAN));

    EXPECT_CALL(*g_rbusMock, rbusValue_GetBoolean(value)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(*g_rbusMock, rbus_open(_, StrEq("WanCnctvtyChkTableConsumer"))).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbus_regDataElements(_, _, _)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    
    result = WANCNCTVTYCHK_SetHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
    free(value);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SetHandler_CASE2_FAIL) {
    g_wanconnectivity_check_enable = FALSE;
    rbusError_t result;
    rbusValue_t value = (rbusValue_t)malloc(sizeof(_rbusValue));

    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.Enable"));
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetValue(_)).Times(1).WillOnce(Return(value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetType(value)).Times(1).WillOnce(Return(RBUS_BOOLEAN));

    EXPECT_CALL(*g_rbusMock, rbusValue_GetBoolean(value)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(*g_rbusMock, rbus_open(_, StrEq("WanCnctvtyChkTableConsumer"))).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbus_regDataElements(_, _, _)).Times(1).WillOnce(Return(RBUS_ERROR_BUS_ERROR));
    
    result = WANCNCTVTYCHK_SetHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_BUS_ERROR);
    free(value);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SetURLHandler) {
    rbusError_t result;
    rbusValue_t value = (rbusValue_t)malloc(sizeof(_rbusValue));

    char mockURL[256] = "www.google.com";
    char mockParam[] = "wanconnectivity_chk_url_1";

    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.TestURL.1.URL"));
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetValue(_)).Times(1).WillOnce(Return(value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetType(value)).Times(1).WillOnce(Return(RBUS_STRING));

    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(value, _)).Times(1).WillOnce(Return("www.facebook.com"));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, StrEq("wanconnectivity_chk_url_1")))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::SetArrayArgument<0>(mockParam, mockParam + strlen(mockParam) + 1),
        Return(0)
    ));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("wanconnectivity_chk_url_1"), _, _)).Times(1)
    .WillOnce(testing::DoAll(
              testing::SetArrayArgument<2>(mockURL, mockURL + strlen(mockURL) + 1),
              Return(0)
    ));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _)).Times(1).WillOnce(Return(-1));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, StrEq("0"))).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_commit()).Times(1).WillOnce(Return(0));

    result = WANCNCTVTYCHK_SetURLHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SubHandler_MonitorResult_CASE1) {
    rbusEventSubAction_t action = RBUS_EVENT_ACTION_SUBSCRIBE;
    char eventName[] = "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.MonitorResult";
    int interval = 10;
    bool autoPublish;
    rbusError_t result;

    result = WANCNCTVTYCHK_SubHandler(NULL, action, eventName, NULL, interval, &autoPublish);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);    
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SubHandler_MonitorResult_CASE2) {
    rbusEventSubAction_t action = RBUS_EVENT_ACTION_UNSUBSCRIBE;
    char eventName[] = "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.[DOCSIS].MonitorResult";
    int interval = 10;
    bool autoPublish;
    rbusError_t result;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, StrEq("DOCSIS"), _, _, _))
    .WillOnce(DoAll(
        testing::SetArgPointee<3>(0),
        Return(EOK)
    ));

    result = WANCNCTVTYCHK_SubHandler(NULL, action, eventName, NULL, interval, &autoPublish);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);    
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SubHandler_QueryNowResult_CASE1) {
    rbusEventSubAction_t action = RBUS_EVENT_ACTION_SUBSCRIBE;
    char eventName[] = "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.QueryNowResult";
    int interval = 10;
    bool autoPublish;
    rbusError_t result;

    result = WANCNCTVTYCHK_SubHandler(NULL, action, eventName, NULL, interval, &autoPublish);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);    
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SubHandler_QueryNowResult_CASE2) {
    rbusEventSubAction_t action = RBUS_EVENT_ACTION_UNSUBSCRIBE;
    char eventName[] = "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.[DOCSIS].QueryNowResult";
    int interval = 10;
    bool autoPublish;
    rbusError_t result;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, StrEq("DOCSIS"), _, _, _))
    .WillOnce(DoAll(
        testing::SetArgPointee<3>(0),
        Return(EOK)
    ));

    result = WANCNCTVTYCHK_SubHandler(NULL, action, eventName, NULL, interval, &autoPublish);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);    
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SubHandler_FAIL) {
    rbusEventSubAction_t action = RBUS_EVENT_ACTION_UNSUBSCRIBE;
    char eventName[] = "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.3.QueryNowResult";
    int interval = 10;
    bool autoPublish;
    rbusError_t result;

    result = WANCNCTVTYCHK_SubHandler(NULL, action, eventName, NULL, interval, &autoPublish);
    EXPECT_EQ(result, RBUS_ERROR_INVALID_INPUT);    
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_PublishEvent) {
    char eventName[] = "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.MonitorResult";
    rbusError_t result;
    uint32_t oldValue = 0;
    uint32_t newValue = 1;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(2);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, _, _)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1).WillOnce(Return(RBUS_ERROR_SUCCESS));
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    result = WANCNCTVTYCHK_PublishEvent(eventName, oldValue, newValue);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_PublishEvent_1) {
    char eventName[] = "Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.MonitorResult";
    rbusError_t result;
    uint32_t oldValue = 0;
    uint32_t newValue = 1;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(2);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, _, _)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1).WillOnce(Return(RBUS_ERROR_INVALID_INPUT));
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    result = WANCNCTVTYCHK_PublishEvent(eventName, oldValue, newValue);
    EXPECT_EQ(result, RBUS_ERROR_INVALID_INPUT);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_CASE1) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterfaceNumberOfEntries"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_CASE2) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("NULL"));

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_INVALID_INPUT);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_Enable) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.Enable"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetBoolean(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_PassiveMonitor) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.[DOCSIS].PassiveMonitor"));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, StrEq("DOCSIS"), _, _, _))
    .WillOnce(DoAll(
        testing::SetArgPointee<3>(0),
        Return(EOK)
    ));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetBoolean(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_ActiveMonitor) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.ActiveMonitor"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetBoolean(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_QueryNow) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.QueryNow"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetBoolean(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_PassiveMonitorTimeout) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.PassiveMonitorTimeout"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_ActiveMonitorInterval) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.ActiveMonitorInterval"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_MonitorResult) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.MonitorResult"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_QueryNowResult) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.QueryNowResult"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_QueryTimeout) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.QueryTimeout"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_QueryRetry) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.QueryRetry"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_Alias) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.Alias"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_InterfaceName) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.InterfaceName"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_RecordType) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.RecordType"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_ServerType) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.ServerType"));

    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_SetValue(_, _)).Times(1);

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_Invalid) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.INVALID"));

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_INVALID_INPUT);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_GetIntfHandler_Invalid2) {
    rbusError_t result;

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.5.INVALID"));

    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(1);

    result = WANCNCTVTYCHK_GetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_INVALID_INPUT);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_SetIntfHandler) {
    rbusError_t result;
    rbusValue_t value = (rbusValue_t)malloc(sizeof(_rbusValue));

    EXPECT_CALL(*g_rbusMock, rbusProperty_GetName(_)).Times(1).WillOnce(Return("Device.Diagnostics.X_RDK_DNSInternet.WANInterface.1.Enable"));
    EXPECT_CALL(*g_rbusMock, rbusProperty_GetValue(_)).Times(1).WillOnce(Return(value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetType(value)).Times(1).WillOnce(Return(RBUS_BOOLEAN));

    EXPECT_CALL(*g_rbusMock, rbusValue_GetBoolean(value)).Times(1).WillOnce(Return(TRUE));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    result = WANCNCTVTYCHK_SetIntfHandler(NULL, NULL, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_StopConnectivityCheck_InvalidParams)
{
    rbusHandle_t handle = NULL;
    rbusObject_t inParams;
    rbusObject_t outParams = NULL;
    rbusValue_t intf_value = (rbusValue_t)malloc(sizeof(_rbusValue));
    rbusValue_t alias_value = (rbusValue_t)malloc(sizeof(_rbusValue));

    // Initialize intf_value with default values
    intf_value->type = RBUS_STRING;
    intf_value->d.bytes = (rbusBuffer_t)malloc(sizeof(_rbusBuffer));
    intf_value->d.bytes->data = (uint8_t*)malloc(strlen("wlan1") + 1);
    strcpy((char*)intf_value->d.bytes->data, "wlan1");
    intf_value->d.bytes->posWrite = strlen("wlan1") + 1;

    // Initialize alias_value with default values
    alias_value->type = RBUS_STRING;
    alias_value->d.bytes = (rbusBuffer_t)malloc(sizeof(_rbusBuffer));
    alias_value->d.bytes->data = (uint8_t*)malloc(strlen("WANOE") + 1);
    strcpy((char*)intf_value->d.bytes->data, "WANOE");
    alias_value->d.bytes->posWrite = strlen("WANOE") + 1;

    EXPECT_CALL(*g_rbusMock, rbusObject_GetValue(_, StrEq("linux_interface_name"))).Times(1).WillOnce(Return(intf_value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(intf_value, _)).Times(1).WillOnce(Return("wlan1"));

    EXPECT_CALL(*g_rbusMock, rbusObject_GetValue(_, StrEq("alias"))).Times(1).WillOnce(Return(alias_value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(alias_value, _)).Times(1).WillOnce(Return("WANOE"));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _)).WillRepeatedly(Return(-1));

    rbusError_t result = WANCNCTVTYCHK_StopConnectivityCheck(handle, "Device.X_RDK_DNSInternet.StopConnectivityCheck()", inParams, outParams, NULL);
    EXPECT_EQ(result, RBUS_ERROR_INVALID_INPUT);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_StopConnectivityCheck_ValidParams)
{
    rbusHandle_t handle = NULL;
    rbusObject_t inParams;
    rbusObject_t outParams = NULL;

    rbusValue_t intf_value = (rbusValue_t)malloc(sizeof(_rbusValue));
    rbusValue_t alias_value = (rbusValue_t)malloc(sizeof(_rbusValue));

    // Initialize intf_value with default values
    intf_value->type = RBUS_STRING;
    intf_value->d.bytes = (rbusBuffer_t)malloc(sizeof(_rbusBuffer));
    intf_value->d.bytes->data = (uint8_t*)malloc(strlen("erouter0") + 1);
    strcpy((char*)intf_value->d.bytes->data, "erouter0");
    intf_value->d.bytes->posWrite = strlen("erouter0") + 1;

    // Initialize alias_value with default values
    alias_value->type = RBUS_STRING;
    alias_value->d.bytes = (rbusBuffer_t)malloc(sizeof(_rbusBuffer));
    alias_value->d.bytes->data = (uint8_t*)malloc(strlen("DOCSIS") + 1);
    strcpy((char*)intf_value->d.bytes->data, "DOCSIS");
    alias_value->d.bytes->posWrite = strlen("DOCSIS") + 1;

    EXPECT_CALL(*g_rbusMock, rbusObject_GetValue(_, StrEq("linux_interface_name"))).Times(1).WillOnce(Return(intf_value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(intf_value, _)).Times(1).WillOnce(Return("erouter0"));

    EXPECT_CALL(*g_rbusMock, rbusObject_GetValue(_, StrEq("alias"))).Times(1).WillOnce(Return(alias_value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(alias_value, _)).Times(1).WillOnce(Return("DOCSIS"));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("DOCSIS"), _, _, _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(EOK)
        ));

    EXPECT_CALL(*g_rbusMock, rbusValue_Init(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Init(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetUInt32(_, _)).Times(2);
    EXPECT_CALL(*g_rbusMock, rbusValue_SetString(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusObject_SetValue(_, _, _)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusEvent_Publish(_, _)).Times(1);
    EXPECT_CALL(*g_rbusMock, rbusValue_Release(_)).Times(3);
    EXPECT_CALL(*g_rbusMock, rbusObject_Release(_)).Times(1);

    rbusError_t result = WANCNCTVTYCHK_StopConnectivityCheck(handle, "Device.X_RDK_DNSInternet.StopConnectivityCheck()", inParams, outParams, NULL);
    EXPECT_EQ(result, RBUS_ERROR_SUCCESS);
}

TEST_F(WanConnectivityCheckTest, WANCNCTVTYCHK_StartConnectivityCheck_InvalidParams)
{
    char intfFile[] = "/sys/class/net/brlan0";
    PWANCNCTVTY_CHK_GLOBAL_INTF_INFO intf_list = NULL;
    
    rbusHandle_t handle = NULL;
    rbusObject_t inParams;
    rbusObject_t outParams = NULL;

    rbusValue_t intf_value = (rbusValue_t)malloc(sizeof(_rbusValue));
    rbusValue_t alias_value = (rbusValue_t)malloc(sizeof(_rbusValue));
    rbusValue_t ipv4_dns_value = (rbusValue_t)malloc(sizeof(_rbusValue));
    rbusValue_t ipv6_dns_value = (rbusValue_t)malloc(sizeof(_rbusValue));
    rbusValue_t ipv4_gateway = (rbusValue_t)malloc(sizeof(_rbusValue));
    rbusValue_t ipv6_gateway = (rbusValue_t)malloc(sizeof(_rbusValue));

    intf_value->type = RBUS_STRING;
    intf_value->d.bytes = (rbusBuffer_t)malloc(sizeof(_rbusBuffer));
    intf_value->d.bytes->data = (uint8_t*)malloc(strlen("brlan0") + 1);
    strcpy((char*)intf_value->d.bytes->data, "brlan0");
    intf_value->d.bytes->posWrite = strlen("brlan0") + 1;

    alias_value->type = RBUS_STRING;
    alias_value->d.bytes = (rbusBuffer_t)malloc(sizeof(_rbusBuffer));
    alias_value->d.bytes->data = (uint8_t*)malloc(strlen("WANOE") + 1);
    strcpy((char*)intf_value->d.bytes->data, "WANOE");
    alias_value->d.bytes->posWrite = strlen("WANOE") + 1;

    ipv4_dns_value->type = RBUS_STRING;
    ipv4_dns_value->d.bytes = (rbusBuffer_t)malloc(sizeof(_rbusBuffer));
    ipv4_dns_value->d.bytes->data = (uint8_t*)malloc(strlen("75.75.75.75,75.75.76.76") + 1);
    strcpy((char*)ipv4_dns_value->d.bytes->data, "75.75.75.75,75.75.76.76");
    ipv4_dns_value->d.bytes->posWrite = strlen("75.75.75.75,75.75.76.76") + 1;

    ipv6_dns_value->type = RBUS_STRING;
    ipv6_dns_value->d.bytes = (rbusBuffer_t)malloc(sizeof(_rbusBuffer));
    ipv6_dns_value->d.bytes->data = (uint8_t*)malloc(strlen("2001:558:feed::1,2001:558:feed::2") + 1);
    strcpy((char*)ipv6_dns_value->d.bytes->data, "2001:558:feed::1,2001:558:feed::2");
    ipv6_dns_value->d.bytes->posWrite = strlen("2001:558:feed::1,2001:558:feed::2") + 1;

    ipv4_gateway->type = RBUS_STRING;
    ipv4_gateway->d.bytes = (rbusBuffer_t)malloc(sizeof(_rbusBuffer));
    ipv4_gateway->d.bytes->data = (uint8_t*)malloc(strlen("127.0.0.1") + 1);
    strcpy((char*)ipv4_gateway->d.bytes->data, "127.0.0.1");
    ipv4_gateway->d.bytes->posWrite = strlen("127.0.0.1") + 1;

    ipv6_gateway->type = RBUS_STRING;
    ipv6_gateway->d.bytes = (rbusBuffer_t)malloc(sizeof(_rbusBuffer));
    ipv6_gateway->d.bytes->data = (uint8_t*)malloc(strlen("2001:558:feed::1") + 1);
    strcpy((char*)ipv6_gateway->d.bytes->data, "2001:558:feed::1");
    ipv6_gateway->d.bytes->posWrite = strlen("2001:558:feed::1") + 1;

    EXPECT_CALL(*g_rbusMock, rbusObject_GetValue(_, StrEq("linux_interface_name"))).Times(1).WillOnce(Return(intf_value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(intf_value, _)).Times(1).WillOnce(Return("brlan0"));

    EXPECT_CALL(*g_rbusMock, rbusObject_GetValue(_, StrEq("alias"))).Times(1).WillOnce(Return(alias_value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(alias_value, _)).Times(1).WillOnce(Return("WANOE"));

    EXPECT_CALL(*g_rbusMock, rbusObject_GetValue(_, StrEq("IPv4_DNS_Servers"))).Times(1).WillOnce(Return(ipv4_dns_value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(ipv4_dns_value, _)).Times(1).WillOnce(Return("75.75.75.75,75.75.76.76"));

    EXPECT_CALL(*g_rbusMock, rbusObject_GetValue(_, StrEq("IPv6_DNS_Servers"))).Times(1).WillOnce(Return(ipv6_dns_value));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(ipv6_dns_value, _)).Times(1).WillOnce(Return("2001:558:feed::1,2001:558:feed::2"));

    EXPECT_CALL(*g_rbusMock, rbusObject_GetValue(_, StrEq("IPv4_Gateway"))).Times(1).WillOnce(Return(ipv4_gateway));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(ipv4_gateway, _)).Times(1).WillOnce(Return("127.0.0.1"));

    EXPECT_CALL(*g_rbusMock, rbusObject_GetValue(_, StrEq("IPv6_Gateway"))).Times(1).WillOnce(Return(ipv6_gateway));
    EXPECT_CALL(*g_rbusMock, rbusValue_GetString(ipv6_gateway, _)).Times(1).WillOnce(Return("127.0.0.1"));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::SetArrayArgument<0>(intfFile, intfFile + strlen(intfFile) + 1),
        Return(0)
    ));
    EXPECT_CALL(*g_fileIOMock, access(StrEq("/sys/class/net/brlan0"), _)).Times(1).WillOnce(Return(0));

    rbusError_t result = WANCNCTVTYCHK_StartConnectivityCheck(handle, "Device.X_RDK_DNSInternet.StartConnectivityCheck()", inParams, outParams, NULL);
    EXPECT_EQ(result, RBUS_ERROR_INVALID_INPUT);

}
