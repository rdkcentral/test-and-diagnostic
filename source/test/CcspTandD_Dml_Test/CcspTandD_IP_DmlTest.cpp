/*
* If not stated otherwise in this file or this component's LICENSE
* file the following copyright and licenses apply:
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

#include "CcspTandD_Dml_Mock.h"

extern PCOSA_BACKEND_MANAGER_OBJECT g_pCosaBEManager;
extern PCOSA_DIAG_PLUGIN_INFO  g_pCosaDiagPluginInfo;
extern BOOL g_is_pingtest_running ;
extern diag_pingtest_stat_t diag_pingtest_stat;
extern  diag_obj_t *diag_ping;
extern diag_obj_t *diag_tracert;
extern diag_obj_t *get_diag_by_mode(diag_mode_t mode);
extern PCOSA_DIAG_PLUGIN_INFO g_pCosaDiagPluginInfo;
extern PBBHM_DIAG_IP_PING_OBJECT g_DiagIpPingObj;
extern PBBHM_DIAG_IP_TRACEROUTE_OBJECT g_DiagIpTracerouteObj;
extern PBBHM_DIAG_NS_LOOKUP_OBJECT g_DiagNSLookupObj;
extern PBBHM_DOWNLOAD_DIAG_OBJECT  g_DiagDownloadObj;
extern  PBBHM_UPLOAD_DIAG_OBJECT  g_DiagUploadObj;
extern PBBHM_UDP_ECHOSRV_OBJECT g_UdpechoObj;
extern BOOL g_enable_speedtest;
extern BOOL g_run_speedtest;
extern char g_argument_speedtest[SPEEDTEST_ARG_SIZE + 1] ;
extern char g_authentication_speedtest[SPEEDTEST_AUTH_SIZE + 1];
extern int g_clienttype_speedtest;
extern int g_status_speedtest;

class CcspTandD_IP_DmlTest : public ::testing::Test {
    protected:
    void SetUp() override {
        g_syscfgMock = new SyscfgMock();
        g_securewrapperMock = new SecureWrapperMock();
        g_msgpackMock = new msgpackMock();
        g_usertimeMock = new UserTimeMock();
        g_safecLibMock = new SafecLibMock();
        g_anscMemoryMock = new AnscMemoryMock();
        g_baseapiMock = new BaseAPIMock();
        g_traceMock = new TraceMock();
        g_base64Mock = new base64Mock();
        g_rbusMock = new rbusMock();
        g_cmHALMock = new CmHalMock();
        g_platformHALMock = new PlatformHalMock();
        g_cjsonMock = new cjsonMock();
        g_syseventMock = new SyseventMock();
        g_webconfigFwMock = new webconfigFwMock();
        g_anscWrapperApiMock = new AnscWrapperApiMock();
        g_dslhDmagntExportedMock = new DslhDmagntExportedMock();
        g_rdkloggerMock = new rdkloggerMock();
        g_utilMock = new UtilMock();
        g_anscTaskMock = new AnscTaskMock();
        g_libevMock = new LibevMock();
        g_psmMock = new PsmMock();
        g_pcapMock = new PcapMock();
        g_resolvMock = new ResolvMock();
    }
    void TearDown() override {
        delete g_syscfgMock;
        delete g_securewrapperMock;
        delete g_msgpackMock;
        delete g_usertimeMock;
        delete g_safecLibMock;
        delete g_anscMemoryMock;
        delete g_baseapiMock;
        delete g_traceMock;
        delete g_base64Mock;
        delete g_rbusMock;
        delete g_cmHALMock;
        delete g_platformHALMock;
        delete g_cjsonMock;
        delete g_syseventMock;
        delete g_webconfigFwMock;
        delete g_anscWrapperApiMock;
        delete g_dslhDmagntExportedMock;
        delete g_rdkloggerMock;
        delete g_utilMock;
        delete g_anscTaskMock;
        delete g_libevMock;
        delete g_psmMock;
        delete g_pcapMock;
        delete g_resolvMock;
        g_syscfgMock = nullptr;
        g_securewrapperMock = nullptr;
        g_msgpackMock = nullptr;
        g_usertimeMock = nullptr;
        g_safecLibMock = nullptr;
        g_anscMemoryMock = nullptr;
        g_baseapiMock = nullptr;
        g_traceMock = nullptr;
        g_base64Mock = nullptr;
        g_rbusMock = nullptr;
        g_cmHALMock = nullptr;
        g_platformHALMock = nullptr;
        g_cjsonMock = nullptr;
        g_syseventMock = nullptr;
        g_webconfigFwMock = nullptr;
        g_anscWrapperApiMock = nullptr;
        g_dslhDmagntExportedMock = nullptr;
        g_rdkloggerMock = nullptr;
        g_utilMock = nullptr;
        g_anscTaskMock = nullptr;
        g_libevMock = nullptr;
        g_psmMock = nullptr;
        g_pcapMock = nullptr;
        g_resolvMock = nullptr;
    }
};

TEST_F(CcspTandD_IP_DmlTest, X_CISCO_COM_ARP_GetParamBoolValue)
{
    EXPECT_FALSE(X_CISCO_COM_ARP_GetParamBoolValue(NULL, NULL, NULL));
}

TEST_F(CcspTandD_IP_DmlTest, X_CISCO_COM_ARP_GetParamIntValue)
{
    EXPECT_FALSE(X_CISCO_COM_ARP_GetParamIntValue(NULL, NULL, NULL));
}

TEST_F(CcspTandD_IP_DmlTest, X_CISCO_COM_ARP_GetParamUlongValue)
{
    EXPECT_FALSE(X_CISCO_COM_ARP_GetParamUlongValue(NULL, NULL, NULL));
}

TEST_F(CcspTandD_IP_DmlTest, X_CISCO_COM_ARP_GetParamStringValue)
{
    EXPECT_EQ(-1, X_CISCO_COM_ARP_GetParamStringValue(NULL, NULL, NULL, NULL));
}

TEST_F(CcspTandD_IP_DmlTest, ARPTable_GetEntryCount_true)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->ArpEntryCount = 1;

    EXPECT_EQ(1, ARPTable_GetEntryCount((ANSC_HANDLE)NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, ARPTable_GetEntry)
{
    ULONG nIndex = 0;
    ULONG pInsNumber = 0;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pArpTable = (PCOSA_DML_DIAG_ARP_TABLE)malloc(2*sizeof(COSA_DML_DIAG_ARP_TABLE));

    PCOSA_DML_DIAG_ARP_TABLE  pArpTable   = (PCOSA_DML_DIAG_ARP_TABLE)pMyObject->pArpTable;

    EXPECT_NE((ANSC_HANDLE)NULL, ARPTable_GetEntry(NULL, nIndex, &pInsNumber));

    free(pMyObject->pArpTable);
    pMyObject->pArpTable = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, ARPTable_IsUpdated_False)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->PreviousVisitTime = 0;

    EXPECT_CALL(*g_usertimeMock, UserGetTickInSeconds2())
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_FALSE(ARPTable_IsUpdated(NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, ARPTable_IsUpdated_True)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->PreviousVisitTime = 200;

    EXPECT_CALL(*g_usertimeMock, UserGetTickInSeconds2())
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_TRUE(ARPTable_IsUpdated(NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, ARPTable_Synchronize_Failure)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pArpTable = (PCOSA_DML_DIAG_ARP_TABLE)malloc(2*sizeof(COSA_DML_DIAG_ARP_TABLE));

    pMyObject->ArpEntryCount = 2;

    ANSC_STATUS returnStatus = ANSC_STATUS_FAILURE;
    ULONG entryCount = 0;

    EXPECT_EQ(ANSC_STATUS_FAILURE, ARPTable_Synchronize((ANSC_HANDLE)NULL));

    free(pMyObject->pArpTable);
    pMyObject->pArpTable = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL; 
}

TEST_F(CcspTandD_IP_DmlTest, ARPTable_GetParamBoolValue)
{
    const char *ParamName = "Static";
    BOOL pBool = 0;
    PCOSA_DML_DIAG_ARP_TABLE pArpTable = (PCOSA_DML_DIAG_ARP_TABLE)malloc(sizeof(COSA_DML_DIAG_ARP_TABLE));
    ASSERT_NE(pArpTable, nullptr);

    pArpTable->Static = TRUE;

    EXPECT_TRUE(ARPTable_GetParamBoolValue((ANSC_HANDLE)pArpTable, (char*)ParamName, &pBool));

    free(pArpTable);
    pArpTable = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, ARPTable_GetParamIntValue)
{
    int pInt = 0;
    EXPECT_FALSE(ARPTable_GetParamIntValue(NULL, NULL, &pInt));
}

TEST_F(CcspTandD_IP_DmlTest, ARPTable_GetParamUlongValue)
{
    ULONG puLong = 0;
    EXPECT_FALSE(ARPTable_GetParamUlongValue(NULL, NULL, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, ARPTable_GetParamStringValue_ipaddress)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "IPAddress";
    PCOSA_DML_DIAG_ARP_TABLE pArpTable = (PCOSA_DML_DIAG_ARP_TABLE)malloc(sizeof(COSA_DML_DIAG_ARP_TABLE));
    ASSERT_NE(pArpTable, nullptr);

    strcpy((char*)pArpTable->IPAddress, "10.126.21.214");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, ARPTable_GetParamStringValue((ANSC_HANDLE)pArpTable, (char*)ParamName, pValue, &pUlSize));

    free(pArpTable);
    pArpTable = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, ARPTable_GetParamStringValue_macaddress_return0)
{
    ULONG pUlSize = 512;
    char pValue[100] = {0};
    const char *ParamName = "MACAddress";
    PCOSA_DML_DIAG_ARP_TABLE pArpTable = (PCOSA_DML_DIAG_ARP_TABLE)malloc(sizeof(COSA_DML_DIAG_ARP_TABLE));
    ASSERT_NE(pArpTable, nullptr);

    pArpTable->MACAddress[0] = 0x00;
    pArpTable->MACAddress[1] = 0x11;
    pArpTable->MACAddress[2] = 0x22;
    pArpTable->MACAddress[3] = 0x33;
    pArpTable->MACAddress[4] = 0x44;
    pArpTable->MACAddress[5] = 0x55;

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, ARPTable_GetParamStringValue((ANSC_HANDLE)pArpTable, (char*)ParamName, pValue, &pUlSize));

    free(pArpTable);
    pArpTable = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, ARPTable_GetParamStringValue_macaddress_return1)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "MACAddress";
    PCOSA_DML_DIAG_ARP_TABLE pArpTable = (PCOSA_DML_DIAG_ARP_TABLE)malloc(sizeof(COSA_DML_DIAG_ARP_TABLE));
    ASSERT_NE(pArpTable, nullptr);

    pArpTable->MACAddress[0] = 0x00;
    pArpTable->MACAddress[1] = 0x11;
    pArpTable->MACAddress[2] = 0x22;
    pArpTable->MACAddress[3] = 0x33;
    pArpTable->MACAddress[4] = 0x44;
    pArpTable->MACAddress[5] = 0x55;

    pUlSize = 5;

    EXPECT_EQ(1, ARPTable_GetParamStringValue((ANSC_HANDLE)pArpTable, (char*)ParamName, pValue, &pUlSize));

    free(pArpTable);
    pArpTable = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_GetParamBoolValue)
{
    const char *ParamName = "Run";
    BOOL pBool = 0;
    g_is_pingtest_running = TRUE;
    EXPECT_TRUE(X_RDKCENTRAL_COM_PingTest_GetParamBoolValue(NULL, (char*)ParamName, &pBool));
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_SetParamBoolValue_g_is_pingtest_running_true)
{
    const char *ParamName = "Run";
    BOOL bValue = 1;
    g_is_pingtest_running = TRUE;
    EXPECT_TRUE(X_RDKCENTRAL_COM_PingTest_SetParamBoolValue(NULL, (char*)ParamName, bValue));
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_GetParamStringValue_PartnerID_return1)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "PartnerID";
    strcpy(diag_pingtest_stat.device_details.PartnerID, "Comcast");
    strcpy(diag_pingtest_stat.device_details.ecmMAC, "10:aa:bc:23:3e:4f");
    strcpy(diag_pingtest_stat.device_details.DeviceID, "CGA4131COM");
    strcpy(diag_pingtest_stat.device_details.DeviceModel, "TCCBR");
    
    EXPECT_EQ(1, X_RDKCENTRAL_COM_PingTest_GetParamStringValue((ANSC_HANDLE)NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_GetParamStringValue_PartnerID_return0)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "PartnerID";
    strcpy(diag_pingtest_stat.device_details.PartnerID, "Comcast");
    strcpy(diag_pingtest_stat.device_details.ecmMAC, "10:aa:bc:23:3e:4f");
    strcpy(diag_pingtest_stat.device_details.DeviceID, "CGA4131COM");
    strcpy(diag_pingtest_stat.device_details.DeviceModel, "TCCBR");
    
    EXPECT_EQ(0, X_RDKCENTRAL_COM_PingTest_GetParamStringValue((ANSC_HANDLE)NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_GetParamStringValue_ecmMAC_return1)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "ecmMAC";
    strcpy(diag_pingtest_stat.device_details.PartnerID, "Comcast");
    strcpy(diag_pingtest_stat.device_details.ecmMAC, "10:aa:bc:23:3e:4f");
    strcpy(diag_pingtest_stat.device_details.DeviceID, "CGA4131COM");
    strcpy(diag_pingtest_stat.device_details.DeviceModel, "TCCBR");

    EXPECT_EQ(1, X_RDKCENTRAL_COM_PingTest_GetParamStringValue((ANSC_HANDLE)NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_GetParamStringValue_ecmMAC_return0)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "ecmMAC";
    strcpy(diag_pingtest_stat.device_details.PartnerID, "Comcast");
    strcpy(diag_pingtest_stat.device_details.ecmMAC, "10:aa:bc:23:3e:4f");
    strcpy(diag_pingtest_stat.device_details.DeviceID, "CGA4131COM");
    strcpy(diag_pingtest_stat.device_details.DeviceModel, "TCCBR");
    
        EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, X_RDKCENTRAL_COM_PingTest_GetParamStringValue((ANSC_HANDLE)NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_GetParamStringValue_DeviceID_return1)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "DeviceID";
    strcpy(diag_pingtest_stat.device_details.PartnerID, "Comcast");
    strcpy(diag_pingtest_stat.device_details.ecmMAC, "10:aa:bc:23:3e:4f");
    strcpy(diag_pingtest_stat.device_details.DeviceID, "CGA4131COM");
    strcpy(diag_pingtest_stat.device_details.DeviceModel, "TCCBR");
    
    EXPECT_EQ(1, X_RDKCENTRAL_COM_PingTest_GetParamStringValue((ANSC_HANDLE)NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_GetParamStringValue_DeviceID_return0)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "DeviceID";
    strcpy(diag_pingtest_stat.device_details.PartnerID, "Comcast");
    strcpy(diag_pingtest_stat.device_details.ecmMAC, "10:aa:bc:23:3e:4f");
    strcpy(diag_pingtest_stat.device_details.DeviceID, "CGA4131COM");
    strcpy(diag_pingtest_stat.device_details.DeviceModel, "TCCBR");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_EQ(0, X_RDKCENTRAL_COM_PingTest_GetParamStringValue((ANSC_HANDLE)NULL, (char*)ParamName, pValue, &pUlSize));
}


TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_GetParamStringValue_DeviceModel_return1)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "DeviceModel";
    strcpy(diag_pingtest_stat.device_details.PartnerID, "Comcast");
    strcpy(diag_pingtest_stat.device_details.ecmMAC, "10:aa:bc:23:3e:4f");
    strcpy(diag_pingtest_stat.device_details.DeviceID, "CGA4131COM");
    strcpy(diag_pingtest_stat.device_details.DeviceModel, "TCCBR");
    
    EXPECT_EQ(1, X_RDKCENTRAL_COM_PingTest_GetParamStringValue((ANSC_HANDLE)NULL, (char*)ParamName, pValue, &pUlSize));
}


TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_GetParamStringValue_DeviceModel_return0)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "DeviceModel";
    strcpy(diag_pingtest_stat.device_details.PartnerID, "Comcast");
    strcpy(diag_pingtest_stat.device_details.ecmMAC, "10:aa:bc:23:3e:4f");
    strcpy(diag_pingtest_stat.device_details.DeviceID, "CGA4131COM");
    strcpy(diag_pingtest_stat.device_details.DeviceModel, "TCCBR");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_EQ(0, X_RDKCENTRAL_COM_PingTest_GetParamStringValue((ANSC_HANDLE)NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_Validate)
{
    ULONG puLength = 0;
    char pReturnParamName[100] = {0};
    EXPECT_TRUE(X_RDKCENTRAL_COM_PingTest_Validate(NULL, pReturnParamName, &puLength));
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_Commit)
{
    EXPECT_EQ(0, X_RDKCENTRAL_COM_PingTest_Commit(NULL));
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_PingTest_Rollback)
{
    EXPECT_EQ(0, X_RDKCENTRAL_COM_PingTest_Rollback(NULL));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamIntValue)
{
    int pInt = 0;
    EXPECT_FALSE(IPPing_GetParamIntValue(NULL, NULL, &pInt));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamBoolValue)
{
    BOOL pBool = 0;
    EXPECT_FALSE(IPPing_GetParamBoolValue(NULL, NULL, &pBool));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_DiagnosticsState_false)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";

    EXPECT_FALSE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_NONE)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";

    diag_init();
    diag_ping->state = DIAG_ST_NONE;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_ACTING)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";

    diag_ping->state = DIAG_ST_ACTING;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_COMPLETE)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";
    diag_ping->state = DIAG_ST_COMPLETE;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_ERROR_DIAG_ERR_RESOLVE)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";

    diag_ping->state = DIAG_ST_ERROR;
    diag_ping->err = DIAG_ERR_RESOLVE;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_ERROR_DIAG_ERR_INTERNAL)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";

    diag_ping->state = DIAG_ST_ERROR;
    diag_ping->err = DIAG_ERR_INTERNAL;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_ERROR_DIAG_ERR_OTHER)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";

    diag_ping->state = DIAG_ST_ERROR;
    diag_ping->err = DIAG_ERR_OTHER;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_ERROR_DEFAULT)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";

    diag_ping->state = DIAG_ST_ERROR;
    diag_ping->err = DIAG_ERR_MAXHOPS;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_NumberOfRepetitions)
{
    ULONG puLong = 0;
    const char *ParamName = "NumberOfRepetitions";
    diag_ping->state = DIAG_ST_ERROR;
    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

}


TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_Timeout)
{
    ULONG puLong = 0;
    const char *ParamName = "Timeout";
    diag_ping->state = DIAG_ST_ERROR;
    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_DataBlockSize)
{
    ULONG puLong = 0;
    const char *ParamName = "DataBlockSize";
    diag_ping->state = DIAG_ST_ERROR;
    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_DSCP)
{
    ULONG puLong = 0;
    const char *ParamName = "DSCP";
    diag_ping->state = DIAG_ST_ERROR;
    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_SuccessCount)
{
    ULONG puLong = 0;
    const char *ParamName = "SuccessCount";
    diag_ping->state = DIAG_ST_ERROR;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_FailureCount)
{
    ULONG puLong = 0;
    const char *ParamName = "FailureCount";
    diag_ping->state = DIAG_ST_ERROR;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_AverageResponseTime)
{
    ULONG puLong = 0;
    const char *ParamName = "AverageResponseTime";
    diag_ping->state = DIAG_ST_ERROR;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_MinimumResponseTime)
{
    ULONG puLong = 0;
    const char *ParamName = "MinimumResponseTime";
    diag_ping->state = DIAG_ST_ERROR;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_MaximumResponseTime)
{
    ULONG puLong = 0;
    const char *ParamName = "MaximumResponseTime";
    diag_ping->state = DIAG_ST_ERROR;

    EXPECT_TRUE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamUlongValue_FALSE)
{
    ULONG puLong = 0;
    const char *ParamName = "None";

    EXPECT_FALSE(IPPing_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamStringValue_Interface_returnMINUS1)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    diag_term();

    EXPECT_EQ(-1, IPPing_GetParamStringValue(NULL, NULL, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamStringValue_Interface_return1)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "Interface";
    diag_init();
    strcpy(diag_ping->cfg.Interface, "eth0");

    EXPECT_EQ(1, IPPing_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamStringValue_Interface_return0)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "Interface";

    strcpy(diag_ping->cfg.Interface, "eth0");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, IPPing_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));
}


TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamStringValue_Host_return1)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "Host";

    strcpy(diag_ping->cfg.host, "www.google.com");

    EXPECT_EQ(1, IPPing_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_GetParamStringValue_Host_return0)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "Host";

    strcpy(diag_ping->cfg.host, "www.google.com");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, IPPing_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamBoolValue)
{
    BOOL bValue = 0;
    EXPECT_FALSE(IPPing_SetParamBoolValue(NULL, NULL, bValue));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamIntValue)
{
    int iValue = 0;
    EXPECT_FALSE(IPPing_SetParamIntValue(NULL, NULL, iValue));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamUlongValue_FALSE)
{
    ULONG uValue = 0;
    const char *ParamName = "None";
    EXPECT_FALSE(IPPing_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamUlongValue_NumberOfRepetitions_FALSE)
{
    ULONG uValue = 0;
    const char *ParamName = "NumberOfRepetitions";
    EXPECT_FALSE(IPPing_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamUlongValue_NumberOfRepetitions_TRUE)
{
    ULONG uValue = 2;
    const char *ParamName = "NumberOfRepetitions";
    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).Times(1).WillRepeatedly(Return(0));

    EXPECT_TRUE(IPPing_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamUlongValue_Timeout)
{
    ULONG uValue = 2;
    const char *ParamName = "Timeout";
    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_TRUE(IPPing_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamUlongValue_DataBlockSize)
{
    ULONG uValue = 2;
    const char *ParamName = "DataBlockSize";
    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(IPPing_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}


TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamUlongValue_DSCP)
{
    ULONG uValue = 2;
    const char *ParamName = "DSCP";
    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_TRUE(IPPing_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamUlongValue_NoPARAM)
{
    ULONG uValue = 2;
    const char *ParamName = "NONE";
    EXPECT_FALSE(IPPing_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamStringValue_FALSE)
{
    char pString[100] = "eth0";
    const char *ParamName = "Interface";
    diag_term();

    EXPECT_FALSE(IPPing_SetParamStringValue(NULL, (char*)ParamName, pString));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamStringValue_Interface_FALSE)
{
    char pString[100] = "eth0  12";
    const char *ParamName = "Interface";
    

    EXPECT_FALSE(IPPing_SetParamStringValue(NULL, (char*)ParamName, pString));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamStringValue_Interface_TRUE)
{
    char pString[100] = "eth0";
    const char *ParamName = "Interface";

    

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).WillRepeatedly(::testing::Return(0));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_FALSE(IPPing_SetParamStringValue(NULL, (char*)ParamName, pString));


}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamStringValue_Host_FALSE)
{
    char pString[100] = "10.21445.121";
    const char *ParamName = "Host";

    

    EXPECT_FALSE(IPPing_SetParamStringValue(NULL, (char*)ParamName, pString));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamStringValue_Host_TRUE)
{
    char pString[100] = "www.google.com";
    const char *ParamName = "Host";

    

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_FALSE(IPPing_SetParamStringValue(NULL, (char*)ParamName, pString));


}

TEST_F(CcspTandD_IP_DmlTest, IPPing_SetParamStringValue_NoPARAM)
{
    char pString[100]={0};
    const char *ParamName = "None";

    

    EXPECT_FALSE(IPPing_SetParamStringValue(NULL, (char*)ParamName, pString));


}

TEST_F(CcspTandD_IP_DmlTest, IPPing_Validate)
{
    ULONG puLength = 0;
    char pReturnParamName[100] = {0};
    EXPECT_TRUE(IPPing_Validate(NULL, pReturnParamName, &puLength));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_Commit)
{
    EXPECT_EQ(0, IPPing_Commit(NULL));
}

TEST_F(CcspTandD_IP_DmlTest, IPPing_Rollback)
{
    EXPECT_EQ(0, IPPing_Rollback(NULL));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamBoolValue)
{
    BOOL pBool = 0;
    EXPECT_FALSE(TraceRoute_GetParamBoolValue(NULL, NULL, &pBool));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamIntValue)
{
    int pInt = 0;
    EXPECT_FALSE(TraceRoute_GetParamIntValue(NULL, NULL, &pInt));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_DiagnosticsState_false)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";

    EXPECT_FALSE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_NONE)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";
    diag_init();
    diag_tracert->state = DIAG_ST_NONE;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_ACTING)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";
    diag_tracert->state = DIAG_ST_ACTING;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_COMPLETE)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";
    diag_tracert->state = DIAG_ST_COMPLETE;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_ERROR_DIAG_ERR_RESOLVE)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";
    diag_tracert->state = DIAG_ST_ERROR;
    diag_tracert->err = DIAG_ERR_RESOLVE;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_ERROR_DIAG_ERR_MAXHOPS)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";
    diag_tracert->state = DIAG_ST_ERROR;
    diag_tracert->err = DIAG_ERR_MAXHOPS;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_ERROR_DIAG_ERR_OTHER)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";
    diag_tracert->state = DIAG_ST_ERROR;
    diag_tracert->err = DIAG_ERR_OTHER;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_DiagnosticsState_true_DIAG_ST_ERROR_DEFAULT)
{
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";
    diag_tracert->state = DIAG_ST_ERROR;
    diag_tracert->err = DIAG_ERR_MAXHOPS;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_NumberOfTries)
{
    ULONG puLong = 0;
    const char *ParamName = "NumberOfTries";
    diag_tracert->state = DIAG_ST_ERROR;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_Timeout)
{
    ULONG puLong = 0;
    const char *ParamName = "Timeout";
    diag_tracert->state = DIAG_ST_ERROR;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_DataBlockSize)
{
    ULONG puLong = 0;
    const char *ParamName = "DataBlockSize";
    diag_tracert->state = DIAG_ST_ERROR;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_DSCP)
{
    ULONG puLong = 0;
    const char *ParamName = "DSCP";
    diag_tracert->state = DIAG_ST_ERROR;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_MaxHopCount)
{
    ULONG puLong = 0;
    const char *ParamName = "MaxHopCount";
    diag_tracert->state = DIAG_ST_ERROR;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_ResponseTime)
{
    ULONG puLong = 0;
    const char *ParamName = "ResponseTime";
    diag_tracert->state = DIAG_ST_ERROR;

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamUlongValue_NoPARAM)
{
    ULONG puLong = 0;
    const char *ParamName = "None";

    EXPECT_TRUE(TraceRoute_GetParamUlongValue(NULL, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamStringValue_Interface_returnMINUS1)
{
    diag_term();
    ULONG pUlSize = 0;
    char pValue[100] = {0};

    EXPECT_EQ(-1, TraceRoute_GetParamStringValue(NULL, NULL, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamStringValue_Interface_return1)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "Interface";
    diag_init();

    strcpy(diag_tracert->cfg.Interface, "eth0");

    EXPECT_EQ(1, TraceRoute_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamStringValue_Interface_return0)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "Interface";

    strcpy(diag_tracert->cfg.Interface, "eth0");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, TraceRoute_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamStringValue_Host_return1)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "Host";

    strcpy(diag_tracert->cfg.host, "www.google.com");

    EXPECT_EQ(1, TraceRoute_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamStringValue_Host_return0)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "Host";

    strcpy(diag_tracert->cfg.host, "www.google.com");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_safecLibMock,_sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, TraceRoute_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_GetParamStringValue_NoPARAM)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "None";

    strcpy(diag_tracert->cfg.host, "www.google.com");

    EXPECT_EQ(-1, TraceRoute_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamBoolValue)
{
    BOOL bValue = 0;
    EXPECT_FALSE(TraceRoute_SetParamBoolValue(NULL, NULL, bValue));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamIntValue)
{
    int iValue = 0;
    EXPECT_FALSE(TraceRoute_SetParamIntValue(NULL, NULL, iValue));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamUlongValue_FALSE)
{
    ULONG uValue = 0;
    const char *ParamName = "None";
    EXPECT_FALSE(TraceRoute_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamUlongValue_DiagnosticsState_DIAG_ST_ACTING)
{
    ULONG uValue = 0;
    const char *ParamName = "DiagnosticsState";

    uValue = DSLH_DIAG_STATE_TYPE_Requested + 2;

    EXPECT_FALSE(TraceRoute_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamUlongValue_NumberOfTries_TRUE)
{
    ULONG uValue = 0;
    const char *ParamName = "NumberOfTries";
    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).Times(1).WillOnce(Return(0));

    EXPECT_TRUE(TraceRoute_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamUlongValue_Timeout)
{
    ULONG uValue = 2;
    const char *ParamName = "Timeout";
    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_TRUE(TraceRoute_SetParamUlongValue(NULL, (char*)ParamName, uValue));

}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamUlongValue_DataBlockSize)
{
    ULONG uValue = 2;
    const char *ParamName = "DataBlockSize";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(TraceRoute_SetParamUlongValue(NULL, (char*)ParamName, uValue));

}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamUlongValue_DSCP)
{
    ULONG uValue = 2;
    const char *ParamName = "DSCP";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).WillRepeatedly(Return(0));

    EXPECT_TRUE(TraceRoute_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}


TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamUlongValue_NoPARAM)
{
    ULONG uValue = 2;
    const char *ParamName = "NONE";

    EXPECT_FALSE(TraceRoute_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamStringValue_FALSE)
{
    char pString[100] = "eth0";
    const char *ParamName = "Interface";
    diag_term();

    EXPECT_FALSE(TraceRoute_SetParamStringValue(NULL, (char*)ParamName, pString));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamStringValue_Interface_FALSE)
{
    diag_init();
    char pString[100] = "eth0  12";
    const char *ParamName = "Interface";

    EXPECT_FALSE(TraceRoute_SetParamStringValue(NULL, (char*)ParamName, pString));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamStringValue_Interface_TRUE)
{
    char pString[100] = "eth0";
    const char *ParamName = "Interface";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).WillRepeatedly(::testing::Return(0));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_FALSE(TraceRoute_SetParamStringValue(NULL, (char*)ParamName, pString));

}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamStringValue_Host_FALSE)
{
    char pString[100] = "10.21445.121";
    const char *ParamName = "Host";

    EXPECT_FALSE(TraceRoute_SetParamStringValue(NULL, (char*)ParamName, pString));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamStringValue_Host_TRUE)
{
    char pString[100] = "www.google.com";
    const char *ParamName = "Host";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_FALSE(TraceRoute_SetParamStringValue(NULL, (char*)ParamName, pString));

}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_SetParamStringValue_NoPARAM)
{
    char pString[100]={0};
    const char *ParamName = "None";

    EXPECT_FALSE(TraceRoute_SetParamStringValue(NULL, (char*)ParamName, pString));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_Validate)
{
    ULONG puLength = 0;
    char pReturnParamName[100] = {0};
    EXPECT_TRUE(TraceRoute_Validate(NULL, pReturnParamName, &puLength));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_Commit)
{
    EXPECT_EQ(0, TraceRoute_Commit(NULL));
}

TEST_F(CcspTandD_IP_DmlTest, TraceRoute_Rollback)
{
    EXPECT_EQ(0, TraceRoute_Rollback(NULL));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetEntryCount_return0)
{
    EXPECT_EQ(0, RouteHops_GetEntryCount(NULL));
}


TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetEntryCount_return1)
{
    diag_ping->stat.u.tracert.nhop = 0;
    EXPECT_EQ(0, RouteHops_GetEntryCount(NULL));

}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetEntry_returnNULL)
{
    diag_term();

    EXPECT_EQ(NULL, RouteHops_GetEntry(NULL, 0, NULL));
}


TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetEntry_returnNULL_nIndex)
{
    diag_init();
    diag_ping->stat.u.tracert.nhop = 1;

    EXPECT_EQ(NULL, RouteHops_GetEntry(NULL, 2, NULL));


}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetEntry_returnNULL_nIndex1)
{
    diag_ping->stat.u.tracert.nhop = 1;

    EXPECT_EQ(NULL, RouteHops_GetEntry(NULL, 1, NULL));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_IsUpdated)
{
    EXPECT_TRUE(RouteHops_IsUpdated(NULL));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_Synchronize)
{
    EXPECT_EQ(0, RouteHops_Synchronize(NULL));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamBoolValue)
{
    BOOL pBool = 0;
    EXPECT_FALSE(RouteHops_GetParamBoolValue(NULL, NULL, &pBool));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamIntValue)
{
    int pInt = 0;
    EXPECT_FALSE(RouteHops_GetParamIntValue(NULL, NULL, &pInt));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamUlongValue_return_hop_FALSE)
{
    ULONG puLong = 0;
    EXPECT_FALSE(RouteHops_GetParamUlongValue(NULL, NULL, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamUlongValue_returnTRUE)
{
    ULONG puLong = 0;
    tracert_hop_t hop;
    hop.icmperr = 1;
    const char *ParamName = "ErrorCode";

    EXPECT_TRUE(RouteHops_GetParamUlongValue((ANSC_HANDLE)&hop, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamUlongValue_returnFALSE)
{
    ULONG puLong = 0;
    tracert_hop_t hop;
    hop.icmperr = 1;
    const char *ParamName = "none";

    EXPECT_FALSE(RouteHops_GetParamUlongValue((ANSC_HANDLE)&hop, (char*)ParamName, &puLong));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamStringValue_returnFALSE)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    EXPECT_EQ(FALSE, RouteHops_GetParamStringValue(NULL, NULL, pValue, &pUlSize));
}


TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamStringValue_return1_Host)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    tracert_hop_t hop;
    hop.host[0] = 'a';
    hop.host[1] = 'b';
    hop.host[2] = '\0';
    const char *ParamName = "Host";

    EXPECT_EQ(1, RouteHops_GetParamStringValue((ANSC_HANDLE)&hop, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamStringValue_return0_Host)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    tracert_hop_t hop;
    hop.host[0] = 'a';
    hop.host[1] = 'b';
    hop.host[2] = '\0';
    const char *ParamName = "Host";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, RouteHops_GetParamStringValue((ANSC_HANDLE)&hop, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamStringValue_return1_HostAddress)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    tracert_hop_t hop;
    hop.addr[0] = 'a';
    hop.addr[1] = 'b';
    hop.addr[2] = '\0';
    const char *ParamName = "HostAddress";

    EXPECT_EQ(1, RouteHops_GetParamStringValue((ANSC_HANDLE)&hop, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamStringValue_return0_HostAddress)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    tracert_hop_t hop;
    hop.addr[0] = 'a';
    hop.addr[1] = 'b';
    hop.addr[2] = '\0';
    const char *ParamName = "HostAddress";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, RouteHops_GetParamStringValue((ANSC_HANDLE)&hop, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamStringValue_return1_RTTimes)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    tracert_hop_t hop;
    hop.rtts[0] = 'a';
    hop.rtts[1] = 'b';
    hop.rtts[2] = '\0';
    const char *ParamName = "RTTimes";

    EXPECT_EQ(1, RouteHops_GetParamStringValue((ANSC_HANDLE)&hop, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamStringValue_return0_RTTimes)
{
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    tracert_hop_t hop;
    hop.rtts[0] = 'a';
    hop.rtts[1] = 'b';
    hop.rtts[2] = '\0';
    const char *ParamName = "RTTimes";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, RouteHops_GetParamStringValue((ANSC_HANDLE)&hop, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, RouteHops_GetParamStringValue_NONE)
{
    ULONG pUlSize = 0;
    char pValue[100] = {0};
    tracert_hop_t hop;
    hop.rtts[0] = 'a';
    hop.rtts[1] = 'b';
    hop.rtts[2] = '\0';
    const char *ParamName = "None";
    diag_term();

    EXPECT_EQ(-1, RouteHops_GetParamStringValue((ANSC_HANDLE)&hop, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamBoolValue)
{
    BOOL pBool = 0;
    EXPECT_FALSE(DownloadDiagnostics_GetParamBoolValue(NULL, NULL, &pBool));
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamIntValue)
{
    int pInt = 0;
    EXPECT_FALSE(DownloadDiagnostics_GetParamIntValue(NULL, NULL, &pInt));
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamUlongValue_DiagnosticsState_FALSE)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    g_pCosaDiagPluginInfo = (PCOSA_DIAG_PLUGIN_INFO )malloc(sizeof(COSA_DIAG_PLUGIN_INFO ));
    ASSERT_NE(g_pCosaDiagPluginInfo, nullptr);

    g_pCosaDiagPluginInfo->uLoadStatus = COSA_STATUS_PENDING;
    ULONG puLong = 0;
    const char *ParamName = "DiagnosticsState";


    EXPECT_FALSE(DownloadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
    free(g_pCosaDiagPluginInfo);
    g_pCosaDiagPluginInfo = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamUlongValue_DSCP_TRUE)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    g_pCosaDiagPluginInfo = (PCOSA_DIAG_PLUGIN_INFO )malloc(sizeof(COSA_DIAG_PLUGIN_INFO ));
    ASSERT_NE(g_pCosaDiagPluginInfo, nullptr);

    g_pCosaDiagPluginInfo->uLoadStatus = 1;
    ULONG puLong = 0;
    const char *ParamName = "DSCP";

    pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)pMyObject->hDiagDownloadInfo;

    pDownloadInfo->DSCP  = 1;

    EXPECT_TRUE(DownloadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
    free(g_pCosaDiagPluginInfo);
    g_pCosaDiagPluginInfo = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamUlongValue_DSCP_FALSE)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;

    ULONG puLong = 0;
    const char *ParamName = "DSCP";

    EXPECT_FALSE(DownloadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamUlongValue_EthernetPriority_TRUE)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);
    ULONG puLong = 0;
    const char *ParamName = "EthernetPriority";

    pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)pMyObject->hDiagDownloadInfo;

    pDownloadInfo->EthernetPriority  = 1;

    EXPECT_TRUE(DownloadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamUlongValue_EthernetPriority_FALSE)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;

    ULONG puLong = 0;
    const char *ParamName = "EthernetPriority";

    EXPECT_FALSE(DownloadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamUlongValue_TestBytesReceived_FALSE)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);
    ULONG puLong = 0;
    const char *ParamName = "TestBytesReceived";

    EXPECT_FALSE(DownloadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamUlongValue_TotalBytesReceived_FALSE)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);
    ULONG puLong = 0;
    const char *ParamName = "TotalBytesReceived";

    EXPECT_FALSE(DownloadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamUlongValue_FALSE)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;
    ULONG puLong = 0;
    const char *ParamName = "None";

    EXPECT_FALSE(DownloadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_Interface_returnMINUS1)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "Interface";
    
    EXPECT_EQ(-1, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_Interface_return0)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "Interface";

    pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)pMyObject->hDiagDownloadInfo;

    strcpy(pDownloadInfo->Interface, "Interface");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_DownloadURL_returnMINUS1)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "DownloadURL";

    EXPECT_EQ(-1, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_DownloadURL_return0)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "DownloadURL";

    pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)pMyObject->hDiagDownloadInfo;

    strcpy(pDownloadInfo->DownloadURL, "DownloadURL");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_ROMTime_returnMINUS1)
{
    PDSLH_TR143_DOWNLOAD_DIAG_STATS pDownloadDiagStats;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagDownloadInfo = NULL;

    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "ROMTime";

    EXPECT_EQ(-1, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_BOMTime_returnMINUS1)
{
    PDSLH_TR143_DOWNLOAD_DIAG_STATS pDownloadDiagStats;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;
    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "BOMTime";

    EXPECT_EQ(-1, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_EOMTime_returnMINUS1)
{
    PDSLH_TR143_DOWNLOAD_DIAG_STATS pDownloadDiagStats;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;

    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "EOMTime";

    EXPECT_EQ(-1, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_TCPOpenRequestTime_returnMINUS1)
{
    PDSLH_TR143_DOWNLOAD_DIAG_STATS pDownloadDiagStats;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagDownloadInfo = NULL;

    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "TCPOpenRequestTime";

    EXPECT_EQ(-1, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_TCPOpenResponseTime_returnMINUS1)
{
    PDSLH_TR143_DOWNLOAD_DIAG_STATS pDownloadDiagStats;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;

    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "TCPOpenResponseTime";

    EXPECT_EQ(-1, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_DownloadTransports_returnMINUS1)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;

    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "DownloadTransports";

    EXPECT_EQ(-1, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, NULL, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_DownloadTransports_return0)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;

    ULONG pUlSize = 100;
    char pValue[100] = {0};
    const char *ParamName = "DownloadTransports";

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_DownloadTransports_return1)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;

    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "DownloadTransports";

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(1, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));
}


TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_GetParamStringValue_NONE)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = NULL;

    ULONG pUlSize = 0;
    char pValue[100] = {0};
    const char *ParamName = "NONE";

    EXPECT_EQ(-1, DownloadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamBoolValue_FALSE)
{
    const char *ParamName = "ParamName";
    BOOL bValue = 1;

    EXPECT_FALSE(DownloadDiagnostics_SetParamBoolValue(NULL, (char*)ParamName, bValue));
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamIntValue_FALSE)
{
    const char *ParamName = "ParamName";
    int iValue = 1;

    EXPECT_FALSE(DownloadDiagnostics_SetParamIntValue(NULL, (char*)ParamName, iValue));
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamUlongValue_DiagnosticsState_returnFALSE)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    const char *ParamName = "DiagnosticsState";
    ULONG uValue = 0;

    EXPECT_FALSE(DownloadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamUlongValue_DiagnosticsState_returnTRUE)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    const char *ParamName = "DiagnosticsState";
    ULONG uValue = 2;

    pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)pMyObject->hDiagDownloadInfo;

    EXPECT_TRUE(DownloadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(pMyObject->hDiagDownloadInfo);
    pMyObject->hDiagDownloadInfo = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamUlongValue_DSCP_returnTRUE)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    const char *ParamName = "DSCP";
    ULONG uValue = 1;

    pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)pMyObject->hDiagDownloadInfo;

    EXPECT_TRUE(DownloadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(pMyObject->hDiagDownloadInfo);
    pMyObject->hDiagDownloadInfo = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamUlongValue_EthernetPriority_returnTRUE)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    const char *ParamName = "EthernetPriority";
    ULONG uValue = 1;

    pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)pMyObject->hDiagDownloadInfo;

    EXPECT_TRUE(DownloadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(pMyObject->hDiagDownloadInfo);
    pMyObject->hDiagDownloadInfo = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamUlongValue_NONE)
{

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);
    const char *ParamName = "NONE";
    ULONG uValue = 1;

    EXPECT_FALSE(DownloadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(pMyObject->hDiagDownloadInfo);
    pMyObject->hDiagDownloadInfo = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamStringValue_Interface_returnTRUE)
{
     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    const char *ParamName = "Interface";
    char pString[100] = {0};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_TRUE(DownloadDiagnostics_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->hDiagDownloadInfo);
    pMyObject->hDiagDownloadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamStringValue_DownloadURL_returnTRUE)
{
     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    const char *ParamName = "DownloadURL";
    char pString[100] = "hi";

    EXPECT_TRUE(DownloadDiagnostics_SetParamStringValue(NULL, (char*)ParamName, pString));
    free(pMyObject->hDiagDownloadInfo);
    pMyObject->hDiagDownloadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamStringValue_DownloadURL_returnFALSE)
{
        g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
        ASSERT_NE(g_pCosaBEManager, nullptr);
        g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
        ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
        PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
        
        pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
        ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);
    
        const char *ParamName = "DownloadURL";
        char pString[100] = {0};
    
        EXPECT_FALSE(DownloadDiagnostics_SetParamStringValue(NULL, (char*)ParamName, NULL));
        free(pMyObject->hDiagDownloadInfo);
        pMyObject->hDiagDownloadInfo = NULL;
        free(g_pCosaBEManager->hDiag);
        g_pCosaBEManager->hDiag = NULL;
        free(g_pCosaBEManager);
        g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_SetParamStringValue_NONE)
{
     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    const char *ParamName = "NONE";
    char pString[100] = {0};

    EXPECT_FALSE(DownloadDiagnostics_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->hDiagDownloadInfo);
    pMyObject->hDiagDownloadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_Validate_returnTRUE)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;
    char pReturnParamName[100] = {0};
    ULONG puLength = 100;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)pMyObject->hDiagDownloadInfo;

    strcpy(pDownloadInfo->DownloadURL, "www.google.com");

    pDownloadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_Requested;

    EXPECT_TRUE(DownloadDiagnostics_Validate(NULL, pReturnParamName, &puLength));

    free(pMyObject->hDiagDownloadInfo);
    pMyObject->hDiagDownloadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_Validate_returnFALSE)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;
    char pReturnParamName[100] = {0};
    ULONG puLength = 100;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)pMyObject->hDiagDownloadInfo;

    pDownloadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_Requested;

    pDownloadInfo->DownloadURL[0] = '\0';
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_FALSE(DownloadDiagnostics_Validate(NULL, NULL, &puLength));

    free(pMyObject->hDiagDownloadInfo);
    pMyObject->hDiagDownloadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_Commit_return0)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;
    char pReturnParamName[100] = {0};
    ULONG puLength = 100;
    char status[] = "192.168.10.1";

    componentStruct_t ** ppComponents = NULL;
     parameterValStruct_t ** parameterVal = NULL;

    ppComponents = (componentStruct_t **)malloc(sizeof(componentStruct_t *));
    ASSERT_NE(ppComponents, nullptr);

    parameterVal = (parameterValStruct_t **)malloc(sizeof(parameterValStruct_t *));
    ASSERT_NE(parameterVal, nullptr);

    *parameterVal  = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    ASSERT_NE(*parameterVal, nullptr);

    *ppComponents = (componentStruct_t *)malloc(sizeof(componentStruct_t));
    ASSERT_NE(*ppComponents, nullptr);

    (*ppComponents)->componentName = strdup("Component1");
    (*ppComponents)->dbusPath = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_dbus_path = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_name = strdup("com.example.component1");

    (*parameterVal)->parameterName = strdup("Device.DeviceInfo.X_COMCAST-COM_WAN_IP");
    (*parameterVal)->parameterValue = strdup("erouter0");
    

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    
    pMyObject->hDiagDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagDownloadInfo, nullptr);

    pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)pMyObject->hDiagDownloadInfo;

    pDownloadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_Requested;
    strcpy(pDownloadInfo->Interface, "eth0");

    g_pCosaDiagPluginInfo = (PCOSA_DIAG_PLUGIN_INFO)malloc(sizeof(COSA_DIAG_PLUGIN_INFO));
    ASSERT_NE(g_pCosaDiagPluginInfo, nullptr);

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::WithArgs<6>([&parameterVal](parameterValStruct_t ***outComponents) {
            *outComponents = parameterVal; 
        }),
        testing::Return(100)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(_))
        .WillRepeatedly(Return());

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("::"))).WillRepeatedly(Return(status));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_, _, _, _, _, _))
    .Times(1)
    .WillRepeatedly(testing::DoAll(
        testing::WithArgs<4>([&ppComponents](componentStruct_t ***outComponents) {
            *outComponents = ppComponents;
        }),
        testing::Return(100)
    ));

    EXPECT_EQ(0, DownloadDiagnostics_Commit(NULL));

    free(*ppComponents);
    *ppComponents = NULL;
    free(ppComponents);
    ppComponents = NULL;
    free(*parameterVal);
    *parameterVal = NULL;
    free(parameterVal);
    parameterVal = NULL;

    free(g_pCosaDiagPluginInfo);
    g_pCosaDiagPluginInfo = NULL;
    free(pMyObject->hDiagDownloadInfo);
    pMyObject->hDiagDownloadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, DownloadDiagnostics_Rollback_ANSC_FAILURE)
{
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo;

    char pReturnParamName[100] = {0};
    ULONG puLength = 100;
    char status[] = " ";
    char status1[] = "www.google.com";
 
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    
    pMyObject->hDiagDownloadInfo = NULL;

    EXPECT_EQ(ANSC_STATUS_FAILURE, DownloadDiagnostics_Rollback(NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamBoolValue_FALSE)
{
    const char *ParamName = "ParamName";
    BOOL pBool = 1;

    EXPECT_FALSE(UploadDiagnostics_GetParamBoolValue(NULL, (char*)ParamName, &pBool));
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamIntValue_FALSE)
{
    const char *ParamName = "ParamName";
    int pInt = 1;

    EXPECT_FALSE(UploadDiagnostics_GetParamIntValue(NULL, (char*)ParamName, &pInt));
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamUlongValue_DiagnosticsState_returnFALSE)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    ULONG puLong = 0;

    g_pCosaDiagPluginInfo = (PCOSA_DIAG_PLUGIN_INFO)malloc(sizeof(COSA_DIAG_PLUGIN_INFO));
    ASSERT_NE(g_pCosaDiagPluginInfo, nullptr);

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    pUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)pMyObject->hDiagUploadInfo;

    g_pCosaDiagPluginInfo->uLoadStatus = 3;

    const char *ParamName = "DiagnosticsState";

    EXPECT_FALSE(UploadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaDiagPluginInfo);
    g_pCosaDiagPluginInfo = NULL;

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}   


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamUlongValue_DSCP_returnTRUE)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    ULONG puLong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    pUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)pMyObject->hDiagUploadInfo;

    pUploadInfo->DSCP = 1;

    const char *ParamName = "DSCP";

    EXPECT_TRUE(UploadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamUlongValue_DSCP_returnFALSE)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    ULONG puLong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = NULL;

    const char *ParamName = "DSCP";

    EXPECT_FALSE(UploadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamUlongValue_EthernetPriority_returnTRUE)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    ULONG puLong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    pUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)pMyObject->hDiagUploadInfo;

    pUploadInfo->EthernetPriority = 1;

    const char *ParamName = "EthernetPriority";

    EXPECT_TRUE(UploadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamUlongValue_EthernetPriority_returnFALSE)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    ULONG puLong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = NULL;

    const char *ParamName = "EthernetPriority";

    EXPECT_FALSE(UploadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamUlongValue_TestFileLength_returnTRUE)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    ULONG puLong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    pUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)pMyObject->hDiagUploadInfo;

    pUploadInfo->TestFileLength = 1;

    const char *ParamName = "TestFileLength";

    EXPECT_TRUE(UploadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamUlongValue_TestFileLength_returnFALSE)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    ULONG puLong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = NULL;

    const char *ParamName = "TestFileLength";

    EXPECT_FALSE(UploadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamUlongValue_TotalBytesSent_returnFALSE)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    ULONG puLong = 0;

    g_pCosaDiagPluginInfo = (PCOSA_DIAG_PLUGIN_INFO)malloc(sizeof(COSA_DIAG_PLUGIN_INFO));
    ASSERT_NE(g_pCosaDiagPluginInfo, nullptr);

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    pUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)pMyObject->hDiagUploadInfo;

    g_pCosaDiagPluginInfo->uLoadStatus = 3;

    const char *ParamName = "TotalBytesSent";

    EXPECT_FALSE(UploadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaDiagPluginInfo);
    g_pCosaDiagPluginInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamUlongValue_NONE)
{
    ULONG puLong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    const char *ParamName = "NONE";

    EXPECT_FALSE(UploadDiagnostics_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamStringValue_Interface_return0)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    char pValue[100] = {0};
    ULONG pUlSize = 100;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    pUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)pMyObject->hDiagUploadInfo;

    strcpy(pUploadInfo->Interface, "eth0");

    const char *ParamName = "Interface";

    EXPECT_EQ(0, UploadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamStringValue_Interface_returnMINUS1)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    char pValue[100] = {0};
    ULONG pUlSize = 100;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = NULL;

    const char *ParamName = "Interface";

    EXPECT_EQ(-1, UploadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamStringValue_UploadURL_return0)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    char pValue[100] = {0};
    ULONG pUlSize = 100;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    pUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)pMyObject->hDiagUploadInfo;

    strcpy(pUploadInfo->UploadURL, "www.google.com");

    const char *ParamName = "UploadURL";

    EXPECT_EQ(0, UploadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamStringValue_UploadURL_returnMINUS1)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    char pValue[100] = {0};
    ULONG pUlSize = 100;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = NULL;

    const char *ParamName = "UploadURL";

    EXPECT_EQ(-1, UploadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamStringValue_ROMTime_returnMINUS1)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    char pValue[100] = {0};
    ULONG pUlSize = 100;

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    const char *ParamName = "ROMTime";

    EXPECT_EQ(-1, UploadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamStringValue_BOMTime_returnMINUS1)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    char pValue[100] = {0};
    ULONG pUlSize = 100;

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    const char *ParamName = "BOMTime";

    EXPECT_EQ(-1, UploadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamStringValue_EOMTime_returnMINUS1)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    char pValue[100] = {0};
    ULONG pUlSize = 100;

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    const char *ParamName = "EOMTime";

    EXPECT_EQ(-1, UploadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamStringValue_TCPOpenRequestTime_returnMINUS1)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    char pValue[100] = {0};
    ULONG pUlSize = 100;

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    const char *ParamName = "TCPOpenRequestTime";

    EXPECT_EQ(-1, UploadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamStringValue_TCPOpenResponseTime_returnMINUS1)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo;

    char pValue[100] = {0};
    ULONG pUlSize = 100;

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    const char *ParamName = "TCPOpenResponseTime";

    EXPECT_EQ(-1, UploadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_GetParamStringValue_NONE)
{
    char pValue[100] = {0};
    ULONG pUlSize = 100;

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);


    const char *ParamName = "NONE";

    EXPECT_EQ(-1, UploadDiagnostics_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamBoolValue_FaultCode_returnFALSE)
{
    BOOL bValue = TRUE;

    const char *ParamName = "FaultCode";

    EXPECT_FALSE(UploadDiagnostics_SetParamBoolValue(NULL, (char*)ParamName, bValue));
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamIntValue_FaultCode_returnFALSE)
{
    int iValue = 1;

    const char *ParamName = "FaultCode";

    EXPECT_FALSE(UploadDiagnostics_SetParamIntValue(NULL, (char*)ParamName, iValue));
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamUlongValue_DiagnosticsState_returnTRUE)
{
    ULONG uValue = 2;

    const char *ParamName = "DiagnosticsState";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);


    EXPECT_TRUE(UploadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamUlongValue_DiagnosticsState_returnFALSE)
{
    ULONG uValue = 1;

    const char *ParamName = "DiagnosticsState";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);


    EXPECT_FALSE(UploadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamUlongValue_DSCP_returnTRUE)
{
    ULONG uValue = 1;

    const char *ParamName = "DSCP";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);


    EXPECT_TRUE(UploadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamUlongValue_EthernetPriority_returnTRUE)
{
    ULONG uValue = 1;

    const char *ParamName = "EthernetPriority";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    EXPECT_TRUE(UploadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamUlongValue_TestFileLength_returnTRUE)
{
    ULONG uValue = 1;

    const char *ParamName = "TestFileLength";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    EXPECT_TRUE(UploadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamUlongValue_TestFileLength_returnFALSE)
{
    ULONG uValue = 0;

    const char *ParamName = "TestFileLength";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    EXPECT_FALSE(UploadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamUlongValue_NONE)
{
    ULONG uValue = 1;

    const char *ParamName = "NONE";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    EXPECT_FALSE(UploadDiagnostics_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamStringValue_Interface_returnTRUE)
{
    char pString[100] = "eth0";

    const char *ParamName = "Interface";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(UploadDiagnostics_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamStringValue_UploadURL_returnTRUE)
{
    char pString[100] = "www.google.com";

    const char *ParamName = "UploadURL";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(UploadDiagnostics_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamStringValue_UploadURL_returnFALSE)
{
    char *pString = NULL;

    const char *ParamName = "UploadURL";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    EXPECT_FALSE(UploadDiagnostics_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_SetParamStringValue_NONE)
{
    char pString[100] = "www.google.com";

    const char *ParamName = "NONE";

     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO )malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO ));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    EXPECT_FALSE(UploadDiagnostics_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_Validate_returnTRUE)
{
    char pReturnParamName[100] = {0};
    ULONG puLength = 100;

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    PDSLH_TR143_UPLOAD_DIAG_INFO pUploadInfo  =(PDSLH_TR143_UPLOAD_DIAG_INFO) pMyObject->hDiagUploadInfo;
    
    pUploadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_Requested;
    strcpy(pUploadInfo->UploadURL, "www.google.com");

    EXPECT_TRUE(UploadDiagnostics_Validate(NULL, pReturnParamName, &puLength));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_Validate_returnFALSE)
{
    char pReturnParamName[100] = {0};
    ULONG puLength = 100;

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo  = (PDSLH_TR143_UPLOAD_DIAG_INFO)pMyObject->hDiagUploadInfo;
    
    pUploadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_Requested;
    strcpy(pUploadInfo->UploadURL, "");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_FALSE(UploadDiagnostics_Validate(NULL, pReturnParamName, &puLength));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_Commit_returnZERO)
{
    componentStruct_t ** ppComponents = NULL;
     parameterValStruct_t ** parameterVal = NULL;

    const char *status = "10.126.32.51";

    ppComponents = (componentStruct_t **)malloc(sizeof(componentStruct_t *));
    ASSERT_NE(ppComponents, nullptr);

    parameterVal = (parameterValStruct_t **)malloc(sizeof(parameterValStruct_t *));
    ASSERT_NE(parameterVal, nullptr);

    *parameterVal  = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    ASSERT_NE(*parameterVal, nullptr);

    *ppComponents = (componentStruct_t *)malloc(sizeof(componentStruct_t));
    ASSERT_NE(*ppComponents, nullptr);

    (*ppComponents)->componentName = strdup("Component1");
    (*ppComponents)->dbusPath = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_dbus_path = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_name = strdup("com.example.component1");

    (*parameterVal)->parameterName = strdup("Device.DeviceInfo.X_COMCAST-COM_WAN_IP");
    (*parameterVal)->parameterValue = strdup("erouter0");

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _))
      .WillRepeatedly(testing::DoAll(testing::WithArgs<6>([&parameterVal](parameterValStruct_t ***outComponents) {
            *outComponents = parameterVal;
        }),
        testing::Return(100)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(_))
        .WillRepeatedly(Return());

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("::"))).WillRepeatedly(Return((char*)status));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_, _, _, _, _, _))
    .WillRepeatedly(testing::DoAll(
        testing::WithArgs<4>([&ppComponents](componentStruct_t ***outComponents) {
            *outComponents = ppComponents;
        }),
        testing::Return(100)
    ));

    EXPECT_EQ(0, UploadDiagnostics_Commit(NULL));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(*ppComponents);
    *ppComponents = NULL;
    free(ppComponents);
    ppComponents = NULL;
    free(*parameterVal);
    *parameterVal = NULL;
    free(parameterVal);
    parameterVal = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_Rollback_return_ANSC_FAILURE)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = NULL;

    EXPECT_EQ(ANSC_STATUS_FAILURE, UploadDiagnostics_Rollback(NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UploadDiagnostics_Rollback_returnZERO)
{
    g_pCosaDiagPluginInfo = NULL;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)malloc(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO));
    ASSERT_NE(pMyObject->hDiagUploadInfo, nullptr);

    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo      = (PDSLH_TR143_UPLOAD_DIAG_INFO)pMyObject->hDiagUploadInfo;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadPreInfo   = NULL;

    EXPECT_EQ(0, UploadDiagnostics_Rollback(NULL));

    free(pMyObject->hDiagUploadInfo);
    pMyObject->hDiagUploadInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamBoolValue_Enable_returnTRUE)
{
    BOOL pBool = TRUE;

    const char *ParamName = "Enable";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG)pMyObject->hDiagUdpechoSrvInfo;

    pUdpEchoInfo->Enable = TRUE;

    EXPECT_TRUE(UDPEchoConfig_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamBoolValue_Enable_returnFALSE)
{
    BOOL pBool = TRUE;

    const char *ParamName = "Enable";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = NULL;

    EXPECT_FALSE(UDPEchoConfig_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamBoolValue_EchoPlusEnabled_returnTRUE)
{
    BOOL pBool = TRUE;

    const char *ParamName = "EchoPlusEnabled";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG) pMyObject->hDiagUdpechoSrvInfo;

    pUdpEchoInfo->EchoPlusEnabled = TRUE;

    EXPECT_TRUE(UDPEchoConfig_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamBoolValue_EchoPlusEnabled_returnFALSE)
{
    BOOL pBool = TRUE;

    const char *ParamName = "EchoPlusEnabled";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = NULL;

    EXPECT_FALSE(UDPEchoConfig_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamBoolValue_EchoPlusSupported_returnTRUE)
{
    BOOL pBool = TRUE;

    const char *ParamName = "EchoPlusSupported";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG) pMyObject->hDiagUdpechoSrvInfo;

    pUdpEchoInfo->EchoPlusSupported = TRUE;

    EXPECT_TRUE(UDPEchoConfig_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamBoolValue_EchoPlusSupported_returnFALSE)
{
    BOOL pBool = TRUE;

    const char *ParamName = "EchoPlusSupported";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = NULL;

    EXPECT_FALSE(UDPEchoConfig_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamIntValue)
{
    int pInt = 1;

    const char *ParamName = "NONE";

    EXPECT_FALSE(UDPEchoConfig_GetParamIntValue(NULL, (char*)ParamName, &pInt));
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamUlongValue_UDPPort_returnTRUE)
{
    ULONG puLong = 1;

    const char *ParamName = "UDPPort";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG)pMyObject->hDiagUdpechoSrvInfo;

    pUdpEchoInfo->UDPPort = 1;

    EXPECT_TRUE(UDPEchoConfig_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamUlongValue_UDPPort_returnFALSE)
{
    ULONG puLong = 1;

    const char *ParamName = "UDPPort";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = NULL;

    EXPECT_FALSE(UDPEchoConfig_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamUlongValue_PacketsReceived_returnFALSE)
{
    ULONG puLong = 1;

    const char *ParamName = "PacketsReceived";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_FALSE(UDPEchoConfig_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamUlongValue_PacketsResponded_returnFALSE)
{
    ULONG puLong = 1;

    const char *ParamName = "PacketsResponded";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_FALSE(UDPEchoConfig_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamUlongValue_BytesReceived_returnFALSE_with_pUdpEchoInfo)
{
    ULONG puLong = 1;

    const char *ParamName = "BytesReceived";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG)pMyObject->hDiagUdpechoSrvInfo;

    pUdpEchoInfo->Enable = TRUE;

    EXPECT_FALSE(UDPEchoConfig_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamUlongValue_BytesReceived_returnTRUE_without_pUdpEchoInfo)
{
    ULONG puLong = 1;

    const char *ParamName = "BytesReceived";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = NULL;

    EXPECT_TRUE(UDPEchoConfig_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamUlongValue_BytesResponded_returnFALSE)
{
    ULONG puLong = 1;

    const char *ParamName = "BytesResponded";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_FALSE(UDPEchoConfig_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamUlongValue_FALSE)
{
    ULONG puLong = 1;

    const char *ParamName = "NONE";

        g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = NULL;

    EXPECT_FALSE(UDPEchoConfig_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamStringValue_Interface_returnZERO)
{
    ULONG pUlSize = 0;
    char pValue[128] = { 0 };

    const char *ParamName = "Interface";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG)pMyObject->hDiagUdpechoSrvInfo;

    strcpy(pUdpEchoInfo->Interface, "eth0");

    EXPECT_EQ(0, UDPEchoConfig_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamStringValue_Interface_returnMINUS1)
{
    ULONG pUlSize = 0;
    char pValue[128] = { 0 };

    const char *ParamName = "Interface";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = NULL;

    EXPECT_EQ(-1, UDPEchoConfig_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamStringValue_SourceIPAddress_returnZERO)
{
    ULONG pUlSize = 0;
    char pValue[128] = { 0 };

    const char *ParamName = "SourceIPAddress";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  =(PDSLH_TR143_UDP_ECHO_CONFIG) pMyObject->hDiagUdpechoSrvInfo;

    strcpy(pUdpEchoInfo->SourceIPName, "10.126.25.14"   );

    EXPECT_EQ(0, UDPEchoConfig_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag );
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamStringValue_SourceIPAddress_returnMINUS1)
{
    ULONG pUlSize = 0;
    char pValue[128] = { 0 };

    const char *ParamName = "SourceIPAddress";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = NULL;

    EXPECT_EQ(-1, UDPEchoConfig_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamStringValue_TimeFirstPacketReceived_returnMINUS1)
{
    ULONG pUlSize = 0;
    char pValue[128] = { 0 };

    const char *ParamName = "TimeFirstPacketReceived";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_EQ(-1, UDPEchoConfig_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamStringValue_TimeLastPacketReceived_returnMINUS1)
{
    ULONG pUlSize = 0;
    char pValue[128] = { 0 };

    const char *ParamName = "TimeLastPacketReceived";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_EQ(-1, UDPEchoConfig_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_GetParamStringValue_NONE_returnMINUS1)
{
    ULONG pUlSize = 0;
    char pValue[128] = { 0 };

    const char *ParamName = "NONE";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_EQ(-1, UDPEchoConfig_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_SetParamBoolValue_Enable_returnTRUE)
{
    BOOL bValue = TRUE;

    const char *ParamName = "Enable";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG)pMyObject->hDiagUdpechoSrvInfo;

    EXPECT_TRUE(UDPEchoConfig_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_SetParamBoolValue_EchoPlusEnabled_returnTRUE)
{
    BOOL bValue = TRUE;

    const char *ParamName = "EchoPlusEnabled";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG)pMyObject->hDiagUdpechoSrvInfo;

    EXPECT_TRUE(UDPEchoConfig_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_SetParamBoolValue_NONE_FALSE)
{
    BOOL bValue = TRUE;

    const char *ParamName = "NONE";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_FALSE(UDPEchoConfig_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_SetParamIntValue_returnFALSE)
{
    int iValue = 1;

    const char *ParamName = "NONE";

    EXPECT_FALSE(UDPEchoConfig_SetParamIntValue(NULL, (char*)ParamName, iValue));
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_SetParamUlongValue_UDPPort_returnTRUE)
{
    ULONG uValue = 1;

    const char *ParamName = "UDPPort";

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_TRUE(UDPEchoConfig_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_SetParamUlongValue_UDPPort_returnFALSE)
{
    ULONG uValue = 0;

    const char *ParamName = "UDPPort";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);


    EXPECT_FALSE(UDPEchoConfig_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_SetParamUlongValue_NONE_returnFALSE)
{
    ULONG uValue = 1;

    const char *ParamName = "NONE";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_FALSE(UDPEchoConfig_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_SetParamStringValue_Interface_returnTRUE)
{
    char pString[128] = "eth0";

    const char *ParamName = "Interface";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(UDPEchoConfig_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_SetParamStringValue_SourceIPAddress_returnTRUE)
{
    char pString[128] = "10.126.15.20";

    const char *ParamName = "SourceIPAddress";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(UDPEchoConfig_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_SetParamStringValue_NONE_returnFALSE)
{
    char pString[128] = "eth0";

    const char *ParamName = "NONE";

     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    
    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_FALSE(UDPEchoConfig_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_Validate_returnTRUE)
{
    ULONG puLength = 0;
    char pReturnParamName[128] = { 0 };

    componentStruct_t ** ppComponents = NULL;
     parameterValStruct_t ** parameterVal = NULL;

    ppComponents = (componentStruct_t **)malloc(sizeof(componentStruct_t *));
    ASSERT_NE(ppComponents, nullptr);

    parameterVal = (parameterValStruct_t **)malloc(sizeof(parameterValStruct_t *));
    ASSERT_NE(parameterVal, nullptr);

    *parameterVal  = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    ASSERT_NE(*parameterVal, nullptr);

    *ppComponents = (componentStruct_t *)malloc(sizeof(componentStruct_t));
    ASSERT_NE(*ppComponents, nullptr);

    (*ppComponents)->componentName = strdup("Component1");
    (*ppComponents)->dbusPath = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_dbus_path = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_name = strdup("com.example.component1");

    (*parameterVal)->parameterName = strdup("Device.DeviceInfo.X_COMCAST-COM_WAN_IP");
    (*parameterVal)->parameterValue = strdup("erouter0");

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG)pMyObject->hDiagUdpechoSrvInfo;

    strcpy(pUdpEchoInfo->Interface, "eth0");
    pUdpEchoInfo->EchoPlusEnabled = TRUE;
    pUdpEchoInfo->EchoPlusSupported = TRUE;
    strcpy(pUdpEchoInfo->SourceIPName, "10.126.35.46");
    pUdpEchoInfo->Enable = TRUE;
    pUdpEchoInfo->UDPPort = 1;

    const char *status = "10.126.38.79";

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::WithArgs<6>([&parameterVal](parameterValStruct_t ***outComponents) {
            *outComponents = parameterVal;
        }),
        testing::Return(100)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(_))
        .WillRepeatedly(Return());

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("::"))).WillRepeatedly(Return((char*)status));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_, _, _, _, _, _))
    .Times(1)
    .WillRepeatedly(testing::DoAll(
        testing::WithArgs<4>([&ppComponents](componentStruct_t ***outComponents) {
            *outComponents = ppComponents; 
        }),
        testing::Return(100)
    ));

    EXPECT_TRUE(UDPEchoConfig_Validate(NULL, pReturnParamName, &puLength));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(*ppComponents);
    *ppComponents = NULL;
    free(ppComponents);
    ppComponents = NULL;
    free(*parameterVal);
    *parameterVal = NULL;
    free(parameterVal);
    parameterVal = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_Validate_EchoPlusSupported_returnFALSE)
{
    ULONG puLength = 0;
    char pReturnParamName[128] = { 0 };

    componentStruct_t ** ppComponents = NULL;
     parameterValStruct_t ** parameterVal = NULL;

    ppComponents = (componentStruct_t **)malloc(sizeof(componentStruct_t *));
    ASSERT_NE(ppComponents, nullptr);

    parameterVal = (parameterValStruct_t **)malloc(sizeof(parameterValStruct_t *));
    ASSERT_NE(parameterVal, nullptr);

    *parameterVal  = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    ASSERT_NE(*parameterVal, nullptr);

    *ppComponents = (componentStruct_t *)malloc(sizeof(componentStruct_t));
    ASSERT_NE(*ppComponents, nullptr);

    (*ppComponents)->componentName = strdup("Component1");
    (*ppComponents)->dbusPath = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_dbus_path = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_name = strdup("com.example.component1");

    (*parameterVal)->parameterName = strdup("Device.DeviceInfo.X_COMCAST-COM_WAN_IP");
    (*parameterVal)->parameterValue = strdup("erouter0");

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG)pMyObject->hDiagUdpechoSrvInfo;

    strcpy(pUdpEchoInfo->Interface, "eth0");
    pUdpEchoInfo->EchoPlusEnabled = TRUE;
    pUdpEchoInfo->EchoPlusSupported = FALSE;
    strcpy(pUdpEchoInfo->SourceIPName, "10.126.35.46");
    pUdpEchoInfo->Enable = TRUE;
    pUdpEchoInfo->UDPPort = 1;

    const char *status = "10.126.38.79";

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::WithArgs<6>([&parameterVal](parameterValStruct_t ***outComponents) {
            *outComponents = parameterVal;
        }),
        testing::Return(100)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(_))
        .WillRepeatedly(Return());

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("::"))).WillRepeatedly(Return((char*)status));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_, _, _, _, _, _))
    .Times(1)
    .WillRepeatedly(testing::DoAll(
        testing::WithArgs<4>([&ppComponents](componentStruct_t ***outComponents) {
            *outComponents = ppComponents;
        }),
        testing::Return(100)
    ));

    EXPECT_FALSE(UDPEchoConfig_Validate(NULL, pReturnParamName, &puLength));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(*ppComponents);
    *ppComponents = NULL;
    free(ppComponents);
    ppComponents = NULL;
    free(*parameterVal);
    *parameterVal = NULL;
    free(parameterVal);
    parameterVal = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_Validate_SourceIPAddress_returnFALSE)
{
    ULONG puLength = 0;
    char pReturnParamName[128] = { 0 };

    componentStruct_t ** ppComponents = NULL;
     parameterValStruct_t ** parameterVal = NULL;

    ppComponents = (componentStruct_t **)malloc(sizeof(componentStruct_t *));
    ASSERT_NE(ppComponents, nullptr);

    parameterVal = (parameterValStruct_t **)malloc(sizeof(parameterValStruct_t *));
    ASSERT_NE(parameterVal, nullptr);

    *parameterVal  = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    ASSERT_NE(*parameterVal, nullptr);

    *ppComponents = (componentStruct_t *)malloc(sizeof(componentStruct_t));
    ASSERT_NE(*ppComponents, nullptr);

    (*ppComponents)->componentName = strdup("Component1");
    (*ppComponents)->dbusPath = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_dbus_path = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_name = strdup("com.example.component1");

    (*parameterVal)->parameterName = strdup("Device.DeviceInfo.X_COMCAST-COM_WAN_IP");
    (*parameterVal)->parameterValue = strdup("erouter0");

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = (PDSLH_TR143_UDP_ECHO_CONFIG)pMyObject->hDiagUdpechoSrvInfo;

     strcpy(pUdpEchoInfo->Interface, "eth0");
    pUdpEchoInfo->EchoPlusEnabled = TRUE;
    pUdpEchoInfo->EchoPlusSupported = FALSE;
    pUdpEchoInfo->SourceIPName[0] = '\0';
    pUdpEchoInfo->Enable = TRUE;
    pUdpEchoInfo->UDPPort = 1;

    const char *status = "10.126.38.79";

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::WithArgs<6>([&parameterVal](parameterValStruct_t ***outComponents) {
            *outComponents = parameterVal;
        }),
        testing::Return(100)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(_))
        .WillRepeatedly(Return());

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("::"))).WillRepeatedly(Return((char*)status));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_, _, _, _, _, _))
    .Times(1)
    .WillRepeatedly(testing::DoAll(
        testing::WithArgs<4>([&ppComponents](componentStruct_t ***outComponents) {
            *outComponents = ppComponents; 
        }),
        testing::Return(100)
    ));

    EXPECT_FALSE(UDPEchoConfig_Validate(NULL, pReturnParamName, &puLength));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(*ppComponents);
    *ppComponents = NULL;
    free(ppComponents);
    ppComponents = NULL;
    free(*parameterVal);
    *parameterVal = NULL;
    free(parameterVal);
    parameterVal = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_Validate_UDPPort_returnFALSE)
{
    ULONG puLength = 0;
    char pReturnParamName[128] = { 0 };

    componentStruct_t ** ppComponents = NULL;
     parameterValStruct_t ** parameterVal = NULL;

    ppComponents = (componentStruct_t **)malloc(sizeof(componentStruct_t *));
    ASSERT_NE(ppComponents, nullptr);

    parameterVal = (parameterValStruct_t **)malloc(sizeof(parameterValStruct_t *));
    ASSERT_NE(parameterVal, nullptr);

    *parameterVal  = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    ASSERT_NE(*parameterVal, nullptr);

    *ppComponents = (componentStruct_t *)malloc(sizeof(componentStruct_t));
    ASSERT_NE(*ppComponents, nullptr);

    (*ppComponents)->componentName = strdup("Component1");
    (*ppComponents)->dbusPath = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_dbus_path = strdup("/com/example/component1");
    (*ppComponents)->remoteCR_name = strdup("com.example.component1");

    (*parameterVal)->parameterName = strdup("Device.DeviceInfo.X_COMCAST-COM_WAN_IP");
    (*parameterVal)->parameterValue = strdup("erouter0");

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  =(PDSLH_TR143_UDP_ECHO_CONFIG)pMyObject->hDiagUdpechoSrvInfo;

     strcpy(pUdpEchoInfo->Interface, "eth0");
    pUdpEchoInfo->EchoPlusEnabled = TRUE;
    pUdpEchoInfo->EchoPlusSupported = FALSE;
    strcpy(pUdpEchoInfo->SourceIPName, "10.126.35.46");
    pUdpEchoInfo->Enable = TRUE;
    pUdpEchoInfo->UDPPort = 0;

    const char *status = "10.126.38.79";

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::WithArgs<6>([&parameterVal](parameterValStruct_t ***outComponents) {
            *outComponents = parameterVal;
        }),
        testing::Return(100)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(_))
        .WillRepeatedly(Return());

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("::"))).WillRepeatedly(Return((char*)status));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_, _, _, _, _, _))
    .Times(1)
    .WillRepeatedly(testing::DoAll(
        testing::WithArgs<4>([&ppComponents](componentStruct_t ***outComponents) {
            *outComponents = ppComponents;
        }),
        testing::Return(100)
    ));

    EXPECT_FALSE(UDPEchoConfig_Validate(NULL, pReturnParamName, &puLength));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(*ppComponents);
    *ppComponents = NULL;
    free(ppComponents);
    ppComponents = NULL;
    free(*parameterVal);
    *parameterVal = NULL;
    free(parameterVal);
    parameterVal = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_Commit_return0)
{
    g_pCosaDiagPluginInfo = (PCOSA_DIAG_PLUGIN_INFO)malloc(sizeof(COSA_DIAG_PLUGIN_INFO));
    ASSERT_NE(g_pCosaDiagPluginInfo, nullptr);

    g_pCosaDiagPluginInfo->uLoadStatus = COSA_STATUS_SUCCESS;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_EQ(0, UDPEchoConfig_Commit(NULL));

    free(g_pCosaDiagPluginInfo);
    g_pCosaDiagPluginInfo = NULL;

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_Rollback_returnANSC_STATUS_FAILURE)
{

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = NULL;

    EXPECT_EQ(ANSC_STATUS_FAILURE, UDPEchoConfig_Rollback(NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, UDPEchoConfig_Rollback_return0)
{

    g_pCosaDiagPluginInfo = NULL;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagUdpechoSrvInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)malloc(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));
    ASSERT_NE(pMyObject->hDiagUdpechoSrvInfo, nullptr);

    EXPECT_EQ(0, UDPEchoConfig_Rollback(NULL));

    free(pMyObject->hDiagUdpechoSrvInfo);
    pMyObject->hDiagUdpechoSrvInfo = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamBoolValue_Enable_Speedtest_returnTRUE)
{
    BOOL pBool = FALSE;

    const char *ParamName = "Enable_Speedtest";

    g_enable_speedtest = TRUE;

    EXPECT_TRUE(SpeedTest_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamBoolValue_Run_returnTRUE)
{
    BOOL pBool = FALSE;

    const char *ParamName = "Run";

    g_run_speedtest = TRUE;

    EXPECT_TRUE(SpeedTest_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamBoolValue_UnsupportedParameter_returnFALSE)
{
    BOOL pBool = FALSE;

    const char *ParamName = "UnsupportedParameter";

    EXPECT_FALSE(SpeedTest_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamBoolValue_Enable_Speedtest_returnTRUE)
{
    BOOL bValue = TRUE;

    const char *ParamName = "Enable_Speedtest";

    EXPECT_TRUE(SpeedTest_SetParamBoolValue(NULL, (char*)ParamName, bValue));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamBoolValue_Run_returnTRUE)
{
    BOOL bValue = TRUE;

    const char *ParamName = "Run";

    EXPECT_TRUE(SpeedTest_SetParamBoolValue(NULL, (char*)ParamName, bValue));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamBoolValue_UnsupportedParameter_returnFALSE)
{
    BOOL bValue = TRUE;

    const char *ParamName = "UnsupportedParameter";

    EXPECT_FALSE(SpeedTest_SetParamBoolValue(NULL, (char*)ParamName, bValue));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_Validate_returnTRUE)
{
    ULONG puLength = 0;
    char pReturnParamName[128] = { 0 };

    g_enable_speedtest = TRUE;
    g_run_speedtest = FALSE;

    EXPECT_TRUE(SpeedTest_Validate(NULL, pReturnParamName, &puLength));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_Validate_returnFALSE)
{
    ULONG puLength = 0;
    char pReturnParamName[128] = { 0 };

    g_enable_speedtest = FALSE;
    g_run_speedtest = TRUE;

     EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_FALSE(SpeedTest_Validate(NULL, pReturnParamName, &puLength));
}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_Commit_return0)
{
    char previous[8] = { 0 };

    g_enable_speedtest = TRUE;
    g_run_speedtest = TRUE;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, SpeedTest_Commit(NULL));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_Commit_return1)
{
    char previous[8] = { 0 };
    char prev[5] = "true";

    g_enable_speedtest = TRUE;
    g_run_speedtest = TRUE;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(1));

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_,_)).WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(1, SpeedTest_Commit(NULL));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_Rollback_return0)
{
    char buf[128] = { 0 };
    char prev[5] = "true";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, SpeedTest_Rollback(NULL));

}

TEST_F(CcspTandD_IP_DmlTest, RDK_SpeedTest_GetParamUlongValue_SubscriberUnPauseTimeOut_returnTRUE)
{
    ULONG pUlong = 0;

    const char *ParamName = "SubscriberUnPauseTimeOut";

    char TO_buf[3] = "10";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<2>(TO_buf, TO_buf + strlen(TO_buf) + 1),
            Return(0)
        ));

    EXPECT_TRUE(RDK_SpeedTest_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, RDK_SpeedTest_GetParamUlongValue_SubscriberUnPauseTimeOut_ELSE_returnFALSE)
{
    ULONG pUlong = 0;

    const char *ParamName = "SubscriberUnPauseTimeOut";

    char TO_buf[1] = "";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<2>(TO_buf, TO_buf + strlen(TO_buf) + 1),
            Return(0)
        ));

    EXPECT_FALSE(RDK_SpeedTest_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, RDK_SpeedTest_SetParamUlongValue_SubscriberUnPauseTimeOut_returnTRUE)
{
    ULONG pUlong = 10;

    const char *ParamName = "SubscriberUnPauseTimeOut";

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(RDK_SpeedTest_SetParamUlongValue(NULL, (char*)ParamName, pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, RDK_SpeedTest_SetParamUlongValue_SubscriberUnPauseTimeOut_syscfg_fail_returnTRUE)
{
    ULONG pUlong = 10;

    const char *ParamName = "SubscriberUnPauseTimeOut";

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_TRUE(RDK_SpeedTest_SetParamUlongValue(NULL, (char*)ParamName, pUlong));

}


TEST_F(CcspTandD_IP_DmlTest, RDK_SpeedTest_SetParamUlongValue_SubscriberUnPauseTimeOut_returnFALSE)
{
    ULONG pUlong = 0;

    const char *ParamName = "SubscriberUnPauseTimeOut";

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_FALSE(RDK_SpeedTest_SetParamUlongValue(NULL, (char*)ParamName, pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, RDK_SpeedTest_SetParamUlongValue_UnsupportedParameter_returnFALSE)
{
    ULONG pUlong = 0;

    const char *ParamName = "UnsupportedParameter";

    EXPECT_FALSE(RDK_SpeedTest_SetParamUlongValue(NULL, (char*)ParamName, pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamStringValue_Argument_return0)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "Argument";

    strcpy(g_argument_speedtest, "speedtest");

    EXPECT_EQ(0, SpeedTest_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamStringValue_Argument_return1)
{
    ULONG pUlSize = 4095;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "Argument";

    strcpy(g_argument_speedtest, "speedtest");

    EXPECT_EQ(1, SpeedTest_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamStringValue_Authentication_return0)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "Authentication";

    strcpy(g_authentication_speedtest, "speedtest");

    EXPECT_EQ(0, SpeedTest_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamStringValue_Authentication_return1)
{
    ULONG pUlSize = 4095;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "Authentication";

    strcpy(g_authentication_speedtest, "speedtest");

    EXPECT_EQ(1, SpeedTest_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamStringValue_ClientVersion_return0)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "ClientVersion";

    strcpy(g_clientversion_speedtest, "2.01");

    EXPECT_EQ(0, SpeedTest_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamStringValue_NONE)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "NONE";

    EXPECT_EQ(-1, SpeedTest_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));
}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamStringValue_Argument_returnTRUE)
{
    char pString[128] = "Enable_Speedtest";

    const char *ParamName = "Argument";

    EXPECT_TRUE(SpeedTest_SetParamStringValue(NULL, (char*)ParamName, pString));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamStringValue_Argument_returnFALSE)
{
    char a[4098];
    memset(a, 'a', sizeof(a));

    const char *ParamName = "Argument";

    EXPECT_FALSE(SpeedTest_SetParamStringValue(NULL, (char*)ParamName, a));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamStringValue_Authentication_returnTRUE)
{
    char pString[128] = "Enable_Speedtest";

    const char *ParamName = "Authentication";

    EXPECT_TRUE(SpeedTest_SetParamStringValue(NULL, (char*)ParamName, pString));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamStringValue_Authentication_returnFALSE)
{
    char a[4098];
    memset(a, 'a', sizeof(a));

    const char *ParamName = "Authentication";

    EXPECT_FALSE(SpeedTest_SetParamStringValue(NULL, (char*)ParamName, a));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamStringValue_UnsupportedParameter_returnFALSE)
{
    char pString[128] = "Enable_Speedtest";

    const char *ParamName = "UnsupportedParameter";

    EXPECT_FALSE(SpeedTest_SetParamStringValue(NULL, (char*)ParamName, pString));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamUlongValue_ClientType_returnTRUE)
{
    ULONG pUlong = 0;

    const char *ParamName = "ClientType";

    g_clienttype_speedtest = 1;

    EXPECT_TRUE(SpeedTest_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamUlongValue_Status_returnTRUE)
{
    ULONG pUlong = 0;

    const char *ParamName = "Status";

    g_status_speedtest = 1;

    EXPECT_TRUE(SpeedTest_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_GetParamUlongValue_UnsupportedParameter_returnFALSE)
{
    ULONG pUlong = 0;

    const char *ParamName = "UnsupportedParameter";

    EXPECT_FALSE(SpeedTest_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamUlongValue_ClientType_returnTRUE)
{
    ULONG pUlong = 1;

    const char *ParamName = "ClientType";

    EXPECT_TRUE(SpeedTest_SetParamUlongValue(NULL, (char*)ParamName, pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamUlongValue_Status_returnTRUE)
{
    ULONG pUlong = 1;

    const char *ParamName = "Status";

    EXPECT_TRUE(SpeedTest_SetParamUlongValue(NULL, (char*)ParamName, pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTest_SetParamUlongValue_UnsupportedParameter_returnFALSE)
{
    ULONG pUlong = 1;

    const char *ParamName = "UnsupportedParameter";

    EXPECT_FALSE(SpeedTest_SetParamUlongValue(NULL, (char*)ParamName, pUlong));

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_GetParamBoolValue_Capability_returnTRUE)
{
    BOOL pBool = FALSE;

    const char *ParamName = "Capability";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    PCOSA_DML_DIAG_SPEEDTEST_SERVER 	pSpeedTestServer = pMyObject->pSpeedTestServer;

    pSpeedTestServer->Capability = TRUE;

    EXPECT_TRUE(SpeedTestServer_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_GetParamBoolValue_UnsupportedParameter_returnFALSE)
{
     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);
    
    BOOL pBool = FALSE;

    const char *ParamName = "UnsupportedParameter";

    EXPECT_FALSE(SpeedTestServer_GetParamBoolValue(NULL, (char*)ParamName, &pBool));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_GetParamStringValue_Key_return0)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "Key";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    PCOSA_DML_DIAG_SPEEDTEST_SERVER 	pSpeedTestServer = pMyObject->pSpeedTestServer;

    strcpy((char*)pSpeedTestServer->Key, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, SpeedTestServer_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_GetParamStringValue_Username_return0)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "Username";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    PCOSA_DML_DIAG_SPEEDTEST_SERVER 	pSpeedTestServer = pMyObject->pSpeedTestServer;

    strcpy((char*)pSpeedTestServer->Username, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, SpeedTestServer_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_GetParamStringValue_Password_return0)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "Password";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    PCOSA_DML_DIAG_SPEEDTEST_SERVER 	pSpeedTestServer = pMyObject->pSpeedTestServer;

    strcpy((char*)pSpeedTestServer->Password, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, SpeedTestServer_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_GetParamStringValue_NONE)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "NONE";

    EXPECT_EQ(-1, SpeedTestServer_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_SetParamStringValue_Key_returnTRUE)
{
    char pString[128] = "Enable_Speedtest";

    const char *ParamName = "Key";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    PCOSA_DML_DIAG_SPEEDTEST_SERVER 	pSpeedTestServer = pMyObject->pSpeedTestServer;

    strcpy((char*)pSpeedTestServer->Key, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SpeedTestServer_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_SetParamStringValue_Key_returnFALSE)
{
    char a[4098];
    memset(a, 'a', 4098);

     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    const char *ParamName = "Key";

    EXPECT_FALSE(SpeedTestServer_SetParamStringValue(NULL, (char*)ParamName, a));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_SetParamStringValue_Username_returnTRUE)
{
    char pString[128] = "Enable";

    const char *ParamName = "Username";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    PCOSA_DML_DIAG_SPEEDTEST_SERVER 	pSpeedTestServer = pMyObject->pSpeedTestServer;

    strcpy((char*)pSpeedTestServer->Username, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SpeedTestServer_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_SetParamStringValue_Username_returnFALSE)
{
    char pString[128] = "Enable_Speedtest";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    const char *ParamName = "Username";

    EXPECT_FALSE(SpeedTestServer_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_SetParamStringValue_Password_returnTRUE)
{
    char pString[128] = "Enable";

    const char *ParamName = "Password";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    PCOSA_DML_DIAG_SPEEDTEST_SERVER 	pSpeedTestServer = pMyObject->pSpeedTestServer;

    strcpy((char*)pSpeedTestServer->Password, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SpeedTestServer_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_SetParamStringValue_Password_returnFALSE)
{
    char pString[128] = "Enable_Speedtest";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    const char *ParamName = "Password";

    EXPECT_FALSE(SpeedTestServer_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, SpeedTestServer_SetParamStringValue_UnsupportedParameter_returnFALSE)
{
    char pString[128] = "Enable_Speedtest";

    const char *ParamName = "UnsupportedParameter";

     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pSpeedTestServer = (PCOSA_DML_DIAG_SPEEDTEST_SERVER)malloc(sizeof(COSA_DML_DIAG_SPEEDTEST_SERVER));
    ASSERT_NE(pMyObject->pSpeedTestServer, nullptr);

    EXPECT_FALSE(SpeedTestServer_SetParamStringValue(NULL, (char*)ParamName, pString));

    free(pMyObject->pSpeedTestServer);
    pMyObject->pSpeedTestServer = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue_InterfaceList_return0)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "InterfaceList";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    strcpy((char*)pRxTXStats->Interfacelist, "speedtest");

    strcpy((char*)pRxTXStats->Interfacelist, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _,_)).Times(1)
    .WillRepeatedly(testing::DoAll(
        testing::SetArgPointee<3>(0),
        Return(0)
    ));

    EXPECT_EQ(0, X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue_InterfaceList_returnMINUS1)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "InterfaceList";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    strcpy((char*)pRxTXStats->Interfacelist, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _,_)).Times(1)
    .WillRepeatedly(testing::DoAll(
        testing::SetArgPointee<3>(0),
        Return(0)
    ));

    EXPECT_NE(0, X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue_PortList_return0)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "PortList";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    strcpy((char*)pRxTXStats->Portlist, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _,_)).Times(1)
    .WillRepeatedly(testing::DoAll(
        testing::SetArgPointee<3>(0),
        Return(0)
    ));

    EXPECT_EQ(0, X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue_PortList_returnMINUS1)
{
    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "PortList";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    strcpy((char*)pRxTXStats->Portlist, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _,_)).Times(2)
    .WillOnce(testing::DoAll(
        testing::SetArgPointee<3>(0),
        Return(-1)))
    .WillOnce(testing::DoAll(
        testing::SetArgPointee<3>(0),
        Return(0)
    ));

    EXPECT_NE(0, X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue_UnsupportedParameter_return1)
{
     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    ULONG pUlSize = 4097;
    char pValue[128] = "Enable_Speedtest";

    const char *ParamName = "UnsupportedParameter";

    EXPECT_EQ(1, X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_SetParamStringValue_InterfaceList_returnTRUE)
{
    char pString[128] = "Enable_Speedtest";

    ULONG pUlSize = 4097;

    const char *ParamName = "InterfaceList";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(X_RDKCENTRAL_COM_RxTxStats_SetParamStringValue(NULL, (char*)ParamName, pString, &pUlSize));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_SetParamStringValue_PortList_returnTRUE)
{
    char pString[128] = "Enable_Speedtest";

    ULONG pUlSize = 4097;

    const char *ParamName = "PortList";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(X_RDKCENTRAL_COM_RxTxStats_SetParamStringValue(NULL, (char*)ParamName, pString, &pUlSize));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_SetParamStringValue_UnsupportedParameter_returnFALSE)
{
    char pString[128] = "Enable_Speedtest";

    ULONG pUlSize = 4097;

    const char *ParamName = "UnsupportedParameter";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    EXPECT_FALSE(X_RDKCENTRAL_COM_RxTxStats_SetParamStringValue(NULL, (char*)ParamName, pString, &pUlSize));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_Validate_returnTRUE)
{
    ULONG pUlSize = 4097;
    char pReturnParamName[128] = "Enable_Speedtest";

    EXPECT_TRUE(X_RDKCENTRAL_COM_RxTxStats_Validate(NULL, pReturnParamName, &pUlSize));

}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_Commit_return1_rxtxstats_interface_list_syscfg_fail)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    strcpy((char*)pRxTXStats->Interfacelist, "speedtest");

    strcpy((char*)pRxTXStats->Portlist, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_EQ(1, X_RDKCENTRAL_COM_RxTxStats_Commit(NULL));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_Commit_return1_rxtxstats_interface_list_syscfg_pass)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    strcpy((char*)pRxTXStats->Interfacelist, "speedtest");

    strcpy((char*)pRxTXStats->Portlist, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(1, X_RDKCENTRAL_COM_RxTxStats_Commit(NULL));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_Commit_return1_rxtxstats_port_list_syscfg_fail)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    strcpy((char*)pRxTXStats->Interfacelist, "speedtest");

    strcpy((char*)pRxTXStats->Portlist, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(-1));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_EQ(1, X_RDKCENTRAL_COM_RxTxStats_Commit(NULL));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_Commit_return1_rxtxstats_port_list_syscfg_pass)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    strcpy((char*)pRxTXStats->Interfacelist, "speedtest");

    strcpy((char*)pRxTXStats->Portlist, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_)).Times(2)
        .WillOnce(::testing::Return(0))
        .WillOnce(::testing::Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(1, X_RDKCENTRAL_COM_RxTxStats_Commit(NULL));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_Commit_return0)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->pRxTxStats = (PCOSA_DML_DIAG_RXTX_STATS)malloc(sizeof(COSA_DML_DIAG_RXTX_STATS));
    ASSERT_NE(pMyObject->pRxTxStats, nullptr);

    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    strcpy((char*)pRxTXStats->Interfacelist, "speedtest");

    strcpy((char*)pRxTXStats->Portlist, "speedtest");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, X_RDKCENTRAL_COM_RxTxStats_Commit(NULL));

    free(pMyObject->pRxTxStats);
    pMyObject->pRxTxStats = NULL;

    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_IP_DmlTest, X_RDKCENTRAL_COM_RxTxStats_Rollback_return0)
{
    EXPECT_EQ(0, X_RDKCENTRAL_COM_RxTxStats_Rollback(NULL));
}