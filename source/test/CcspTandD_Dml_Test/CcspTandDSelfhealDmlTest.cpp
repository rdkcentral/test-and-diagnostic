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

using namespace std;
using std::filesystem::exists;

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::HasSubstr;
using ::testing::SetArgPointee;
using ::testing::DoAll;


class CcspTandDSelfhealDmlTest : public ::testing::Test {
    protected:
    PCOSA_DATAMODEL_SELFHEAL pMyObject;
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

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamBoolValue_Enable) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_Enable";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    BOOL bValue = FALSE;
    pMyObject->Enable = TRUE;

    EXPECT_TRUE(SelfHeal_GetParamBoolValue(NULL,(char*) ParamName, &bValue));

    EXPECT_EQ(bValue, TRUE);

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamBoolValue_DNSPingTest_Enable) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DNS_PINGTEST_Enable";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    BOOL bValue = FALSE;
    pMyObject->DNSPingTest_Enable = TRUE;

    EXPECT_TRUE(SelfHeal_GetParamBoolValue(NULL,(char*)ParamName, &bValue));

    EXPECT_EQ(bValue, TRUE);

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamBoolValue_DiagnosticMode) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DiagnosticMode";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    BOOL bValue = FALSE;
    pMyObject->DiagnosticMode = TRUE;

    EXPECT_TRUE(SelfHeal_GetParamBoolValue(NULL, (char*)ParamName, &bValue));

    EXPECT_EQ(bValue, TRUE);

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamBoolValue_NoWaitLogSync) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_NoWaitLogSync";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    BOOL bValue = FALSE;
    pMyObject->NoWaitLogSync = TRUE;

    EXPECT_TRUE(SelfHeal_GetParamBoolValue(NULL, (char*)ParamName, &bValue));

    EXPECT_EQ(bValue, TRUE);

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamBoolValue_Enable_bValueTrue) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_Enable";
    BOOL bValue = TRUE;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    pMyObject->Enable = TRUE;
    EXPECT_TRUE(SelfHeal_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamBoolValue_Enable_bValueFalse) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_Enable";
    BOOL bValue = TRUE;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    pMyObject->Enable = FALSE;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, StrEq("selfheal_enable"), "true"))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_,_)).WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    
    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
} 

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamBoolValue_Enable_bValueFalse_False) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_Enable";
    BOOL bValue = FALSE;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    pMyObject->Enable = TRUE;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, StrEq("selfheal_enable"), "true"))
        .WillRepeatedly(::testing::Return(1));
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_securewrapperMock, v_secure_popen(_,_,_))
        .WillRepeatedly(::testing::Return((FILE*)0x1));

    EXPECT_CALL(*g_securewrapperMock, v_secure_pclose(_))
        .WillRepeatedly(::testing::Return(0));
    
     EXPECT_CALL(*g_securewrapperMock, v_secure_popen(StrEq("r"), _, _))
        .WillRepeatedly(::testing::Return(nullptr));
    EXPECT_CALL(*g_securewrapperMock, v_secure_pclose(_)).Times(::testing::AtLeast(1));

    EXPECT_TRUE(SelfHeal_SetParamBoolValue(NULL, (char*)ParamName, bValue));


    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
} 


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamBoolValue_DNSPingTest_Enable_bValueTrue) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DNS_PINGTEST_Enable";
    BOOL bValue = TRUE;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    pMyObject->DNSPingTest_Enable = TRUE;

    EXPECT_TRUE(SelfHeal_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamBoolValue_DNSPingTest_Enable_bValueFalse) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DNS_PINGTEST_Enable";
    BOOL bValue = FALSE;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    pMyObject->DNSPingTest_Enable = TRUE;
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_EQ(ANSC_STATUS_SUCCESS, CosaDmlModifySelfHealDNSPingTestStatus(pMyObject, bValue));
    EXPECT_TRUE(SelfHeal_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamBoolValue_DiagnosticMode_bValueTrue) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DiagnosticMode";
    BOOL bValue = TRUE;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    pMyObject->DiagnosticMode = TRUE;

    EXPECT_TRUE(SelfHeal_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamBoolValue_DiagnosticMode_bValueFalse) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DiagnosticMode";
    BOOL bValue = FALSE;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 
    pMyObject->pConnTest = (PCOSA_DML_CONNECTIVITY_TEST)malloc(sizeof(COSA_DML_CONNECTIVITY_TEST));

    pMyObject->DiagnosticMode = TRUE;
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_syscfgMock,syscfg_get(NULL, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_,_)).WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, CosaDmlModifySelfHealDiagnosticModeStatus(pMyObject, bValue));
    EXPECT_TRUE(SelfHeal_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamBoolValue_NoWaitLogSync_bValueTrue) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_NoWaitLogSync";
    BOOL bValue = TRUE;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    pMyObject->NoWaitLogSync = TRUE;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, StrEq("log_backup_enable"), "true"))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamBoolValue_NoWaitLogSync_bValueFalse) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_NoWaitLogSync";
    BOOL bValue = FALSE;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    pMyObject->NoWaitLogSync = TRUE;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(1));

    EXPECT_TRUE(SelfHeal_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamUlongValue_FreeMemThreshold) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_FreeMemThreshold";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    ULONG puLong = 0;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    EXPECT_TRUE(SelfHeal_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}   

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamUlongValue_MemFragThreshold) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MemFragThreshold";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    ULONG puLong = 0;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    EXPECT_TRUE(SelfHeal_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamUlongValue_CpuMemFragInterval) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_CpuMemFragInterval";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    ULONG puLong = 0;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    EXPECT_TRUE(SelfHeal_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamUlongValue_MaxRebootCount) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MaxRebootCount";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    ULONG puLong = 0;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    EXPECT_TRUE(SelfHeal_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamUlongValue_MaxResetCount) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MaxResetCount";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    ULONG puLong = 0;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    EXPECT_TRUE(SelfHeal_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamUlongValue_DiagMode_LogUploadFrequency) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DiagMode_LogUploadFrequency";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    ULONG puLong = 0;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    EXPECT_TRUE(SelfHeal_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamUlongValue_LogBackupThreshold) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_LogBackupThreshold";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    ULONG puLong = 0;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal; 

    EXPECT_TRUE(SelfHeal_GetParamUlongValue(NULL, (char*)ParamName, &puLong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_FreeMemThreshold) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_FreeMemThreshold";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->FreeMemThreshold = 10;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, StrEq("Free_Mem_Threshold"), uValue))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_MemFragThreshold) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MemFragThreshold";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->MemFragThreshold = 10;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, StrEq("Mem_Frag_Threshold"), uValue))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_CpuMemFragInterval) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_CpuMemFragInterval";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->CpuMemFragInterval = 10;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, StrEq("CpuMemFrag_Interval"), uValue))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

     EXPECT_CALL(*g_securewrapperMock, v_secure_system(_,_)).WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_MaxRebootCount) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MaxRebootCount";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->MaxRebootCnt = 10;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, StrEq("max_reboot_count"), uValue))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_MaxRebootCount_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MaxRebootCount";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->MaxRebootCnt = 11;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, StrEq("max_reboot_count"), uValue))
        .WillRepeatedly(::testing::Return(0));

     EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_MaxResetCount) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MaxResetCount";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->MaxResetCnt = 10;

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_MaxResetCount_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MaxResetCount";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->MaxResetCnt = 11;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, StrEq("max_reset_count"), uValue))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_DiagMode_LogUploadFrequency) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DiagMode_LogUploadFrequency";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->DiagModeLogUploadFrequency = 10;

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_DiagMode_LogUploadFrequency_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DiagMode_LogUploadFrequency";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->DiagModeLogUploadFrequency = 11;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, StrEq("diagMode_LogUploadFrequency"), uValue))
        .WillRepeatedly(::testing::Return(0));

     EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_LogBackupThreshold) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_LogBackupThreshold";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->LogBackupThreshold = 10;

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamUlongValue_LogBackupThreshold_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_LogBackupThreshold";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    ULONG puLong = 0;
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->LogBackupThreshold = 11;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, StrEq("log_backup_threshold"), uValue))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamStringValue_DNS_URL) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DNS_URL";
    char pValue[256] = {0};
    ULONG pUlSize = 256;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    errno_t rc = -1;

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0, SelfHeal_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_GetParamStringValue_DNS_URL_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DNS_URL";
    char pValue[256] = {0};
    ULONG pUlSize = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    errno_t rc = -1;

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    EXPECT_EQ(1, SelfHeal_GetParamStringValue(NULL, (char*)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_SetParamStringValue_DNS_URL) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_DNS_URL";
    char strValue[256] = "www.google.com";

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    errno_t rc = -1;

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    EXPECT_CALL(*g_safecLibMock,_strcpy_s_chk(_,_,_,_))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _,_))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(SelfHeal_SetParamStringValue(NULL, (char*)ParamName, strValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_Validate) 
{
    char pReturnParamName[256] = {0};
    ULONG puLength = 0;

    EXPECT_TRUE(SelfHeal_Validate(NULL, pReturnParamName, &puLength));
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_Commit) 
{
    EXPECT_EQ(0, SelfHeal_Commit(NULL));
}

TEST_F(CcspTandDSelfhealDmlTest, SelfHeal_Rollback) 
{
    EXPECT_EQ(0, SelfHeal_Rollback(NULL));
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_GetParamBoolValue_CorrectiveAction) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_CorrectiveAction";
    BOOL bValue = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->pConnTest->CorrectiveAction = 0;

    EXPECT_TRUE(ConnectivityTest_GetParamBoolValue(NULL, (char*)ParamName, &bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamBoolValue_CorrectiveAction) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_CorrectiveAction";
    BOOL bValue = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->pConnTest->CorrectiveAction = 0;

    EXPECT_TRUE(ConnectivityTest_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamBoolValue_CorrectiveAction_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_CorrectiveAction";
    BOOL bValue = 1;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->pConnTest->CorrectiveAction = 0;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(ConnectivityTest_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamBoolValue_CorrectiveAction_false_syscfg_set_commit) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_CorrectiveAction";
    BOOL bValue = 1;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->pConnTest->CorrectiveAction = 0;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(-1));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_FALSE(ConnectivityTest_SetParamBoolValue(NULL, (char*)ParamName, bValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_GetParamUlongValue_PingInterval) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_PingInterval";
    ULONG pUlong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->pConnTest->PingInterval = 10;

    EXPECT_TRUE(ConnectivityTest_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_GetParamUlongValue_NumPingsPerServer) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_NumPingsPerServer";
    ULONG pUlong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->pConnTest->PingCount = 10;

    EXPECT_TRUE(ConnectivityTest_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_GetParamUlongValue_MinNumPingServer) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MinNumPingServer";
    ULONG pUlong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->pConnTest->MinPingServer = 10;

    EXPECT_TRUE(ConnectivityTest_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_GetParamUlongValue_PingRespWaitTime) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_PingRespWaitTime";
    ULONG pUlong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->pConnTest->WaitTime = 10;

    EXPECT_TRUE(ConnectivityTest_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_GetParamUlongValue_LastReboot) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_LastReboot";
    ULONG pUlong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    char buf[64] = "10";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_FALSE(ConnectivityTest_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_GetParamIntValue_RebootInterval) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_RebootInterval";
    int pInt = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->RouterRebootInterval = 10;

    EXPECT_TRUE(ConnectivityTest_GetParamIntValue(NULL, (char*)ParamName, &pInt));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_GetParamIntValue_CurrentCount) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_CurrentCount";
    int pInt = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    char buf[16] = "10";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->RouterRebootInterval = 10;

    EXPECT_FALSE(ConnectivityTest_GetParamIntValue(NULL, (char*)ParamName, &pInt));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_PingInterval) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_PingInterval";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));

    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->PingInterval = 10;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;

    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_PingInterval_false_syscfg_set_commit) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_PingInterval";
    ULONG uValue = 17;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));

    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->PingInterval = 11;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(-1));
        
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_FALSE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;

    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_PingInterval_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_PingInterval";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));

    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->PingInterval = 11;

    EXPECT_FALSE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;

    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_PingInterval_false_range) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_PingInterval";
    ULONG uValue = 17;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));

    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->PingInterval = 11;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;

    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_NumPingsPerServer) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_NumPingsPerServer";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));

    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->PingCount = 10;

    EXPECT_TRUE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;

    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_NumPingsPerServer_syscfg_commit) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_NumPingsPerServer";
    ULONG uValue = 11;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));

    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->PingCount = 10;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;

    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_NumPingsPerServer_syscfg_commit_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_NumPingsPerServer";
    ULONG uValue = 11;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));

    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->PingCount = 10;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(-1));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_FALSE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;

    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_MinNumPingServer) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MinNumPingServer";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));

    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->MinPingServer = 10;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;

    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_MinNumPingServer_syscfg_commit) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MinNumPingServer";
    ULONG uValue = 11;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    
    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->MinPingServer = 10;
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_TRUE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));
    
    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_MinNumPingServer_syscfg_commit_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_MinNumPingServer";
    ULONG uValue = 11;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    
    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->MinPingServer = 10;
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(-1));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(-1));
    
    EXPECT_FALSE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));
    
    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_PingRespWaitTime) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_PingRespWaitTime";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));

    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);

    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->WaitTime = 10;

    EXPECT_TRUE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));

    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;

    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_PingRespWaitTime_syscfg_commit) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_PingRespWaitTime";
    ULONG uValue = 11;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    
    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->WaitTime = 10;
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_TRUE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));
    
    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamUlongValue_PingRespWaitTime_syscfg_commit_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_PingRespWaitTime";
    ULONG uValue = 11;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    
    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->WaitTime = 10;
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(-1));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_FALSE(ConnectivityTest_SetParamUlongValue(NULL, (char*)ParamName, uValue));
    
    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamIntValue_RebootInterval) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_RebootInterval";
    int pInt = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    
    errno_t rc = -1;
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->RouterRebootInterval = 10;
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_TRUE(ConnectivityTest_SetParamIntValue(NULL, (char*)ParamName, pInt));
    
    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamIntValue_RebootInterval_syscfg_commit_true) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_RebootInterval";
    int pInt = 11;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);
    
    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->RouterRebootInterval = 10;
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_TRUE(ConnectivityTest_SetParamIntValue(NULL, (char*)ParamName, pInt));
    
    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}

TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_SetParamIntValue_RebootInterval_syscfg_commit_false) 
{
    const char *ParamName = "X_RDKCENTRAL-COM_RebootInterval";
    int pInt = 11;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pConnTest->RouterRebootInterval = 10;
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(-1));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(-1));
    
    EXPECT_FALSE(ConnectivityTest_SetParamIntValue(NULL, (char*)ParamName, pInt));
    
    free(g_pCosaBEManager->hSelfHeal);
    g_pCosaBEManager->hSelfHeal = nullptr;
    
    free(g_pCosaBEManager);
    g_pCosaBEManager = nullptr;
}


TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_Validate) 
{
    char pReturnParamName[256] = "X_RDKCENTRAL-COM_RebootInterval";
    ULONG puLength = 0;

    EXPECT_TRUE(ConnectivityTest_Validate(NULL, pReturnParamName, &puLength));
}


TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_Commit) 
{
    EXPECT_TRUE(ConnectivityTest_Commit(NULL));
}


TEST_F(CcspTandDSelfhealDmlTest, ConnectivityTest_Rollback) 
{
    EXPECT_TRUE(ConnectivityTest_Rollback(NULL));
}

TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_GetEntryCount) 
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->IPV4PingServerList.Depth = 0;

    EXPECT_EQ(0, IPv4PingServerTable_GetEntryCount(NULL));
}

TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_GetEntry_ValidIndex) 
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    
    AnscSListInitializeHeader(&pMyObject->IPV4PingServerList);

    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pEntry1 = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));
    pEntry1->InstanceNumber = 1;
    AnscSListPushEntry(&pMyObject->IPV4PingServerList, &pEntry1->Linkage);
    
    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pEntry2 = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));
    pEntry2->InstanceNumber = 2;
    AnscSListPushEntry(&pMyObject->IPV4PingServerList, &pEntry2->Linkage);
    
    ULONG nIndex = 1;
    ULONG pInsNumber = 0;

    EXPECT_CALL(*g_anscWrapperApiMock, AnscSListSearchEntryByIndex(testing::_, 1))
    .WillOnce(testing::Return(reinterpret_cast<_SINGLE_LINK_ENTRY*>(&pEntry2->Linkage)));
    
    ANSC_HANDLE result = IPv4PingServerTable_GetEntry(NULL, nIndex, &pInsNumber);
    
    EXPECT_EQ(result, (ANSC_HANDLE)&pEntry2->Linkage);
    EXPECT_EQ(pInsNumber, 2);
}

TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_IsUpdated) 
{
    EXPECT_TRUE(IPv4PingServerTable_IsUpdated(NULL));
}


TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_Synchronize) 
{
    EXPECT_EQ(ANSC_STATUS_SUCCESS, IPv4PingServerTable_Synchronize(NULL));
}

TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_AddEntry) 
{
    ULONG pInsNumber = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->pConnTest = (PCOSA_DML_CONNECTIVITY_TEST)malloc(sizeof(COSA_DML_CONNECTIVITY_TEST));

    ANSC_HANDLE pSelfHealCxtLink;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _)).WillRepeatedly(::testing::Return(0));

    pSelfHealCxtLink = IPv4PingServerTable_AddEntry(NULL, &pInsNumber);

    EXPECT_NE(nullptr, pSelfHealCxtLink);
}


TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_DelEntry) 
{
    ANSC_HANDLE hInstance = NULL;
     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pSelfHealCxtLink = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));

    pSelfHealCxtLink->hContext = (PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE)malloc(sizeof(COSA_DML_SELFHEAL_IPv4_SERVER_TABLE));

    PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE pServerIpv4 = (PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE)pSelfHealCxtLink->hContext;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_unset(_,_)) .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_commit())
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscSListPopEntryByLink(testing::_, testing::_))
        .WillRepeatedly(testing::Return(TRUE));
    
    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(testing::_))
        .WillRepeatedly(testing::Return());

    pMyObject->pConnTest = (PCOSA_DML_CONNECTIVITY_TEST)malloc(sizeof(PCOSA_DML_CONNECTIVITY_TEST));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, RemovePingServerURI((PingServerType)0, (ULONG)1));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, IPv4PingServerTable_DelEntry(NULL, pSelfHealCxtLink));
}

TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_GetParamStringValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_Ipv4PingServerURI";
    char pValue[256] = {0};
    const char* ip = "192.168.0.1"; 
    ULONG pUlSize = sizeof(pValue);

    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pSelfHealCxtLink = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));
    pSelfHealCxtLink->hContext = (PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE)malloc(sizeof(COSA_DML_SELFHEAL_IPv4_SERVER_TABLE));
    PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE pServerIpv4  = (PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE)pSelfHealCxtLink->hContext;
    strcpy(reinterpret_cast<char*>(pServerIpv4->Ipv4PingServerURI), ip);
    hInsContext = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)pSelfHealCxtLink;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _ , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(ip, ip + strlen(ip) + 1),
            Return(0)
        ));

    ULONG result = IPv4PingServerTable_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 0);
    EXPECT_STREQ(pValue, "192.168.0.1");
}

TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_GetParamStringValue_InvalidParamName) 
{
   ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_Ipv4PingServerURI";
    char pValue[5] = {0};
    const char* ip = "192.168.0.1";  
    ULONG pUlSize = sizeof(pValue);

    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pSelfHealCxtLink = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));
    pSelfHealCxtLink->hContext = (PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE)malloc(sizeof(COSA_DML_SELFHEAL_IPv4_SERVER_TABLE));
    PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE pServerIpv4  = (PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE)pSelfHealCxtLink->hContext;
    strcpy(reinterpret_cast<char*>(pServerIpv4->Ipv4PingServerURI), ip);
    hInsContext = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)pSelfHealCxtLink;

    ULONG result = IPv4PingServerTable_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 1);
}

TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_SetParamStringValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_Ipv4PingServerURI";
    char strValue[] = "Ipv4_PingServer_0";
    
    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pSelfHealCxtLink = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));
    pSelfHealCxtLink->hContext = (PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE)malloc(sizeof(COSA_DML_SELFHEAL_IPv4_SERVER_TABLE));
    PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE pServerIpv4  = (PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE)pSelfHealCxtLink->hContext;
    hInsContext = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)pSelfHealCxtLink;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _ , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(pServerIpv4->Ipv4PingServerURI, pServerIpv4->Ipv4PingServerURI + sizeof(pServerIpv4->Ipv4PingServerURI)),
            Return(0)
        ));
    
    BOOL result = IPv4PingServerTable_SetParamStringValue(hInsContext, ParamName, strValue);

    EXPECT_TRUE(result);
}

TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_Validate) 
{
    char pReturnParamName[256] = "X_RDKCENTRAL-COM_Ipv4PingServerURI";
    ULONG puLength = 0;

    EXPECT_TRUE(IPv4PingServerTable_Validate(NULL, pReturnParamName, &puLength));
}

TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_Commit) 
{
    EXPECT_EQ(0, IPv4PingServerTable_Commit(NULL));
}

TEST_F(CcspTandDSelfhealDmlTest, IPv4PingServerTable_Rollback) 
{
    EXPECT_EQ(0, IPv4PingServerTable_Rollback(NULL));
}

TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_GetEntryCount) 
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    EXPECT_EQ(0, IPv6PingServerTable_GetEntryCount(NULL));
}


TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_GetEntry_ValidIndex) 
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    
    AnscSListInitializeHeader(&pMyObject->IPV6PingServerList);

    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pEntry1 = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));
    pEntry1->InstanceNumber = 1;
    AnscSListPushEntry(&pMyObject->IPV6PingServerList, &pEntry1->Linkage);
    
    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pEntry2 = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));
    pEntry2->InstanceNumber = 2;
    AnscSListPushEntry(&pMyObject->IPV6PingServerList, &pEntry2->Linkage);
    
    ULONG nIndex = 1;
    ULONG pInsNumber = 0;

    EXPECT_CALL(*g_anscWrapperApiMock, AnscSListSearchEntryByIndex(testing::_, 1))
    .WillOnce(testing::Return(reinterpret_cast<_SINGLE_LINK_ENTRY*>(&pEntry2->Linkage)));
    
    ANSC_HANDLE result = IPv6PingServerTable_GetEntry(NULL, nIndex, &pInsNumber);
    
    EXPECT_EQ(result, (ANSC_HANDLE)&pEntry2->Linkage);
    EXPECT_EQ(pInsNumber, 2);
}

TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_IsUpdated) 
{
    EXPECT_TRUE(IPv6PingServerTable_IsUpdated(NULL));
}

TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_Synchronize) 
{
    EXPECT_EQ(ANSC_STATUS_SUCCESS, IPv6PingServerTable_Synchronize(NULL));
}

TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_AddEntry) 
{
    ULONG pInsNumber = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    pMyObject->pConnTest = (PCOSA_DML_CONNECTIVITY_TEST)malloc(sizeof(COSA_DML_CONNECTIVITY_TEST));

    ANSC_HANDLE pSelfHealCxtLink;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _)).WillRepeatedly(::testing::Return(0));

    pSelfHealCxtLink = IPv6PingServerTable_AddEntry(NULL, &pInsNumber);

    EXPECT_NE(nullptr, pSelfHealCxtLink);

}

TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_DelEntry) 
{
    ANSC_HANDLE hInstance = NULL;
     g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;

    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pSelfHealCxtLink = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));

    pSelfHealCxtLink->hContext = (PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE)malloc(sizeof(COSA_DML_SELFHEAL_IPv6_SERVER_TABLE));

    PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE pServerIpv6 = (PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE)pSelfHealCxtLink->hContext;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_unset(_,_)) .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_commit())
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscSListPopEntryByLink(testing::_, testing::_))
        .WillRepeatedly(testing::Return(TRUE));
    
    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(testing::_))
        .WillRepeatedly(testing::Return());

    pMyObject->pConnTest = (PCOSA_DML_CONNECTIVITY_TEST)malloc(sizeof(PCOSA_DML_CONNECTIVITY_TEST));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, RemovePingServerURI((PingServerType)1, (ULONG)1));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, IPv6PingServerTable_DelEntry(NULL, pSelfHealCxtLink));

}

TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_GetParamStringValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_Ipv6PingServerURI";
    char pValue[256] = {0};
    const char* ip = "2001:db8:85a3:8d3:1319:8a2e:370:7348";
    ULONG pUlSize = sizeof(pValue);

    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pSelfHealCxtLink = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));

    pSelfHealCxtLink->hContext = (PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE)malloc(sizeof(COSA_DML_SELFHEAL_IPv6_SERVER_TABLE));

    PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE pServerIpv6  = (PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE)pSelfHealCxtLink->hContext;

    strcpy(reinterpret_cast<char*>(pServerIpv6->Ipv6PingServerURI), ip);

    hInsContext = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)pSelfHealCxtLink;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _ , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(ip, ip + strlen(ip) + 1),
            Return(0)
        ));

    ULONG result = IPv6PingServerTable_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 0);

    EXPECT_STREQ(pValue, "2001:db8:85a3:8d3:1319:8a2e:370:7348");

}


TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_GetParamStringValue_InvalidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_Ipv6PingServerURI";
    char pValue[5] = {0};
    const char* ip = "2001:db8:85a3:8d3:1319:8a2e:370:7348";
    ULONG pUlSize = sizeof(pValue);

    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pSelfHealCxtLink = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));

    pSelfHealCxtLink->hContext = (PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE)malloc(sizeof(COSA_DML_SELFHEAL_IPv6_SERVER_TABLE));

    PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE pServerIpv6  = (PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE)pSelfHealCxtLink->hContext;

    strcpy(reinterpret_cast<char*>(pServerIpv6->Ipv6PingServerURI), ip);

    hInsContext = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)pSelfHealCxtLink;

    ULONG result = IPv6PingServerTable_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 1);
}

TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_SetParamStringValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_Ipv6PingServerURI";
    char strValue[] = "Ipv6_PingServer_0";

    PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT pSelfHealCxtLink = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)malloc(sizeof(COSA_CONTEXT_SELFHEAL_LINK_OBJECT));
    pSelfHealCxtLink->hContext = (PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE)malloc(sizeof(COSA_DML_SELFHEAL_IPv6_SERVER_TABLE));
    PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE pServerIpv6  = (PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE)pSelfHealCxtLink->hContext;
    hInsContext = (PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT)pSelfHealCxtLink;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _ , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(pServerIpv6->Ipv6PingServerURI, pServerIpv6->Ipv6PingServerURI + sizeof(pServerIpv6->Ipv6PingServerURI)),
            Return(0)
        ));
    
    BOOL result = IPv6PingServerTable_SetParamStringValue(hInsContext, ParamName, strValue);

    EXPECT_TRUE(result);
}


TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_Validate) 
{
    char pReturnParamName[256] = "X_RDKCENTRAL-COM_Ipv6PingServerURI";
    ULONG puLength = 0;

    EXPECT_TRUE(IPv6PingServerTable_Validate(NULL, pReturnParamName, &puLength));
}


TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_Commit) 
{
    EXPECT_EQ(0, IPv6PingServerTable_Commit(NULL));
}


TEST_F(CcspTandDSelfhealDmlTest, IPv6PingServerTable_Rollback) 
{
    EXPECT_EQ(0, IPv6PingServerTable_Rollback(NULL));
}

TEST_F(CcspTandDSelfhealDmlTest, ResourceMonitor_GetParamUlongValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_UsageComputeWindow";
    ULONG puLong = 0;

    // Set up the test environment
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pResMonitor = (PCOSA_DML_RESOUCE_MONITOR)malloc(sizeof(COSA_DML_RESOUCE_MONITOR));
    pMyObject->pResMonitor->MonIntervalTime = 10;

    hInsContext = (ANSC_HANDLE)pMyObject;

    BOOL result = ResourceMonitor_GetParamUlongValue(hInsContext, ParamName, &puLong);

    EXPECT_TRUE(result);
    EXPECT_EQ(puLong, 10);
}

TEST_F(CcspTandDSelfhealDmlTest, ResourceMonitor_GetParamUlongValue_ValidParamName1) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_AvgCPUThreshold";
    ULONG puLong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pResMonitor = (PCOSA_DML_RESOUCE_MONITOR)malloc(sizeof(COSA_DML_RESOUCE_MONITOR));
    pMyObject->pResMonitor->AvgCpuThreshold = 10;

    hInsContext = (ANSC_HANDLE)pMyObject;

    BOOL result = ResourceMonitor_GetParamUlongValue(hInsContext, ParamName, &puLong);

    EXPECT_TRUE(result);
    EXPECT_EQ(puLong, 10);
}

TEST_F(CcspTandDSelfhealDmlTest, ResourceMonitor_GetParamUlongValue_ValidParamName2) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_AvgMemoryThreshold";
    ULONG puLong = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pResMonitor = (PCOSA_DML_RESOUCE_MONITOR)malloc(sizeof(COSA_DML_RESOUCE_MONITOR));
    pMyObject->pResMonitor->AvgMemThreshold = 10;

    hInsContext = (ANSC_HANDLE)pMyObject;

    BOOL result = ResourceMonitor_GetParamUlongValue(hInsContext, ParamName, &puLong);

    EXPECT_TRUE(result);
    EXPECT_EQ(puLong, 10);
}

TEST_F(CcspTandDSelfhealDmlTest, ResourceMonitor_SetParamUlongValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_UsageComputeWindow";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pResMonitor = (PCOSA_DML_RESOUCE_MONITOR)malloc(sizeof(COSA_DML_RESOUCE_MONITOR));
    pMyObject->pResMonitor->MonIntervalTime = 10;

    hInsContext = (ANSC_HANDLE)pMyObject;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = ResourceMonitor_SetParamUlongValue(hInsContext, ParamName, uValue);

    EXPECT_TRUE(result);
    EXPECT_EQ(pMyObject->pResMonitor->MonIntervalTime, 10);
}

TEST_F(CcspTandDSelfhealDmlTest, ResourceMonitor_SetParamUlongValue_ValidParamName1) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_AvgCPUThreshold";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pResMonitor = (PCOSA_DML_RESOUCE_MONITOR)malloc(sizeof(COSA_DML_RESOUCE_MONITOR));
    pMyObject->pResMonitor->AvgCpuThreshold = 10;

    hInsContext = (ANSC_HANDLE)pMyObject;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = ResourceMonitor_SetParamUlongValue(hInsContext, ParamName, uValue);

    EXPECT_TRUE(result);
    EXPECT_EQ(pMyObject->pResMonitor->AvgCpuThreshold, 10);
}


TEST_F(CcspTandDSelfhealDmlTest, ResourceMonitor_SetParamUlongValue_ValidParamName2) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "X_RDKCENTRAL-COM_AvgMemoryThreshold";
    ULONG uValue = 10;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pResMonitor = (PCOSA_DML_RESOUCE_MONITOR)malloc(sizeof(COSA_DML_RESOUCE_MONITOR));
    pMyObject->pResMonitor->AvgMemThreshold = 10;

    hInsContext = (ANSC_HANDLE)pMyObject;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = ResourceMonitor_SetParamUlongValue(hInsContext, ParamName, uValue);

    EXPECT_TRUE(result);
    EXPECT_EQ(pMyObject->pResMonitor->AvgMemThreshold, 10);
}

TEST_F(CcspTandDSelfhealDmlTest, ResourceMonitor_Validate) 
{
    char pReturnParamName[256] = "X_RDKCENTRAL-COM_UsageComputeWindow";
    ULONG puLength = 0;

    EXPECT_TRUE(ResourceMonitor_Validate(NULL, pReturnParamName, &puLength));
}


TEST_F(CcspTandDSelfhealDmlTest, ResourceMonitor_Commit) 
{
    EXPECT_EQ(0, ResourceMonitor_Commit(NULL));
}


TEST_F(CcspTandDSelfhealDmlTest, ResourceMonitor_Rollback) 
{
    EXPECT_EQ(0, ResourceMonitor_Rollback(NULL));
}


TEST_F(CcspTandDSelfhealDmlTest, CpuMemFrag_GetEntryCount) 
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pCpuMemFrag = (PCOSA_DML_CPU_MEM_FRAG)malloc(sizeof(COSA_DML_CPU_MEM_FRAG));
    pMyObject->pCpuMemFrag->InstanceNumber = 10;

    EXPECT_EQ(10, CpuMemFrag_GetEntryCount(NULL));
}



TEST_F(CcspTandDSelfhealDmlTest, CpuMemFrag_GetEntry) 
{
    ULONG nIndex = 0;
    ULONG pInsNumber = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hSelfHeal = (PCOSA_DATAMODEL_SELFHEAL)malloc(sizeof(COSA_DATAMODEL_SELFHEAL));
    ASSERT_NE(g_pCosaBEManager->hSelfHeal , nullptr);
    
    PCOSA_DATAMODEL_SELFHEAL pMyObject = (PCOSA_DATAMODEL_SELFHEAL)g_pCosaBEManager->hSelfHeal;
    pMyObject->pCpuMemFrag = (PCOSA_DML_CPU_MEM_FRAG)malloc(sizeof(COSA_DML_CPU_MEM_FRAG));
    pMyObject->pCpuMemFrag->InstanceNumber = 10;

    ANSC_HANDLE result = CpuMemFrag_GetEntry(NULL, nIndex, &pInsNumber);

    EXPECT_NE(nullptr, result);
    EXPECT_EQ(pInsNumber, 1);
}



TEST_F(CcspTandDSelfhealDmlTest, CpuMemFrag_GetParamStringValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "DMA";
    char pValue[256] = {0};
    const char* dma = "DMA"; 
    ULONG pUlSize = sizeof(pValue);

    PCOSA_DML_CPU_MEM_FRAG_DMA pCpuMemFragDma = (PCOSA_DML_CPU_MEM_FRAG_DMA)malloc(sizeof(COSA_DML_CPU_MEM_FRAG_DMA));

    strcpy(reinterpret_cast<char*>(pCpuMemFragDma->dma), dma);

    hInsContext = (ANSC_HANDLE)pCpuMemFragDma;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _ , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(dma, dma + strlen(dma) + 1),
            Return(0)
        ));

    ULONG result = CpuMemFrag_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 0);

    EXPECT_STREQ(pValue, "DMA");

}

TEST_F(CcspTandDSelfhealDmlTest, CpuMemFrag_GetParamStringValue_ValidParamName1) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "DMA32";
    char pValue[256] = {0};
    const char* dma32 = "DMA32";
    ULONG pUlSize = sizeof(pValue);

    PCOSA_DML_CPU_MEM_FRAG_DMA pCpuMemFragDma = (PCOSA_DML_CPU_MEM_FRAG_DMA)malloc(sizeof(COSA_DML_CPU_MEM_FRAG_DMA));

    strcpy(reinterpret_cast<char*>(pCpuMemFragDma->dma32), dma32);

    hInsContext = (ANSC_HANDLE)pCpuMemFragDma;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _ , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(dma32, dma32 + strlen(dma32) + 1),
            Return(0)
        ));

    ULONG result = CpuMemFrag_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 0);

    EXPECT_STREQ(pValue, "DMA32");

}


TEST_F(CcspTandDSelfhealDmlTest, CpuMemFrag_GetParamStringValue_ValidParamName2) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "Normal";
    char pValue[256] = {0};
    const char* normal = "Normal";
    ULONG pUlSize = sizeof(pValue);

    PCOSA_DML_CPU_MEM_FRAG_DMA pCpuMemFragDma = (PCOSA_DML_CPU_MEM_FRAG_DMA)malloc(sizeof(COSA_DML_CPU_MEM_FRAG_DMA));

    strcpy(reinterpret_cast<char*>(pCpuMemFragDma->normal), normal);

    hInsContext = (ANSC_HANDLE)pCpuMemFragDma;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _ , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(normal, normal + strlen(normal) + 1),
            Return(0)
        ));

    ULONG result = CpuMemFrag_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 0);

    EXPECT_STREQ(pValue, "Normal");

}


TEST_F(CcspTandDSelfhealDmlTest, CpuMemFrag_GetParamStringValue_ValidParamName3) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "Highmem";
    char pValue[256] = {0};
    const char* highmem = "Highmem";
    ULONG pUlSize = sizeof(pValue);

    PCOSA_DML_CPU_MEM_FRAG_DMA pCpuMemFragDma = (PCOSA_DML_CPU_MEM_FRAG_DMA)malloc(sizeof(COSA_DML_CPU_MEM_FRAG_DMA));

    strcpy(reinterpret_cast<char*>(pCpuMemFragDma->highmem), highmem);

    hInsContext = (ANSC_HANDLE)pCpuMemFragDma;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _ , _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(highmem, highmem + strlen(highmem) + 1),
            Return(0)
        ));

    ULONG result = CpuMemFrag_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 0);

    EXPECT_STREQ(pValue, "Highmem");

}




TEST_F(CcspTandDSelfhealDmlTest, CpuMemFrag_GetParamUlongValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "FragPercentage";
    ULONG pInt = 0;

    PCOSA_DML_CPU_MEM_FRAG_DMA pCpuMemFragDma = (PCOSA_DML_CPU_MEM_FRAG_DMA)malloc(sizeof(COSA_DML_CPU_MEM_FRAG_DMA));
    pCpuMemFragDma->FragPercentage = 10;

    hInsContext = (ANSC_HANDLE)pCpuMemFragDma;

    BOOL result = CpuMemFrag_GetParamUlongValue(hInsContext, ParamName, &pInt);

    EXPECT_TRUE(result);
    EXPECT_EQ(pCpuMemFragDma->FragPercentage, 10);
}


TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_GetParamBoolValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "Enable";
    BOOL bValue = 0;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_GetParamBoolValue(hInsContext, ParamName, &bValue);

    EXPECT_TRUE(result);
}

TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_GetParamBoolValue_ValidParamName1) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "DynamicProcess";
    BOOL bValue = 0;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_GetParamBoolValue(hInsContext, ParamName, &bValue);

    EXPECT_TRUE(result);
}


TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_GetParamBoolValue_ValidParamName2) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "MonitorAllProcess";
    BOOL bValue = 0;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_GetParamBoolValue(hInsContext, ParamName, &bValue);

    EXPECT_TRUE(result);
}


TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_GetParamBoolValue_ValidParamName3) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "TelemetryOnly";
    BOOL bValue = 0;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    BOOL result = CPUProcAnalyzer_GetParamBoolValue(hInsContext, ParamName, &bValue);

    EXPECT_TRUE(result);
}

TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_SetParamBoolValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "Enable";
    BOOL bValue = 1;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_,_)).WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_SetParamBoolValue(hInsContext, ParamName, bValue);

    EXPECT_TRUE(result);
}

TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_SetParamBoolValue_ValidParamName1) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "DynamicProcess";
    BOOL bValue = 1;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_SetParamBoolValue(hInsContext, ParamName, bValue);

    EXPECT_TRUE(result);
}


TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_SetParamBoolValue_ValidParamName2) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "MonitorAllProcess";
    BOOL bValue = 1;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_SetParamBoolValue(hInsContext, ParamName, bValue);

    EXPECT_TRUE(result);
}



TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_SetParamBoolValue_ValidParamName3) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "TelemetryOnly";
    BOOL bValue = 1;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_SetParamBoolValue(hInsContext, ParamName, bValue);

    EXPECT_TRUE(result);
}



TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_GetParamUlongValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "SleepInterval";
    ULONG puLong = 0;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_GetParamUlongValue(hInsContext, ParamName, &puLong);

    EXPECT_TRUE(result);
}

TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_GetParamUlongValue_ValidParamName1) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "TimeToRun";
    ULONG puLong = 0;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_GetParamUlongValue(hInsContext, ParamName, &puLong);

    EXPECT_TRUE(result);
}



TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_GetParamUlongValue_ValidParamName2) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "MemoryLimit";
    ULONG puLong = 0;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_GetParamUlongValue(hInsContext, ParamName, &puLong);

    EXPECT_TRUE(result);
}



TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_GetParamStringValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "ProcessList";
    char pValue[256] = {0};
    ULONG pUlSize = sizeof(pValue);

    ULONG result = CPUProcAnalyzer_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 0);
}

TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_GetParamStringValue_ValidParamName1) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "SystemStatsToMonitor";
    char pValue[256] = {0};
    ULONG pUlSize = sizeof(pValue);

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    ULONG result = CPUProcAnalyzer_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 0);
}



TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_GetParamStringValue_ValidParamName2) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "ProcessStatsToMonitor";
    char pValue[256] = {0};
    ULONG pUlSize = sizeof(pValue);

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    ULONG result = CPUProcAnalyzer_GetParamStringValue(hInsContext, ParamName, pValue, &pUlSize);

    EXPECT_EQ(result, 0);
}




TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_SetParamStringValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "ProcessList";
    char strValue[] = "ProcessList";

    BOOL result = CPUProcAnalyzer_SetParamStringValue(hInsContext, ParamName, strValue);

    EXPECT_TRUE(result);
}

TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_SetParamStringValue_ValidParamName1) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "SystemStatsToMonitor";
    char strValue[] = "SystemStatsToMonitor";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_SetParamStringValue(hInsContext, ParamName, strValue);

    EXPECT_TRUE(result);
}



TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_SetParamStringValue_ValidParamName2) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "ProcessStatsToMonitor";
    char strValue[] = "ProcessStatsToMonitor";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_SetParamStringValue(hInsContext, ParamName, strValue);

    EXPECT_TRUE(result);
}

TEST_F(CcspTandDSelfhealDmlTest, CPUProcAnalyzer_SetParamUlongValue_ValidParamName) 
{
    ANSC_HANDLE hInsContext = NULL;
    char ParamName[] = "SleepInterval";
    ULONG uValue = 10;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    BOOL result = CPUProcAnalyzer_SetParamUlongValue(hInsContext, ParamName, uValue);

    EXPECT_TRUE(result);
}



