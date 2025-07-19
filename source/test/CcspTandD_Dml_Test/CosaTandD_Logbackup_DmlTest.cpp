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
extern ULONG g_logbackup_interval;
extern BOOL g_logbackup_enable;

class CcspTandD_Logbackup_DmlTest : public ::testing::Test {
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

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_GetParamBoolValue_NONE_FALSE)
{
    const char* ParamName="None";
    BOOL pBool;
    EXPECT_FALSE(LogBackup_GetParamBoolValue(NULL, (char*)ParamName, &pBool));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_GetParamBoolValue_X_RDKCENTRAL_COM_Enable_TRUE)
{
    const char* ParamName="X_RDKCENTRAL-COM_Enable";
    BOOL pBool;
    EXPECT_TRUE(LogBackup_GetParamBoolValue(NULL, (char*)ParamName, &pBool));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_GetParamBoolValue_X_RDKCENTRAL_COM_SyncandUploadLogs_FALSE)
{
    const char* ParamName="X_RDKCENTRAL-COM_SyncandUploadLogs";
    BOOL pBool;
    EXPECT_TRUE(LogBackup_GetParamBoolValue(NULL, (char*)ParamName, &pBool));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_SetParamBoolValue_g_logbackup_enable_TRUE)
{
    const char* ParamName="X_RDKCENTRAL-COM_Enable";
    BOOL pBool = true;

    g_logbackup_enable = pBool;
    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(1));
    
    EXPECT_TRUE(LogBackup_SetParamBoolValue(NULL, (char*)ParamName, pBool));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_SetParamBoolValue_X_RDKCENTRAL_COM_Enable_TRUE)
{
    const char* ParamName="X_RDKCENTRAL-COM_Enable";
    BOOL pBool  = true;

    g_logbackup_enable = FALSE;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_TRUE(LogBackup_SetParamBoolValue(NULL, (char*)ParamName, pBool));
}


TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_SetParamBoolValue_X_RDKCENTRAL_COM_Enable_FALSE)
{
    const char* ParamName="X_RDKCENTRAL-COM_Enable";
    BOOL pBool = TRUE;

    g_logbackup_enable = FALSE;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(-1));
    
    EXPECT_FALSE(LogBackup_SetParamBoolValue(NULL, (char*)ParamName, pBool));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_SetParamBoolValue_X_RDKCENTRAL_COM_SyncandUploadLogs_TRUE)
{
    const char* ParamName="X_RDKCENTRAL-COM_SyncandUploadLogs";
    BOOL pBool;
    EXPECT_CALL(*g_securewrapperMock, v_secure_system(_,_)).WillRepeatedly(::testing::Return(0));
    EXPECT_TRUE(LogBackup_SetParamBoolValue(NULL, (char*)ParamName, pBool));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_SetParamBoolValue_NONE_FALSE)
{
    const char* ParamName="None";
    BOOL pBool;
    EXPECT_FALSE(LogBackup_SetParamBoolValue(NULL, (char*)ParamName, pBool));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_GetParamUlongValue_X_RDKCENTRAL_COM_Interval_TRUE)
{
    const char* ParamName="X_RDKCENTRAL-COM_Interval";
    ULONG pUlong;
    EXPECT_TRUE(LogBackup_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_GetParamUlongValue_NONE_FALSE)
{
    const char* ParamName="None";
    ULONG pUlong;
    EXPECT_FALSE(LogBackup_GetParamUlongValue(NULL, (char*)ParamName, &pUlong));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_SetParamUlongValue_X_RDKCENTRAL_COM_Interval_TRUE)
{
    const char* ParamName="X_RDKCENTRAL-COM_Interval";
    ULONG pUlong = 10;

    g_logbackup_interval = pUlong;

    EXPECT_TRUE(LogBackup_SetParamUlongValue(NULL, (char*)ParamName, pUlong));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_SetParamUlongValue_X_RDKCENTRAL_COM_Interval_TRUE_after_syscfgset)
{
    const char* ParamName="X_RDKCENTRAL-COM_Interval";
    ULONG pUlong = 10;

    g_logbackup_interval = 11;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_u_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));
    
    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_TRUE(LogBackup_SetParamUlongValue(NULL, (char*)ParamName, pUlong));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_SetParamUlongValue_X_RDKCENTRAL_COM_Interval_after_syscfgset_FALSE)
{
    const char* ParamName="X_RDKCENTRAL-COM_Interval";
    ULONG pUlong = 10;

     g_logbackup_interval = 11;

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_u_commit(_, _))
        .WillRepeatedly(::testing::Return(-1));

    EXPECT_FALSE(LogBackup_SetParamUlongValue(NULL, (char*)ParamName, pUlong));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_SetParamUlongValue_NONE_FALSE)
{
    const char* ParamName="None";
    ULONG pUlong = 10;
    EXPECT_FALSE(LogBackup_SetParamUlongValue(NULL, (char*)ParamName, pUlong));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_Validate_TRUE)
{
    ULONG pUlong;
    EXPECT_TRUE(LogBackup_Validate(NULL, NULL, &pUlong));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_Commit_TRUE)
{
    EXPECT_EQ(ANSC_STATUS_SUCCESS, LogBackup_Commit(NULL));
}

TEST_F(CcspTandD_Logbackup_DmlTest, LogBackup_Rollback_TRUE)
{
    EXPECT_EQ(ANSC_STATUS_SUCCESS, LogBackup_Rollback(NULL));
}

TEST_F(CcspTandD_Logbackup_DmlTest, get_logbackupcfg)
{
    char TO_buf[16]="Yes";
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(2)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<2>(TO_buf, TO_buf + strlen(TO_buf) + 1),
            Return(0)))
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<2>(TO_buf, TO_buf + strlen(TO_buf) + 1),
            Return(0)));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

    get_logbackupcfg();

}

TEST_F(CcspTandD_Logbackup_DmlTest, get_logbackupcfg_else)
{
    char TO_buf[16]={0};
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(2)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<2>(TO_buf, TO_buf + strlen(TO_buf) + 1),
            Return(1)))
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<2>(TO_buf, TO_buf + strlen(TO_buf) + 1),
            Return(1)));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(0));

    get_logbackupcfg();

}

TEST_F(CcspTandD_Logbackup_DmlTest, get_logbackupcfg_syscfg_commit_else)
{
    char TO_buf[16]={0};
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .Times(2)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<2>(TO_buf, TO_buf + strlen(TO_buf) + 1),
            Return(1)))
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<2>(TO_buf, TO_buf + strlen(TO_buf) + 1),
            Return(1)));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_commit(_, _, _))
        .WillRepeatedly(::testing::Return(1));

    EXPECT_CALL(*g_syscfgMock, syscfg_set_nns_commit(_,_))
        .WillRepeatedly(::testing::Return(1));
    
    get_logbackupcfg();

}