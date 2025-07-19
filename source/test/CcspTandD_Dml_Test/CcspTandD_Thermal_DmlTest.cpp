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
extern fanInfo_t fanInfo[1];

class CcspTandD_PowerMGT_DmlTest : public ::testing::Test {
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
        g_fileIOMock = new FileIOMock();
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
        delete g_fileIOMock;
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
        g_fileIOMock = nullptr;
        g_pcapMock = nullptr;
        g_resolvMock = nullptr;
    }
};

TEST_F(CcspTandD_PowerMGT_DmlTest, Fan_GetEntryCount)
{
    ULONG count;
    EXPECT_EQ(1, Fan_GetEntryCount(NULL));
}

TEST_F(CcspTandD_PowerMGT_DmlTest, Fan_GetEntry_TRUE)
{
    ULONG insNumber = 1;
    ULONG index = 0;
    fanInfo[0].fanIndex = 0;
    fanInfo[0].status = 1;
    fanInfo[0].speed = 2;
    fanInfo[0].rotorLock = 3;
    fanInfo[0].maxOverride = 4;

    EXPECT_NE((ANSC_HANDLE)NULL, Fan_GetEntry(NULL, index, &insNumber));
}

TEST_F(CcspTandD_PowerMGT_DmlTest, Fan_GetEntry_FALSE)
{
    ULONG insNumber = 0;
    ULONG index = 2;
    fanInfo[0].fanIndex = 0;
    fanInfo[0].status = 1;
    fanInfo[0].speed = 2;
    fanInfo[0].rotorLock = 3;
    fanInfo[0].maxOverride = 4;

    EXPECT_EQ((ANSC_HANDLE)NULL, Fan_GetEntry(NULL, index, &insNumber));
}

TEST_F(CcspTandD_PowerMGT_DmlTest, Fan_GetParamBoolValue_FALSE)
{
    BOOL bValue;
    EXPECT_FALSE(Fan_GetParamBoolValue(NULL, NULL, &bValue));
}

TEST_F(CcspTandD_PowerMGT_DmlTest, Fan_SetParamBoolValue_FALSE)
{
    BOOL bValue = false;
    EXPECT_FALSE(Fan_SetParamBoolValue(NULL, NULL, bValue));
}

TEST_F(CcspTandD_PowerMGT_DmlTest, Fan_GetParamUlongValue_FALSE)
{
    ULONG pUlong;
    EXPECT_FALSE(Fan_GetParamUlongValue(NULL, NULL, &pUlong));
}

TEST_F(CcspTandD_PowerMGT_DmlTest, Fan_Validate_TRUE)
{
    ULONG puLength;
    EXPECT_TRUE(Fan_Validate(NULL, NULL, &puLength));
}

TEST_F(CcspTandD_PowerMGT_DmlTest, Fan_Commit_TRUE)
{
    EXPECT_EQ(ANSC_STATUS_SUCCESS, Fan_Commit(NULL));
}

TEST_F(CcspTandD_PowerMGT_DmlTest, Fan_Rollback_TRUE)
{
    EXPECT_EQ(0, Fan_Rollback(NULL));
}