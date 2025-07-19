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

class CcspTandD_DNS_DmlTest : public ::testing::Test {
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

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamBoolValue)
{
    BOOL pBool;
    EXPECT_FALSE(NSLookupDiagnostics_GetParamBoolValue(NULL, NULL, &pBool));
    EXPECT_FALSE(NSLookupDiagnostics_GetParamBoolValue(NULL, NULL, &pBool));
    EXPECT_FALSE(NSLookupDiagnostics_GetParamBoolValue(NULL, NULL, &pBool));
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamIntValue)
{
    int pInt;
    EXPECT_FALSE(NSLookupDiagnostics_GetParamIntValue(NULL, NULL, &pInt));
    EXPECT_FALSE(NSLookupDiagnostics_GetParamIntValue(NULL, NULL, &pInt));
    EXPECT_FALSE(NSLookupDiagnostics_GetParamIntValue(NULL, NULL, &pInt));
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamUlongValue)
{
    const char *ParamName = "DiagnosticsState";
    ULONG puLong;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    ASSERT_NE(pMyObject->hDiagNSLookInfo, nullptr);

    EXPECT_FALSE(NSLookupDiagnostics_GetParamUlongValue(NULL, (char *)ParamName, &puLong));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamUlongValue_Timeout_TRUE)
{
    const char *ParamName = "Timeout";
    ULONG puLong;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    ASSERT_NE(pMyObject->hDiagNSLookInfo, nullptr);

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    pNSLookupDiagInfo->Timeout =1;

    EXPECT_TRUE(NSLookupDiagnostics_GetParamUlongValue(NULL, (char *)ParamName, &puLong));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamUlongValue_Timeout_FALSE)
{
    const char *ParamName = "Timeout";
    ULONG puLong;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    EXPECT_FALSE(NSLookupDiagnostics_GetParamUlongValue(NULL, (char *)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}



TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamUlongValue_NumberOfRepetitions_TRUE)
{
    const char *ParamName = "NumberOfRepetitions";
    ULONG puLong;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    ASSERT_NE(pMyObject->hDiagNSLookInfo, nullptr);

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    pNSLookupDiagInfo->NumberOfRepetitions =1;

    EXPECT_TRUE(NSLookupDiagnostics_GetParamUlongValue(NULL, (char *)ParamName, &puLong));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamUlongValue_NumberOfRepetitions_FALSE)
{
    const char *ParamName = "NumberOfRepetitions";
    ULONG puLong;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    EXPECT_FALSE(NSLookupDiagnostics_GetParamUlongValue(NULL, (char *)ParamName, &puLong));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamUlongValue_SuccessCount_TRUE)
{
    const char *ParamName = "SuccessCount";
    ULONG puLong;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    ASSERT_NE(pMyObject->hDiagNSLookInfo, nullptr);

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    pNSLookupDiagInfo->SuccessCount =1;

    EXPECT_FALSE(NSLookupDiagnostics_GetParamUlongValue(NULL, (char *)ParamName, &puLong));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamStringValue_Interface_EXIT)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = NULL;

    EXPECT_EQ(-1,NSLookupDiagnostics_GetParamStringValue(NULL, NULL, NULL, NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamStringValue_Interface_TRUE)
{
    const char *ParamName = "Interface";
    ULONG pUlSize = 0;
    char pValue[10] = {0};

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    ASSERT_NE(pMyObject->hDiagNSLookInfo, nullptr);

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    strcpy(pNSLookupDiagInfo->Interface, "Interface");

    EXPECT_EQ(1,NSLookupDiagnostics_GetParamStringValue(NULL, (char *)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamStringValue_Interface_FALSE)
{
    const char *ParamName = "Interface";
    ULONG pUlSize = 256;
    char pValue[256] = {0};

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    strcpy(pNSLookupDiagInfo->Interface, "Interface");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0,NSLookupDiagnostics_GetParamStringValue(NULL, (char *)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamStringValue_HostName_TRUE)
{
    const char *ParamName = "HostName";
    ULONG pUlSize = 0;
    char pValue[10] = {0};

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    ASSERT_NE(pMyObject->hDiagNSLookInfo, nullptr);

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    strcpy(pNSLookupDiagInfo->HostName, "HostName");

    EXPECT_TRUE(NSLookupDiagnostics_GetParamStringValue(NULL, (char *)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamStringValue_HostName_FALSE)
{
    const char *ParamName = "HostName";
    ULONG pUlSize = 256;
    char pValue[256] = {0};

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    strcpy(pNSLookupDiagInfo->Interface, "Hostna");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0,NSLookupDiagnostics_GetParamStringValue(NULL, (char *)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamStringValue_DNSServer_TRUE)
{
    const char *ParamName = "DNSServer";
    ULONG pUlSize = 0;
    char pValue[10] = {0};

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    ASSERT_NE(pMyObject->hDiagNSLookInfo, nullptr);

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    strcpy(pNSLookupDiagInfo->DNSServer, "DNSServer");

    EXPECT_TRUE(NSLookupDiagnostics_GetParamStringValue(NULL, (char *)ParamName, pValue, &pUlSize));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_GetParamStringValue_DNSServer_FALSE)
{
    const char *ParamName = "DNSServer";
    ULONG pUlSize = 256;
    char pValue[256] = {0};

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    strcpy(pNSLookupDiagInfo->Interface, "DNS");

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_EQ(0,NSLookupDiagnostics_GetParamStringValue(NULL, (char *)ParamName, pValue, &pUlSize));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamBoolValue)
{
    BOOL bValue;
    EXPECT_FALSE(NSLookupDiagnostics_SetParamBoolValue(NULL, NULL, bValue));
    EXPECT_FALSE(NSLookupDiagnostics_SetParamBoolValue(NULL, NULL, bValue));
    EXPECT_FALSE(NSLookupDiagnostics_SetParamBoolValue(NULL, NULL, bValue));
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamIntValue)
{
    int iValue;
    EXPECT_FALSE(NSLookupDiagnostics_SetParamIntValue(NULL, NULL, iValue));
    EXPECT_FALSE(NSLookupDiagnostics_SetParamIntValue(NULL, NULL, iValue));
    EXPECT_FALSE(NSLookupDiagnostics_SetParamIntValue(NULL, NULL, iValue));
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamUlongValue)
{
    ULONG uValue;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = NULL;
    EXPECT_FALSE(NSLookupDiagnostics_SetParamUlongValue(NULL, NULL, uValue));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamUlongValue_DiagnosticsState_FALSE)
{
    const char *ParamName = "DiagnosticsState";
    ULONG uValue = 1;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    ASSERT_NE(pMyObject->hDiagNSLookInfo, nullptr);

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
     pNSLookupDiagInfo->bForced = FALSE;

    EXPECT_FALSE(NSLookupDiagnostics_SetParamUlongValue(NULL, (char *)ParamName, uValue));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamUlongValue_DiagnosticsState_TRUE)
{
    const char *ParamName = "DiagnosticsState";
    ULONG uValue = 2;
g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    ASSERT_NE(pMyObject->hDiagNSLookInfo, nullptr);

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
     pNSLookupDiagInfo->bForced = FALSE;

    EXPECT_TRUE(NSLookupDiagnostics_SetParamUlongValue(NULL, (char *)ParamName, uValue));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamUlongValue_Timeout_TRUE)
{
    const char *ParamName = "Timeout";
    ULONG uValue = 1;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    ASSERT_NE(pMyObject->hDiagNSLookInfo, nullptr);

    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    EXPECT_TRUE(NSLookupDiagnostics_SetParamUlongValue(NULL, (char *)ParamName, uValue));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamUlongValue_Timeout_FALSE)
{
    const char *ParamName = "Timeout";
    ULONG uValue = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    EXPECT_TRUE(NSLookupDiagnostics_SetParamUlongValue(NULL, (char *)ParamName, uValue));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamUlongValue_NumberOfRepetitions_TRUE)
{
    const char *ParamName = "NumberOfRepetitions";
    ULONG uValue = 1;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    EXPECT_TRUE(NSLookupDiagnostics_SetParamUlongValue(NULL, (char *)ParamName, uValue));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamUlongValue_NumberOfRepetitions_FALSE)
{
    const char *ParamName = "NumberOfRepetitions";
    ULONG uValue = 0;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    EXPECT_TRUE(NSLookupDiagnostics_SetParamUlongValue(NULL, (char *)ParamName, uValue));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamStringValue_EXIT)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    pMyObject->hDiagNSLookInfo = NULL;
    EXPECT_FALSE(NSLookupDiagnostics_SetParamStringValue(NULL, NULL, NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamStringValue_Interface_TRUE)
{
    char status[] = "Up";
    const char * Parameter = "Interface";
    char pString[10] = "inter";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Requested;
    pNSLookupDiagInfo->Interface[0] = 'a';

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(status)).WillRepeatedly(Return(status));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_, _, _, _, _,_))
        .WillRepeatedly(::testing::Return(CCSP_SUCCESS));

    EXPECT_TRUE(NSLookupDiagnostics_SetParamStringValue(NULL, (char*)Parameter,pString ));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamStringValue_HostName_TRUE)
{
    char status[] = "Up";
    const char * Parameter = "HostName";
    char pString[10] = "inter";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Requested;
    pNSLookupDiagInfo->HostName[0] = 'a';

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(status)).WillRepeatedly(Return(status));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_, _, _, _, _,_))
        .WillRepeatedly(::testing::Return(CCSP_SUCCESS));

    EXPECT_TRUE(NSLookupDiagnostics_SetParamStringValue(NULL, (char*)Parameter,pString ));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_SetParamStringValue_DNSServer_TRUE)
{
    char status[] = "Up";
    const char * Parameter = "DNSServer";
    char pString[10] = "inter";
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Requested;
    pNSLookupDiagInfo->DNSServer[0] = 'a';

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(status)).WillRepeatedly(Return(status));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_, _, _, _, _,_))
        .WillRepeatedly(::testing::Return(CCSP_SUCCESS));

    EXPECT_TRUE(NSLookupDiagnostics_SetParamStringValue(NULL, (char*)Parameter,pString ));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Validate_Exit)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    pMyObject->hDiagNSLookInfo = NULL;

    EXPECT_FALSE(NSLookupDiagnostics_Validate(NULL, NULL, NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Validate_Interface_FALSE)
{
    char pReturnParamName[10] = "wan0";
    ULONG puLength = 10;
    char status[] = "::";
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
    ASSERT_NE(g_pCosaBEManager->hDiag , nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO  pNSLookupDiagInfo   = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    int sizet = sizeof(**ppComponents);
    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Requested;

    strcpy(pNSLookupDiagInfo->Interface, "wan0");

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::WithArgs<6>([&parameterVal](parameterValStruct_t ***outComponents) {
            *outComponents = parameterVal;
        }),
        testing::Return(100)
    ));

    
    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("::"))).WillRepeatedly(Return(status));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_discComponentSupportingNamespace(_, _, _, _, _, _))
    .Times(1)
    .WillRepeatedly(testing::DoAll(
        testing::WithArgs<4>([&ppComponents](componentStruct_t ***outComponents) {
            *outComponents = ppComponents; 
        }),
        testing::Return(100)
    ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_CALL(*g_anscMemoryMock, AnscFreeMemoryOrig(testing::_))
        .WillRepeatedly(testing::Return());

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));

    EXPECT_FALSE(NSLookupDiagnostics_Validate(NULL, pReturnParamName, &puLength));
    free(*ppComponents);
    *ppComponents = NULL;
    free(*parameterVal);
    *parameterVal = NULL;
    free(parameterVal);
    parameterVal = NULL;
    free(ppComponents);
    ppComponents = NULL;

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;

}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Validate_DNSSERVER_TRUE)
{
    char pReturnParamName[10] = "wan0";
    ULONG puLength = 10;
    parameterValStruct_t varStruct;
    char ucEntryNameValue[128] = "10.12.35.12";
    int ulEntryNameLen = sizeof(ucEntryNameValue);

    const char* paramName = "Device.DNS.Client.Server.1.DNSServer";
    varStruct.parameterName = const_cast<char*>(paramName); 
    varStruct.parameterValue = ucEntryNameValue;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;

    strcpy(pNSLookupDiagInfo->HostName, "");
    strcpy(pNSLookupDiagInfo->Interface, "");
    strcpy(pNSLookupDiagInfo->DNSServer, "10.126.252.10");
    pNSLookupDiagInfo->Timeout = 1001;
    pNSLookupDiagInfo->NumberOfRepetitions = 11;

EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
    .WillRepeatedly(::testing::Return(0));

EXPECT_TRUE(NSLookupDiagnostics_Validate(NULL, pReturnParamName, &puLength));

free(pMyObject->hDiagNSLookInfo);
pMyObject->hDiagNSLookInfo = NULL;
free(g_pCosaBEManager->hDiag);
g_pCosaBEManager->hDiag = NULL;
free(g_pCosaBEManager);
g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Validate_DNSSERVER_FALSE)
{
    char pReturnParamName[10] = "wan0";
    ULONG puLength = 10;
    parameterValStruct_t varStruct;
    char ucEntryNameValue[128] = "10.12";
    int ulEntryNameLen = sizeof(ucEntryNameValue);

    const char* paramName = "Device.DNS.Client.Server.1.DNSServer";
    varStruct.parameterName = const_cast<char*>(paramName); 
    varStruct.parameterValue = ucEntryNameValue;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;

    strcpy(pNSLookupDiagInfo->HostName, "");
    strcpy(pNSLookupDiagInfo->Interface, "");
    strcpy(pNSLookupDiagInfo->DNSServer, "10.126.");
    pNSLookupDiagInfo->Timeout = 1001;
    pNSLookupDiagInfo->NumberOfRepetitions = 11;

EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
    .WillRepeatedly(::testing::Return(0));

EXPECT_FALSE(NSLookupDiagnostics_Validate(NULL, pReturnParamName, &puLength));

free(pMyObject->hDiagNSLookInfo);
pMyObject->hDiagNSLookInfo = NULL;
free(g_pCosaBEManager->hDiag);
g_pCosaBEManager->hDiag = NULL;
free(g_pCosaBEManager);
g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Validate_DNSSERVER_FALSE1)
{
    char pReturnParamName[10] = "wan0";
    ULONG puLength = 10;
    parameterValStruct_t varStruct;
    char ucEntryNameValue[128] = "10.12.35.12";
    int ulEntryNameLen = sizeof(ucEntryNameValue);

    const char* paramName = "Device.DNS.Client.Server.1.DNSServer";
    varStruct.parameterName = const_cast<char*>(paramName); 
    varStruct.parameterValue = ucEntryNameValue;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;

    strcpy(pNSLookupDiagInfo->HostName, "");
    strcpy(pNSLookupDiagInfo->Interface, "");
    strcpy(pNSLookupDiagInfo->DNSServer, "");
    pNSLookupDiagInfo->Timeout = 100;
    pNSLookupDiagInfo->NumberOfRepetitions = 11;

EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
    .WillRepeatedly(::testing::Return(0));

EXPECT_FALSE(NSLookupDiagnostics_Validate(NULL, pReturnParamName, &puLength));

free(pMyObject->hDiagNSLookInfo);
pMyObject->hDiagNSLookInfo = NULL;
free(g_pCosaBEManager->hDiag);
g_pCosaBEManager->hDiag = NULL;
free(g_pCosaBEManager);
g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Validate_DNSSERVER_FALSE2)
{
    char pReturnParamName[10] = "wan0";
    ULONG puLength = 10;
    parameterValStruct_t varStruct;
    char ucEntryNameValue[128] = "10.12.35.12";
    int ulEntryNameLen = sizeof(ucEntryNameValue);

    const char* paramName = "Device.DNS.Client.Server.1.DNSServer";
    varStruct.parameterName = const_cast<char*>(paramName); 
    varStruct.parameterValue = ucEntryNameValue;

    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;

    strcpy(pNSLookupDiagInfo->HostName, "");
    strcpy(pNSLookupDiagInfo->Interface, "");
    strcpy(pNSLookupDiagInfo->DNSServer, "");
    pNSLookupDiagInfo->Timeout = 1003;
    pNSLookupDiagInfo->NumberOfRepetitions = 0;

EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
    .WillRepeatedly(::testing::Return(0));

EXPECT_FALSE(NSLookupDiagnostics_Validate(NULL, pReturnParamName, &puLength));

free(pMyObject->hDiagNSLookInfo);
pMyObject->hDiagNSLookInfo = NULL;
free(g_pCosaBEManager->hDiag);
g_pCosaBEManager->hDiag = NULL;
free(g_pCosaBEManager);
g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Commit_Exit)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_FAILURE;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = NULL;
    EXPECT_EQ(returnStatus, NSLookupDiagnostics_Commit(NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Commit_Requested)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_FAILURE;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Requested;

    EXPECT_EQ(ANSC_STATUS_SUCCESS, NSLookupDiagnostics_Commit(NULL));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo  = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Commit_None)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_FAILURE;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;

    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;

    EXPECT_EQ(ANSC_STATUS_SUCCESS, NSLookupDiagnostics_Commit(NULL));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo  = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Rollback_Exit)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = NULL;
    EXPECT_EQ(ANSC_STATUS_FAILURE, NSLookupDiagnostics_Rollback(NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, NSLookupDiagnostics_Rollback_Requested)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO pNSLookupInfo = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));

    EXPECT_EQ(ANSC_STATUS_SUCCESS, NSLookupDiagnostics_Rollback(NULL));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetEntryCount_Exit)
{
    ULONG returnStatus = 0;
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = NULL;
    EXPECT_EQ(returnStatus, Result_GetEntryCount(NULL));
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetEntry_Exit)
{
    ULONG nIndex = 0;
    ULONG* pInsNumber = 0;
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = NULL;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)NULL;

    EXPECT_EQ((ANSC_HANDLE)NULL, Result_GetEntry(NULL, nIndex, pInsNumber));
}

TEST_F(CcspTandD_DNS_DmlTest, Result_IsUpdated_Exit)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = NULL;

    EXPECT_FALSE(Result_IsUpdated(NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_IsUpdated_True)
{
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO pNSLookupInfo = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));

    pNSLookupDiagInfo->UpdatedAt = 100;

    EXPECT_FALSE(Result_IsUpdated(NULL));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_Synchronize_Exit)
{
    ULONG returnStatus = ANSC_STATUS_FAILURE;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = NULL;
    EXPECT_EQ(ANSC_STATUS_FAILURE, Result_Synchronize(NULL));

    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, Result_Synchronize_True)
{
    ULONG returnStatus = ANSC_STATUS_FAILURE;
    g_pCosaBEManager = (PCOSA_BACKEND_MANAGER_OBJECT)malloc(sizeof(COSA_BACKEND_MANAGER_OBJECT));
    ASSERT_NE(g_pCosaBEManager, nullptr);

    g_pCosaBEManager->hDiag = (PCOSA_DATAMODEL_DIAG)malloc(sizeof(COSA_DATAMODEL_DIAG));
    ASSERT_NE(g_pCosaBEManager->hDiag, nullptr);

    PCOSA_DATAMODEL_DIAG pMyObject = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;

    pMyObject->hDiagNSLookInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));
    PDSLH_NSLOOKUP_INFO pNSLookupInfo = (PDSLH_NSLOOKUP_INFO)pMyObject->hDiagNSLookInfo;
    PDSLH_NSLOOKUP_INFO pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)malloc(sizeof(DSLH_NSLOOKUP_INFO));

    pNSLookupDiagInfo->UpdatedAt = 100;

    EXPECT_EQ(ANSC_STATUS_FAILURE, Result_Synchronize(NULL));

    free(pMyObject->hDiagNSLookInfo);
    pMyObject->hDiagNSLookInfo = NULL;
    free(g_pCosaBEManager->hDiag);
    g_pCosaBEManager->hDiag = NULL;
    free(g_pCosaBEManager);
    g_pCosaBEManager = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamBoolValue)
{
    BOOL pBool = 0;
    EXPECT_FALSE(Result_GetParamBoolValue(NULL, NULL, &pBool));
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamIntValue)
{
    int pInt = 0;
    EXPECT_FALSE(Result_GetParamIntValue(NULL, NULL, &pInt));
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamUlongValue)
{
    ULONG puLong = 0;
    EXPECT_FALSE(Result_GetParamUlongValue(NULL, NULL, &puLong));
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamUlongValue_status)
{
    ULONG puLong = 0;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "Status";
    EXPECT_TRUE(Result_GetParamUlongValue(pEchoInfo, (char*) paramName, &puLong));

    free(pEchoInfo);
    pEchoInfo = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamUlongValue_AnswerType)
{
    ULONG puLong = 0;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "AnswerType";
    EXPECT_TRUE(Result_GetParamUlongValue(pEchoInfo, (char*) paramName, &puLong));

    free(pEchoInfo);
    pEchoInfo = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamUlongValue_ResponseTime)
{
    ULONG puLong = 0;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "ResponseTime";
    EXPECT_TRUE(Result_GetParamUlongValue(pEchoInfo, (char*) paramName, &puLong));

    free(pEchoInfo);
    pEchoInfo = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamUlongValue_FALSE)
{
    ULONG puLong = 0;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "nothing";
    EXPECT_FALSE(Result_GetParamUlongValue(pEchoInfo, (char*) paramName, &puLong));

    free(pEchoInfo);
    pEchoInfo = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamStringValue)
{
    char pValue[10] = "wan0";
    ULONG pUlSize = 10;
    EXPECT_EQ(-1, Result_GetParamStringValue(NULL, NULL, pValue, &pUlSize));
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamStringValue_HostNameReturned_0)
{
    char pValue[10] = {0};
    ULONG pUlSize = 10;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "HostNameReturned";
    pEchoInfo->HostNameReturned = (char*)malloc(10);
    strcpy(pEchoInfo->HostNameReturned, "wan0");
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_EQ(0, Result_GetParamStringValue(pEchoInfo, (char*) paramName, pValue, &pUlSize));

    free(pEchoInfo);
    pEchoInfo = NULL;

}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamStringValue_HostNameReturned_1)
{
    char pValue[10] = {0};
    ULONG pUlSize = 1;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "HostNameReturned";
    pEchoInfo->HostNameReturned = (char*)malloc(10);
    strcpy(pEchoInfo->HostNameReturned, "wan0");
    EXPECT_EQ(1, Result_GetParamStringValue(pEchoInfo, (char*) paramName, pValue, &pUlSize));

    free(pEchoInfo);
    pEchoInfo = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamStringValue_HostNameReturned_MINUS1)
{
    char pValue[10] = {0};
    ULONG pUlSize = 1;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "HostNameReturned";
    pEchoInfo->HostNameReturned = NULL;
    EXPECT_EQ(-1, Result_GetParamStringValue(pEchoInfo, (char*) paramName, pValue, &pUlSize));

    free(pEchoInfo);
    pEchoInfo = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamStringValue_IPAddresses)
{
    char pValue[10] = "wan0";
    ULONG pUlSize = 10;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "IPAddresses";
    pEchoInfo->IPAddresses = (char*)malloc(10);
    strcpy(pEchoInfo->IPAddresses, "wan0");
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_EQ(0, Result_GetParamStringValue(pEchoInfo, (char*) paramName, pValue, &pUlSize));

    free(pEchoInfo);
    pEchoInfo = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamStringValue_IPAddresses_1)
{
    char pValue[10] = "wan0";
    ULONG pUlSize = 1;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "IPAddresses";
    pEchoInfo->IPAddresses = (char*)malloc(10);
    strcpy(pEchoInfo->IPAddresses, "wan0");
    EXPECT_EQ(1, Result_GetParamStringValue(pEchoInfo, (char*) paramName, pValue, &pUlSize));

    free(pEchoInfo);
    pEchoInfo = NULL;
}

TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamStringValue_IPAddresses_MINUS1)
{
    char pValue[10] = "wan0";
    ULONG pUlSize = 1;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "IPAddresses";
    pEchoInfo->IPAddresses = NULL;
    EXPECT_EQ(-1, Result_GetParamStringValue(pEchoInfo, (char*) paramName, pValue, &pUlSize));

    free(pEchoInfo);
    pEchoInfo = NULL;
}


TEST_F(CcspTandD_DNS_DmlTest, Result_GetParamStringValue_DNSServerIP)
{
    char pValue[10] = "wan0";
    ULONG pUlSize = 10;
    PBBHM_NS_LOOKUP_ECHO_ENTRY pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)malloc(sizeof(BBHM_NS_LOOKUP_ECHO_ENTRY));
    ASSERT_NE(pEchoInfo, nullptr);
    const char* paramName = "DNSServerIP";
    pEchoInfo->DNSServerIPName = (char*)malloc(10);
    strcpy(pEchoInfo->DNSServerIPName, "wan0");
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(::testing::Return(0));
    EXPECT_EQ(0, Result_GetParamStringValue(pEchoInfo, (char*) paramName, pValue, &pUlSize));

    free(pEchoInfo);
    pEchoInfo = NULL;
}