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

#include <gtest/gtest.h>
#include "CcspTandD_Dml_Mock.h"

extern "C" {

/*struct xle_attributes
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
}xle_attributes;*/

extern struct xle_attributes xle_params;
}

class CcspTandD_XLE_SelfHealTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_libnetMock = new LibnetMock();
        g_messagebusMock = new MessageBusMock();
        g_psmMock = new PsmMock();
        g_baseapiMock = new BaseAPIMock();

    }

    void TearDown() override {
        delete g_libnetMock;
        delete g_messagebusMock;
        delete g_psmMock;
        delete g_baseapiMock;

        g_libnetMock = nullptr;
        g_messagebusMock = nullptr;
        g_psmMock = nullptr;
        g_baseapiMock = nullptr;
    }
};

ACTION_P(SetPsmValueArg4, value)
{
    *static_cast<char**>(arg4) = strdup(*value);
}


TEST_F(CcspTandD_XLE_SelfHealTest, test_PopulateParameters)
{

    parameterValStruct_t ** parameterVal = NULL;


    parameterVal = (parameterValStruct_t **)malloc(4*sizeof(parameterValStruct_t *));
    ASSERT_NE(parameterVal, nullptr);

    parameterVal[0]  = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    ASSERT_NE(*parameterVal, nullptr);

    parameterVal[0]->parameterName = strdup("Device.Cellular.X_RDK_Status");
    parameterVal[0]->parameterValue = strdup("CONNECTED");


    parameterVal[1]  = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    ASSERT_NE(*parameterVal, nullptr);

    parameterVal[1]->parameterName = strdup("Device.Cellular.X_RDK_Enable");
    parameterVal[1]->parameterValue = strdup("true");

    parameterVal[2]  = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    ASSERT_NE(*parameterVal, nullptr);

    parameterVal[2]->parameterName = strdup("Device.Cellular.Interface.1.Enable");
    parameterVal[2]->parameterValue = strdup("true");


    parameterVal[3]  = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
    ASSERT_NE(*parameterVal, nullptr);

    parameterVal[3]->parameterName = strdup("Device.Cellular.Interface.1.X_RDK_ContextProfile.1.IpAddressFamily");
    parameterVal[3]->parameterValue = strdup("IPv4");


    EXPECT_CALL(*g_messagebusMock, CCSP_Message_Bus_Init(_, _, _, _, _))
        .Times(testing::AtLeast(1))
        .WillOnce(testing::Return(0));

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::WithArgs<6>([&parameterVal](parameterValStruct_t ***outComponents) {
            *outComponents = parameterVal;
        }),
        testing::Return(100)
    ));

    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_, _, _)).Times(1);

    char mockValue[] = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.Mesh.WAN.Interface.Name"), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&mockValue),
            ::testing::Return(CCSP_FAILURE)
        ));

    int status = 1;
    EXPECT_CALL(*g_libnetMock, interface_status(_, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            ::testing::SetArgPointee<1>(status),
            ::testing::Return(CNL_STATUS_SUCCESS)
        ));

    xle_params.devicemode = 1;

    EXPECT_CALL(*g_libnetMock, get_ipv6_address(_, _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            ::testing::Invoke([](auto, char* out_ipv6, auto) {
                strcpy(out_ipv6, "2001:db8:85a3:8d3:1319:8a2e:370:7348");
            }),
            ::testing::Return(CNL_STATUS_SUCCESS)
        ));

    char ip_address[] = "10.32.43.4";
    EXPECT_CALL(*g_libnetMock, interface_get_ip(_))
        .Times(1)
        .WillOnce(::testing::Return(ip_address));


    PopulateParameters();
}

