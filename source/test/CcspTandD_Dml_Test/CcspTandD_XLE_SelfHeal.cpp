#include <gtest/gtest.h>
#include "CcspTandD_Dml_Mock.h"

extern "C" {

struct xle_attributes {
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

extern struct xle_attributes xle_params;
void PopulateParameters(void);
}

class CcspTandD_XLE_SelfHealTest : public ::testing::Test {
protected:
    void SetUp() override {
        ::testing::Mock::VerifyAndClearExpectations(g_libnetMock);
        ::testing::Mock::VerifyAndClearExpectations(g_messagebusMock);
        ::testing::Mock::VerifyAndClearExpectations(g_psmMock);
        ::testing::Mock::VerifyAndClearExpectations(g_baseapiMock);
    }
};

TEST_F(CcspTandD_XLE_SelfHealTest, test_PopulateParameters)
{
    /* prepare parameter values */
    parameterValStruct_t **parameterVal =
        (parameterValStruct_t **)calloc(4, sizeof(parameterValStruct_t*));

    const char* names[] = {
        "Device.Cellular.X_RDK_Status",
        "Device.Cellular.X_RDK_Enable",
        "Device.Cellular.Interface.1.Enable",
        "Device.Cellular.Interface.1.X_RDK_ContextProfile.1.IpAddressFamily"
    };
    const char* values[] = { "CONNECTED", "true", "true", "IPv4" };

    for (int i = 0; i < 4; i++) {
        parameterVal[i] = (parameterValStruct_t*)calloc(1, sizeof(parameterValStruct_t));
        parameterVal[i]->parameterName = strdup(names[i]);
        parameterVal[i]->parameterValue = strdup(values[i]);
    }

    EXPECT_CALL(*g_messagebusMock,
        CCSP_Message_Bus_Init(_, _, _, _, _))
        .WillOnce(::testing::Return(CCSP_SUCCESS));

    EXPECT_CALL(*g_baseapiMock,
        CcspBaseIf_getParameterValues(_, _, _, _, _, _, _))
        .WillOnce(::testing::DoAll(
            ::testing::WithArgs<6>([&](parameterValStruct_t*** out) {
                *out = parameterVal;
            }),
            ::testing::Return(100)
        ));

    EXPECT_CALL(*g_baseapiMock,
        free_parameterValStruct_t(_, _, _))
        .Times(1);

    EXPECT_CALL(*g_psmMock,
        PSM_Get_Record_Value2(_, _, _, _, _))
        .WillOnce(::testing::Return(CCSP_FAILURE));

    EXPECT_CALL(*g_libnetMock,
        interface_status(_, _))
        .WillOnce(::testing::DoAll(
            ::testing::SetArgPointee<1>(1),
            ::testing::Return(CNL_STATUS_SUCCESS)
        ));

    EXPECT_CALL(*g_libnetMock,
        get_ipv6_address(_, _, _))
        .WillOnce(::testing::DoAll(
            ::testing::Invoke([](const char*, char* out, size_t) {
                strcpy(out, "2001:db8::1");
            }),
            ::testing::Return(CNL_STATUS_SUCCESS)
        ));

    EXPECT_CALL(*g_libnetMock,
        interface_get_ip(_))
        .WillOnce(::testing::Return((char*)"10.32.43.4"));

    xle_params.devicemode = 1;

    PopulateParameters();
}
