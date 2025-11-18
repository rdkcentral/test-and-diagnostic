
/*********************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
******************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "sysevent/sysevent.h"
#include "safec_lib_common.h"
#include "ccsp_psm_helper.h"
#include <ccsp_base_api.h>
#include "ccsp_memory.h"
#include <syscfg/syscfg.h>
#ifdef CORE_NET_LIB
#include <libnet.h>
#endif
#include "xle_reliability_monitoring.h"

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
}xle_attributes;

#define BUFLEN_128  128
#define BUFLEN_256  256

struct xle_attributes xle_params;
static char default_wan_ifname[50];
static char current_wan_ifname[50];
int            sysevent_fd = -1;
token_t        sysevent_token;
int retPsmGet = CCSP_SUCCESS;
char mesh_interface_name[BUFLEN_128] = {0};
char comp_status_cmd[BUFLEN_256] = {0};
char lte_wan_status[BUFLEN_128] = {0};
char lte_backup_enable[BUFLEN_128] = {0};
char lte_interface_enable[BUFLEN_128]={0};
char ipaddr_family[16]={0};

static char *g_Subsystem = "eRT." ;
/* CID 282121 fix */
char InterfaceStatus[BUFLEN_256] = {0};
#define MESH_IFNAME        "br-home"
static void*    bus_handle = NULL;
#define CELLULAR_COMPONENT_NAME  "eRT.com.cisco.spvtg.ccsp.cellularmanager"
#define CELLULAR_DBUS_PATH  "/com/cisco/spvtg/ccsp/cellularmanager" 

FILE* logFp = NULL;

void check_lte_provisioned(char* lte_wan,char* lte_backup_enable, char* lte_interface_enable, char* ipaddr_family)
{
    char *paramNames[]= { "Device.Cellular.X_RDK_Status", "Device.Cellular.X_RDK_Enable", "Device.Cellular.Interface.1.Enable", "Device.Cellular.Interface.1.X_RDK_ContextProfile.1.IpAddressFamily" };
    parameterValStruct_t **retVal = NULL;
    int nval;
     int ret = CcspBaseIf_getParameterValues( 
		bus_handle,
        CELLULAR_COMPONENT_NAME,
        CELLULAR_DBUS_PATH,
        paramNames,
        4,
        &nval,
        &retVal);
    if (CCSP_SUCCESS == ret)
    {
    if (retVal)
        {
        if (NULL != retVal[0]->parameterValue)
        {
            strncpy(lte_wan, retVal[0]->parameterValue, strlen(retVal[0]->parameterValue) + 1);
        }
        if (NULL != retVal[1]->parameterValue)
        {
            strncpy(lte_backup_enable, retVal[1]->parameterValue, strlen(retVal[1]->parameterValue) + 1);
        }
        if (NULL != retVal[2]->parameterValue)
        {
            strncpy(lte_interface_enable, retVal[2]->parameterValue, strlen(retVal[2]->parameterValue) + 1);
        }
        if (NULL != retVal[3]->parameterValue)
        {
            strncpy(ipaddr_family, retVal[3]->parameterValue, strlen(retVal[3]->parameterValue) + 1);
        }
        free_parameterValStruct_t(bus_handle, nval, retVal);
    }
    }
}
void GetInterfaceStatus( char* InterfaceStatus, char* comp_status_cmd, int size )
{
  FILE *fp;
	char path[256] = {0};
	fp = popen(comp_status_cmd,"r");
	if( fp != NULL )
	{
		if(fgets(path, sizeof(path)-1, fp) != NULL)
		{
			char *p;
			path[strlen(path) - 1] = '\0';
			 if ((p = strchr(path, '\n'))) {
 				*p = '\0';
			}
			strncpy(InterfaceStatus,path,size-1);
    }
     pclose(fp);
  }
}

int is_cellular_interface_exist(void)
{
    memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
    sprintf(comp_status_cmd,"ifconfig wwan0");
    memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
    GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
    if ( InterfaceStatus[0] != '\0' )
    {
        xle_log("[xle_self_heal] wwan0 exists\n");
        return 1;
    }
    else
    {
        xle_log("[xle_self_heal] wwan0 does not exist\n");
        return 0;
    }
}
void check_cellular_interface(void)
{
    int count = 1;
    while(is_cellular_interface_exist() == 0)
    {
        xle_log("[xle_self_heal] wwan0 is not detected : Count %d\n" ,count);
        if(count >= 3)
        {
            xle_log("[xle_self_heal] Rebooting in next selfheal cycle because wwan0 not available\n");
            sysevent_set(sysevent_fd, sysevent_token, "LTE_DOWN", "1", 0);
            break;
        }
        count++;
        xle_log("[xle_self_heal] sleeping 120 sec\n");
        sleep(120);
    }
}
void PopulateParameters()
{
    char mesh_status[128] = {0};
    char countBuffer[4] = {0};
    sysevent_fd =  sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "xle_selfheal", &sysevent_token);
    sysevent_get(sysevent_fd, sysevent_token, "wan_ifname", default_wan_ifname, sizeof(default_wan_ifname));
    sysevent_get(sysevent_fd, sysevent_token, "current_wan_ifname", current_wan_ifname, sizeof(current_wan_ifname));
    sysevent_get(sysevent_fd, sysevent_token, "mesh_wan_linkstatus", mesh_status, sizeof(mesh_status));
    sysevent_get(sysevent_fd, sysevent_token, "cellular_restart_count", countBuffer, sizeof(countBuffer));
    char *paramValue = NULL;
    char*  component_id = "ccsp.xle_self";
    int ret = 0;
    ret = CCSP_Message_Bus_Init(component_id,
                                CCSP_MSG_BUS_CFG,
                                &bus_handle,
                                (CCSP_MESSAGE_BUS_MALLOC)Ansc_AllocateMemory_Callback,
                                Ansc_FreeMemory_Callback);
    if (ret != CCSP_SUCCESS) {
    xle_log("CCSP_Message_Bus_Init failed for component %s: %d\n", component_id, ret);
    return;  // or handle error appropriately
    }
    int retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, "dmsb.Mesh.WAN.Interface.Name", NULL, &paramValue);
    if (retPsmGet == CCSP_SUCCESS)
    {        strncpy(mesh_interface_name,paramValue,sizeof(mesh_interface_name)-1);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(paramValue);
    }
    check_cellular_interface();
    check_lte_provisioned(lte_wan_status, lte_backup_enable, lte_interface_enable, ipaddr_family);
    if(( 0 == strncmp( lte_wan_status, "CONNECTED", 9 )) && ( 0 == strncmp( lte_backup_enable, "true", 4 )))
    {
#ifdef CORE_NET_LIB
        int status;
        libnet_status result;
        result = interface_status(current_wan_ifname, &status);
        if (result == CNL_STATUS_SUCCESS) {
             xle_log(" interface_status successfully retrieved\n");
        }
        if ( status == 1 )
#else
        sprintf(comp_status_cmd,"ifconfig %s | grep UP",current_wan_ifname);
        memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
        GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
        if ( InterfaceStatus[0] != '\0' )
#endif
        {
            xle_params.is_lte_wan_up = 1;
        }
        else
        {
            xle_params.is_lte_wan_up = 0;
        }
        
        if(  xle_params.is_lte_wan_up )
        {
            if( xle_params.devicemode )
            {
                memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
                sprintf(comp_status_cmd,"ps | grep dnsmasq | grep -v grep");
                memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
                GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
                if ( InterfaceStatus[0] != '\0' )
                {
                    xle_params.isdhcp_server_running = 1;
                    memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
                    sprintf(comp_status_cmd,"grep %s /var/dnsmasq.conf",mesh_interface_name);
                    memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
                    GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
                    if ( InterfaceStatus[0] != '\0' )
                    {
                        xle_params.iswan_dhcp_server = 1;
                    }
                    else
                    {
                        xle_params.iswan_dhcp_server = 0;
                    }
                }
                else
                {
                    xle_params.isdhcp_server_running=0;
                }
            }
            else
            {
                memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
                sprintf(comp_status_cmd,"ps w | grep udhcpc | grep %s | grep -v grep",mesh_interface_name);
                memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
                GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
                if ( InterfaceStatus[0] != '\0' )
                {
                    xle_params.iswan_dhcp_client = 1;
                }
                else
                {
                    xle_params.iswan_dhcp_client = 0;
                }
            }
            
           strcpy(xle_params.mesh_wan_status,  mesh_status);
#ifdef CORE_NET_LIB
            libnet_status result_ipv6;
            char ipv6_addr[INET6_ADDRSTRLEN] = {0};

            result_ipv6 = get_ipv6_address(default_wan_ifname, ipv6_addr, sizeof(ipv6_addr));
            if (result_ipv6 == CNL_STATUS_SUCCESS) {
                 xle_log(" get_ipv6_address api successfully returned\n");
                 xle_log("IPv6 address: %s\n", ipv6_addr);
            }
            if( ipv6_addr[0] != '\0' )
#else
            memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
            sprintf(comp_status_cmd,"ifconfig %s | grep inet6 | grep \"Scope:Global\"",default_wan_ifname);
            memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
            GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
            if ( InterfaceStatus[0] != '\0' )
#endif
            {
                xle_params.is_ipv6present = 1;
            }
            else
            {
                xle_params.is_ipv6present = 0;
            }
#ifdef CORE_NET_LIB
            char *ip_address = interface_get_ip(default_wan_ifname);
            xle_log("IPv4 address: %s\n", ip_address);
            if( ip_address )
#else
            memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
            sprintf(comp_status_cmd,"ifconfig %s | grep \"inet\" | grep -v \"inet6\"",default_wan_ifname);
            memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
            GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
            if ( InterfaceStatus[0] != '\0' )
#endif
            {
                xle_params.is_ipv4present = 1;
            }
            else
            {
                xle_params.is_ipv4present = 0;
            }
        }
    }
    else
    {
        xle_log("cannot check wan connectivity as it is not provisioned \n");

    }
    
    if( xle_params.devicemode )
    {

        memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
        sprintf(comp_status_cmd,"ip route show table 12 | grep \"default via\" | grep %s",default_wan_ifname);
        memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
        GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
        if ( InterfaceStatus[0] != '\0' )
        {
            xle_params.is_ipv4_wan_route_table = 1;
        }
        else
        {
            xle_params.is_ipv4_wan_route_table = 0;
        }

        memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
        sprintf(comp_status_cmd,"ip -6 route show table 12 | grep \"default via\"  | grep %s",default_wan_ifname);
        memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
        GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
        if ( InterfaceStatus[0] != '\0' )
        {
            xle_params.is_ipv6_wan_route_table= 1;
        }
        else
        {
            xle_params.is_ipv6_wan_route_table = 0;
        }

        memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
        sprintf(comp_status_cmd,"ip route show table 11 | grep \"default via\" | grep %s",mesh_interface_name);
        memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
        GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
        if ( InterfaceStatus[0] != '\0' )
        {
            xle_params.is_ipv4_mesh_route_table = 1;
        }
        else
        {
            xle_params.is_ipv4_mesh_route_table  = 0;
        }

        memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
        sprintf(comp_status_cmd,"ip -6 route show table 11 | grep \"default via\" | grep %s",mesh_interface_name);
        memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
        GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
        if ( InterfaceStatus[0] != '\0' )
        {
            xle_params.is_ipv6_mesh_route_table = 1;
        }
        else
        {
            xle_params.is_ipv6_mesh_route_table = 0;
        }


        memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
        sprintf(comp_status_cmd,"ip route show | grep %s",mesh_interface_name);
        memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
        GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
        if ( InterfaceStatus[0] != '\0' )
        {
            xle_params.is_ipv4_mesh_brWan_link = 1;
        }
        else
        {
            xle_params.is_ipv4_mesh_brWan_link = 0;
        }


        memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
        sprintf(comp_status_cmd,"ip -6 route show | grep %s",mesh_interface_name);
        memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
        GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
        if ( InterfaceStatus[0] != '\0' )
        {
            xle_params.is_ipv6_mesh_brWan_link = 1;
        }
        else
        {
            xle_params.is_ipv6_mesh_brWan_link = 0;
        }
        
        memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
        sprintf(comp_status_cmd,"ip route list | grep \"default via\" | grep %s",MESH_IFNAME);
        memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
        GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
        if ( InterfaceStatus[0] != '\0' )
        {
            xle_params.is_mesh_default_route = 1;
        }
        else
        {
            xle_params.is_mesh_default_route = 0;
        }
    }
    else
    {
        memset(comp_status_cmd, 0, sizeof(comp_status_cmd));
        sprintf(comp_status_cmd,"ip route list | grep \"default via\" | grep %s",current_wan_ifname);
        memset(InterfaceStatus, 0, sizeof(InterfaceStatus));
        GetInterfaceStatus( InterfaceStatus, comp_status_cmd, sizeof(comp_status_cmd) );
        if ( InterfaceStatus[0] != '\0' )
        {
            xle_params.is_default_route = 1;
        }
        else
        {
            xle_params.is_default_route = 0;
        }
    }
    xle_params.cellular_restart_count = atoi(countBuffer);
}

void isWan_up()
{
    if( xle_params.is_lte_wan_up )
    {
        xle_log("[xle_self_heal] current wan interface is up \n");
    }
    else
    {
        xle_log("[xle_self_heal] current wan interface is down \n");
    }
}

int Get_Device_Mode()
{
    int deviceMode = 0;
    char buf[8]= {0};
    memset(buf,0,sizeof(buf));
    if ( 0 == syscfg_get(NULL, "Device_Mode", buf, sizeof(buf)))
    {   
        if (buf[0] != '\0' && strlen(buf) != 0 )
            deviceMode = atoi(buf);
    }
    return deviceMode;

}

int xle_reliability_monitoring()
{
    char MeshBackHaulIfname[128] = {0};
    char RDKConnectionInterface[128] = {0};
    int rc = 0;

    xle_log("[xle_self_heal] %s Entry \n", __FUNCTION__);

    if (access(NTP_SYNC_FILE, F_OK) != 0) {
        xle_log("[xle_self_heal] NTP sync file not found...\n");
        if (access(NTP_STARTED_ONCE_GW_TIMESYNC , F_OK) != 0) {
           xle_log("[xle_self_heal] %s file also not found. calling ntpd_selfheal_sync_primary \n", NTP_STARTED_ONCE_GW_TIMESYNC );
           ntpd_selfheal_sync_primary();
        } else {
           xle_log("[xle_self_heal] ntp sync from primary GW is not success \n" );
           xle_log("[xle_self_heal] ntpd restart again without sync from XB \n" );
           sysevent_set(sysevent_fd, sysevent_token, "ntpd-syncTimeFromPrimary", "", 0);
           sysevent_set(sysevent_fd, sysevent_token, "ntpd-restart", "", 0);
        }
    } else {
        xle_log("[xle_self_heal] NTP sync file found. No action needed.\n");
    }

    //checking & correcting the interface only when Device is in Extender mode
    xle_log("[xle_self_heal] RBUS Get for Device.X_RDK_Connection.Interface and Device.X_RDK_MeshAgent.MeshBackHaul.Ifname values\n");
    rc = rbus_getStringValue(MeshBackHaulIfname, "Device.X_RDK_MeshAgent.MeshBackHaul.Ifname");
    rc |= rbus_getStringValue(RDKConnectionInterface, "Device.X_RDK_Connection.Interface");
    if (rc != 0) {
        xle_log("[xle_self_heal] RBUS ERROR on getting Device.X_RDK_Connection.Interface or Device.X_RDK_MeshAgent.MeshBackHaul.Ifname values\n");
        return 0;
    }
    if (strncmp(MeshBackHaulIfname, RDKConnectionInterface, sizeof(MeshBackHaulIfname)-1) != 0) {
        xle_log("[xle_self_heal] Device.X_RDK_Connection.Interfacee=%s not same with Device.X_RDK_MeshAgent.MeshBackHaul.Ifname=%s in Ext mode \n", RDKConnectionInterface, MeshBackHaulIfname);
     }

     return 0;
}


#ifdef UNIT_TEST_DOCKER_SUPPORT
int xle_selfheal_main(int argc, char *argv[])
#else
int main(int argc,char *argv[])
#endif
{

    char CurrentActiveInterface[128] = {0};
    if(argc<2){
        xle_log("Syntax: error - no of arguments\n");
#ifndef UNIT_TEST_DOCKER_SUPPORT
        exit(1);
#else
        return 1;
#endif
    }
    logFp = fopen("/rdklogs/logs/SelfHeal.txt.0","a+") ;
    xle_params.devicemode = atoi( argv[1]);
    PopulateParameters();
    xle_selfheal_rbus_init();

    //check the device is in extender mode and take care timesync
    if(Get_Device_Mode()) {
        // Calling the xle_monitoring api
        xle_reliability_monitoring();
    }
    if(rbus_getStringValue(CurrentActiveInterface, "Device.X_RDK_WanManager.CurrentActiveInterface") == 0) {
        if(strncmp(CurrentActiveInterface, current_wan_ifname , sizeof(current_wan_ifname)-1) != 0) {
            xle_log("[xle_self_heal] WanManager CurrentActiveInterface %s is not matching with current_wan_ifname %s \n", CurrentActiveInterface,current_wan_ifname);
        }
    } else
        xle_log("[xle_self_heal] RBUS Get ERROR for Device.X_RDK_WanManager.CurrentActiveInterface");

    if( xle_params.devicemode == Get_Device_Mode())
    {
        xle_log("[xle_self_heal] Device modes are same, printing the details\n");
        xle_log("[xle_self_heal] lte_wan_provisioned status :%s\n", lte_wan_status);
        if(( 0 == strncmp( lte_wan_status, "CONNECTED", 9 )) && ( 0 == strncmp( lte_backup_enable, "true", 4 )))
        {
            isWan_up();
            if( xle_params.is_lte_wan_up )
            {
                if(xle_params.devicemode)
                {
                    if( xle_params.isdhcp_server_running )
                    {
                        xle_log("[xle_self_heal] dhcp server running \n"); 
                        xle_log("[xle_self_heal] dhcp server running on mesh interface status:%d \n", xle_params.iswan_dhcp_server);
                    }
                    else
                    {
                         xle_log("[xle_self_heal] dhcp server is not running \n"); 
                    }
                }
                else
                {
                    xle_log("[xle_self_heal] dhcp client running on mesh interface status:%d \n", xle_params.iswan_dhcp_client);
                }
                
                xle_log("[xle_self_heal] mesh wan status is :%s \n", xle_params.mesh_wan_status);
                xle_log("[xle_self_heal] lte wan interface(wwan0) is having ip v4 address status :%d \n", xle_params.is_ipv4present);
                xle_log("[xle_self_heal] lte wan interface(wwan0) is having ip v6 address status :%d \n", xle_params.is_ipv6present);
              
            }
        }

        if( xle_params.devicemode )
        {
            if(xle_params.is_ipv4_wan_route_table)
            {
                xle_log("[xle_self_heal] ipv4  route table 12 is having wwan0 default interface name \n");
            }
            else
            {
                xle_log("[xle_self_heal] ipv4 route table 12 is not having wwan0 interface name \n");
            }
            if(xle_params.is_ipv6_wan_route_table)
            {
                xle_log("[xle_self_heal] ipv6 route table 12 is having wwan0 interface name \n");
            }
            else
            {
                xle_log("[xle_self_heal] ipv6  route table 12 is not having wwan0 interface name \n");
            }
            if(xle_params.is_ipv4_mesh_route_table)
            {
                xle_log("[xle_self_heal] ipv4 is route table 11 is having default mesh interface name \n");
            }
            else
            {
                xle_log("[xle_self_heal] ipv4 route table 11 is not having default mesh interface name \n");
            }
            if(xle_params.is_ipv6_mesh_route_table)
            {
                xle_log("[xle_self_heal] ipv6 route table 11 is having default mesh interface name \n");
            }
            else
            {
                xle_log("[xle_self_heal] ipv6 route table 11  is not having default mesh interface name \n");
            }
            if(xle_params.is_ipv4_mesh_brWan_link)
            {
                xle_log("[xle_self_heal] ip route show is having brWAN interface link\n");
            }
            else
            {
                xle_log("[xle_self_heal] ip  route show is not having brWAN interface link \n");
            }
            if(xle_params.is_ipv6_mesh_brWan_link)
            {
                xle_log("[xle_self_heal] ipv6 route show is having brWAN interface link \n");
            }
            else
            {
                xle_log("[xle_self_heal] ipv6 route show is not having brWAN interface link \n");
            }

            if(xle_params.is_mesh_default_route ) 
            {
                xle_log("[xle_self_heal] default route contains br-home in device mode %d\n", xle_params.devicemode); 
            }
            else
            {
                xle_log("[xle_self_heal] default route doesnot contains br-home in device mode %d\n", xle_params.devicemode); 
            }
        }
        else
        {
            if(xle_params.is_default_route ) 
            {
                xle_log("[xle_self_heal] default route contains %s in device mode %d\n",current_wan_ifname, xle_params.devicemode); 
            }
            else
            {
                xle_log("[xle_self_heal] default route doesnot contains %s in device mode %d\n",current_wan_ifname, xle_params.devicemode); 
            }
        }
    }
    else
    {
       xle_log("[xle_self_heal] Device mode changedin between, no need to print the details\n"); 
    }
    
    //LTE SelfHeal Enhancement
    xle_log("[xle_self_heal] ip address family: %s\n", ipaddr_family);
    if((0 == strncmp( lte_interface_enable, "true", 4)) && ( 0 == strncmp( lte_backup_enable, "true", 4 )))
    {
        if((0 != strncmp( lte_wan_status, "CONNECTED", 9 )) || ((strstr(ipaddr_family,"IPv4")) && (xle_params.is_ipv4present == 0)) || ((strstr(ipaddr_family,"IPv6")) && (xle_params.is_ipv6present == 0)))
        {
            if(xle_params.cellular_restart_count < 3)
            {
                int count = xle_params.cellular_restart_count;
                char count1[2];
                count+=1;
                snprintf(count1, sizeof(count1), "%d", count);
                sysevent_set(sysevent_fd, sysevent_token, "cellular_restart_count", count1, 0);
                int ret = system("systemctl restart RdkCellularManager.service &");
                if (ret == -1) {
                    xle_log("system() call failed\n");
                }
                xle_log("[xle_self_heal] Cellular manager restarted. Number of times restarted=%d \n", count);
            }
            else
            {
                xle_log("[xle_self_heal] Today's limit for cellular manager restart has exceeded\n");
                sysevent_set(sysevent_fd, sysevent_token, "LTE_DOWN", "1", 0);
            }
        }
    }
    
    if ( logFp != NULL)
    {
        fclose(logFp);
        logFp= NULL;
    }
    sysevent_close(sysevent_fd, sysevent_token);
 return 1 ;
}



