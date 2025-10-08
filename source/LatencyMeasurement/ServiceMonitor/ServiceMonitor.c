/*
 * If not stated otherwise in this file or this component's LICENSE file
 * the following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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

#include<stdio.h>
#include <stdlib.h>
#include<string.h>
#include<pthread.h>
#include<sys/inotify.h>
#include<errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include "ccsp_trace.h"
#include <syscfg/syscfg.h>
#include <sysevent/sysevent.h>
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include "secure_wrapper.h"
#include "ServiceMonitor.h"
#include "lowlatency_util_apis.h"
pthread_t tid[NUM_PTHREADS];
pthread_cond_t Monitor_cond=PTHREAD_COND_INITIALIZER;
pthread_cond_t cond=PTHREAD_COND_INITIALIZER;
pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
char IPv6_addr[ARRAY_LEN],IPv4_addr[ARRAY_LEN];
int curr_wan_mode=0;
char current_wan_ifname[64]={0};
bool Percentile_Enable=false;
int IPv4PID=-1,IPV6PID=-1,DP_PID=-1;
void Get_IPv4_addr( );
static int sysevent_fd_g = -1;
static token_t sysevent_token_g = 0;
extern int latencyMeasurementCount;
int reportInterval_prev=0;
bool IsPthreadisBusy=false;
bool IsTR181_triger_at_PthreadisBusy=false;
bool gLowLatency_Enable=false;

/*adding _SCER11BEL_PRODUCT_REQ_ , because both lan_prefix and ipv6_prefix has same value in XER10 US Device*/
/*For Example:
root@xer10:~# sysevent get lan_prefix
2601:9c0:280:4cb0::/64
root@xer10:~#
root@xer10:~# sysevent get ipv6_prefix
2601:9c0:280:4cb0::/64
*/
#if defined(_HUB4_PRODUCT_REQ_) || defined(_SR213_PRODUCT_REQ_) || defined(_SCER11BEL_PRODUCT_REQ_) || defined(_SCXF11BFL_PRODUCT_REQ_)
#define LAN_PREFIX_SYSEVENT "ipv6_prefix"
#else
#define LAN_PREFIX_SYSEVENT "lan_prefix"

#endif
/**************************************************************************/	
void* isMonitorService_thread_free(void *arg)
{
	UNREFERENCED_PARAMETER(arg);
	struct timespec ts;
	int Status=0;
	//pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
	pthread_condattr_t SyncAttr;
	pthread_condattr_init(&SyncAttr);
	pthread_condattr_setclock(&SyncAttr, CLOCK_MONOTONIC);
	pthread_cond_init(&cond,&SyncAttr);
	while(1)
	{	
		memset(&ts,0,sizeof(ts));
		clock_gettime(CLOCK_MONOTONIC, &ts);
		ts.tv_nsec = 0;
		ts.tv_sec +=TIMER_VALUE;
		pthread_mutex_lock(&lock);
		Status=pthread_cond_timedwait(&cond,&lock,&ts);
		if((Status != 0)&&(Status != ETIMEDOUT))
		{
			CcspTraceInfo(("%s pthread_cond_timedwait failed\n",__func__));
			pthread_mutex_unlock(&lock);
			continue;
		}
		pthread_mutex_unlock(&lock);
		sleep(1);
		UpdateLatencyMeasurement_EnableCount(gLowLatency_Enable);
		IsTR181_triger_at_PthreadisBusy=false;
		break;
	}
	pthread_detach(tid[WAIT_FOR_MONITOR_FREE_PTHREAD_ID]);
	CcspTraceInfo(("pthread_detach WAIT_FOR_MONITOR_FREE_PTHREAD_ID %s\n",__func__));
	return NULL;
}
int UpdateLatencyMeasurement_EnableCount(bool LowLatency_Enable)
{
	char new_val_buf[20];
	static int status_flag;
	if(IsTR181_triger_at_PthreadisBusy == true && status_flag==0)
	{
		int Error=0;
		
		gLowLatency_Enable=LowLatency_Enable;
		Error=pthread_create(&tid[WAIT_FOR_MONITOR_FREE_PTHREAD_ID],NULL,isMonitorService_thread_free,NULL);
		if (Error)
		{
			CcspTraceInfo(("%s isMonitorService_thread_free error : %d\n",__func__,Error));
		}
		else{
			CcspTraceInfo(("%s isMonitorService_thread_free thread is created\n",__func__));
			status_flag=1;
		}
		return 0;
	}
	else if(IsTR181_triger_at_PthreadisBusy==false && status_flag==1)
	{
		status_flag=0;
	}
	IsTR181_triger_at_PthreadisBusy = true;
	if(LowLatency_Enable==true)
	{
		if(latencyMeasurementCount==0)
		{
			LatencyMeasurement_Config_Init();
		}
		else
		{
			SendConditional_pthread_cond_signal();
		}
		latencyMeasurementCount++;
		//set updated value in db
		sprintf(new_val_buf, "%d", latencyMeasurementCount);
		if (!LowLatency_SetValueToDb(LATENCY_MEASUREMENT_ENABLE_COUNT, new_val_buf, SYSCFG_DB)) {
			CcspTraceError(("%s: db set failed for value '%s'\n", __FUNCTION__, new_val_buf));
			return 1;
		}
		CcspTraceInfo(("%s: latencyMeasurementCount:%d,new_val_buf:%s\n", __FUNCTION__,latencyMeasurementCount,new_val_buf));
	}
	else if(LowLatency_Enable==false)
	{
		if(latencyMeasurementCount>0)
		{
			latencyMeasurementCount--;
		}
		SendConditional_pthread_cond_signal();
		CcspTraceInfo(("%s: latencyMeasurementCount:%d\n", __FUNCTION__,latencyMeasurementCount));
		if(latencyMeasurementCount==0)
		{
			if(0 > sysevent_fd_g)
			{
				CcspTraceInfo(("Failed to execute sysevent_set. sysevent_fd_g have no value:'%d'\n", sysevent_fd_g));
				return FALSE;
			}
			else
			{
				if(sysevent_set(sysevent_fd_g, sysevent_token_g, LATENCY_MEASUREMENT_DISABLE, " ", 0) != 0)
				{
					CcspTraceInfo(("Failed to execute sysevent_set from %s:%d\n", __FUNCTION__, __LINE__));
					return FALSE;
				}
			}
		}
		//set updated value in db
		sprintf(new_val_buf, "%d", latencyMeasurementCount);
		if (!LowLatency_SetValueToDb(LATENCY_MEASUREMENT_ENABLE_COUNT, new_val_buf, SYSCFG_DB)) {
			CcspTraceError(("%s: db set failed for value '%s'\n", __FUNCTION__, new_val_buf));
			return 1;
		}
		CcspTraceInfo(("%s: latencyMeasurementCount:%d,new_val_buf:%s\n", __FUNCTION__,latencyMeasurementCount,new_val_buf));
	}
	return 0;
}	
/**************************************************/
bool GetLatencyMeasurementEnableStatus(char parameter_name[]){
	char buf[8];
	memset(buf,0,sizeof(buf));
	syscfg_get(NULL,parameter_name, buf, sizeof(buf));
	CcspTraceInfo(("%s : parameter_name is %s Status is %s\n", __FUNCTION__,parameter_name,buf));
	if(strcmp(buf,"true")==0)
		return true;
	else
		return false;
}

int GetTCPReportInterval(){
	char interval[ARRAY_LEN];
	int reportInterval=0;
	syscfg_get(NULL,TCPREPORTINTERVAL, interval, sizeof(interval));
	reportInterval=atoi(interval);
	if(reportInterval == 0 )
		reportInterval=15;

	CcspTraceInfo(("Enter into %s ReportInterval:%d:\n", __FUNCTION__,reportInterval));
	return reportInterval;
}
/***********************************************************************************************
MonitorLatencyMeasurementServices() function monitor the services and if the serice is not running 
start the service again based on IPv4Enable and IPv6Enable.
************************************************************************************************/
void MonitorLatencyMeasurementServices()
{
	bool IPv4Enable=false,IPv6Enable=false;
	int ReportInterval=0;
	char report_name[BUF_SIZE]="Device.QOS.X_RDK_LatencyMeasure_TCP_Stats_Report\0";
	char ServicePID[BUF_SIZE]={0};
	char Ipv6Cmd[ARRAY_SIZE]={0};
	char lan_ifname[BUF_SIZE]={0};
	char* token;
	char* rest = ServicePID;
	char* token1;
	char* rest1 = ServicePID;
	char* token_ipv4;
	char* rest_ipv4 = ServicePID;
	int xNetSniffer_PID1=0;
	int xNetSniffer_PID2=0;
	bool latency_measure_disabled =0;
	bool LanIpv6_prefix_flag=false;
	bool Lan_prefix_flag=false;
	/** get the IPv4Enable, IPv6Enable and ReportInterval from TR181****/
	CcspTraceInfo(("Entering %s: \n", __FUNCTION__));
	ReportInterval=GetTCPReportInterval() * 60 ; 
	IPv6Enable=GetLatencyMeasurementEnableStatus(IPV6_LATENCY_MEASUREMENT_ENABLE);
	IPv4Enable=GetLatencyMeasurementEnableStatus(IPV4_LATENCY_MEASUREMENT_ENABLE);
	/**check the xNetDP service is running or not if not running start the service****/
	if(CheckLatencyMeasurementServiceStatus(DP_SERVICE,ServicePID)==SERVICE_NOT_ACTIVE)  
	{
		if((IPv4Enable==true)||(IPv6Enable==true)) // check IPv6Enable or  IPv4Enable enable any one is enable start the xNetDP service
		{
			CcspTraceInfo(("%s: Initializing xNetDP service. \n", __FUNCTION__));
			v_secure_system("/usr/bin/xNetDP -t 1 -i %d -n %s &",ReportInterval,report_name);
			CheckLatencyMeasurementServiceStatus(DP_SERVICE,ServicePID);
			DP_PID=atoi(ServicePID);
		}
		else
		{
			 CcspTraceInfo(("%sIPv4Enable:%d: IPv6Enable :%d xNetDP not running\n", __FUNCTION__,IPv4Enable,IPv6Enable));
		}
	}
	else
	{
		if (ReportInterval != reportInterval_prev)
		{

			if((IPv4Enable==true)||(IPv6Enable==true)) // check IPv6Enable or  IPv4Enable enable any one is enable start the xNetDP service
			{
				CcspTraceInfo(("%s: Reporting interval is updated, restarting xNetDP service\n", __FUNCTION__));
				v_secure_system("killall xNetDP");
				v_secure_system("/usr/bin/xNetDP -t 1 -i %d -n %s  &",ReportInterval,report_name);
				CheckLatencyMeasurementServiceStatus(DP_SERVICE,ServicePID);
				DP_PID=atoi(ServicePID);
			}	
		}
	}
	CheckLatencyMeasurementServiceStatus(SNIFFER_SERVICE,ServicePID);
	
	token1 = strtok_r(rest1, " ", &rest1);
	if(token1!=NULL)
	{
		xNetSniffer_PID1=atoi(rest1);
		xNetSniffer_PID2=atoi(token1);
	}

	CcspTraceInfo(("%s: xNetSniffer_PID1:%d,xNetSniffer_PID2:%d\n", __FUNCTION__,xNetSniffer_PID1,xNetSniffer_PID2));
	CcspTraceInfo(("%s: IPv4PID:%d,IPV6PID:%d\n", __FUNCTION__,IPv4PID,IPV6PID));
	/**check the xNetSniffer service is running or not if not running start the service****/
	//if((CheckLatencyMeasurementServiceStatus(SNIFFER_SERVICE,ServicePID)==SERVICE_NOT_ACTIVE)||(IPv4PID==0||IPV6PID==0))
	if((!xNetSniffer_PID1)||(!xNetSniffer_PID2))  
	{
		syscfg_get(NULL, "lan_ifname", lan_ifname, sizeof(lan_ifname));
		CcspTraceInfo(("%s: xNetSniffer service not running\n", __FUNCTION__));
		if((IPv4PID!=xNetSniffer_PID1)&&(IPv4PID!=xNetSniffer_PID2))
		{
			if(IPv4Enable==true)// check IPv4Enable enable is enable start the xNetSniffer service with IPv4
			{
				Get_IPv4_addr();

				CcspTraceInfo(("%s: Initializing xNetSniffer service on IPv4 IPv4_addr:%s len:%ld.\n", __FUNCTION__,IPv4_addr,strlen(IPv4_addr)));

				if (strlen(IPv4_addr) > 0 )
				{
					v_secure_system("/usr/bin/xNetSniffer -i %s -f IPv4 -p %s &",lan_ifname,IPv4_addr);
				}
				else{
					//v_secure_system("/usr/bin/xNetSniffer -i %s -f IPv4 &",lan_ifname);
					Lan_prefix_flag=true;
				}
				CheckLatencyMeasurementServiceStatus(SNIFFER_SERVICE,ServicePID);
				token_ipv4 = strtok_r(rest_ipv4, " ", &rest_ipv4);
				CcspTraceInfo(("%s: xNetSniffer_v4 service PID:%s rest:%s\n", __FUNCTION__,token_ipv4,rest_ipv4));
				if(IPV6PID==atoi(rest_ipv4))
				{
					IPv4PID=atoi(token_ipv4);
				}
				else if(IPV6PID==atoi(token_ipv4))
				{
					IPv4PID=atoi(rest_ipv4);
				}
				else{
					IPv4PID=atoi(ServicePID);
				}
				CcspTraceInfo(("%s: ServicePID:%s xNetSniffer IPv4:%d service started in background\n", __FUNCTION__,ServicePID,IPv4PID));
			}
		}

		if((IPV6PID!=xNetSniffer_PID1)&&(IPV6PID!=xNetSniffer_PID2))
		{
			if(IPv6Enable==true) // check IPv6Enable enable is enable start the xNetSniffer service with IPv6
			{
				sysevent_get(sysevent_fd_g, sysevent_token_g, LAN_PREFIX_SYSEVENT, IPv6_addr, sizeof(IPv6_addr));
				
				CcspTraceInfo(("%s: Initializing xNetSniffer service on IPv6:IPv6_addr:%s.Len:%ld\n", __FUNCTION__,IPv6_addr,strlen(IPv6_addr)));

				if (strlen(IPv6_addr) > 0 )
				{
					v_secure_system("/usr/bin/xNetSniffer -i %s -f IPv6 -p %s &",lan_ifname,IPv6_addr);
				}
				else
				{
					//v_secure_system("/usr/bin/xNetSniffer -i %s -f IPv6 &",lan_ifname);
					LanIpv6_prefix_flag=true;
				}
				//v_secure_system("/usr/bin/xNetSniffer -i %s -f IPv6 -D &",lan_ifname);
				
				CheckLatencyMeasurementServiceStatus(SNIFFER_SERVICE,ServicePID);
				CcspTraceInfo(("xNetSniffer service PID:%s ServicePID:%s\n",rest,ServicePID));
				token = strtok_r(rest, " ", &rest);
				CcspTraceInfo(("%s: xNetSniffer service PID:%s rest:%s\n", __FUNCTION__,token,rest));
				if(IPv4PID==atoi(rest))
				{
					IPV6PID=atoi(token);
				}
				else if(IPv4PID==atoi(token))
				{
					IPV6PID=atoi(rest);
				}
				else{
					IPV6PID=atoi(ServicePID);
				}
				CcspTraceInfo(("IPV6PID:%s %d\n",rest,IPV6PID));
				CcspTraceInfo(("%s: xNetSniffer IPv6::%s service started in background\n", __FUNCTION__,Ipv6Cmd));
			}
		}
	}
	else
	{
		CcspTraceInfo(("%s: xNetSniffer service running\n", __FUNCTION__));
	}

	if((IPv4Enable==false)&&(IPv4PID>0))
	{
		v_secure_system("kill -9 %d",IPv4PID);
		CcspTraceInfo(("%s:killed IPv4PID:%d,IPv4Enable:%d\n",__FUNCTION__,IPv4PID,IPv4Enable));
		IPv4PID=-1;
		latency_measure_disabled=1;
	}
	
	if((IPv6Enable==false)&&(IPV6PID>0))
	{
		v_secure_system("kill -9 %d",IPV6PID);
		CcspTraceInfo(("%s:killed IPV6PID:%d,IPv6Enable:%d\n",__FUNCTION__,IPV6PID,IPv6Enable));
		IPV6PID=-1;
		latency_measure_disabled=1;
	}
	if((LanIpv6_prefix_flag==true)&&(IPV6PID==0))
	{
		IPV6PID=-1;
		LanIpv6_prefix_flag=false;
	}
	if((Lan_prefix_flag==true)&&(IPv4PID==0))
	{
		IPv4PID=-1;
		Lan_prefix_flag=false;
	}
	if (latency_measure_disabled == 1 )
	{
		if((IPv4Enable == false) && (IPv6Enable == false) )
		{
			v_secure_system("killall xNetDP");
		}
	}
	reportInterval_prev=ReportInterval;

}
/*************************************************************************************************
Stop_LatencyMeasurement_Services() function if the xNet serice is running then send signal and 
stop the service 
**************************************************************************************************/
void Stop_LatencyMeasurement_Services(Lm_ServiceType LM_Service)
{
	char ServicePID[BUF_SIZE]={0};
	char* token;
	char* rest = ServicePID;
	CcspTraceInfo(("entry %s LM_Service:%d:\n", __FUNCTION__,LM_Service));
	if(LM_Service==LM_DP_SERVICE)
	{
		/**************check DP_SERVICE service is runnig or not if it is running stop the service ****/
		if(CheckLatencyMeasurementServiceStatus(DP_SERVICE,ServicePID)==SERVICE_ACTIVE)
		{
			if(DP_PID==atoi(ServicePID))
			{
				CcspTraceInfo(("%s: xNetDP service active\n", __FUNCTION__));
				v_secure_system("kill -9 %s",ServicePID);
				CcspTraceInfo(("%s: xNetDP service is stopped PID :%s\n", __FUNCTION__,ServicePID));
			}
		}
		else
		{
			CcspTraceInfo(("%s: xNetDP service not running\n", __FUNCTION__));
		}
	}
	else //LM_IPV4_SNIFFER_SERVICE,  LM_IPV6_SNIFFER_SERVICE
	{
		/**************check xNetSniffer service is runnig or not if it is running stop the service ****/
		if(CheckLatencyMeasurementServiceStatus(SNIFFER_SERVICE,ServicePID)==SERVICE_ACTIVE)
		{
			CcspTraceInfo(("%s: xNetSniffer service active :\n", __FUNCTION__));
			while ((token = strtok_r(rest, " ", &rest))){
				if(LM_Service==LM_IPV4_SNIFFER_SERVICE)
				{
					if(IPv4PID==atoi(token)){
						v_secure_system("kill -9 %s",token);
						IPv4PID=-1;
						CcspTraceInfo(("%s: xNetSniffer service is stopped PID:%s IPv4PID:%d\n", __FUNCTION__,token,IPv4PID));
					}
				}
				else if(LM_Service==LM_IPV6_SNIFFER_SERVICE)
				{
					if(IPV6PID==atoi(token)){
						v_secure_system("kill -9 %s",token);
						IPV6PID=-1;
						CcspTraceInfo(("%s: xNetSniffer service is stopped PID:%s IPv4PID:%d\n", __FUNCTION__,token,IPv4PID));
					}
				}
			}
		}
		else
		{
			CcspTraceInfo(("%s: xNetSniffer service not running\n", __FUNCTION__));
		}
	}
}
/***********************************************************************************
 * Stop all Latency measurement services 
***********************************************************************************/
void Stop_all_LatencyMeasurement_Services()
{
	Stop_LatencyMeasurement_Services(LM_DP_SERVICE);
	Stop_LatencyMeasurement_Services(LM_IPV4_SNIFFER_SERVICE);
	Stop_LatencyMeasurement_Services(LM_IPV6_SNIFFER_SERVICE);
}
/**********************************************************************
    prototype
        int CheckLatencyMeasurementServiceStatus()
    description:
        This function is called to check if Xnet service is running or not
    argument:
        xNet_CMD: xNet service 
		Pidbuf : xNet service PID
    return:
        1 - If proc Xnet service running
        0 - If proc Xnet service not running
**********************************************************************/
int CheckLatencyMeasurementServiceStatus(int Service_Type,char *Pidbuf)
{
    char buf[BUF_SIZE] = {0};
    FILE *fp;
    if(Service_Type==SNIFFER_SERVICE){
    	fp = v_secure_popen("r",SNIFFER_CMD);
	}
	else //if(Service_Type==DP_SERVICE)
	{
		fp = v_secure_popen("r",DP_CMD);
	}
    if ( fp == 0 )
    {
        CcspTraceInfo(("%s: Not able to read cmd\n", __FUNCTION__));
    }
    else
    {
        copy_command_output(fp, buf, sizeof(buf));
        v_secure_pclose(fp);
    }
    strcpy(Pidbuf,buf);
	CcspTraceInfo(("PID's :%s \n",Pidbuf));
    if(buf[0] != '\0')
    {
        CcspTraceInfo(("%s: %s is RUNNING!\n", __FUNCTION__,buf));
        return 1;
    }
    else
    {
        CcspTraceInfo(("%s: %s is NOT RUNNING!\n", __FUNCTION__,buf));
        return 0;
    }
}

void copy_command_output(FILE *fp, char * buf, int len)
{
    char * p;
    if (fp)
    {
        fgets(buf, len, fp);
        buf[len-1] = '\0';
        /*we need to remove the \n char in buf*/
        if ((p = strchr(buf, '\n'))) {
                *p = 0;
        }
    }
}

int Get_Status_of_bridge_mode()
{
	char strValue[64] = {0};
	int bridgemode=1;
	if(sysevent_get(sysevent_fd_g, sysevent_token_g, "bridge_mode", strValue, sizeof(strValue)) != 0)
	{
		CcspTraceInfo(("Failed to execute sysevent_get from %s:%d\n", __FUNCTION__, __LINE__));
		return FALSE;
	}
	else{
		bridgemode=atoi(strValue);
		CcspTraceInfo(("sysevent_get bridge_mode :%d from %s:%d\n",bridgemode, __FUNCTION__, __LINE__));
	}
	return bridgemode;
}

void Get_IPv4_addr( )
{
	char lan_ipaddr[ARRAY_LEN]={0};
	char lan_ifname[ARRAY_LEN]={0};
	char Command[ARRAY_SIZE]={0};
	char buf[ARRAY_LEN]={0};
	FILE *fp;
	syscfg_get(NULL, "lan_ifname", lan_ifname, sizeof(lan_ifname));
	syscfg_get(NULL, "lan_ipaddr", lan_ipaddr, sizeof(lan_ipaddr));
	CcspTraceInfo(("%slan_ipaddr : %s  : lan_ifname:%s\n",__func__, lan_ipaddr,lan_ifname));
	//ip route show | grep brlan0 | grep 10.0.0.1 | awk '{print $1}
	snprintf(Command,ARRAY_SIZE,"ip route show | grep %s | grep %s | awk '{print $1}' ",lan_ifname,lan_ipaddr);
	CcspTraceInfo(("command:%s IP\n",Command));
	fp = popen(Command,"r");
	if(fp==NULL)
	{
		CcspTraceInfo(("popen failed :%s\n",Command));
		return;
	}
    copy_command_output(fp, buf, sizeof(buf));
    pclose(fp);
    fp=NULL;
	strcpy(IPv4_addr,buf);	
}
/*****************************************************************************
	SendConditional_pthread_cond_signal(): using this function sent signal to
	pthread condition wait in monitoring thread
******************************************************************************/
void SendConditional_pthread_cond_signal()
{
	pthread_cond_signal(&Monitor_cond);
	CcspTraceInfo(("%s Send conditional signal to monitoring thread\n",__func__));
}

/*****************************************************************************
	LatencyMeasurementServiceInit() is used to initialize the Xnet services  
******************************************************************************/

int LatencyMeasurementServiceInit()
{
	if ((sysevent_fd_g = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "latency_measurement", &sysevent_token_g)) < 0)
		{
			CcspTraceInfo(("Failed to open sysevent.\n"));
			return FALSE;
		}
	return 0; 
}
/*****************************************************************************
	SysEventHandlerThrd_for_Monitorservice() is used to get the sysevents and based 
	on the sysevent parameters start or stop the xNet services 
******************************************************************************/
void *SysEventHandlerThrd_for_Monitorservice(void *data)
{
	//UNREFERENCED_PARAMETER(data);
	async_id_t interface_asyncid;
	static int sysevent_fd = -1;
    static token_t sysevent_token = 0;
	int err,BridgeMode_value=0;
	char name[64] = {0}, value[64] = {0};
	//char lan_ipaddr[ARRAY_LEN]={0};
	//char lan_ifname[ARRAY_LEN]={0};
	char IPv4_addr_pre[ARRAY_LEN]={0};
	CcspTraceInfo(("Entering %s :\n",__func__));
	sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "latency_measurement", &sysevent_token);
	sysevent_set_options(sysevent_fd, sysevent_token, "bridge_mode", TUPLE_FLAG_EVENT);
	sysevent_setnotification(sysevent_fd, sysevent_token,"bridge_mode",  &interface_asyncid);
	sysevent_set_options(sysevent_fd, sysevent_token, "lan_ip_config_modified", TUPLE_FLAG_EVENT);
	sysevent_setnotification(sysevent_fd, sysevent_token,"lan_ip_config_modified",  &interface_asyncid);
	sysevent_set_options(sysevent_fd, sysevent_token, LAN_PREFIX_SYSEVENT, TUPLE_FLAG_EVENT);
	sysevent_setnotification(sysevent_fd, sysevent_token,LAN_PREFIX_SYSEVENT,  &interface_asyncid);
	sysevent_set_options(sysevent_fd, sysevent_token, "current_wan_ifname", TUPLE_FLAG_EVENT);
	sysevent_setnotification(sysevent_fd, sysevent_token,"current_wan_ifname",  &interface_asyncid);
	sysevent_set_options(sysevent_fd, sysevent_token, "current_wan_mode_update", TUPLE_FLAG_EVENT);
	sysevent_setnotification(sysevent_fd, sysevent_token,"current_wan_mode_update",  &interface_asyncid);
	sysevent_set_options(sysevent_fd, sysevent_token, LATENCY_MEASUREMENT_DISABLE, TUPLE_FLAG_EVENT);
	sysevent_setnotification(sysevent_fd, sysevent_token,LATENCY_MEASUREMENT_DISABLE,  &interface_asyncid);
	sysevent_set_options(sysevent_fd, sysevent_token,"LatencyMeasure_PercentileCalc_Enable",TUPLE_FLAG_EVENT);
	sysevent_setnotification(sysevent_fd, sysevent_token,"LatencyMeasure_PercentileCalc_Enable",  &interface_asyncid);
	/*Get_IPv4_addr();LATENCY_MEASUREMENT_DISABLE
	sysevent_get(sysevent_fd, sysevent_token, "lan_prefix", IPv6_addr, sizeof(IPv6_addr));*/
	while(1)
	{
		async_id_t getnotification_asyncid;
		memset(name,0,sizeof(name)); 
		memset(value,0,sizeof(value));
		int namelen = sizeof(name);
		int vallen  = sizeof(value);
		err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen, value , &vallen, &getnotification_asyncid);
		if (err)
		{
			CcspTraceInfo(("sysevent_getnotification failed with error: %d %s\n", err,__FUNCTION__));
			if ( 0 != v_secure_system("pidof syseventd")) 
			{
				CcspTraceInfo(("%s syseventd not running ,breaking the receive notification loop \n",__FUNCTION__));
				break;
			}
		}
		else
		{
			CcspTraceInfo(("%s Recieved notification event  %s value is %s\n",__FUNCTION__,name,value));
			
			if(strcmp(name,"bridge_mode")==0)
			{
				BridgeMode_value=atoi(value);
				if(BridgeMode_value==ROUTER_MODE)// router mode 
				{
					Get_IPv4_addr();
					sysevent_get(sysevent_fd, sysevent_token, LAN_PREFIX_SYSEVENT, IPv6_addr, sizeof(IPv6_addr));
					SendConditional_pthread_cond_signal();
				}
				else // bridge mode 
				{
					Stop_all_LatencyMeasurement_Services();
				}
			}
			else if(strcmp(name,"lan_ip_config_modified")==0)
			{
				sleep(10);
				Get_IPv4_addr();
				CcspTraceInfo(("Current IPv4_addr is %s Previous IPv4_addr is %s\n",IPv4_addr,IPv4_addr_pre));
				if(strcmp(IPv4_addr_pre,IPv4_addr) != 0)
				{
					Stop_LatencyMeasurement_Services(LM_IPV4_SNIFFER_SERVICE);
					/*******************start the xnet services *****/
					if(Get_Status_of_bridge_mode()==ROUTER_MODE)// router mode 
					{
						SendConditional_pthread_cond_signal();
					}
					strncpy(IPv4_addr_pre,IPv4_addr,strlen(IPv4_addr_pre));
				}
			}
			else if(strcmp(name,LAN_PREFIX_SYSEVENT)==0)
			{
				if(strcmp(value,IPv6_addr)!=0)
				{
					CcspTraceInfo(("lan_prefix updated, old value is %s , new value is %s\n",IPv6_addr,value));
					Stop_LatencyMeasurement_Services(LM_IPV6_SNIFFER_SERVICE);
					/*******************start the xnet services *****/
					if(Get_Status_of_bridge_mode()==ROUTER_MODE)// router mode 
					{
						SendConditional_pthread_cond_signal();
					}
					strncpy(IPv6_addr,value,sizeof(IPv6_addr)-1);
				}
			}
			else if((strcmp(name,"current_wan_ifname")==0)||(strcmp(name,"LatencyMeasure_PercentileCalc_Enable")==0))
			{
				CcspTraceInfo(("%s current_wan_ifname %s value:%s\n",__func__,current_wan_ifname,value));
				if((strcmp(value,current_wan_ifname)!=0)||(atoi(value)!=Percentile_Enable))
				{
					Stop_all_LatencyMeasurement_Services();
					/*******************start the xnet services *****/
					if(Get_Status_of_bridge_mode()==ROUTER_MODE)// router mode 
					{
						SendConditional_pthread_cond_signal();
					}
					strncpy(current_wan_ifname,value,sizeof(current_wan_ifname)-1);
					Percentile_Enable=atoi(value);
				}
			}
			else if(strcmp(name,"current_wan_mode_update")==0)
			{
				CcspTraceInfo(("%s curr_wan_mode %d value:%s\n",__func__,curr_wan_mode,value));
				if(curr_wan_mode!=atoi(value))
				{
					Stop_all_LatencyMeasurement_Services();
					/*******************start the xnet services *****/
					if(Get_Status_of_bridge_mode()==ROUTER_MODE)// router mode 
					{
						SendConditional_pthread_cond_signal();
					}
					curr_wan_mode=atoi(value);
				}
			}
			else if(strcmp(name,LATENCY_MEASUREMENT_DISABLE)==0)
			{
				CcspTraceInfo(("LATENCY_MEASUREMENT_DISABLE %s\n",__func__));
				break;
			}
		}
	}
	pthread_detach(tid[SYSEVENT_PTHREAD_ID]);
	CcspTraceInfo(("pthread_detach SYSEVENT_PTHREAD_ID %s\n",__func__));
	return NULL;
}
/*********************************************************************************************
 @brief This function monitors the services  xNetSniffer,xNetDP
*********************************************************************************************/
void* LatencyMeasurement_MonitorService(void *arg)
{
	//UNREFERENCED_PARAMETER(arg);
	char strValue[64] = {0};
	int Status=0;
	struct timespec ts; 
	pthread_condattr_t SyncAttr;
	int Error=0;
	struct sysinfo s_info;
	sysinfo(&s_info);
	pthread_mutex_lock(&lock);
	while(s_info.uptime < 900)// 900 this wait for device boot up then only monitor services will run
	{
		sysinfo(&s_info);
		sleep(60);//60sec
	}
	CcspTraceInfo(("%s : Device uptime is more than 15 mins \n",__func__));
	Error=pthread_create(&tid[SYSEVENT_PTHREAD_ID],NULL,SysEventHandlerThrd_for_Monitorservice,NULL);
	if (Error)
	{
		CcspTraceInfo(("%s Failed create SysEventHandlerThrd_for_Monitorservice thread. Error num:%d\n",__func__,Error));
	}
	else{
		CcspTraceInfo(("%s Successfully created SysEventHandlerThrd_for_Monitorservice thread \n",__func__));
	}
	pthread_condattr_init(&SyncAttr);
	pthread_condattr_setclock(&SyncAttr, CLOCK_MONOTONIC);
	pthread_cond_init(&Monitor_cond,&SyncAttr);
	LatencyMeasurementServiceInit();
	sysevent_get(sysevent_fd_g, sysevent_token_g, "current_wan_ifname", current_wan_ifname, sizeof(strValue));
	sysevent_get(sysevent_fd_g, sysevent_token_g, "current_wan_mode_update", strValue, sizeof(strValue));
	curr_wan_mode=atoi(strValue);
	if(Get_Status_of_bridge_mode()==ROUTER_MODE)
	{
		MonitorLatencyMeasurementServices();
	}
	pthread_mutex_unlock(&lock);
	if(IsTR181_triger_at_PthreadisBusy==true)
	{
		sleep(1);
		pthread_cond_signal(&cond);
	}
	IsTR181_triger_at_PthreadisBusy=false;
	
	while(1)
	{	
		memset(&ts,0,sizeof(ts));
		clock_gettime(CLOCK_MONOTONIC, &ts);
		ts.tv_nsec = 0;
		ts.tv_sec +=TIMERINTERVEL;		
		pthread_mutex_lock(&lock);
		Status=pthread_cond_timedwait(&Monitor_cond,&lock,&ts);
		if((Status != 0)&&(Status != ETIMEDOUT))
		{
			CcspTraceInfo(("%s pthread_cond_timedwait failed\n",__func__));
			pthread_mutex_unlock(&lock);
			continue;
		}
		if(ROUTER_MODE == Get_Status_of_bridge_mode())
		{
			MonitorLatencyMeasurementServices();
		}
		pthread_mutex_unlock(&lock);
		if(IsTR181_triger_at_PthreadisBusy==true)
		{
			sleep(1);
			pthread_cond_signal(&cond);
		}
		IsTR181_triger_at_PthreadisBusy=false;

		if(latencyMeasurementCount==0)
		{
			CcspTraceInfo(("LATENCY_MEASUREMENT_DISABLE %s\n",__func__));
			break;
		}
	}
	pthread_detach(tid[MONITOR_PTHREAD_ID]);
	CcspTraceInfo(("pthread_detach MONITOR_PTHREAD_ID %s\n",__func__));
	return NULL;
}
/*****************************************************************************
	LatencyMeasurement_Config_Init() is used for Xnet services configuration initialization
******************************************************************************/
int LatencyMeasurement_Config_Init()
{
	int Error=0;
	CcspTraceInfo(("Enter into %s\n",__func__));
	Error=pthread_create(&tid[MONITOR_PTHREAD_ID],NULL,LatencyMeasurement_MonitorService,NULL);
	if (Error)
	{
		CcspTraceInfo(("%s LatencyMeasurement_MonitorService error : %d\n",__func__,Error));
	}
	else{
		CcspTraceInfo(("%s LatencyMeasurement_MonitorService thread is created\n",__func__));
	}
	return 0;
}
