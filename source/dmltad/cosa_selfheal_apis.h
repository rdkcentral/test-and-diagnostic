/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
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

#include "cosa_apis.h"
#include "dslh_definitions_tr143.h"

#define   COSA_DML_SELFHEAL_PINGSERVER_ACCESS_INTERVAL   60 /* seconds*/

#define  COSA_CONTEXT_SELFHEAL_LINK_CLASS_CONTENT                                  \
        COSA_CONTEXT_LINK_CLASS_CONTENT                                            \
        BOOL                            bFound;                                    \


/***********************************
    Actual definition declaration
************************************/
#define  COSA_IREP_FOLDER_NAME_SELFHEAL                       "SelfHeal"
#define  COSA_IREP_FOLDER_NAME_PORTMAPPING               "PORTMAPPING"
#define  COSA_IREP_FOLDER_NAME_PORTTRIGGER               "PORTTRIGGER"
#define  COSA_DML_RR_NAME_NATNextInsNumber               "NextInstanceNumber"
#define  COSA_DML_RR_NAME_NATAlias                       "Alias"
#define  COSA_DML_RR_NAME_NATbNew                        "bNew"

#define COSA_DML_HOST		1
#define COSA_DML_PEER		2

#define CPA_DEFAULT_CONF_FILE     "/etc/procanalyzerconfig.ini"
#define CPA_CONFIG_FILE           "/nvram/procanalyzerconfig.ini"
#define CPA_PROCESS_LIST_FILE     "/nvram/processes.list"
#define CPA_PARAM_NAME_PREPEND    "FEATURE.CPUPROCANALYZER."
#define BUF_16     16
#define BUF_32     32
#define BUF_64     64
#define BUF_128    128

#define SYNC_CPA_CONF_FILE()                               \
    {                                                      \
        if(access(CPA_CONFIG_FILE, F_OK))                  \
        {                                                  \
            char buf[BUF_128] = {0};                       \
            FILE *fp1 = fopen(CPA_DEFAULT_CONF_FILE, "r"); \
            if(fp1)                                        \
            {                                              \
                FILE *fp2 = fopen(CPA_CONFIG_FILE, "w");   \
                if(fp2)                                    \
                {                                          \
                    while(fscanf(fp1,"%[^\n] ",buf) != EOF)     \
                    {                                      \
                        fprintf(fp2, "%s\n", buf);         \
                        memset(buf, 0, BUF_128);           \
                    }                                      \
                    fclose(fp2);                           \
                }                                          \
                fclose(fp1);                               \
            }                                              \
        }                                                  \
    }


#define GET_CPA_CONF_FILE(f)                              \
    {                                                     \
        if(access(CPA_CONFIG_FILE, F_OK))                 \
        {                                                 \
            f = CPA_DEFAULT_CONF_FILE;                    \
        }                                                 \
        else                                              \
        {                                                 \
            f = CPA_CONFIG_FILE;                          \
        }                                                 \
    }

typedef enum _PingServerType
{
	PingServerType_IPv4 = 0,
	PingServerType_IPv6
}PingServerType;
typedef  struct
_COSA_CONTEXT_SELFHEAL_LINK_OBJECT
{
    COSA_CONTEXT_SELFHEAL_LINK_CLASS_CONTENT
}
COSA_CONTEXT_SELFHEAL_LINK_OBJECT,  *PCOSA_CONTEXT_SELFHEAL_LINK_OBJECT;

typedef  struct
_COSA_DML_SELFHEAL_IPv4_SERVER
{
    ULONG                           InstanceNumber;
    UCHAR                           Ipv4PingServerURI[256];  /* IPv4 or IPv4 string address */
}
COSA_DML_SELFHEAL_IPv4_SERVER_TABLE,  *PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE;

typedef  struct
_COSA_DML_SELFHEAL_IPv6_SERVER
{
    ULONG                           InstanceNumber;
    UCHAR                           Ipv6PingServerURI[256];  /* IPv4 or IPv4 string address */
}
COSA_DML_SELFHEAL_IPv6_SERVER_TABLE,  *PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE;



typedef  struct
_PCOSA_DML_CONNECTIVITY_TEST
{
    BOOL                            CorrectiveAction;  
    ULONG                           PingInterval;  
    ULONG                           PingCount;
    ULONG                           WaitTime;
    ULONG                           MinPingServer;
    ULONG                      	    IPv4EntryCount;                                    
    PCOSA_DML_SELFHEAL_IPv4_SERVER_TABLE    pIPv4Table;    
    ULONG                      	    IPv6EntryCount;                                    
    PCOSA_DML_SELFHEAL_IPv6_SERVER_TABLE    pIPv6Table;
    int                             RouterRebootInterval; 
}
COSA_DML_CONNECTIVITY_TEST,  *PCOSA_DML_CONNECTIVITY_TEST;

typedef struct
_COSA_DML_RESOUCE_MONITOR
{
    ULONG                  MonIntervalTime;
    ULONG                  AvgCpuThreshold;
    ULONG                  AvgMemThreshold;
}
COSA_DML_RESOUCE_MONITOR, *PCOSA_DML_RESOUCE_MONITOR;


typedef struct
_COSA_DML_CPU_MEM_FRAG_DMA
{
    UCHAR       dma[128];
    UCHAR       dma32[128];
    UCHAR       normal[128];
	UCHAR       highmem[128];
	int 		index;
	ULONG 		FragPercentage;
}
COSA_DML_CPU_MEM_FRAG_DMA,  *PCOSA_DML_CPU_MEM_FRAG_DMA;


typedef struct
_COSA_DML_CPU_MEM_FRAG
{
	PCOSA_DML_CPU_MEM_FRAG_DMA pCpuMemFragDma;
	ULONG							InstanceNumber;
}
COSA_DML_CPU_MEM_FRAG,  *PCOSA_DML_CPU_MEM_FRAG;


#define  COSA_DATAMODEL_SELFHEAL_CLASS_CONTENT                                                  \
    /* duplication of the base object class content */                                      \
    COSA_BASE_CONTENT                                                                       \
    BOOL                       Enable;                                    \
    BOOL                        DNSPingTest_Enable;                                    \
    CHAR                        DNSPingTest_URL[ 512 ];                                    \
    BOOL                       DiagnosticMode;                                    \
    ULONG                       DiagModeLogUploadFrequency;                                    \
    ULONG                       MaxRebootCnt;                                    \
    ULONG                       MaxResetCnt;                                    \
    ULONG                       PreviousVisitTime;                                    \
    BOOL                        NoWaitLogSync;                                    \
    ULONG                       LogBackupThreshold;                                    \
	ULONG                       MaxInstanceNumber;                                    \
	ULONG                       ulIPv4NextInstanceNumber;                                    \
	ULONG                       ulIPv6NextInstanceNumber;                                    \
	ULONG                       FreeMemThreshold;                                    \
	ULONG                       MemFragThreshold;                                    \
	ULONG                       CpuMemFragInterval;                                    \
    SLIST_HEADER                IPV4PingServerList;                                        \
    SLIST_HEADER                IPV6PingServerList;                                        \
    PCOSA_DML_CONNECTIVITY_TEST    pConnTest;                                        \
    PCOSA_DML_RESOUCE_MONITOR   pResMonitor;						\
	PCOSA_DML_CPU_MEM_FRAG 		pCpuMemFrag;					\
	ANSC_HANDLE                     hIrepFolderSelfHeal;                                         \
    ANSC_HANDLE                     hIrepFolderSelfHealCoTest;                                       \
    /* end of Diagnostic object class content */                                                    \


typedef  struct
_COSA_DATAMODEL_SELFHEAL
{
    COSA_DATAMODEL_SELFHEAL_CLASS_CONTENT
}
COSA_DATAMODEL_SELFHEAL,  *PCOSA_DATAMODEL_SELFHEAL;

#define  ACCESS_COSA_CONTEXT_SELFHEAL_LINK_OBJECT(p)              \
         ACCESS_CONTAINER(p, COSA_CONTEXT_SELFHEAL_LINK_OBJECT, Linkage)
/**********************************
    Standard function declaration
***********************************/
ANSC_HANDLE
CosaSelfHealCreate
    (
        VOID
    );

ANSC_STATUS
CosaSelfHealInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaSelfHealRemove
    (
        ANSC_HANDLE                 hThisObject
    );
void SavePingServerURI(PingServerType type, char *URL, int InstNum);
ANSC_STATUS RemovePingServerURI(PingServerType type, int InstNum);
ANSC_STATUS CosaDmlModifySelfHealDNSPingTestStatus( ANSC_HANDLE hThisObject, 
																BOOL		bValue );

ANSC_STATUS CosaDmlModifySelfHealDNSPingTestURL( ANSC_HANDLE hThisObject, 
															  PCHAR 	  pString );
ANSC_STATUS CosaDmlModifySelfHealDiagnosticModeStatus( ANSC_HANDLE hThisObject, 
												                    BOOL        bValue );
VOID CosaSelfHealAPIModifyCronSchedule( BOOL bForceRun );


void CpuMemFragCronSchedule(ULONG uinterval, BOOL bConnectnow);
void CosaDmlGetSelfHealCpuMemFragData(PCOSA_DML_CPU_MEM_FRAG_DMA pCpuMemFragDma );
void copy_command_output(FILE *fp, char * buf, int len);

//Proc Analyzer TR-181 support
char* RemoveSpaces(char *str);
void CosaReadProcAnalConfig(const char *paramname, char *res);
void CosaWriteProcAnalConfig(const char *paramname, char *res);
int CosaIsProcAnalRunning();
