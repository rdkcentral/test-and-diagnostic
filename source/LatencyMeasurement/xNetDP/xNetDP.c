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


// C Program for Message Queue (Reader Process)
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include<time.h>
#include <pthread.h>
#include<stdio.h>
#include<stdlib.h>
#include<getopt.h>
#include<string.h>
#include<stdbool.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <math.h>
#include <rbus/rbus.h>
#include "syscfg/syscfg.h"
#define ADD_MAX_SAMPLE 10
#define MAX_SAMPLE 50
#define MIN_SAMPLE 10
#define swap(T, x, y) \
    {                 \
        T tmp = x;    \
        x = y;        \
        y = tmp;      \
    }
static rbusHandle_t bus_handle_rbus = NULL;

pthread_mutex_t latency_report_lock = PTHREAD_MUTEX_INITIALIZER;
//#define LATENCY_REPORT_FILE "/tmp/LatencyReport.txt"
#define SYN 0x2 //1
#define SYN_ACK 0x12 //18
#define ACK 0x10 //16
#define SIZE 1024


#define MAX_REPORT_SIZE 1024*1024  //1 MB
#define MAX_TCP_SYN_ACK_TIMEOUT 6


#define INDEX_SYN 0
#define INDEX_SYN_ACK 1
#define INDEX_ACK 2
#define NUM_TCP_ISN 3

#define TRUE 1
#define FALSE 0
#define BUF_SIZE 200
enum ip_family
{
    IPV4=0,
    IPV6=1 
};

typedef struct mesg_buffer {
    long mesg_type;
    u_int   th_flag;
    u_int   th_seq;                
    u_int   th_ack; 
    u_int key;
    long long tv_sec;
    long long tv_usec;
    char    mac[18];
    u_int   ip_type;
    u_short th_dport;
} msg;


typedef struct _tcp_header_
{
    u_int   th_flag;
    u_int   th_seq;                
    u_int   th_ack;
    long long tv_sec;
    long long tv_usec; 

}TcpHeader;
typedef struct TCP_SNIFFER_ {
 //   u_char mesg_type;
    
    u_short key;
    long long latency_sec;
    long long latency_usec;
    long long Lan_latency_sec;
    long long Lan_latency_usec;  
    TcpHeader TcpInfo[NUM_TCP_ISN];
    char    mac[18];
    char bComputed;
    u_int   ip_type;
    u_short th_dport;
}TcpSniffer;
typedef struct {
	long long Samples[SIZE];
	long long Samples_age[SIZE];
	long long Number_of_Samples;
	double Percentile;
}Calt_Percentile_info;
typedef enum{
    LAN_PERCENTILE,
    WAN_PERCENTILE
}percentleType;

msg message;
u_int g_HashCount = 0;
//msg PcktHashTable[SIZE];
  
// structure for message queue
/*struct mesg_buffer {
    long mesg_type;
    char mesg_text[100];
} message;*/


/*
struct DataItem {
   int data;   
   int key;
};*/

TcpSniffer hashArray[SIZE]; 
msg dummyItem;
msg item;


/* Command line options. */
struct option longopts[] =
{
  { "Report Type",                          required_argument,       NULL, 't'},
  { "Report Interval",                      required_argument,       NULL, 'i'},
  { "Report Name",                          required_argument,       NULL, 'n'},
  { "Aggregated Report",                    no_argument,             NULL, 'a'},
  { "Aggregated Report per MAC per PORT",   no_argument,             NULL, 'p'},
  { "DebugMode",                            no_argument,             NULL, 'D'},
  { "FilePath",                             required_argument,       NULL, 'F'},
  { "VerboseMode",                          no_argument,             NULL, 'v'},
  { "help",                                 no_argument,             NULL, 'h'},
  { 0 }
};

#define MAX_LOG_BUFF_SIZE 2048

//Enable ENABLE_95th_PERCENTILE macro to calculate 95th percentile
//#define ENABLE_95th_PERCENTILE

FILE *logFp = NULL;
char log_buff[MAX_LOG_BUFF_SIZE] ;
#define VALIDATION_SUCCESS 0
#define VALIDATION_FAILED  -1

#define dbg_log(fmt ...)    {\
                            if (args.dbg_mode){\
                            snprintf(log_buff, MAX_LOG_BUFF_SIZE-1,fmt);\
                            if(logFp != NULL){ \
                                            fprintf(logFp,"DBG_LOG : %s", log_buff);\
                                            fflush(logFp);}\
                            else \
                                printf("%s",log_buff);\
                            }\
                         }

enum rep_type
{
    REP_TYPE_FILE=0,
    REP_TYPE_T2=1 
};

/*
enum latency_measurment_type
{
    LANWAN = 0 ,
    LANONLY = 1 ,
    WANONLY = 2
}; */

typedef struct Params
{
  bool dbg_mode;  
  bool verbose_mode;  
  bool aggregated_data;
  bool aggregated_data_per_port;
  int  report_type;
  int  report_interval;
  char report_name[256];
  char log_file[64];
}Param;

Param args;

#define MAX_PORTS 32
typedef struct LatencyTable
{
    char   mac[18];
    long long SynAckMinLatency_sec;
    long long SynAckMinLatency_usec;
    long long SynAckMaxLatency_sec;
    long long SynAckMaxLatency_usec;  
    long long SynAckAggregatedLatency_sec;
    long long SynAckAggregatedLatency_usec;
    long long SynAckPercentileLatency;
    long long AckMinLatency_sec;
    long long AckMinLatency_usec;
    long long AckMaxLatency_sec;
    long long AckMaxLatency_usec; 
    long long AckAggregatedLatency_sec;
    long long AckAggregatedLatency_usec;
    long long AckPercentileLatency;
    unsigned long num_of_flows; 
    bool   bHasLatencyEntry;
    int port[MAX_PORTS];
    int num_of_ports;
    long long wanSamples[BUF_SIZE];
    long long lanSamples[BUF_SIZE];
    long long SamplesAges[BUF_SIZE];
    long long Num_of_Sample;
    long long SampleAge;
    long long NthMaxValue;
    int atFirstInitTime;
    Calt_Percentile_info Percentile_info[2];
}LatencyTable;

#define MAX_NUM_OF_CLIENTS 100

LatencyTable Ipv4HashLatencyTable[MAX_NUM_OF_CLIENTS];
LatencyTable Ipv6HashLatencyTable[MAX_NUM_OF_CLIENTS];

#define FILTER_BUF_SIZE 128
#define PERCENTILE_CALCULATION_ENABLE 		"LatencyMeasure_PercentileCalc_Enable"
bool PercentileCalculationEnable=0;

#ifdef ENABLE_95th_PERCENTILE
#define PERCENTILE_VALUE 95
#else
#define PERCENTILE_VALUE 99
#endif

int PercentileValue=PERCENTILE_VALUE;
int print_Samples(long long arr[],long long age[], long long size);
/****************percentile calculation code part***********************************/
/*********************************************************************************
	Api					-	bool isLowLatency_PercentileCalculationEnable()
	Function			-	check percentile calculation enable or not 
	Supported Values	-	true or false
**********************************************************************************/
bool isLowLatency_PercentileCalculationEnable()
{
    char out_value[64] = {0};
	memset(out_value, 0, sizeof(out_value));
    dbg_log("Enter %s :\n",__FUNCTION__);
    if(!syscfg_get(NULL, PERCENTILE_CALCULATION_ENABLE, out_value, sizeof(out_value))) {
        if(strncmp(out_value,"true",strlen("true"))==0)
        {
            return true;
        }
	}
    return false;
}
// Partition the array using the last element as the pivot
int partition(int low, int high,Calt_Percentile_info *Percentile_info) {
	long long pivot = Percentile_info->Samples[high];
	int i = (low - 1);
    //printf("partition:%d\n",t++);
	for (int j = low; j <= high - 1; j++) {
		if (Percentile_info->Samples[j] < pivot) {
			i++;
			swap(long long,Percentile_info->Samples[i],Percentile_info->Samples[j]);
			swap(int,Percentile_info->Samples_age[i],Percentile_info->Samples_age[j]);
		}
	}
	swap(long long,Percentile_info->Samples[i + 1], Percentile_info->Samples[high]);
	swap(int,Percentile_info->Samples_age[i+1],Percentile_info->Samples_age[high]);
	return (i + 1);
}
/*********************************************************************************
	Api					-	int Sorting_ascending_order(int low, int high,Calt_Percentile_info *Percentile_info)
	Function			-	sort the samples in ascending order
	arg			        -	arg3->lower sample value arg3->higer sample value 
                            arg3-> Percentile structure 
	Supported Values	-	calculated percentile value
**********************************************************************************/
int Sorting_ascending_order(int low, int high,Calt_Percentile_info *Percentile_info)
{
    // Function to implement Quick Sort
	if (low < high) {
		int pi = partition(low, high,Percentile_info);
		Sorting_ascending_order( low, pi - 1,Percentile_info);
		Sorting_ascending_order( pi + 1, high,Percentile_info);
	}
	return 0;
}
/*********************************************************************************
	Api					-	long long Calculate_Percentile(Calt_Percentile_info *Percentile_info)
	Function			-	Remove old latency samples and add new samples
	arg			        -	arg1-> Percentile structure 
	Supported Values	-	calculated percentile value
**********************************************************************************/
long long Calculate_Percentile(Calt_Percentile_info *Percentile_info)
{
	int percentile_index=0;
	Percentile_info->Percentile=(Percentile_info->Percentile/100);
	dbg_log("before sort :\n");
	dbg_log("%d\n",print_Samples(Percentile_info->Samples,Percentile_info->Samples_age,Percentile_info->Number_of_Samples));
	Sorting_ascending_order(0,(Percentile_info->Number_of_Samples-1),Percentile_info);
	//dbg_log("Percentile_info.Percentile:%f\n",Percentile_info->Percentile);
	dbg_log("after sort :\n");
	dbg_log("%d\n",print_Samples(Percentile_info->Samples,Percentile_info->Samples_age, Percentile_info->Number_of_Samples));
	percentile_index=(int)round(Percentile_info->Number_of_Samples*Percentile_info->Percentile);

	dbg_log("Percentile_info.Samples:%lld,percentile_index:%d \n",Percentile_info->Samples[percentile_index-1],(percentile_index-1));
    return Percentile_info->Samples[percentile_index-1];
}
/*********************************************************************************
	Api					-	int Remove_OldSample_Add_NewSample(Calt_Percentile_info *Percentile_info,long long New_Sample[],
                                    long long SamplesAge[],int NthMaxValue)
	Function			-	Remove old latency samples and add new samples
	arg			        -	arg1-> Percentile structure arg2 -> new latency sample 
                            arg3 -> new latency sample age arg4-> Nth max
	Supported Values	-	True or False
**********************************************************************************/
int Remove_OldSample_Add_NewSample(Calt_Percentile_info *Percentile_info,long long New_Sample[],long long SamplesAge[],long long NthMaxValue)
{
    int Sample_Index=0,index=0;
    dbg_log("NthMaxValue:%lld\n",NthMaxValue);
    for(Sample_Index=0;Sample_Index<Percentile_info->Number_of_Samples;Sample_Index++)
    {
        if(Percentile_info->Samples_age[Sample_Index] < NthMaxValue)
        {
			dbg_log("old Samples :%lld New_Sample: %lld\n", Percentile_info->Samples[Sample_Index],New_Sample[index]);
            Percentile_info->Samples[Sample_Index]=New_Sample[index];
            Percentile_info->Samples_age[Sample_Index]=SamplesAge[index++];
        }
    }
    return 0;
}
/*********************************************************************************
	Api					-	int print_Samples(long long arr[],long long age[], int size)
	Function			-	Prints debug logs regarding Latency samples and respective age
	arg			        -	arg1-> Latency sample arg2 -> latency sample age arg3-> length
	Supported Values	-	True or False
**********************************************************************************/
int print_Samples(long long arr[],long long age[], long long size)
{
    int i;
    for (i = 0; i < size; i++)
        dbg_log("sample:%lld age:%lld \n", arr[i],age[i]);
    dbg_log("\n");
    return 0;
}
/************************/
static unsigned int hash_latency (const char *str)
{
    unsigned int hash = 5381 % MAX_NUM_OF_CLIENTS;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; 
    }
    return hash % MAX_NUM_OF_CLIENTS;
}

int hashCode(int key) {
   //return key % (SIZE*sizeof(u_int));
   return key % SIZE;
}

int search(int key) {
   //get the hash 
   //int hashIndex = hashCode(key);
    int i = 0;
    int hashIndex = hashCode((u_short)key);    
     dbg_log("search, hashIndex - %d\n",hashIndex);
   //move in array until an empty 
   while(hashIndex < SIZE) {
      if(i > SIZE) // make sure to move only once in array
      {
            dbg_log("search, No SYN Seq found, g_HashCount - %d\n",g_HashCount);
            return -1;
      }

      if(hashArray[hashIndex].key == (u_short)key)
         return hashIndex; 
            
      //go to next cell
      ++hashIndex;
      i++;  
      //wrap around the table
      hashIndex %= SIZE;
      if(g_HashCount > SIZE)
      {
            dbg_log("search, Hash is full last entry update, g_HashCount - %d\n",g_HashCount);
            break;
      }
   }         
   return -1;        
}

void insert(int key,msg data) {

   //struct DataItem *item = (struct DataItem*) malloc(sizeof(struct DataItem));
   //item->data = data;  
   //item->key = key;

   //get the hash 
   //u_int hashIndex = hashCode(key);
    //int hashIndex = hashCode(key);
    int hashIndex = hashCode((u_short)key);
  // printf("Insert, hashIndex - %lu\n",hashIndex);
   dbg_log("Insert, hashIndex - %d\n",hashIndex);
   //move in array until an empty or deleted cell
   while(hashIndex < SIZE && hashArray[hashIndex].key != 0) {
      if(hashArray[hashIndex].key == (u_short)key)
      {
        dbg_log("Ignoring insert as SYN entry for seq - %u already exists..\n",data.th_seq);
        return;
      }
      //go to next cell
      ++hashIndex;
        
      //wrap around the table
      hashIndex %= SIZE;
      if(g_HashCount >= SIZE)
      {
        dbg_log("Insert Hash is full, g_HashCount - %d\n",g_HashCount);
        return;
      }
   }
   dbg_log("Insert, call memcpy\n");
   //data.key = hashIndex;
   data.key = (u_short)key;
   g_HashCount++;
   //memcpy(&hashArray[hashIndex],&data,sizeof(mesg)); 
   hashArray[hashIndex].TcpInfo[INDEX_SYN].th_flag = data.th_flag;
   hashArray[hashIndex].TcpInfo[INDEX_SYN].th_seq  = data.th_seq;
   hashArray[hashIndex].TcpInfo[INDEX_SYN].th_ack  = data.th_ack;
   hashArray[hashIndex].TcpInfo[INDEX_SYN].tv_sec  = data.tv_sec;
   hashArray[hashIndex].TcpInfo[INDEX_SYN].tv_usec  = data.tv_usec;
   hashArray[hashIndex].key = (u_short)key;
   hashArray[hashIndex].ip_type = message.ip_type; 
   hashArray[hashIndex].th_dport = message.th_dport;

   memcpy(hashArray[hashIndex].mac,data.mac,18); 

   dbg_log("hashIndex %d MAC: %s FLAG: %d ACK: %u Seq: %u TS: %lld.%06lld\n",hashIndex,hashArray[hashIndex].mac,hashArray[hashIndex].TcpInfo[INDEX_SYN].th_flag,hashArray[hashIndex].TcpInfo[INDEX_SYN].th_ack,hashArray[hashIndex].TcpInfo[INDEX_SYN].th_seq,hashArray[hashIndex].TcpInfo[INDEX_SYN].tv_sec,hashArray[hashIndex].TcpInfo[INDEX_SYN].tv_usec);
  // hashArray[hashIndex] = data;
}
/*
struct DataItem* delete(struct DataItem* item) {
   int key = item->key;

   //get the hash 
   int hashIndex = hashCode(key);

   //move in array until an empty
   while(hashArray[hashIndex] != NULL) {
    
      if(hashArray[hashIndex]->key == key) {
         struct DataItem* temp = hashArray[hashIndex]; 
            
         //assign a dummy item at deleted position
         hashArray[hashIndex] = dummyItem; 
         return temp;
      }
        
      //go to next cell
      ++hashIndex;
        
      //wrap around the table
      hashIndex %= SIZE;
   }      
    
   return NULL;        
}*/

void display() {
   int i = 0;
    
   for(i = 0; i<SIZE; i++) {
    
     // if(hashArray[i] != NULL)
        // printf(" i = %d (%d,%d)\n",i,hashArray[i].key,hashArray[i].th_seq);
           //  printf("HashTable %d MAC: %s FLAG: %d ACK: %lu Seq: %lu TS: %lld.%06ld\n", 
            //        i,hashArray[i].mac,hashArray[i].th_flag,hashArray[i].th_ack,hashArray[i].th_seq,hashArray[i].tv_sec,hashArray[i].tv_usec);

            if(hashArray[i].key != 0)
            {

           /*  printf("\nHashTable - %d MAC: %s   Latency   : %lld.%06ld\n        SYN FLAG    : %d ACK: %lu Seq: %lu TS: %lld.%06ld\n        SYN ACK FLAG: %d ACK: %lu Seq: %lu TS: %lld.%06ld\n", 
                    i,hashArray[i].mac,hashArray[i].latency_sec,hashArray[i].latency_usec,
                    hashArray[i].TcpInfo[INDEX_SYN].th_flag,hashArray[i].TcpInfo[INDEX_SYN].th_ack,hashArray[i].TcpInfo[INDEX_SYN].th_seq,hashArray[i].TcpInfo[INDEX_SYN].tv_sec,hashArray[i].TcpInfo[INDEX_SYN].tv_usec,
                    hashArray[i].TcpInfo[INDEX_SYN_ACK].th_flag,hashArray[i].TcpInfo[INDEX_SYN_ACK].th_ack,hashArray[i].TcpInfo[INDEX_SYN_ACK].th_seq,hashArray[i].TcpInfo[INDEX_SYN_ACK].tv_sec,hashArray[i].TcpInfo[INDEX_SYN_ACK].tv_usec);
            
*/
               dbg_log("\n ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \n");
               dbg_log("\nhashIndex %d | MAC: %s | FLAG: %d | ACK: %u | Seq: %u | TS: %lld.%06lld |\n",i,hashArray[i].mac,hashArray[i].TcpInfo[INDEX_SYN].th_flag,hashArray[i].TcpInfo[INDEX_SYN].th_ack,hashArray[i].TcpInfo[INDEX_SYN].th_seq,hashArray[i].TcpInfo[INDEX_SYN].tv_sec,hashArray[i].TcpInfo[INDEX_SYN].tv_usec);
               dbg_log("hashIndex %d | MAC: %s | FLAG: %d | ACK: %u | Seq: %u | TS: %lld.%06lld |\n",i,hashArray[i].mac,hashArray[i].TcpInfo[INDEX_SYN_ACK].th_flag,hashArray[i].TcpInfo[INDEX_SYN_ACK].th_ack,hashArray[i].TcpInfo[INDEX_SYN_ACK].th_seq,hashArray[i].TcpInfo[INDEX_SYN_ACK].tv_sec,hashArray[i].TcpInfo[INDEX_SYN_ACK].tv_usec);
               dbg_log("hashIndex %d | MAC: %s | FLAG: %d | ACK: %u | Seq: %u | TS: %lld.%06lld |\n",i,hashArray[i].mac,hashArray[i].TcpInfo[INDEX_ACK].th_flag,hashArray[i].TcpInfo[INDEX_ACK].th_ack,hashArray[i].TcpInfo[INDEX_ACK].th_seq,hashArray[i].TcpInfo[INDEX_ACK].tv_sec,hashArray[i].TcpInfo[INDEX_ACK].tv_usec);
               dbg_log("WAN side Latency for MAC: %s | Seq: %u | %lld.%06lld |\n",hashArray[i].mac,hashArray[i].TcpInfo[INDEX_SYN].th_seq,hashArray[i].latency_sec,hashArray[i].latency_usec);
               dbg_log("LAN side Latency for MAC: %s | Seq: %u | %lld.%06lld |\n",hashArray[i].mac,hashArray[i].TcpInfo[INDEX_SYN].th_seq,hashArray[i].Lan_latency_sec,hashArray[i].Lan_latency_usec);
               dbg_log("\n ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \n");
            }
     // else 
      //   printf(" ~~ ");
   }
    
   dbg_log("\n");
}
 int
 timeval_subtract (struct timeval *result,struct timeval *T1,struct timeval *T2)
 {
   /* Perform the carry for the later subtraction by updating y. */
   if (T1->tv_usec < T2->tv_usec) {
     int nsec = (T2->tv_usec - T1->tv_usec) / 1000000 + 1;
     T2->tv_usec -= 1000000 * nsec;
     T2->tv_sec += nsec;
   }
   if (T1->tv_usec - T2->tv_usec > 1000000) {
     int nsec = (T1->tv_usec - T2->tv_usec) / 1000000;
     T2->tv_usec += 1000000 * nsec;
     T2->tv_sec -= nsec;
   }

   /* Compute the time remaining to wait.
      tv_usec is certainly positive. */
   result->tv_sec = T1->tv_sec - T2->tv_sec;
   result->tv_usec = T1->tv_usec - T2->tv_usec;

   /* Return 1 if result is negative. */
   return T1->tv_sec < T2->tv_sec;
}

long long latency_in_microsecond(long long latency_sec,long long latency_usec)
{
    return (latency_sec*1000000 + latency_usec);
}

void UpdateReportingTable(int hashIndex)
{
    pthread_mutex_lock(&latency_report_lock);
    int index = hash_latency(hashArray[hashIndex].mac);
    int i = 0 ;
    LatencyTable *hashLatencyTable = NULL ;
    if (hashArray[hashIndex].ip_type == IPV4 )
        hashLatencyTable = Ipv4HashLatencyTable ;
    else
        hashLatencyTable = Ipv6HashLatencyTable ;

    if ( index < MAX_NUM_OF_CLIENTS )
    {
       
        if (strcmp(hashLatencyTable[index].mac,hashArray[hashIndex].mac) == 0)
        {

            if(PercentileCalculationEnable)
            {
                hashLatencyTable[index].wanSamples[hashLatencyTable[index].Num_of_Sample]=latency_in_microsecond(hashArray[hashIndex].latency_sec,hashArray[hashIndex].latency_usec);
                hashLatencyTable[index].lanSamples[hashLatencyTable[index].Num_of_Sample]=latency_in_microsecond(hashArray[hashIndex].Lan_latency_sec,hashArray[hashIndex].Lan_latency_usec);
                dbg_log("lanSamples:%lld wanSamples:%lld \n", hashLatencyTable[index].lanSamples[ hashLatencyTable[index].Num_of_Sample],hashLatencyTable[index].wanSamples[ hashLatencyTable[index].Num_of_Sample]);
                hashLatencyTable[index].SamplesAges[ hashLatencyTable[index].Num_of_Sample++]= hashLatencyTable[index].SampleAge++;
                dbg_log("hashIndex:%d,index:%d,atFirstInitTime:%d Num_of_Sample:%lld\n",hashIndex,index, hashLatencyTable[index].atFirstInitTime, hashLatencyTable[index].Num_of_Sample);
                if(( hashLatencyTable[index].atFirstInitTime==0)&&( hashLatencyTable[index].Num_of_Sample<=MAX_SAMPLE &&  hashLatencyTable[index].Num_of_Sample>=MIN_SAMPLE))
                {
                    dbg_log("SynAck_%d_PercentileLatency: \n",PercentileValue);
                    /***** pecentaile calculation for wan******/
                    memcpy( hashLatencyTable[index].Percentile_info[WAN_PERCENTILE].Samples,hashLatencyTable[index].wanSamples,sizeof(long long)* hashLatencyTable[index].Num_of_Sample);
                    memcpy( hashLatencyTable[index].Percentile_info[WAN_PERCENTILE].Samples_age,hashLatencyTable[index].SamplesAges,sizeof(long long)* hashLatencyTable[index].Num_of_Sample);
                    hashLatencyTable[index].Percentile_info[WAN_PERCENTILE].Number_of_Samples= hashLatencyTable[index].Num_of_Sample;
                    hashLatencyTable[index].Percentile_info[WAN_PERCENTILE].Percentile=PercentileValue;
                    hashLatencyTable[index].SynAckPercentileLatency=Calculate_Percentile(&hashLatencyTable[index].Percentile_info[WAN_PERCENTILE]);
                    /***** pecentaile calculation for lan******/
                    dbg_log("Ack_%d_PercentileLatency: \n",PercentileValue);
                    memcpy( hashLatencyTable[index].Percentile_info[LAN_PERCENTILE].Samples,hashLatencyTable[index].lanSamples,sizeof(long long)* hashLatencyTable[index].Num_of_Sample);
                    memcpy( hashLatencyTable[index].Percentile_info[LAN_PERCENTILE].Samples_age,hashLatencyTable[index].SamplesAges,sizeof(long long)* hashLatencyTable[index].Num_of_Sample);
                    hashLatencyTable[index].Percentile_info[LAN_PERCENTILE].Number_of_Samples= hashLatencyTable[index].Num_of_Sample;
                    hashLatencyTable[index].Percentile_info[LAN_PERCENTILE].Percentile=PercentileValue;
                    hashLatencyTable[index].AckPercentileLatency=Calculate_Percentile(&hashLatencyTable[index].Percentile_info[LAN_PERCENTILE]);
                    dbg_log("Index:%d Ack_Percentile_%d:%lld SyncACk_Percentile_%d::%lld\n",index,PercentileValue,hashLatencyTable[index].AckPercentileLatency,PercentileValue,hashLatencyTable[index].SynAckPercentileLatency);
                    if( hashLatencyTable[index].Num_of_Sample>=MAX_SAMPLE)
                    {
                        hashLatencyTable[index].atFirstInitTime=1;
                        memset(hashLatencyTable[index].wanSamples,0,sizeof(long long)* hashLatencyTable[index].Num_of_Sample);
                        memset(hashLatencyTable[index].lanSamples,0,sizeof(long long)* hashLatencyTable[index].Num_of_Sample);
                        hashLatencyTable[index].Num_of_Sample=0;
                    }
                    dbg_log("wanSamples and lanSamples Memory set to Zero: \n");
                }
                else if(( hashLatencyTable[index].Num_of_Sample>=ADD_MAX_SAMPLE)&&( hashLatencyTable[index].atFirstInitTime==1))
                {
                    hashLatencyTable[index].NthMaxValue= hashLatencyTable[index].NthMaxValue+ hashLatencyTable[index].Num_of_Sample;
                    dbg_log("SynAck_%d_PercentileLatency: \n",PercentileValue);
                    Remove_OldSample_Add_NewSample(&hashLatencyTable[index].Percentile_info[WAN_PERCENTILE],hashLatencyTable[index].wanSamples,hashLatencyTable[index].SamplesAges, hashLatencyTable[index].NthMaxValue);
                    hashLatencyTable[index].Percentile_info[WAN_PERCENTILE].Percentile=PercentileValue;
                    hashLatencyTable[index].SynAckPercentileLatency=Calculate_Percentile(&hashLatencyTable[index].Percentile_info[WAN_PERCENTILE]);
                    /***** pecentaile calculation for lan******/
                    dbg_log("Ack_%d_PercentileLatency: \n",PercentileValue);
                    Remove_OldSample_Add_NewSample(&hashLatencyTable[index].Percentile_info[LAN_PERCENTILE],hashLatencyTable[index].lanSamples,hashLatencyTable[index].SamplesAges, hashLatencyTable[index].NthMaxValue);
                    hashLatencyTable[index].Percentile_info[LAN_PERCENTILE].Percentile=PercentileValue;
                    hashLatencyTable[index].AckPercentileLatency=Calculate_Percentile(&hashLatencyTable[index].Percentile_info[LAN_PERCENTILE]);
                    dbg_log("index:%d Ack_Percentile_%d:%lld SynACk_Percentile_%d::%lld\n",index,PercentileValue,hashLatencyTable[index].AckPercentileLatency,PercentileValue,hashLatencyTable[index].SynAckPercentileLatency);
                    memset(hashLatencyTable[index].wanSamples,0,sizeof(long long)* hashLatencyTable[index].Num_of_Sample);
                    memset(hashLatencyTable[index].lanSamples,0,sizeof(long long)* hashLatencyTable[index].Num_of_Sample);
                    hashLatencyTable[index].Num_of_Sample=0;
                     dbg_log("wanSamples and lanSamples Memory set to Zero: \n");
                }
            }

          dbg_log("Before comparing latency, SynAckMinLatency is %lld.%06lld,SynAckMinLatency %lld.%06lld\n",
                        hashLatencyTable[index].SynAckMinLatency_sec,hashLatencyTable[index].SynAckMinLatency_usec,
                        hashLatencyTable[index].SynAckMaxLatency_sec,hashLatencyTable[index].SynAckMaxLatency_usec 
                    );
            if ( hashArray[hashIndex].latency_sec < hashLatencyTable[index].SynAckMinLatency_sec)
            {
                hashLatencyTable[index].SynAckMinLatency_sec = hashArray[hashIndex].latency_sec;
                hashLatencyTable[index].SynAckMinLatency_usec = hashArray[hashIndex].latency_usec;
            }
            else if(hashArray[hashIndex].latency_sec == hashLatencyTable[index].SynAckMinLatency_sec)
            {
                if(hashArray[hashIndex].latency_usec < hashLatencyTable[index].SynAckMinLatency_usec)
                {
                    hashLatencyTable[index].SynAckMinLatency_sec = hashArray[hashIndex].latency_sec;
                    hashLatencyTable[index].SynAckMinLatency_usec = hashArray[hashIndex].latency_usec;
                }
            }

            if ( hashArray[hashIndex].latency_sec > hashLatencyTable[index].SynAckMaxLatency_sec)
            {
                hashLatencyTable[index].SynAckMaxLatency_sec = hashArray[hashIndex].latency_sec ;
                hashLatencyTable[index].SynAckMaxLatency_usec = hashArray[hashIndex].latency_usec ;
            }
            else if( hashArray[hashIndex].latency_sec == hashLatencyTable[index].SynAckMaxLatency_sec)
            {
                if(hashArray[hashIndex].latency_usec > hashLatencyTable[index].SynAckMaxLatency_usec)
                {
                    hashLatencyTable[index].SynAckMaxLatency_sec = hashArray[hashIndex].latency_sec ;
                    hashLatencyTable[index].SynAckMaxLatency_usec = hashArray[hashIndex].latency_usec ;
                }
            }
           dbg_log("Before comparing latency,AckMinLatency is %lld.%06lld,SynAckMinLatency %lld.%06lld\n",
                        hashLatencyTable[index].AckMinLatency_sec,hashLatencyTable[index].AckMinLatency_usec,
                        hashLatencyTable[index].AckMaxLatency_sec,hashLatencyTable[index].AckMaxLatency_usec 
                    );

            if( hashArray[hashIndex].Lan_latency_sec < hashLatencyTable[index].AckMinLatency_sec)
            {
                hashLatencyTable[index].AckMinLatency_sec = hashArray[hashIndex].Lan_latency_sec;
                hashLatencyTable[index].AckMinLatency_usec = hashArray[hashIndex].Lan_latency_usec;
            }
            else if(hashArray[hashIndex].Lan_latency_sec == hashLatencyTable[index].AckMinLatency_sec)
            {
                if(hashArray[hashIndex].Lan_latency_usec < hashLatencyTable[index].AckMinLatency_usec)
                {
                    hashLatencyTable[index].AckMinLatency_sec = hashArray[hashIndex].Lan_latency_sec;
                    hashLatencyTable[index].AckMinLatency_usec = hashArray[hashIndex].Lan_latency_usec;
                }
            } 
             if ( hashArray[hashIndex].Lan_latency_sec > hashLatencyTable[index].AckMaxLatency_sec)
            {
                hashLatencyTable[index].AckMaxLatency_sec = hashArray[hashIndex].Lan_latency_sec ;
                hashLatencyTable[index].AckMaxLatency_usec = hashArray[hashIndex].Lan_latency_usec ;
            }
            else if(hashArray[hashIndex].Lan_latency_sec == hashLatencyTable[index].AckMaxLatency_sec)
            {
                if(hashArray[hashIndex].Lan_latency_usec > hashLatencyTable[index].AckMaxLatency_usec)
                {
                    hashLatencyTable[index].AckMaxLatency_sec = hashArray[hashIndex].Lan_latency_sec ;
                    hashLatencyTable[index].AckMaxLatency_usec = hashArray[hashIndex].Lan_latency_usec ;
                }
            }
            hashLatencyTable[index].SynAckAggregatedLatency_sec += hashArray[hashIndex].latency_sec  ;
            hashLatencyTable[index].SynAckAggregatedLatency_usec += hashArray[hashIndex].latency_usec ;
            hashLatencyTable[index].AckAggregatedLatency_sec += hashArray[hashIndex].Lan_latency_sec ;
            hashLatencyTable[index].AckAggregatedLatency_usec += hashArray[hashIndex].Lan_latency_usec ;

            goto LOG_MINMAX_LATENCY;
        }

        while ( hashLatencyTable[index].mac[0] != '\0')
        {
            if (i >= MAX_NUM_OF_CLIENTS )
            {
                dbg_log("%s : Hash table is full,returning\n",__FUNCTION__); 
                pthread_mutex_unlock(&latency_report_lock);
                return;
            }
            ++index ;
            i++;

            //wrap around the table
            index %= MAX_NUM_OF_CLIENTS;

        }
        dbg_log("New entry for mac %s\n",hashArray[hashIndex].mac);
        strncpy(hashLatencyTable[index].mac,hashArray[hashIndex].mac,sizeof(hashArray[hashIndex].mac)-1);

        hashLatencyTable[index].SynAckMinLatency_sec = hashArray[hashIndex].latency_sec;
        hashLatencyTable[index].SynAckMinLatency_usec = hashArray[hashIndex].latency_usec;

        hashLatencyTable[index].SynAckMaxLatency_sec = hashArray[hashIndex].latency_sec ;
        hashLatencyTable[index].SynAckMaxLatency_usec = hashArray[hashIndex].latency_usec ;

        hashLatencyTable[index].AckMinLatency_sec = hashArray[hashIndex].Lan_latency_sec;
        hashLatencyTable[index].AckMinLatency_usec = hashArray[hashIndex].Lan_latency_usec;

        hashLatencyTable[index].AckMaxLatency_sec = hashArray[hashIndex].Lan_latency_sec ;
        hashLatencyTable[index].AckMaxLatency_usec = hashArray[hashIndex].Lan_latency_usec ;

        // Avg latency will be implemented in phase 2
        hashLatencyTable[index].SynAckAggregatedLatency_sec = hashArray[hashIndex].latency_sec  ;
        hashLatencyTable[index].SynAckAggregatedLatency_usec = hashArray[hashIndex].latency_usec ;

        hashLatencyTable[index].SynAckPercentileLatency = -1 ;
        hashLatencyTable[index].AckAggregatedLatency_sec = hashArray[hashIndex].Lan_latency_sec ;
        hashLatencyTable[index].AckAggregatedLatency_usec = hashArray[hashIndex].Lan_latency_usec ;

        hashLatencyTable[index].AckPercentileLatency = -1 ;

        hashLatencyTable[index].bHasLatencyEntry = true ;
        hashLatencyTable[index].wanSamples[ hashLatencyTable[index].Num_of_Sample]=latency_in_microsecond(hashArray[hashIndex].latency_sec,hashArray[hashIndex].latency_usec);
        hashLatencyTable[index].lanSamples[ hashLatencyTable[index].Num_of_Sample]=latency_in_microsecond(hashArray[hashIndex].Lan_latency_sec,hashArray[hashIndex].Lan_latency_usec);
        hashLatencyTable[index].SamplesAges[ hashLatencyTable[index].Num_of_Sample++]= hashLatencyTable[index].SampleAge++;        
    }

LOG_MINMAX_LATENCY :
        hashLatencyTable[index].num_of_flows++;

        for(int j=0 ; j < MAX_PORTS ;j++)
        {
            if (hashLatencyTable[index].port[j] == 0 )
            {
                dbg_log("Port %d not found , adding it to mac %s list\n",hashArray[hashIndex].th_dport,hashArray[hashIndex].mac);
                hashLatencyTable[index].port[j] = hashArray[hashIndex].th_dport;
                hashLatencyTable[index].num_of_ports++;
                break;
            }
            else if ( hashArray[hashIndex].th_dport == hashLatencyTable[index].port[j])
            {
                dbg_log("Port %d already exists for mac %s\n",hashArray[hashIndex].th_dport,hashArray[hashIndex].mac);
                break;
            }
        }
        dbg_log("Ip type is %u\n",hashArray[hashIndex].ip_type);
        dbg_log("Port is %d\n",hashArray[hashIndex].th_dport);
        dbg_log("Num of flows for %s hashLatencyTable[%d].num_of_flows is %lu\n",hashArray[hashIndex].mac,index,hashLatencyTable[index].num_of_flows);
        dbg_log("SynAckMinLatency is %lld.%06lld,SynAckMinLatency %lld.%06lld\n",
                hashLatencyTable[index].SynAckMinLatency_sec,hashLatencyTable[index].SynAckMinLatency_usec,
                hashLatencyTable[index].SynAckMaxLatency_sec,hashLatencyTable[index].SynAckMaxLatency_usec 
            );
        dbg_log("AckMinLatency is %lld.%06lld,SynAckMinLatency %lld.%06lld\n",
                hashLatencyTable[index].AckMinLatency_sec,hashLatencyTable[index].AckMinLatency_usec,
                hashLatencyTable[index].AckMaxLatency_sec,hashLatencyTable[index].AckMaxLatency_usec 
            );
        dbg_log("SynAckAggregatedLatency is %lld.%06lld , AckAggregatedLatency is %lld.%06lld for mac %s\n",
                    hashLatencyTable[index].SynAckAggregatedLatency_sec,hashLatencyTable[index].SynAckAggregatedLatency_usec,
                    hashLatencyTable[index].AckAggregatedLatency_sec,hashLatencyTable[index].AckAggregatedLatency_usec,
                    hashArray[hashIndex].mac);

        pthread_mutex_unlock(&latency_report_lock);

}

void MeasureTCPLatency(int hashIndex)
{
    //1000000 * header->ts.tv_sec + header->ts.tv_usec
   /* hashArray[hashIndex].latency_sec  = hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].tv_sec - hashArray[hashIndex].TcpInfo[INDEX_SYN].tv_sec;
    hashArray[hashIndex].latency_usec = (1000000 * hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].tv_usec) - hashArray[hashIndex].TcpInfo[INDEX_SYN].tv_usec;

    hashArray[hashIndex].Lan_latency_sec  = hashArray[hashIndex].TcpInfo[INDEX_ACK].tv_sec - hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].tv_sec;
    hashArray[hashIndex].Lan_latency_usec = (1000000 * hashArray[hashIndex].TcpInfo[INDEX_ACK].tv_usec) - hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].tv_usec;

    printf("WAN Latency for %s %lu is %lld.%ld\n",hashArray[hashIndex].mac,hashArray[hashIndex].TcpInfo[INDEX_SYN].th_seq,hashArray[hashIndex].latency_sec,hashArray[hashIndex].latency_usec);
    printf("LAN Latency for %s %lu is %lld.%ld\n",hashArray[hashIndex].mac,hashArray[hashIndex].TcpInfo[INDEX_SYN].th_seq,hashArray[hashIndex].Lan_latency_sec,hashArray[hashIndex].Lan_latency_usec);
 */
    struct timeval t1, t2, t3, diff_time;
    t2.tv_sec = hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].tv_sec;
    t2.tv_usec = hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].tv_usec;
    t1.tv_sec = hashArray[hashIndex].TcpInfo[INDEX_SYN].tv_sec;
    t1.tv_usec = hashArray[hashIndex].TcpInfo[INDEX_SYN].tv_usec;
    t3.tv_sec = hashArray[hashIndex].TcpInfo[INDEX_ACK].tv_sec;
    t3.tv_usec = hashArray[hashIndex].TcpInfo[INDEX_ACK].tv_usec;  
    //timercmp(&t1,&t2,diff_time);

	
    timeval_subtract(&diff_time,&t2,&t1);
    hashArray[hashIndex].latency_sec = diff_time.tv_sec;
    hashArray[hashIndex].latency_usec = diff_time.tv_usec;
    dbg_log("WAN Latency for %s %u is %lld.%06lld\n",hashArray[hashIndex].mac,hashArray[hashIndex].TcpInfo[INDEX_SYN].th_seq,hashArray[hashIndex].latency_sec,hashArray[hashIndex].latency_usec);
        
    timeval_subtract(&diff_time,&t3,&t2);
    hashArray[hashIndex].Lan_latency_sec = diff_time.tv_sec;
    hashArray[hashIndex].Lan_latency_usec = diff_time.tv_usec;
    dbg_log("LAN Latency for %s %u is %lld.%06lld\n",hashArray[hashIndex].mac,hashArray[hashIndex].TcpInfo[INDEX_SYN].th_seq,hashArray[hashIndex].Lan_latency_sec,hashArray[hashIndex].Lan_latency_usec);
    
    if ( args.verbose_mode == false )
    {
        UpdateReportingTable(hashIndex);
        dbg_log("latency is computed for mac %s, seq %u, clearing data\n",hashArray[hashIndex].mac,hashArray[hashIndex].TcpInfo[INDEX_SYN].th_seq);
        memset(&hashArray[hashIndex],0,sizeof(TcpSniffer));
        g_HashCount--;  
    }
    else
    {
        hashArray[hashIndex].bComputed = TRUE;
    }
             
    if ( args.dbg_mode == true )
        display();
}
void* LatencyReportThread(void* arg)
{
    // detach the current thread 
    int i = 0;
    int byteCount = 0;
    int tempCount = 0;
    int port_sz_count = 0;
    int hashSize= sizeof(LatencyTable)+1;
    char str[hashSize];
    char port_buff[SIZE];
    char buf[128]={0};
    int num_of_ipv4_clients = 0;  
    int num_of_ipv6_clients = 0;  
    char *report_buf = NULL ;
    char *tmp_report_buf = NULL ;
    report_buf = (char*) malloc (MAX_REPORT_SIZE);
    if (report_buf == NULL )
        return NULL;

    tmp_report_buf = (char*) malloc (MAX_REPORT_SIZE);
    if (tmp_report_buf == NULL )
    {
        free(report_buf);
        return NULL;
    }
    memset(str,0,hashSize);

    pthread_detach(pthread_self());
  
    dbg_log("Inside the LatencyReportThread\n");
    FILE *fp = NULL;
    //fp = fopen("LatencyReport.txt", "w+");
    while(1)
    {
        memset(report_buf,0,MAX_REPORT_SIZE);
        memset(tmp_report_buf,0,MAX_REPORT_SIZE);
        num_of_ipv4_clients=0, num_of_ipv6_clients =0;
        dbg_log("args.report_interval is %d\n",args.report_interval);
        sleep(args.report_interval);
        // display();

        pthread_mutex_lock(&latency_report_lock);
        while(i < MAX_NUM_OF_CLIENTS)
        {
            memset(port_buff,0,sizeof(port_buff));
            // calculate ipv4
            memset(str,0,hashSize);
            if(Ipv4HashLatencyTable[i].bHasLatencyEntry == true)
            {
                printf("Index i is %d,Ipv4HashLatencyTable[i].bHasLatencyEntry\n",i);
                tempCount = snprintf(str,sizeof(str),";%s;%lu,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld;",Ipv4HashLatencyTable[i].mac,Ipv4HashLatencyTable[i].num_of_flows,
                    latency_in_microsecond(Ipv4HashLatencyTable[i].SynAckMinLatency_sec,Ipv4HashLatencyTable[i].SynAckMinLatency_usec),
                    latency_in_microsecond(Ipv4HashLatencyTable[i].SynAckMaxLatency_sec,Ipv4HashLatencyTable[i].SynAckMaxLatency_usec),
                    latency_in_microsecond(Ipv4HashLatencyTable[i].SynAckAggregatedLatency_sec,Ipv4HashLatencyTable[i].SynAckAggregatedLatency_usec)/Ipv4HashLatencyTable[i].num_of_flows,
                    Ipv4HashLatencyTable[i].SynAckPercentileLatency,
                    latency_in_microsecond(Ipv4HashLatencyTable[i].AckMinLatency_sec,Ipv4HashLatencyTable[i].AckMinLatency_usec),
                    latency_in_microsecond(Ipv4HashLatencyTable[i].AckMaxLatency_sec,Ipv4HashLatencyTable[i].AckMaxLatency_usec),
                    latency_in_microsecond(Ipv4HashLatencyTable[i].AckAggregatedLatency_sec,Ipv4HashLatencyTable[i].AckAggregatedLatency_usec)/Ipv4HashLatencyTable[i].num_of_flows,
                    Ipv4HashLatencyTable[i].AckPercentileLatency
                    );
            
                for(int port_count=0;port_count < Ipv4HashLatencyTable[i].num_of_ports;port_count++)
                {
                    memset(buf,0,sizeof(buf));
                    if (port_count == Ipv4HashLatencyTable[i].num_of_ports-1)
                    {
                        port_sz_count += snprintf(buf,sizeof(buf),"%d",Ipv4HashLatencyTable[i].port[port_count]);
                    }
                    else
                    {
                        port_sz_count += snprintf(buf,sizeof(buf),"%d,",Ipv4HashLatencyTable[i].port[port_count]);
                    }
                    dbg_log("Inside the LatencyReportThread before strcat ports\n");
                    strncat(port_buff,buf,(SIZE-strlen(port_buff)-1));
                    dbg_log("Inside the LatencyReportThread strcat ports\n");
                }  
                if(tempCount)
                {
                    if((byteCount+tempCount+port_sz_count) < (MAX_REPORT_SIZE-FILTER_BUF_SIZE))
                    {
                        byteCount += tempCount+port_sz_count;
                        dbg_log("Flush Ipv4HashLatencyTable\n");
                        memset(&Ipv4HashLatencyTable[i],0,sizeof(LatencyTable));
                        strncat(tmp_report_buf,str,(MAX_REPORT_SIZE-strlen(tmp_report_buf)-1));
                        strncat(tmp_report_buf,port_buff,(MAX_REPORT_SIZE-strlen(tmp_report_buf)-1));
                        num_of_ipv4_clients++;
                         dbg_log("after Flush Ipv4HashLatencyTable concat report \n");
                    }
                    else
                    {
                        dbg_log("Report size full, this data will go in next report\n");
                        break;
                    }
                }
                //strcat(str,str1);
                dbg_log("i = %d str = %s\n",i,str);
                memset(str,0,hashSize);
            }
            i++;
        }
        i = 0;

        memset(buf,0,sizeof(buf));
        tempCount = snprintf(buf,sizeof(buf),"Private,AnyDSCP,AnyECN,AnyPort,IPv4,%d",num_of_ipv4_clients);
        byteCount += tempCount;

        snprintf(report_buf,(MAX_REPORT_SIZE-1),"%s%s",buf,tmp_report_buf);
        strncat(report_buf,"|",(MAX_REPORT_SIZE-strlen(report_buf)-1));

        memset(buf,0,sizeof(buf));
        memset(tmp_report_buf,0,MAX_REPORT_SIZE);
        memset(port_buff,0,sizeof(port_buff));
        memset(str,0,hashSize);

        while(i < MAX_NUM_OF_CLIENTS)
        {
            memset(port_buff,0,sizeof(port_buff));
            if(Ipv6HashLatencyTable[i].bHasLatencyEntry == true)
            {
                tempCount = snprintf(str,sizeof(str),";%s;%lu,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld;",Ipv6HashLatencyTable[i].mac,Ipv6HashLatencyTable[i].num_of_flows,
                    latency_in_microsecond(Ipv6HashLatencyTable[i].SynAckMinLatency_sec,Ipv6HashLatencyTable[i].SynAckMinLatency_usec),
                    latency_in_microsecond(Ipv6HashLatencyTable[i].SynAckMaxLatency_sec,Ipv6HashLatencyTable[i].SynAckMaxLatency_usec),
                    latency_in_microsecond(Ipv6HashLatencyTable[i].SynAckAggregatedLatency_sec,Ipv6HashLatencyTable[i].SynAckAggregatedLatency_usec)/Ipv6HashLatencyTable[i].num_of_flows,
                    Ipv6HashLatencyTable[i].SynAckPercentileLatency,
                    latency_in_microsecond(Ipv6HashLatencyTable[i].AckMinLatency_sec,Ipv6HashLatencyTable[i].AckMinLatency_usec),
                    latency_in_microsecond(Ipv6HashLatencyTable[i].AckMaxLatency_sec,Ipv6HashLatencyTable[i].AckMaxLatency_usec),
                    latency_in_microsecond(Ipv6HashLatencyTable[i].AckAggregatedLatency_sec,Ipv6HashLatencyTable[i].AckAggregatedLatency_usec)/Ipv6HashLatencyTable[i].num_of_flows,
                    Ipv6HashLatencyTable[i].AckPercentileLatency
                );
                for(int port_count=0;port_count < Ipv6HashLatencyTable[i].num_of_ports;port_count++)
                {
                    memset(buf,0,sizeof(buf));
                    if (port_count == Ipv6HashLatencyTable[i].num_of_ports-1)
                        port_sz_count += snprintf(buf,sizeof(buf),"%d",Ipv6HashLatencyTable[i].port[port_count]);
                    else
                        port_sz_count += snprintf(buf,sizeof(buf),"%d,",Ipv6HashLatencyTable[i].port[port_count]);
                    
                    dbg_log("Inside IPV6 the LatencyReportThread before strcat ports\n");
                    strncat(port_buff,buf,(SIZE-strlen(port_buff)-1));
                     dbg_log("Inside IPV6 the LatencyReportThread strcat ports\n");
                }

                // TODO port num
                if(tempCount)
                {
                    if((byteCount+tempCount+port_sz_count) < (MAX_REPORT_SIZE-FILTER_BUF_SIZE))
                    {
                        byteCount += tempCount+port_sz_count;
                        dbg_log("Flush Ipv6HashLatencyTable\n");
                        memset(&Ipv6HashLatencyTable[i],0,sizeof(LatencyTable));
                        strncat(tmp_report_buf,str,(MAX_REPORT_SIZE-strlen(tmp_report_buf)-1));
                        strncat(tmp_report_buf,port_buff,(MAX_REPORT_SIZE-strlen(tmp_report_buf)-1));
                        num_of_ipv6_clients++;
                        dbg_log("Flush Ipv6HashLatencyTable done concat reports\n");
                    }
                    else
                    {
                        dbg_log("Report size full, this data will go in next report\n");
                        break;
                    }
                }
                //strcat(str,str1);
                dbg_log("i = %d str = %s\n",i,str);
                memset(str,0,hashSize);
            }
            i++;
        }
        pthread_mutex_unlock(&latency_report_lock);

        i = 0;
        memset(buf,0,sizeof(buf));

        snprintf(buf,sizeof(buf),"Private,AnyDSCP,AnyECN,AnyPort,IPv6,%d",num_of_ipv6_clients);
        dbg_log("before Report_buf is %s\n",report_buf);
        strncat(report_buf,buf,(MAX_REPORT_SIZE-strlen(report_buf)-1));
        strncat(report_buf,tmp_report_buf,(MAX_REPORT_SIZE-strlen(report_buf)-1));
        strncat(report_buf,"|",(MAX_REPORT_SIZE-strlen(report_buf)-1));

        dbg_log("Report_buf is %s\n",report_buf);

        if (args.report_type == REP_TYPE_T2 && strlen(args.report_name) !=0 )
        {
            dbg_log("Set param %s\n",args.report_name);
            rbus_setStr(bus_handle_rbus, args.report_name,report_buf);
        }
        else if (args.report_type  == REP_TYPE_FILE && strlen(args.report_name) !=0 )
        {
            fp = fopen(args.report_name, "a+");
            if(fp != NULL)
            {
                fputs(report_buf,fp);
                fclose(fp);
            }
        }
        byteCount = 0;
        if ( args.dbg_mode == true )
        {
            dbg_log("Report generated - Dislpay\n");
            display();     
        }
    }
   
    if (report_buf != NULL )
    {
        free(report_buf);
        report_buf=NULL;
    }
    if (tmp_report_buf != NULL )
    {
        free(tmp_report_buf);
        tmp_report_buf=NULL;
    }
    return NULL;
    // exit the current thread
    //pthread_exit(NULL);
}


#if 1
void* LatencyReportThreadPerSession(void* arg)
{
    // detach the current thread 
    int i = 0;
    int byteCount = 0;
    int tempCount = 0;
    int count = 0;
    char *str = NULL;
    char str1[1024];
    str = (char*) malloc (MAX_REPORT_SIZE);
    if (str == NULL )
        return NULL;

    memset(str,0,MAX_REPORT_SIZE);
    pthread_detach(pthread_self());
    dbg_log("Inside the LatencyReportThreadPerSession\n");
    FILE *fp;
    //fp = fopen("LatencyReport.txt", "w+");

    while(1)
    {
        sleep(5);
        //fp = fopen("LatencyReport.txt", "a+");
        //if(fp != NULL)
        {
           // display();
            while(i < SIZE)
            {
               // printf("hashArray[%d].bComputed = %d\n",i,hashArray[i].bComputed);
                if(hashArray[i].bComputed == TRUE)
                {
                    tempCount = snprintf(str1,sizeof(str1),"%s,%u,%lld.%lld,%lld.%06lld|",hashArray[i].mac,hashArray[i].TcpInfo[INDEX_SYN].th_seq,hashArray[i].latency_sec,hashArray[i].latency_usec,hashArray[i].Lan_latency_sec,hashArray[i].Lan_latency_usec);
                    if(tempCount)
                    {
                        if((byteCount+tempCount) < MAX_REPORT_SIZE)
                        {
                            byteCount += tempCount;
                            memset(&hashArray[i],0,sizeof(TcpSniffer));
                            g_HashCount--;
                            strncat(str,str1,(MAX_REPORT_SIZE-strlen(str)-1));
                        }
                        else
                        {
                                dbg_log("Report size full, this data will go in next report\n");
                        }

                    }
                    //strcat(str,str1);
                    dbg_log("i = %d str = %s\n",i,str);
                    memset(str1,0,sizeof(str1));
                }
                i++;
            }
            i = 0;
        }
        count++;
        if( byteCount > 0 && ( ((count * 5) >= args.report_interval )||(byteCount >= MAX_REPORT_SIZE - 24)) ) // send report after 60 seconds or when report around MAX_REPORT_SIZE
        {
            dbg_log("Report generated - count in sec is %d byteCount = %d\n",count * 5,byteCount);

            if (args.report_type  == REP_TYPE_FILE && strlen(args.report_name) !=0 )
            {
                fp = fopen(args.report_name, "a+");
                if(fp != NULL)
                {
                    fputs(str, fp);
                    fclose(fp);
                }                    
                    //system("cat /tmp/LatencyReport.txt");
                    //memset(str1,0,MAX_REPORT_SIZE);  
            }
            else if (args.report_type  == REP_TYPE_T2 && strlen(args.report_name) !=0 )
            {

                dbg_log("Set param %s\n",args.report_name);
                rbus_setStr(bus_handle_rbus, args.report_name,str);
            }

            count = 0;
            byteCount = 0;
            memset(str,0,MAX_REPORT_SIZE);
            if( args.dbg_mode == true )
            {
                dbg_log("Report generated - Dislpay\n");
                display();     
            }
        }
    }
    if (str != NULL )
    {
        free(str);
        str=NULL;
    }
    // exit the current thread
    //pthread_exit(NULL);
}
#endif


void* ClearHashThread(void* arg)
{
    // detach the current thread 
    int i = 0;

    pthread_detach(pthread_self());
  
    dbg_log("Inside the ClearHashThread\n");
            while(1)
            {
                sleep(7);
                while(i < SIZE)
                {
                    //struct timeval te; 
                    //gettimeofday(&te, NULL); // get current time
                    //long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000;
                    time_t seconds;
         
                    seconds = time(NULL);
                    if((hashArray[i].bComputed == FALSE) && (hashArray[i].key != 0))
                    {
                      /* printf("te.tv_sec - %lu hashArray[%d].TcpInfo[INDEX_SYN].tv_sec %ld\n",(te.tv_sec*1000LL),i, hashArray[i].TcpInfo[INDEX_SYN].tv_sec);
       
                        if(((te.tv_sec*1000LL) - hashArray[i].TcpInfo[INDEX_SYN].tv_sec) > MAX_TCP_SYN_ACK_TIMEOUT)*/
                        dbg_log("te.tv_sec - %lu hashArray[%d].TcpInfo[INDEX_SYN].tv_sec %u\n",seconds,i,(u_int)hashArray[i].TcpInfo[INDEX_SYN].tv_sec);
                        int diff = seconds - (u_int)hashArray[i].TcpInfo[INDEX_SYN].tv_sec;
                        dbg_log("diff time %u\n",diff);
                        //if((seconds - (u_int)hashArray[i].TcpInfo[INDEX_SYN].tv_sec) > MAX_TCP_SYN_ACK_TIMEOUT)
                        if(diff > MAX_TCP_SYN_ACK_TIMEOUT)
                        {
                                dbg_log("Clearing un-acknowledged SYN enteries\n");
                                memset(&hashArray[i],0,sizeof(TcpSniffer));
                                g_HashCount--;
                        }

                    }
                    i++;
                }
                i = 0;
            }
    
    //fp = 

}

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s -h' for more information.\n", progname);
  else
    {
      printf ("Usage : %s [OPTION...]\n\n"\
              "-D,   Enable dbg logs\n"\
              "-F,   Log File\n"\
              "-t,   Report type: 0 = file, 1 = T2\n"\
              "-i,   Report Interval is secs\n"\
              "-n,   Report name: File path name or RBus data model name\n"\
              "-s,   Report Size in Bytes\n"\
              "-v,   Verbose Mode\n"\
             /* "-a,   To get aggregated report \n"\
              "-p,   To get aggregated report per macaddress per port\n"\ */
              "-h,   Display this help and exit\n"\
              "\n",progname
              );
    }
  exit (status);
}
int validateParams()
{
    if ( REP_TYPE_FILE != args.report_type &&  REP_TYPE_T2 != args.report_type )
    {
        printf("report_type validation failed\n");
        return VALIDATION_FAILED;
    }
    else if ( 0 == args.report_interval )
    {
        printf("report_interval can't be null\n");
        return VALIDATION_FAILED;
    }
    else if (strlen(args.report_name) == 0 )
    {
        printf("report_name can't be null\n");
        return VALIDATION_FAILED;
    }
    return VALIDATION_SUCCESS;
}

void rbusInit(char *progname)
{
          dbg_log("Entering %s\n", __FUNCTION__);
          int ret = RBUS_ERROR_SUCCESS;
          ret = rbus_open(&bus_handle_rbus, progname);
          if(ret != RBUS_ERROR_SUCCESS) {
              dbg_log("%s: init failed with error code %d \n", __FUNCTION__, ret);
               return ;
         }    
}

int main(int argc,char **argv)
{

      char *progname;
  char *p;
 
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  if(argc == 1 )
    usage (progname, 1);

  int opt;
  memset(&args,0,sizeof(Param));
  memset(&Ipv4HashLatencyTable,0,sizeof(LatencyTable) * MAX_NUM_OF_CLIENTS);
  memset(&Ipv6HashLatencyTable,0,sizeof(LatencyTable) * MAX_NUM_OF_CLIENTS);

    while (1)
    {
      opt = getopt_long (argc, argv, "apDhvi:t:s:n:F:", longopts, 0);

      if (opt == EOF)
      {
            break;
      }
        switch (opt)
        {
            case 'i':
              args.report_interval = atoi(optarg);
              break;
            case 't':
              args.report_type = atoi(optarg);
              break;
            case 'n':
              strncpy(args.report_name,optarg,sizeof(args.report_name)-1);
              break;
            case 'D':
              args.dbg_mode = true;
              break;
            case 'v':
              args.verbose_mode = true;
              break;
           /* case 'a':
              args.aggregated_data = true;
              break;
            case 'p':
              args.aggregated_data_per_port = true;
              break; */
            case 'F':
             // data.log_file = optarg;
              strncpy(args.log_file,optarg,sizeof(args.log_file)-1);
              logFp = fopen(args.log_file,"w+");
              break;
            case 'h':
              usage (progname, 0);
              break;
            default:
              usage (progname, 1);
              break;  
        }
    }

    if ( VALIDATION_SUCCESS == validateParams() )
    {
        dbg_log("Arg validation success\n");
    }
    else
    {
        printf("Validation failed, exiting\n");
        exit(0);
    }

    if ( REP_TYPE_T2 == args.report_type )
    {
        if(RBUS_ENABLED == rbus_checkStatus()) 
        {
            rbusInit(progname);
        }
    }

    key_t key;
    int msgid;
    pthread_t ptid;
    pthread_t ptid1;

    // Creating a new thread
    if(args.verbose_mode == true )
    {
        pthread_create(&ptid, NULL, &LatencyReportThreadPerSession, NULL);
    }
    else
    {
        pthread_create(&ptid, NULL, &LatencyReportThread, NULL);
    }
    pthread_create(&ptid1, NULL, &ClearHashThread, NULL);

    memset(hashArray,0,sizeof(TcpSniffer)*SIZE);
    // ftok to generate unique key
    key = ftok("progfile", 65);
  
    // msgget creates a message queue
    // and returns identifier
    msgid = msgget(key, 0666 | IPC_CREAT);
    //if((msgid = msgget(12345, 0666 | IPC_CREAT)) == -1)
    //perror( "server: Failed to create message queue:" );

    PercentileCalculationEnable=isLowLatency_PercentileCalculationEnable();
    // msgrcv to receive message
    //msgrcv(msgid, &message, sizeof(message), 1, 0);
    while(msgrcv(msgid, &message, sizeof(message), 1, 0))
    {
  //perror( "server: Failed to create message queue:" );
    // display the message
   // printf("Data Received is : %s \n", message.mesg_text);
    dbg_log("Data Received is : %d \nFLAG: %d \nACK: %u\nSeq %u\n TS: %lld.%06lld\n", 
                    message.mesg_type,message.th_flag,message.th_ack,message.th_seq,message.tv_sec,message.tv_usec);
    if((message.th_flag & SYN_ACK) == SYN_ACK)
    {
        //insert(message.th_ack,message);
        int hashIndex = 0;
        hashIndex = search((message.th_ack - 1)); // Because SYN-ACK is sequence number incremented  by 1
        if(hashIndex != -1)
        {
            dbg_log("Calculate latency\n");
            /*hashArray[hashIndex].th_flag = message.th_flag;
            hashArray[hashIndex].th_ack = message.th_ack;
            hashArray[hashIndex].tv_sec  = message.tv_sec - hashArray[hashIndex].tv_sec;
            hashArray[hashIndex].tv_usec  = message.tv_usec - hashArray[hashIndex].tv_usec;*/
 
            hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].th_flag = message.th_flag;
            hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].th_seq  = message.th_seq;
            hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].th_ack  = message.th_ack;
            hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].tv_sec  = message.tv_sec;
            hashArray[hashIndex].TcpInfo[INDEX_SYN_ACK].tv_usec = message.tv_usec; 
	    //MeasureTCPLatency(hashIndex);
        }
    }
    else if((message.th_flag & SYN) == SYN)
    {
        insert((u_short)message.th_seq,message);
    }
    else if((message.th_flag & ACK) == ACK)
    {
                //insert(message.th_ack,message);
        int hashIndex = 0;
        hashIndex = search((message.th_seq - 1)); // Because SYN-ACK is sequence number incremented  by 1
        if(hashIndex != -1)
        {
            if(hashArray[hashIndex].bComputed == TRUE)
            {
                dbg_log("Already processed ack sequence... Ignoring\n");
            }
            else
            {
                dbg_log("Calculate latency after ack\n");
                /*hashArray[hashIndex].th_flag = message.th_flag;
                hashArray[hashIndex].th_ack = message.th_ack;
                hashArray[hashIndex].tv_sec  = message.tv_sec - hashArray[hashIndex].tv_sec;
                hashArray[hashIndex].tv_usec  = message.tv_usec - hashArray[hashIndex].tv_usec;*/
                hashArray[hashIndex].TcpInfo[INDEX_ACK].th_flag = message.th_flag;
                hashArray[hashIndex].TcpInfo[INDEX_ACK].th_seq  = message.th_seq;
                hashArray[hashIndex].TcpInfo[INDEX_ACK].th_ack  = message.th_ack;
                hashArray[hashIndex].TcpInfo[INDEX_ACK].tv_sec  = message.tv_sec;
                hashArray[hashIndex].TcpInfo[INDEX_ACK].tv_usec  = message.tv_usec; 
		MeasureTCPLatency(hashIndex);
            }
        }
    }
    else
    {
        //pass it
    }

   // printf("call display\n");
  //  display();
    }
  
    // to destroy the message queue
    msgctl(msgid, IPC_RMID, NULL);

    if (logFp != NULL)
    {
        fclose(logFp);
        logFp=NULL;
    }  
    return 0;
}
