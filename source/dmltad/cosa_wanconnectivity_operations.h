/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/


#ifndef  _WANCHK_RBUS_OPERATIONS_H
#define  _WANCHK_RBUS_OPERATIONS_H

#include <cosa_wanconnectivity_apis.h>
#include "ev.h"
#include <linux/filter.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <pcap.h>
#include <poll.h>

/* Generated with tcpdump -dd "udp src port 53" */
struct sock_filter dns_packet_filter[] = {
                { 0x28, 0, 0, 0x0000000c },
                { 0x15, 0, 6, 0x000086dd },
                { 0x30, 0, 0, 0x00000014 },
                { 0x15, 0, 15, 0x00000011 },
                { 0x28, 0, 0, 0x00000036 },
                { 0x15, 12, 0, 0x00000035 },
                { 0x28, 0, 0, 0x00000038 },
                { 0x15, 10, 11, 0x00000035 },
                { 0x15, 0, 10, 0x00000800 },
                { 0x30, 0, 0, 0x00000017 },
                { 0x15, 0, 8, 0x00000011 },
                { 0x28, 0, 0, 0x00000014 },
                { 0x45, 6, 0, 0x00001fff },
                { 0xb1, 0, 0, 0x0000000e },
                { 0x48, 0, 0, 0x0000000e },
                { 0x15, 2, 0, 0x00000035 },
                { 0x48, 0, 0, 0x00000010 },
                { 0x15, 0, 1, 0x00000035 },
                { 0x6, 0, 0, 0x00040000 },
                { 0x6, 0, 0, 0x00000000 },
            };

#define SIZE_OF_PACKET_FILTER(filter) (sizeof(filter)/sizeof(struct sock_filter))
#define DNS_PACKET_FILTER_SIZE SIZE_OF_PACKET_FILTER(dns_packet_filter)
#define ACTV_MNTR_PAUSE        "/tmp/actv_mon_pause_%s"

typedef enum _queryinvoke_type {
        QUERYNOW_INVOKE  = 1,
        ACTIVE_MONITOR_INVOKE  = 2,
} queryinvoke_type_t;


struct mk_query {
    unsigned char query[512];
    unsigned int qlen;
    unsigned int resp_recvd;
};


struct query {
    char ifname[MAX_INTF_NAME_SIZE];
    char ns[MAX_URL_SIZE];
    unsigned int skt_family;
    ULONG query_timeout;
    unsigned int query_retry;
    unsigned int query_count;
    recordtype_t rqstd_rectype;
    char IPv4Gateway[IPv4_STR_LEN];
    char IPv6Gateway[IPv6_STR_LEN];
};

typedef struct _wan_chk_passive_monitor
{
    /* libev stuff */
    struct ev_loop     *loop;
    ev_io              evio;                 /* libev I/O event handler */
    ev_timer           bgtimer;              /* background dns response monitor timer */

    /* libpcap stuff */
    pcap_t             *pcap;
    int                pcap_fd;
    struct bpf_program bpf_fp;

    /* To update monitor status */
    ULONG              InstanceNumber;
    /* To pause active monitor */
    UCHAR              InterfaceName[MAX_INTF_NAME_SIZE];
    /* To check passive monitor running on primary or backup interface */
    BOOL               IsPrimary;
    BOOL               doInfoLogOnce;
}
WAN_CNCTVTY_CHK_PASSIVE_MONITOR,*PWAN_CNCTVTY_CHK_PASSIVE_MONITOR;

typedef struct _wan_chk_active_monitor
{
    /* libev stuff */
    struct ev_loop     *loop;
    ev_timer           actvtimer;             /* background dns response monitor timer */
    ev_stat            pause_actv_mntr;       /* file watcher to pause active monitor */

    /* To pause active monitor */
    UCHAR              InterfaceName[MAX_INTF_NAME_SIZE];
}
WAN_CNCTVTY_CHK_ACTIVE_MONITOR,*PWAN_CNCTVTY_CHK_ACTIVE_MONITOR;

typedef struct ping_packet {
      struct icmphdr hdr;
      char msg[64-sizeof(struct icmphdr)];
}
WAN_CNCTVTY_CHK_PING_PKT,*PWAN_CNCTVTY_CHK_PING_PKT;



/* Function Definfitions*/
void wancnctvty_chk_dml_process_change(BOOL bValue);
void *wancnctvty_chk_ProcessThread( void *arg );
ANSC_STATUS wancnctvty_chk_start_querynow(PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo);
ANSC_STATUS wancnctvty_chk_start_active(PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo);
ANSC_STATUS wancnctvty_chk_start_passive(PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo);
ANSC_STATUS wancnctvty_chk_copy_ctxt_data (PWANCNCTVTY_CHK_GLOBAL_INTF_INFO gIntfInfo,
                                        PCOSA_DML_WANCNCTVTY_CHK_QUERYNOW_CTXT_INFO pQuerynowCtxt);
void *wancnctvty_chk_querynow_thread( void *arg);
int send_query(PCOSA_DML_WANCNCTVTY_CHK_QUERYNOW_CTXT_INFO pQuerynowCtxt, struct mk_query *query_list,
               int no_of_queries,struct pollfd *,BOOL disable_info_log, UCHAR* ipv4_addr, UCHAR* ipv6_addr,
               int poll_cnt);
int process_resp (PCOSA_DML_WANCNCTVTY_CHK_QUERYNOW_CTXT_INFO pQuerynowCtxt, struct mk_query *query_list,
                  int no_of_queries, struct pollfd *pfd, BOOL disable_info_log, BOOL *URL_v4_resolved,
                  BOOL *URL_v6_resolved, UCHAR* ipv4_addr, UCHAR* ipv6_addr, 
                  int ipv4_present, int ipv6_present, int poll_cnt);
int dns_parse(const unsigned char *msg, size_t len);
int send_query_create_raw_skt(struct query *query_info);
unsigned int send_query_frame_raw_pkt(struct query *query_info,struct mk_query *query,
                                                                           unsigned char *packet);
int send_query_create_udp_skt(struct query *query_info);

void *wancnctvty_chk_passive_thread( void *arg );
void *wancnctvty_chk_active_thread( void *arg );
void wanchk_bgtimeout_cb (EV_P_ ev_timer *w, int revents);
void wanchk_pckt_recv_v4(EV_P_ ev_io *ev, int revents);
void wanchk_pckt_recv_v6(EV_P_ ev_io *ev, int revents);
int wancnctvty_chk_create_nfq (u_int16_t family, PWAN_CNCTVTY_CHK_PASSIVE_MONITOR pPassive);
int get_record_type(char *recordtype_string,recordtype_t *output);
int get_server_type(char *servertype_string,servertype_t *output);
ANSC_STATUS wancnctvty_chk_frame_and_send_query(
    PCOSA_DML_WANCNCTVTY_CHK_QUERYNOW_CTXT_INFO pQuerynowCtxt,queryinvoke_type_t invoke_type);
void wanchk_actv_querytimeout_cb (EV_P_ ev_timer *w, int revents);
void actv_mntr_pause_cb (struct ev_loop *loop, ev_stat *w, int revents);

ANSC_STATUS wancnctvty_chk_start_threads(ULONG InstanceNumber,service_type_t type);
ANSC_STATUS wancnctvty_chk_stop_threads(ULONG InstanceNumber,service_type_t type);
ANSC_STATUS wancnctvty_chk_monitor_result_update(ULONG InstanceNumber,monitor_result_t result);
ANSC_STATUS wancnctvty_chk_querynow_result_update(ULONG InstanceNumber,querynow_result_t result);
int get_dns_payload(int family, char *payload,unsigned payload_len,
                                                    char *dns_payload,unsigned int *dns_payload_len);
void *wancnctvty_chk_actvquery_cbthread( void *arg);

#endif
