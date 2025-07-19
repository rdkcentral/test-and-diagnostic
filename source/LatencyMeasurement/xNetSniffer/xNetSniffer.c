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

/*
Based on code from https://www.tcpdump.org/other/sniffex.c which is:
Copyright (c) 2002 Tim Carsten
Copyright (c) 2005 The Tcpdump Group
Licensed under a BSD-3 style license reproduced in LICENSE
*/

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include<time.h>
#include<getopt.h>
#include<stdbool.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>


// C Program for Message Queue (Writer Process)
#include <sys/ipc.h>
#include <sys/msg.h>
#define MAX 1024
  
#define SYN 0x2 //2
#define SYN_ACK 0x12 //18
#define ACK 0x10 //16

#define FALSE 0
#define TRUE 1

// structure for message queue

struct mesg_buffer {
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

} message;
  /*
  struct mesg_buffer {
    long mesg_type;
    char mesg_text[100];
} message;*/
   key_t key;
    int msgid;
int ack_req = TRUE;


enum ip_family
{
    IPV4=0,
    IPV6=1 
};

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

#define IPV6_PROTO_TCP 6
#define ETHER_TYPE_IP6 0x86dd
#define ETHER_TYPE_IP  0x800
/* IPv6 header */
struct sniff_ip6 {
        u_int  ip_ver :4;                 /* version << 4 | header length >> 2 */
        u_int  traffic_class:8;                 /* type of service */
        u_int  flow_label :20;
        u_int  payload_len:16;                 /* payload length */
        u_int  next_header:8;                  /* Next Header */
        u_int  hop_limit : 8;                 /* time to live */
        struct  in6_addr ip6_src,ip6_dst;  /* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


/* Command line options. */
struct option longopts[] =
{
  { "PhysicalInterfaceName",required_argument,       NULL, 'i'},
  { "IPFamily",             required_argument,       NULL, 'f'},
  { "DebugMode",            no_argument,       NULL, 'D'},
  { "FilePath",             required_argument, NULL, 'F'},
  { "LanPrefix",            required_argument, NULL, 'p'},
  { "help",                 no_argument,       NULL, 'h'},
  { 0 }
};

#define MAX_LOG_BUFF_SIZE 2048
FILE *logFp = NULL;
char log_buff[MAX_LOG_BUFF_SIZE] ;
#define VALIDATION_SUCCESS 0
#define VALIDATION_FAILED  -1
#define INTERFACE_NOT_EXIST -1
#define INTERFACE_EXIST 0

typedef struct Params
{
  bool dbg_mode;  
  char interface_name[32];
  char log_file[64];
  char lan_prefix[128];
  char family[8];
}Param;

Param data;
#define dbg_log(fmt ...)    {\
                            if (data.dbg_mode){\
                            snprintf(log_buff, MAX_LOG_BUFF_SIZE-1,fmt);\
                            if(logFp != NULL){ \
                                            fprintf(logFp,"DBG_LOG : %s", log_buff);\
                                            fflush(logFp);}\
                            else \
                                printf("%s",log_buff);\
                            }\
                         }
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);



#if 0
void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    dbg_log("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        dbg_log("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            dbg_log(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        dbg_log(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            dbg_log("   ");
        }
    }
    dbg_log("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
        {
            dbg_log("%c", *ch);
        }
        else
        {
            dbg_log(".");
        }
        ch++;
    }

    dbg_log("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                 /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

return;
}

long long current_timestamp() {
    struct timeval te; 
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // calculate milliseconds
    // printf("milliseconds: %lld\n", milliseconds);
    return milliseconds;
}
#endif

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    static int count = 1;
    static int allowAck =0;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
   // const char *payload;                    /* Packet payload */
    const struct sniff_ip6 *ip6;    

    int size_ip;
    int size_tcp;

    //printf("\nPacket number %d:\n", count);
    count++;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    if(ntohs(ethernet->ether_type) == ETHER_TYPE_IP6)
    {
        //printf("   Ethernet Header type: %x \n", ntohs(ethernet->ether_type));
        ip6 = (struct sniff_ip6*)(packet + SIZE_ETHERNET);
        if( IPV6_PROTO_TCP == ip6->next_header)
        {
                //printf("   *  IPv6 header length: %hu bytes\n", ntohs(ip6->payload_len));
                dbg_log("   *  IPv6 header length: %d bytes\n", ntohs(ip6->payload_len));
                dbg_log("   *  IPv6 next header : %d \n", ip6->next_header);
                dbg_log("   *  IPv6 Hop limit : %d \n", ip6->hop_limit);
                dbg_log("   *  IPv6 version shift : %d \n", ip6->ip_ver);
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + 40);
        }
        else
            return;

        message.ip_type = IPV6;

    }
    else if(ntohs(ethernet->ether_type) == ETHER_TYPE_IP)
    {
                /* define/compute ip header offset */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) 
        {
            dbg_log("   * Invalid IP header length: %u bytes\n", size_ip);
            return;
        }

        /* determine protocol */
        switch(ip->ip_p) 
        {
            case IPPROTO_TCP:
                //printf("   Protocol: TCP\n");
                break;
            case IPPROTO_UDP:
            //  printf("   Protocol: UDP\n");
                return;
            case IPPROTO_ICMP:
                dbg_log("   Protocol: ICMP\n");
                return;
            case IPPROTO_IP:
                dbg_log("   Protocol: IP\n");
                return;
            default:
                dbg_log("   Protocol: unknown\n");
                return;
        }
            /* define/compute tcp header offset */
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) 
        {
            dbg_log("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return;
        }

        message.ip_type = IPV4;
             //printf("       From: %s\n", inet_ntoa(ip->ip_src));
            //printf("         To: %s\n", inet_ntoa(ip->ip_dst));
    }
    else
        return;


    /*
     *  OK, this packet is TCP.
     */

    //if(ip->ip_p == IPPROTO_TCP )
    {
        if ((tcp->th_flags & TH_SYN) != 0)
        {
            if ((tcp->th_flags & TH_ACK) != 0)
            {
                dbg_log("  ----- Packet SYN_ACK FLAG \n");
                message.mesg_type = 1;
                sprintf(message.mac,"%02x:%02x:%02x:%02x:%02x:%02x", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
                allowAck += 5;
                dbg_log("  ----- Packet SYN_ACK FLAG allowAck %d\n", allowAck);

            }
            else
            {
                message.mesg_type = 1;
                dbg_log("  ------  Packet SYN FLAG -----\n");
                sprintf(message.mac,"%02x:%02x:%02x:%02x:%02x:%02x", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
            }

            //exit(0);
        }
        else if (ack_req && (allowAck != 0))
        {
            if (tcp->th_flags == ACK)
            {
            // then bit is set
               dbg_log("   Packet TH_ACK FLAG %d\n",tcp->th_flags);
               message.mesg_type = 1;
               sprintf(message.mac,"%02x:%02x:%02x:%02x:%02x:%02x", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);

                if(allowAck)
                    --allowAck;

                dbg_log("  ----- Packet ACK FLAG allowAck %d\n", allowAck);

            }
            else
                return;
        }
        else
        return;

            dbg_log("\n MAC src: %02x:%02x:%02x:%02x:%02x:%02x", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
            dbg_log("\n MAC drc: %02x:%02x:%02x:%02x:%02x:%02x", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
            dbg_log("   Src port: %d\n", ntohs(tcp->th_sport));
            dbg_log("   Dst port: %d\n", ntohs(tcp->th_dport));
            dbg_log("   Seq     : %d\n", ntohs(tcp->th_seq));
            dbg_log("   ack     : %d\n", ntohs(tcp->th_ack));
            dbg_log("   Seq  ll : %u\n", ntohl(tcp->th_seq));
            dbg_log("   ack  ll : %u\n", ntohl(tcp->th_ack));
            dbg_log("   Packet FLAG : %d\n", tcp->th_flags);


           // then bit is set
            dbg_log("Recieved at ..... %s\n",ctime((const time_t*)&header->ts.tv_sec)); 
            //printf("microseconds: %lld\n", 1000000 * header->ts.tv_sec + header->ts.tv_usec);
            dbg_log("microseconds: %ld\n",header->ts.tv_usec);
            dbg_log("Seconds     : %ld\n", header->ts.tv_sec);
            dbg_log("       MAC: %s\n", message.mac);
            //printf("milliseconds: %lld\n", current_timestamp());

        

            message.th_flag = tcp->th_flags;
            message.th_seq = ntohl(tcp->th_seq);
            message.th_ack = ntohl(tcp->th_ack);

            message.tv_sec = header->ts.tv_sec;
            message.tv_usec = header->ts.tv_usec;
            message.th_dport = ntohs(tcp->th_dport);

            dbg_log(" -------------- Ready to send ------------------ \n");
            dbg_log("Data Received is : %d \nFLAG: %d \nACK: %u\nSeq %u\n Port %d\n TS: %lld.%06lld\n", 
                        message.mesg_type,message.th_flag,message.th_ack,message.th_seq,message.th_dport,message.tv_sec,message.tv_usec);
            // msgsnd to send message
            int length = sizeof(struct mesg_buffer) - sizeof(long);
            msgsnd(msgid, &message, length, 0);
      
            // display the message
            dbg_log("Data send is : %d \n", message.mesg_type );
            dbg_log(" -------------- END ------------------ \n");
       
    }
    return;
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
              "-i,   Physical interface name\n"\
              "-f,   IP Family\n"\
              "-D,   Debug Mode\n"\
              "-F,   Log File\n"\
              "-p,   Lan prefix\n"\
              "-h,   Display this help and exit\n"\
              "\n",progname
              );
    }

  exit (status);
}
// Function to check if interface is created
int checkIfExists(char* iface_name)
{
    struct ifreq ifr;
    int fd;
    if (strlen(iface_name) >= sizeof(ifr.ifr_name)) {
        printf("%s interface name too long \n",iface_name);
        return INTERFACE_NOT_EXIST;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return INTERFACE_NOT_EXIST;
    strncpy(ifr.ifr_name, iface_name, sizeof(ifr.ifr_name)-1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        if (errno == ENODEV) {
            printf("%s Interface doesn't exists \n",iface_name);
            close(fd);
            return INTERFACE_NOT_EXIST;
        }
    }
    close(fd);
    return INTERFACE_EXIST;
}

int validateParams()
{
    if ( strlen(data.interface_name) == 0 || INTERFACE_NOT_EXIST == checkIfExists(data.interface_name))
    {
        printf("Interface validation failed\n");
        return VALIDATION_FAILED;
    }
        if ( strlen(data.lan_prefix) == 0 )
    {
        printf("Lan Prefix validation failed\n");
        return VALIDATION_FAILED;
    }

    if ( (strcmp(data.family,"IPv4") != 0) && (strcmp(data.family,"IPv6") != 0 ) )
    {
        printf("Ip family validation failed\n");
        return VALIDATION_FAILED;
    }

    return VALIDATION_SUCCESS;
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle;             /* packet capture handle */
    char filter_exp[256]; 
    //char filter_exp[] = ""; 
    //char filter_exp[] = "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0";       /* filter expression [2] and [18] */
    struct bpf_program fp;          /* compiled filter program (expression) */
    bpf_u_int32 mask;           /* subnet mask */
    bpf_u_int32 net;            /* ip */
    int num_packets = 0;            /* number of packets to capture */

   // print_app_banner();

  char *progname;
  char *p;

  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  if(argc == 1 )
    usage (progname, 1);
  int opt;
  memset(&data,0,sizeof(Param));

    while (1)
    {
      opt = getopt_long (argc, argv, "Dhi:f:F:p:", longopts, 0);

      if (opt == EOF)
      {
            break;
      }
      switch (opt)
      {
            case 'i':
              strncpy(data.interface_name,optarg,sizeof(data.interface_name)-1);
              break;
            case 'D':
              data.dbg_mode = TRUE;
              break;
            case 'f':
              //data.family = optarg;
              strncpy(data.family,optarg,sizeof(data.family)-1);
              break;
            case 'F':
             // data.log_file = optarg;
              strncpy(data.log_file,optarg,sizeof(data.log_file)-1);
              logFp = fopen(data.log_file,"w+");
              break;
            case 'p':
             // data.log_file = optarg;
              strncpy(data.lan_prefix,optarg,sizeof(data.lan_prefix)-1);
              break;
            case 'h':
              usage (progname, 0);
              break;
            default:
              usage (progname, 1);
              break;  
        }
    }
    printf("data.dbg_mode is %d\n",data.dbg_mode);
    if ( VALIDATION_SUCCESS == validateParams() )
    {
        dbg_log("Arg validation success\n");
    }
    else
    {
        dbg_log("Validation failed, exiting\n");
        exit(1);

    }
    memset(filter_exp,0,sizeof(filter_exp));
    if(strcmp(data.family,"IPv4") == 0)
    {
        if (strlen(data.lan_prefix) != 0 )
            snprintf(filter_exp,sizeof(filter_exp),"tcp[tcpflags] & (tcp-syn|tcp-ack) != 0 and net %s",data.lan_prefix);
        else
            snprintf(filter_exp,sizeof(filter_exp),"tcp[tcpflags] & (tcp-syn|tcp-ack) != 0");
    }
    else if(strcmp(data.family,"IPv6") == 0)
    {
        if (strlen(data.lan_prefix) != 0 )
            snprintf(filter_exp,sizeof(filter_exp),"(ip6[6] = 6) and (ip6[53] & 0x12 != 0) and net %s",data.lan_prefix);
        else
            snprintf(filter_exp,sizeof(filter_exp),"(ip6[6] = 6) and (ip6[53] & 0x12 != 0)");
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(data.interface_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            data.interface_name, errbuf);

        dbg_log("Couldn't get netmask for device %s: %s\n",
            data.interface_name, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    dbg_log("Filter expression: %s\n", filter_exp);

    /* open capture device */
    handle = pcap_open_live(data.interface_name, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", data.interface_name, errbuf);
                dbg_log("Couldn't open device %s: %s\n", data.interface_name, errbuf);

        exit(EXIT_FAILURE);
    }
     //printf("Timestamp type = %d\n",pcap_set_tstamp_type(handle, PCAP_TSTAMP_ADAPTER));

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", data.interface_name);
                dbg_log("%s is not an Ethernet\n", data.interface_name);

        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));

        dbg_log("Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));

        dbg_log("Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // ftok to generate unique key
    key = ftok("progfile", 65);
  
    // msgget creates a message queue
    // and returns identifier
    msgid = msgget(key, 0666 | IPC_CREAT);

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    if (logFp != NULL)
    {
        fclose(logFp);
        logFp=NULL;
    }
    dbg_log("\nCapture complete.\n");
    return 0;
}
