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


/**********************************************************************

    module:    bbhm_diagip_property.h

        For Ping Tool (PING),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This file defines the configuration parameters that can be
        applied to the Pingection Speed Tool.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Li Shi

    ---------------------------------------------------------------

    revision:

        08/08/09    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGIP_PROPERTY_
#define  _BBHM_DIAGIP_PROPERTY_


/*
 * We have to use some of the constant values defined in the TCP/UDP packet format definitions, so we
 * include the header file here.
 */
#include  "ansc_packet_binary.h"


/***********************************************************
      PPPOE SESSION CONFIGURATION PARAMETERS DEFINITION
***********************************************************/

#define  tempId                                         5
/*
 * We allow the wrapper object to configure pretty much every aspect of the Pingection Speed Tool
 */
#define  BBHM_IP_PING_INET_ADDRESS_TYPE_UNKNOWN         0
#define  BBHM_IP_PING_INET_ADDRESS_TYPE_IPV4            1
#define  BBHM_IP_PING_INET_ADDRESS_TYPE_IPV6            2
#define  BBHM_IP_PING_INET_ADDRESS_TYPE_DNS             16

#define  BBHM_IP_PING_DEF_INET_ADDRESS_TYPE             BBHM_IP_PING_INET_ADDRESS_TYPE_IPV4

#define  BBHM_IP_PING_PROTOCOL_UDP                      1
#define  BBHM_IP_PING_PROTOCOL_TCP                      2

#define  BBHM_IP_PING_DEF_PROTOCOL                      BBHM_IP_PING_PROTOCOL_UDP
#define  BBHM_IP_PING_DEF_SRC_IP                        0xC0A80001

#define  BBHM_IP_PING_MAX_NUMBER_PACKETS                100
#define  BBHM_IP_PING_MIN_NUMBER_PACKETS                1

#define  BBHM_IP_PING_DEF_NUMBER_PACKETS                1

#define  BBHM_IP_PING_MAX_PACKET_SIZE                   1518
#define  BBHM_IP_PING_MIN_PACKET_SIZE                   64

#define  BBHM_IP_PING_DEF_PACKET_SIZE                   64

#define  BBHM_IP_PING_MAX_TIME_BETWEEN_IN_MILLISECONDS  600000        /* in milliseconds */
#define  BBHM_IP_PING_MIN_TIME_BETWEEN_IN_MILLISECONDS  0

#define  BBHM_IP_PING_DEF_TIME_BETWEEN_IN_MILLISECONDS  1000

#define  BBHM_IP_PING_MAX_TIME_OUT_IN_MILLISECONDS       600000        /* in milliseconds */
#define  BBHM_IP_PING_MIN_TIME_OUT_IN_MILLISECONDS       0

#define  BBHM_IP_PING_DEF_TIME_OUT_IN_MILLISECONDS       1000

#define  BBHM_IP_PING_CONTROL_START                      1
#define  BBHM_IP_PING_CONTROL_ABORT                      2
#define  BBHM_IP_PING_CONTROL_STOP                       3

#define  BBHM_IP_PING_DEF_CONTROL                        BBHM_IP_PING_CONTROL_ABORT

#define  BBHM_IP_PING_STATUS_NOTRUN                      1
#define  BBHM_IP_PING_STATUS_RUNNING                     2
#define  BBHM_IP_PING_STATUS_COMPLETE                    3
#define  BBHM_IP_PING_STATUS_ABORT                       4
#define  BBHM_IP_PING_STATUS_TIMEOUT                     5
#define  BBHM_IP_PING_STATUS_STOP                        6
#define  BBHM_IP_PING_STATUS_ERROR_HostName              7

#define  BBHM_IP_PING_DEF_STATUS                         BBHM_IP_PING_STATUS_NOTRUN

#define  BBHM_IP_PING_MAX_PACKETS_SENT                   4
#define  BBHM_IP_PING_MIN_PACKETS_SENT                   0

#define  BBHM_IP_PING_MAX_PACKETS_RECV                   4
#define  BBHM_IP_PING_MIN_PACKETS_RECV                   0

#define  BBHM_IP_PING_RTT_MAX_IN_MILLISECONDS            600000
#define  BBHM_IP_PING_RTT_MIN_IN_MILLISECONDS            0

#define  BBHM_IP_PING_MAX_NUM_ICMP_ERROR                 4
#define  BBHM_IP_PING_MIN_NUM_ICMP_ERROR                 0

#define  BBHM_IP_PING_MAX_ICMP_ERROR                     255
#define  BBHM_IP_PING_MIN_ICMP_ERROR                     0

#define  BBHM_IP_PING_DEF_RETRY_INTERVAL                 BBHM_IP_PING_DEF_TIME_BETWEEN_IN_MILLISECONDS        /* in milliseconds */
#define  BBHM_IP_PING_DEF_RETRY_TIMES                    0          /* retransmissions */
#define  BBHM_IP_PING_DEF_IDLE_TIMEOUT                   600         /* in seconds      */

typedef  struct
_BBHM_IP_PING_PROPERTY
{
    ULONG                                SrcIpType;
    ANSC_IPV4_ADDRESS                    SrcIp;
    char*                                pSrcAddrName;
    ULONG                                DstIpType;
    ANSC_IPV4_ADDRESS                    DstIp;
    char*                                pDstAddrName;
    ULONG                                NumPkts;
    ULONG                                PktSize;
    ULONG                                TimeBetween;
    ULONG                                TimeOut;
    ULONG                                Control;
    ULONG                                Status;
    ULONG                                PktsSent;
    ULONG                                PktsRecv;
    ULONG                                BytesSent;
    ULONG                                BytesRecv;
    ULONG                                AvgRTT;
    ULONG                                MaxRTT;
    ULONG                                MinRTT;
    ULONG                                NumIcmpError;
    ULONG                                IcmpError;
    ULONG                                NumCalculate;
    ULONG                                SumRTT;
}
BBHM_IP_PING_PROPERTY,  *PBBHM_IP_PING_PROPERTY;


#endif

