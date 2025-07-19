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

    module:    bbhm_diagit_properties.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This file defines the configuration parameters that can be
        applied to the Tracertection Speed Tool.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Du Li, Li Shi

    ---------------------------------------------------------------

    revision:

        08/06/09    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGIT_PROPERTY_
#define  _BBHM_DIAGIT_PROPERTY_


/*
 * We have to use some of the constant values defined in the TCP/UDP packet format definitions, so we
 * include the header file here.
 */
#include  "ansc_packet_binary.h"


/***********************************************************
      PPPOE SESSION CONFIGURATION PARAMETERS DEFINITION
***********************************************************/

#define  tempId                                    5
/*
 * We allow the wrapper object to configure pretty much every aspect of the Tracertection Speed Tool
 */
#define  BBHM_TRACERT_INET_ADDRESS_TYPE_UNKNOWN         0
#define  BBHM_TRACERT_INET_ADDRESS_TYPE_IPV4            1
#define  BBHM_TRACERT_INET_ADDRESS_TYPE_IPV6            2
#define  BBHM_TRACERT_INET_ADDRESS_TYPE_DNS             16

#define  BBHM_TRACERT_DEF_INET_ADDRESS_TYPE             BBHM_TRACERT_INET_ADDRESS_TYPE_IPV4

#define  BBHM_TRACERT_PROTOCOL_UDP                      1
#define  BBHM_TRACERT_PROTOCOL_TCP                      2
#define  BBHM_TRACERT_PROTOCOL_ICMP                     3

#define  BBHM_TRACERT_DEF_PROTOCOL                      BBHM_TRACERT_PROTOCOL_ICMP
#define  BBHM_TRACERT_DEF_SRC_IP                        0xC0A80001

#define  BBHM_TRACERT_MAX_NUMBER_PACKETS                3
#define  BBHM_TRACERT_MIN_NUMBER_PACKETS                1

#define  BBHM_TRACERT_DEF_NUMBER_PACKETS                1

#define  BBHM_TRACERT_MAX_PACKET_SIZE                   65535
#define  BBHM_TRACERT_MIN_PACKET_SIZE                   1

#define  BBHM_TRACERT_DEF_PACKET_SIZE                   32

#define  BBHM_TRACERT_MAX_TIME_BETWEEN_IN_MILLISECONDS  600000        /* in milliseconds */
#define  BBHM_TRACERT_MIN_TIME_BETWEEN_IN_MILLISECONDS  0

#define  BBHM_TRACERT_DEF_TIME_BETWEEN_IN_MILLISECONDS  1000

#define  BBHM_TRACERT_MAX_TIME_OUT_IN_MILLISECONDS      600000        /* in milliseconds */
#define  BBHM_TRACERT_MIN_TIME_OUT_IN_MILLISECONDS      0

#define  BBHM_TRACERT_DEF_TIME_OUT_IN_MILLISECONDS      1000

#define  BBHM_TRACERT_CONTROL_START                     1
#define  BBHM_TRACERT_CONTROL_ABORT                     2

#define  BBHM_TRACERT_DEF_CONTROL                       BBHM_TRACERT_CONTROL_ABORT

#define  BBHM_TRACERT_STATUS_NOTRUN                     1
#define  BBHM_TRACERT_STATUS_RUNNING                    2
#define  BBHM_TRACERT_STATUS_COMPLETE                   3
#define  BBHM_TRACERT_STATUS_ABORT                      4
#define  BBHM_TRACERT_STATUS_TIMEOUT                    5

#define  BBHM_TRACERT_DEF_STATUS                        BBHM_TRACERT_STATUS_NOTRUN

#define  BBHM_TRACERT_MAX_PACKETS_SENT                  4
#define  BBHM_TRACERT_MIN_PACKETS_SENT                  0

#define  BBHM_TRACERT_MAX_PACKETS_RECV                  4
#define  BBHM_TRACERT_MIN_PACKETS_RECV                  0

#define  BBHM_TRACERT_RTT_MAX_IN_MILLISECONDS           600000
#define  BBHM_TRACERT_RTT_MIN_IN_MILLISECONDS           0

#define  BBHM_TRACERT_MAX_NUM_ICMP_ERROR                4
#define  BBHM_TRACERT_MIN_NUM_ICMP_ERROR                0

#define  BBHM_TRACERT_MAX_ICMP_ERROR                    255
#define  BBHM_TRACERT_MIN_ICMP_ERROR                    0

#define  BBHM_TRACERT_DEF_RETRY_INTERVAL                BBHM_TRACERT_DEF_TIME_BETWEEN_IN_MILLISECONDS        /* in milliseconds */
#define  BBHM_TRACERT_DEF_RETRY_TIMES                   0          /* retransmissions */
#define  BBHM_TRACERT_DEF_IDLE_TIMEOUT                  600        /* in seconds      */

#define  BBHM_TRACERT_ROUTE_HOPS_UPDATED                1
#define  BBHM_TRACERT_ROUTE_HOPS_NOT_UPDATED            0

typedef  struct
_BBHM_TRACERT_PROPERTY
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
    ULONG                                Ttl;
    BOOL                                 LastHopReached;
}
BBHM_TRACERT_PROPERTY,  *PBBHM_TRACERT_PROPERTY;


#endif

