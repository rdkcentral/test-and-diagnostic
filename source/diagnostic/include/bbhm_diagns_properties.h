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

    module: bbhm_diagns_property.h

        For NSLookup Tool,
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This file defines the configuration parameters that can be
        applied to the NSLookup Tool.

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


#ifndef  _BBHM_NS_LOOKUP_PROPERTY_
#define  _BBHM_NS_LOOKUP_PROPERTY_


/*
 * We have to use some of the constant values defined in the TCP/UDP packet format definitions, so we
 * include the header file here.
 */
#include  "ansc_packet_binary.h"


/***********************************************************
      PPPOE SESSION CONFIGURATION PARAMETERS DEFINITION
***********************************************************/

/*
 * We allow the wrapper object to configure pretty much every aspect of the NSLookup Tool
 */

#define  BBHM_NS_LOOKUP_MAX_NUMBER_PACKETS                  100
#define  BBHM_NS_LOOKUP_MIN_NUMBER_PACKETS                  1

#define  BBHM_NS_LOOKUP_DEF_NUMBER_PACKETS                  1

#define  BBHM_NS_LOOKUP_DEF_PACKET_SIZE                     1000
#define  BBHM_NS_LOOKUP_MAX_PACKET_SIZE                     2000

#define  BBHM_NS_LOOKUP_MAX_TIME_BETWEEN_IN_MILLISECONDS    600000      /* in milliseconds */
#define  BBHM_NS_LOOKUP_MIN_TIME_BETWEEN_IN_MILLISECONDS    0

#define  BBHM_NS_LOOKUP_DEF_TIME_BETWEEN_IN_MILLISECONDS    1000

#define  BBHM_NS_LOOKUP_MAX_TIME_OUT_IN_MILLISECONDS        600000      /* in milliseconds */
#define  BBHM_NS_LOOKUP_MIN_TIME_OUT_IN_MILLISECONDS        0

#define  BBHM_NS_LOOKUP_DEF_TIME_OUT_IN_MILLISECONDS        1000

#define  BBHM_NS_LOOKUP_CONTROL_START                       1
#define  BBHM_NS_LOOKUP_CONTROL_ABORT                       2
#define  BBHM_NS_LOOKUP_CONTROL_STOP                        3

#define  BBHM_NS_LOOKUP_DEF_CONTROL                         BBHM_NS_LOOKUP_CONTROL_ABORT

#define  BBHM_NS_LOOKUP_STATUS_NOTRUN                       1
#define  BBHM_NS_LOOKUP_STATUS_RUNNING                      2
#define  BBHM_NS_LOOKUP_STATUS_COMPLETE                     3
#define  BBHM_NS_LOOKUP_STATUS_ABORT                        4
#define  BBHM_NS_LOOKUP_STATUS_TIMEOUT                      5
#define  BBHM_NS_LOOKUP_STATUS_STOP                         6
#define  BBHM_NS_LOOKUP_STATUS_DNS                          7
#define  BBHM_NS_LOOKUP_STATUS_INTERNAL                     8
#define  BBHM_NS_LOOKUP_STATUS_OTHER                        9

#define  BBHM_NS_LOOKUP_DEF_STATUS                          BBHM_NS_LOOKUP_STATUS_NOTRUN

#define  BBHM_NS_LOOKUP_MAX_PACKETS_SENT                    4
#define  BBHM_NS_LOOKUP_MIN_PACKETS_SENT                    0

#define  BBHM_NS_LOOKUP_MAX_PACKETS_RECV                    4
#define  BBHM_NS_LOOKUP_MIN_PACKETS_RECV                    0

#define  BBHM_NS_LOOKUP_MAX_ICMP_ERROR                      255
#define  BBHM_NS_LOOKUP_MIN_ICMP_ERROR                      0

#define  BBHM_NS_LOOKUP_DEF_RETRY_INTERVAL                  BBHM_NS_LOOKUP_DEF_TIME_BETWEEN_IN_MILLISECONDS        /* in milliseconds */
#define  BBHM_NS_LOOKUP_DEF_RETRY_TIMES                     0          /* retransmissions */
#define  BBHM_NS_LOOKUP_DEF_IDLE_TIMEOUT                    600         /* in seconds      */

#define  BBHM_NS_LOOKUP_STATUS_Success                          0
#define  BBHM_NS_LOOKUP_STATUS_Error_DNSServerNotAvailable      1
#define  BBHM_NS_LOOKUP_STATUS_Error_HostNameNotResolved        2
#define  BBHM_NS_LOOKUP_STATUS_Error_Timeout                    3
#define  BBHM_NS_LOOKUP_STATUS_Error_Other                      4

#define  BBHM_NS_LOOKUP_RESULT_None                             0
#define  BBHM_NS_LOOKUP_RESULT_Authoritative                    1
#define  BBHM_NS_LOOKUP_RESULT_NonAuthoritative                 2

#define DSLH_DIAG_STATE_TYPE_Error_NSLookup_DNSServer           3
#define DSLH_DIAG_STATE_TYPE_Error_NSLookup_Internal            4
#define DSLH_DIAG_STATE_TYPE_Error_NSLookup_Other               5

#define NS_LOOKUP_MAX_ADDRNAME_LEN                              257


typedef  struct
_BBHM_NS_LOOKUP_PROPERTY
{
  /*ANSC_IPV4_ADDRESS                   SrcIp;
    ANSC_IPV4_ADDRESS                   DstIp;*/
    char                                SrcAddrName[NS_LOOKUP_MAX_ADDRNAME_LEN];
    char                                DstAddrName[NS_LOOKUP_MAX_ADDRNAME_LEN];
    ULONG                               TimeBetween;
    ULONG                               TimeOut;
    ULONG                               Control;
    ULONG                               Status;
    ULONG                               PktsSent;
    ULONG                               PktsRecv;
    ULONG                               NumPkts;
    ULONG                               PktSize;
    ULONG                               NumDnsSuccess;
}
BBHM_NS_LOOKUP_PROPERTY,  *PBBHM_NS_LOOKUP_PROPERTY;


#endif

