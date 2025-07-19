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

    module:    bbhm_diagit_interface.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines all the platform-independent
        functions and macros for the Bbhm IpPing Diagnostic Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Du Li, Li Shi

    ---------------------------------------------------------------

    revision:

        07/30/09    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGIT_INTERFACE_
#define  _BBHM_DIAGIT_INTERFACE_


/*
 * This object is derived a virtual base object defined by the underlying framework. We include the
 * interface header files of the base object here to shield other objects from knowing the derived
 * relationship between this object and its base class.
 */
#include "ansc_co_interface.h"
#include "ansc_co_external_api.h"
#include "bbhm_diageo_interface.h"
#include "bbhm_diagit_properties.h"
/*#include "bbhm_properties.h"*/
#include "bbhm_diageo_interface.h"

#define  BBHM_TRACERT_TDO_NAME                            "TracerouteTimerDescriptor"

#define  BBHM_TRACERT_TDO_OID                             BBHM_DIAG_IP_TRACEROUTE_OID + 0x0001
#define  BBHM_TRACERT_ICMP_TIMEOUT                        0xFFFFFFFF

#define  MAX_ECHO_TABLE_SIZE                              10

#define  BBHM_TRACERT_SINK_MAX_MESSAGE_SIZE              2048

#define  BBHM_TRACERT_IP4_TRANSPORT                      0

/***********************************************************
          BBHM LAN LINK COMPONENT OBJECT DEFINITION
***********************************************************/

/*
 * Define some const values that will be used in the object mapper object definition.
 */

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support),
 * we have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ANSC_HANDLE
(*PFN_BBHMDIAGIT_GET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_SET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hContext
    );

typedef  ANSC_HANDLE
(*PFN_BBHMDIAGIT_GET_IF)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_SET_IF)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hInterface
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_SET_DIAG)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hContext
    );

typedef  ANSC_HANDLE
(*PFN_BBHMDIAGIT_GET_DIAG)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ULONG
(*PFN_BBHMDIAGIT_GET_TYPE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_SET_TYPE)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulType
    );

typedef  PUCHAR
(*PFN_BBHMDIAGIT_GET_ADDR)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_SET_ADDR)
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      address
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_RESET)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_HALF_OPEN)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_OPEN)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_RETRIEVE)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_CONFIGURE)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_CLOSE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_EXPIRE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_ACCEPT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                    hNewSocket
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_RECV)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                    hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_SEND)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                    hSinkObject,
        PVOID                        buffer,
        ULONG                        ulSize
    );

typedef  ULONG
(*PFN_BBHMDIAGIT_GET_ULONG)
    (
        ANSC_HANDLE                    hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_SET_ULONG)
    (
        ANSC_HANDLE                    hThisObject,
        ULONG                        ulValue
    );

typedef  BOOL
(*PFN_BBHMDIAGIT_GET_BOOL)
    (
        ANSC_HANDLE                    hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_SET_BOOL)
    (
        ANSC_HANDLE                    hThisObject,
        BOOL                        ulValue
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_TEST)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_SET_STOP_TIME)
    (
        ANSC_HANDLE                    hThisObject,
        USHORT                        SeqNumber,
        ULONG                        StopTime
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_ADD_ENTRY)
    (
        ANSC_HANDLE                    hThisObject,
        USHORT                        SeqNumber,
        ULONG                        StartTime,
        ULONG                       TimeToLive
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_CALCULATE_RESULT)
    (
        ANSC_HANDLE                    hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_NOTIFY)
    (
        ANSC_HANDLE                    hThisObject,
        ULONG                        eventType,
        ANSC_HANDLE                    hReserved
    );

typedef  ULONG
(*PFN_BBHMDIAGIT_RESOLVE)
    (
        ANSC_HANDLE                    hThisObject,
        ANSC_HANDLE                    hHostName
    );

typedef  PUCHAR
(*PFN_BBHMDIAGIT_RRESOLVE)
    (
        ANSC_HANDLE                    hThisObject,
        ULONG                         IpAddr
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIT_UPDATE_ENTRY)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       seqId,
        xskt_addrinfo*              pHopAddrInfo,
        ULONG                       StopTime,
        ULONG                       ErrorCode
    );

typedef  char*
(*PFN_BBHMDIAGIT_GET_STRING)
    (
        ANSC_HANDLE                 hThisObject
    );

/*
 *  All diagnostic object specified in DSLH shares some common behaviors: set test parameters,
 *  fire the diagnostic request and a "8 DIAGNOSTICS COMPLETE" is sent out after the test is
 *  done.
 *
 *  These common beahaviors are incorporated into this base object, which the child objects,
 *  like IpPingDiag, WanDslDiag, WanAtmF5Loopback will inherit on.
 */
#define  BBHM_DIAG_IP_TRACEROUTE_CLASS_CONTENT                                        \
    /* duplication of the base object class content */                                \
    BBHM_DIAG_EXEC_CLASS_CONTENT                                                      \
    /* start of object class content */                                               \
    BBHM_TRACERT_PROPERTY                   Property;                                 \
    ULONG                                   IPProtocol;                               \
                                                                                      \
    ANSC_HANDLE                             hStateTimer;                              \
                                                                                      \
    char *                                  hSendBuffer;                              \
                                                                                      \
    ANSC_HANDLE                             hTracertCspIf;                            \
    ANSC_HANDLE                             hTracertCarIf;                            \
                                                                                      \
    ANSC_HANDLE                             hSinkObject;                              \
    ANSC_HANDLE                             hDiagInfo;                                \
    SLIST_HEADER                            EchoTable[MAX_ECHO_TABLE_SIZE];           \
    ANSC_LOCK                               EchoTableLock;                            \
                                                                                      \
    PFN_BBHMDIAGIT_RESET                    ResetProperty;                            \
    PFN_BBHMDIAGIT_RESET                    ResetPropertyCounter;                     \
                                                                                      \
    PFN_BBHMDIAGIT_SET_STOP_TIME            SetStopTime;                              \
    PFN_BBHMDIAGIT_ADD_ENTRY                AddEchoEntry;                             \
                                                                                      \
    PFN_BBHMDIAGIT_CALCULATE_RESULT         CalculateResult;                          \
                                                                                      \
    PFN_BBHMDIAGIT_OPEN                     Start;                                    \
    PFN_BBHMDIAGIT_OPEN                     SendEcho;                                 \
    PFN_BBHMDIAGIT_OPEN                     Stop;                                     \
    PFN_BBHMDIAGIT_OPEN                     Open;                                     \
    PFN_BBHMDIAGIT_OPEN                     Close;                                    \
    PFN_BBHMDIAGIT_RETRIEVE                 GetProperty;                              \
    PFN_BBHMDIAGIT_CONFIGURE                SetProperty;                              \
    PFN_BBHMDIAGIT_EXPIRE                   Expire1;                                  \
    PFN_BBHMDIAGIT_EXPIRE                   Expire2;                                  \
                                                                                      \
    PFN_BBHMDIAGIT_ACCEPT                   Accept;                                   \
    PFN_BBHMDIAGIT_RECV                     Recv;                                     \
    PFN_BBHMDIAGIT_SEND                     Send;                                     \
                                                                                      \
    PFN_BBHMDIAGIT_RESOLVE                  ResolveHost;                              \
    PFN_BBHMDIAGIT_RRESOLVE                 ResolveHostName;                          \
    PFN_BBHMDIAGIT_UPDATE_ENTRY             UpdateEntry;                              \
    PFN_BBHMDIAGIT_GET_ULONG                GetSrcIpType;                             \
    PFN_BBHMDIAGIT_SET_ULONG                SetSrcIpType;                             \
    PFN_BBHMDIAGIT_GET_ADDR                 GetSrcIp;                                 \
    PFN_BBHMDIAGIT_SET_ADDR                 SetSrcIp;                                 \
    PFN_BBHMDIAGIT_GET_ULONG                GetDstIpType;                             \
    PFN_BBHMDIAGIT_SET_ULONG                SetDstIpType;                             \
    PFN_BBHMDIAGIT_GET_ADDR                 GetDstIp;                                 \
    PFN_BBHMDIAGIT_SET_ADDR                 SetDstIp;                                 \
    PFN_BBHMDIAGIT_GET_ULONG                GetNumPkts;                               \
    PFN_BBHMDIAGIT_SET_ULONG                SetNumPkts;                               \
    PFN_BBHMDIAGIT_GET_ULONG                GetPktSize;                               \
    PFN_BBHMDIAGIT_SET_ULONG                SetPktSize;                               \
    PFN_BBHMDIAGIT_GET_ULONG                GetTimeBetween;                           \
    PFN_BBHMDIAGIT_SET_ULONG                SetTimeBetween;                           \
    PFN_BBHMDIAGIT_GET_ULONG                GetTimeOut;                               \
    PFN_BBHMDIAGIT_SET_ULONG                SetTimeOut;                               \
    PFN_BBHMDIAGIT_GET_ULONG                GetControl;                               \
    PFN_BBHMDIAGIT_SET_ULONG                SetControl;                               \
    PFN_BBHMDIAGIT_GET_ULONG                GetStatus;                                \
    PFN_BBHMDIAGIT_SET_ULONG                SetStatus;                                \
    PFN_BBHMDIAGIT_GET_ULONG                GetPktsSent;                              \
    PFN_BBHMDIAGIT_SET_ULONG                SetPktsSent;                              \
    PFN_BBHMDIAGIT_GET_ULONG                GetPktsRecv;                              \
    PFN_BBHMDIAGIT_SET_ULONG                SetPktsRecv;                              \
    PFN_BBHMDIAGIT_GET_ULONG                GetAvgRTT;                                \
    PFN_BBHMDIAGIT_SET_ULONG                SetAvgRTT;                                \
    PFN_BBHMDIAGIT_GET_ULONG                GetMaxRTT;                                \
    PFN_BBHMDIAGIT_SET_ULONG                SetMaxRTT;                                \
    PFN_BBHMDIAGIT_GET_ULONG                GetMinRTT;                                \
    PFN_BBHMDIAGIT_SET_ULONG                SetMinRTT;                                \
    PFN_BBHMDIAGIT_GET_ULONG                GetNumIcmpError;                          \
    PFN_BBHMDIAGIT_SET_ULONG                SetNumIcmpError;                          \
    PFN_BBHMDIAGIT_GET_ULONG                GetIcmpError;                             \
    PFN_BBHMDIAGIT_SET_ULONG                SetIcmpError;                             \
    PFN_BBHMDIAGIT_GET_ULONG                GetTtl;                                   \
    PFN_BBHMDIAGIT_SET_ULONG                SetTtl;                                   \
    PFN_BBHMDIAGIT_GET_DIAG                 GetDiagInfo;                              \
    PFN_BBHMDIAGIT_SET_DIAG                 SetDiagInfo;                              \
    PFN_BBHMDIAGIT_GET_BOOL                 GetStateUpdated;                          \
    PFN_BBHMDIAGIT_SET_BOOL                 SetStateUpdated;                          \
    PFN_BBHMDIAGIT_GET_ULONG                GetDstIpVal;                              \
    PFN_BBHMDIAGIT_SET_ULONG                SetDstIpVal;                              \
    PFN_BBHMDIAGIT_GET_STRING               GetDstAddrName;                           \
                                                                                      \
    /* virtual functions start point */                                               \
    /* virtual functions end point */                                                 \
                                                                                      \
    /* end of object class content */                                                 \

typedef  struct
_BBHM_DIAG_IP_TRACEROUTE_OBJECT
{
    BBHM_DIAG_IP_TRACEROUTE_CLASS_CONTENT
}
BBHM_DIAG_IP_TRACEROUTE_OBJECT,  *PBBHM_DIAG_IP_TRACEROUTE_OBJECT;

#define  ACCESS_BBHM_DIAG_IP_TRACEROUTE_OBJECT(p)         ACCESS_CONTAINER(p, BBHM_DIAG_IP_TRACEROUTE_OBJECT, Linkage)

/***********************************************************
               POEMC TIMER SMO OBJECT DEFINITION
***********************************************************/

/*
 * Define some const values that will be used in the os wrapper object definition.
 */

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support), we
 * have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ULONG
(*PFN_TRACERTTDO_GET_ULONG)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_TRACERTTDO_SET_ULONG)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulValue
    );

/*
 * Many extension or feature objects need to perform some background cleaning and maintenance work
 * in the Pptm environment. This type of work can be implemented via separate low-priority tasks
 * or periodic timer-based callback functions, depending on the support of the underlying real-time
 * operating system. From our previous experience, timer callback implementation has more os-
 * support than background task based approach.
 */
#define  BBHM_TRACERT_TDO_CLASS_CONTENT                                                     \
    /* duplication of the base object class content */                                      \
    ANSC_TIMER_DESCRIPTOR_CLASS_CONTENT                                                     \
                                                                                            \
    ULONG                                    Counter;                                       \
    ULONG                                    StopTime;                                      \
    PFN_TRACERTTDO_GET_ULONG                 GetCounter;                                    \
    PFN_TRACERTTDO_SET_ULONG                 SetCounter;                                    \
    PFN_TRACERTTDO_GET_ULONG                 GetStopTime;                                   \
    PFN_TRACERTTDO_SET_ULONG                 SetStopTime;                                   \
                                                                                            \
    /* end of object class content */                                                       \

typedef  struct
_BBHM_TRACERT_TDO_OBJECT
{
    BBHM_TRACERT_TDO_CLASS_CONTENT
}
BBHM_TRACERT_TDO_OBJECT,  *PBBHM_TRACERT_TDO_OBJECT;

#define  ACCESS_BBHM_TRACERT_TDO_OBJECT(p)                                              \
         ACCESS_CONTAINER(p, BBHM_TRACERT_TDO_OBJECT, Linkage)


#define  BBHM_TRACERT_SINK_MAX_MESSAGE_SIZE              2048

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support),
 * we have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ANSC_HANDLE
(*PFN_TRACERTSINK_GET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_TRACERTSINK_SET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hController
    );

typedef  ANSC_STATUS
(*PFN_TRACERTSINK_RESET)
    (
        ANSC_HANDLE                 hThisObject
    );

/*
 * DHCP uses UDP as its transport protocol. DHCP messages from a client to a server are sent to
 * the 'DHCP server' port (67), and DHCP messages from a server to a client are sent to the 'DHCP
 * client' port (68). A server with multiple network address (e.g., a multi-homed host) MAY use
 * any of its network addresses in outgoing DHCP messages.
 */
#define  BBHM_TRACERT_SINK_CLASS_CONTENT                                                    \
    /* duplication of the base object class content */                                      \
    ANSC_XSINK_CLASS_CONTENT                                                                 \
    /* start of object class content */                                                     \
                                                                                            \
    char                            RecvBuffer[BBHM_TRACERT_SINK_MAX_MESSAGE_SIZE];         \
    ULONG                           CurMessageSize;                                         \
    ULONG                           MaxMessageSize;                                         \
    ULONG                           Offset;                                                 \
                                                                                            \
    PFN_TRACERTSINK_RESET           Reset;                                                  \
    /* end of object class content */                                                       \

typedef  struct
_BBHM_TRACERT_SINK_OBJECT
{
    BBHM_TRACERT_SINK_CLASS_CONTENT
}
BBHM_TRACERT_SINK_OBJECT,  *PBBHM_TRACERT_SINK_OBJECT;

#define  ACCESS_BBHM_TRACERT_SINK_OBJECT(p)                                                 \
         ACCESS_CONTAINER(p, BBHM_TRACERT_SINK_OBJECT, Linkage)

typedef  struct
_BBHM_TRACERT_ECHO_ENTRY
{
    SINGLE_LINK_ENTRY               Linkage;
    USHORT                          SeqId;
    ULONG                           StartTime;
    ULONG                           StopTime;
    xskt_addrinfo*                  pHostAddrInfo;
    ULONG                           ErrorCode;
    ULONG                           TimeToLive;
}
BBHM_TRACERT_ECHO_ENTRY,  *PBBHM_TRACERT_ECHO_ENTRY;

#define  ACCESS_BBHM_TRACERT_ECHO_ENTRY(p)                                                  \
         ACCESS_CONTAINER(p, BBHM_TRACERT_ECHO_ENTRY, Linkage)


#endif
