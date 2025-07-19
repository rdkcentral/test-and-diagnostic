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

    module:    bbhm_diagip_interface.h

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

        Ding Hua, Li Shi

    ---------------------------------------------------------------

    revision:

        02/08/07    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGIP_INTERFACE_
#define  _BBHM_DIAGIP_INTERFACE_


/*
 * This object is derived a virtual base object defined by the underlying framework. We include the
 * interface header files of the base object here to shield other objects from knowing the derived
 * relationship between this object and its base class.
 */
#include "ansc_co_interface.h"
#include "ansc_co_external_api.h"
#include "ansc_socket.h"
#include "ansc_tso_interface.h"
#include "ansc_tso_external_api.h"
#include "bbhm_diageo_interface.h"
#include "bbhm_diagip_properties.h"
/*#include "bbhm_properties.h"*/

#define  BBHM_IP_PING_TDO_NAME                                                          "PingTimerDescriptor"

#define  BBHM_IP_PING_TDO_OID                                                           BBHM_DIAG_IP_PING_OID + 0x0001

#define  MAX_ECHO_TABLE_SIZE                                            10
#define  BBHM_IP_PING_SINK_MAX_MESSAGE_SIZE                             2048

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
(*PFN_BBHMDIAGIP_GET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_SET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hContext
    );

typedef  ANSC_HANDLE
(*PFN_BBHMDIAGIP_GET_IF)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_SET_IF)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hInterface
    );

typedef  ULONG
(*PFN_BBHMDIAGIP_GET_TYPE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_SET_TYPE)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulType
    );

typedef  PUCHAR
(*PFN_BBHMDIAGIP_GET_ADDR)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_SET_ADDR)
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      address
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_RESET)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_OPEN)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_RETRIEVE)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_CONFIGURE)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_CLOSE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_EXPIRE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_ACCEPT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hNewSocket
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_RECV)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_SEND)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    );

typedef  ULONG
(*PFN_BBHMDIAGIP_GET_ULONG)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_SET_ULONG)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulValue
    );

typedef  UCHAR
(*PFN_BBHMDIAGIP_GET_UCHAR)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_TEST)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_SET_STOP_TIME)
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                      SeqNumber,
        ULONG                       PktSize,
        UCHAR                       TTL,
        ULONG                       StopTime
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_ADD_ENTRY_ECHO)
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                      SeqNumber,
        ULONG                       StartTime
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_CALCULATE_RESULT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGIP_SET_ENV)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  CHAR*
(*PFN_BBHMDIAGIP_GET_MRESULT)
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
#define  BBHM_DIAG_IP_PING_CLASS_CONTENT                                                    \
    /* duplication of the base object class content */                                      \
    BBHM_DIAG_EXEC_CLASS_CONTENT                                                            \
    /* start of object class content */                                                     \
    BBHM_IP_PING_PROPERTY           Property;                                               \
    ULONG                           IPProtocol;                                             \
                                                                                            \
    ANSC_HANDLE                     hStateTimer;                                            \
                                                                                            \
    char *                          hSendBuffer;                                            \
                                                                                            \
    ANSC_HANDLE                     hSinkObject;                                            \
    SLIST_HEADER                    EchoTable[MAX_ECHO_TABLE_SIZE];                         \
    SLIST_HEADER                    MiddleResult;                                           \
    ANSC_LOCK                       EchoTableLock;                                          \
    ANSC_LOCK                       MiddleResultLock;                                       \
                                                                                            \
    PFN_BBHMDIAGIP_RESET            ResetProperty;                                          \
    PFN_BBHMDIAGIP_RESET            ResetPropertyCounter;                                   \
                                                                                            \
    PFN_BBHMDIAGIP_SET_STOP_TIME    SetStopTime;                                            \
    PFN_BBHMDIAGIP_ADD_ENTRY_ECHO   AddEchoEntry;                                           \
                                                                                            \
    PFN_BBHMDIAGIP_CALCULATE_RESULT CalculateResult;                                        \
    PFN_BBHMDIAGIP_SET_ENV          SetEnv;                                                 \
                                                                                            \
    PFN_BBHMDIAGIP_OPEN             Start;                                                  \
    PFN_BBHMDIAGIP_OPEN             Stop;                                                   \
    PFN_BBHMDIAGIP_OPEN             Open;                                                   \
    PFN_BBHMDIAGIP_OPEN             Close;                                                  \
    PFN_BBHMDIAGIP_RETRIEVE         GetProperty;                                            \
    PFN_BBHMDIAGIP_CONFIGURE        SetProperty;                                            \
    PFN_BBHMDIAGIP_EXPIRE           Expire1;                                                \
    PFN_BBHMDIAGIP_EXPIRE           Expire2;                                                \
                                                                                            \
    PFN_BBHMDIAGIP_ACCEPT           Accept;                                                 \
    PFN_BBHMDIAGIP_RECV             Recv;                                                   \
    PFN_BBHMDIAGIP_SEND             Send;                                                   \
                                                                                            \
    PFN_BBHMDIAGIP_GET_ULONG        GetSrcIpType;                                           \
    PFN_BBHMDIAGIP_SET_ULONG        SetSrcIpType;                                           \
    PFN_BBHMDIAGIP_GET_ADDR         GetSrcIp;                                               \
    PFN_BBHMDIAGIP_SET_ADDR         SetSrcIp;                                               \
    PFN_BBHMDIAGIP_GET_ULONG        GetDstIpType;                                           \
    PFN_BBHMDIAGIP_SET_ULONG        SetDstIpType;                                           \
    PFN_BBHMDIAGIP_GET_ADDR         GetDstIp;                                               \
    PFN_BBHMDIAGIP_SET_ADDR         SetDstIp;                                               \
    PFN_BBHMDIAGIP_GET_ULONG        GetNumPkts;                                             \
    PFN_BBHMDIAGIP_SET_ULONG        SetNumPkts;                                             \
    PFN_BBHMDIAGIP_GET_ULONG        GetPktSize;                                             \
    PFN_BBHMDIAGIP_SET_ULONG        SetPktSize;                                             \
    PFN_BBHMDIAGIP_GET_ULONG        GetTimeBetween;                                         \
    PFN_BBHMDIAGIP_SET_ULONG        SetTimeBetween;                                         \
    PFN_BBHMDIAGIP_GET_ULONG        GetTimeOut;                                             \
    PFN_BBHMDIAGIP_SET_ULONG        SetTimeOut;                                             \
    PFN_BBHMDIAGIP_GET_ULONG        GetControl;                                             \
    PFN_BBHMDIAGIP_SET_ULONG        SetControl;                                             \
    PFN_BBHMDIAGIP_GET_ULONG        GetStatus;                                              \
    PFN_BBHMDIAGIP_SET_ULONG        SetStatus;                                              \
    PFN_BBHMDIAGIP_GET_ULONG        GetPktsSent;                                            \
    PFN_BBHMDIAGIP_SET_ULONG        SetPktsSent;                                            \
    PFN_BBHMDIAGIP_GET_ULONG        GetPktsRecv;                                            \
    PFN_BBHMDIAGIP_SET_ULONG        SetPktsRecv;                                            \
    PFN_BBHMDIAGIP_GET_ULONG        GetAvgRTT;                                              \
    PFN_BBHMDIAGIP_SET_ULONG        SetAvgRTT;                                              \
    PFN_BBHMDIAGIP_GET_ULONG        GetMaxRTT;                                              \
    PFN_BBHMDIAGIP_SET_ULONG        SetMaxRTT;                                              \
    PFN_BBHMDIAGIP_GET_ULONG        GetMinRTT;                                              \
    PFN_BBHMDIAGIP_SET_ULONG        SetMinRTT;                                              \
    PFN_BBHMDIAGIP_GET_ULONG        GetNumIcmpError;                                        \
    PFN_BBHMDIAGIP_SET_ULONG        SetNumIcmpError;                                        \
    PFN_BBHMDIAGIP_GET_ULONG        GetIcmpError;                                           \
    PFN_BBHMDIAGIP_SET_ULONG        SetIcmpError;                                           \
    PFN_BBHMDIAGIP_GET_ULONG        GetNumCalculate;                                        \
    PFN_BBHMDIAGIP_SET_ULONG        SetNumCalculate;                                        \
    PFN_BBHMDIAGIP_GET_ULONG        GetSumRTT;                                              \
    PFN_BBHMDIAGIP_SET_ULONG        SetSumRTT;                                              \
    PFN_BBHMDIAGIP_GET_MRESULT      GetMiddleResult;                                        \
                                                                                            \
    /* end of object class content */                                                       \

typedef  struct
_BBHM_DIAG_IP_PING_OBJECT
{
    BBHM_DIAG_IP_PING_CLASS_CONTENT
}
BBHM_DIAG_IP_PING_OBJECT,  *PBBHM_DIAG_IP_PING_OBJECT;

#define  ACCESS_BBHM_DIAG_IP_PING_OBJECT(p)         ACCESS_CONTAINER(p, BBHM_DIAG_IP_PING_OBJECT, Linkage)

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
(*PFN_PINGTDO_GET_ULONG)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_PINGTDO_SET_ULONG)
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
#define  BBHM_IP_PING_TDO_CLASS_CONTENT                                                     \
    /* duplication of the base object class content */                                      \
    ANSC_TIMER_DESCRIPTOR_CLASS_CONTENT                                                     \
                                                                                            \
    ULONG                           Counter;                                                \
    ULONG                           StopTime;                                               \
    PFN_PINGTDO_GET_ULONG           GetCounter;                                             \
    PFN_PINGTDO_SET_ULONG           SetCounter;                                             \
    PFN_PINGTDO_GET_ULONG           GetStopTime;                                            \
    PFN_PINGTDO_SET_ULONG           SetStopTime;                                            \
                                                                                            \
    /* end of object class content */                                                       \

typedef  struct
_BBHM_IP_PING_TDO_OBJECT
{
    BBHM_IP_PING_TDO_CLASS_CONTENT
}
BBHM_IP_PING_TDO_OBJECT,  *PBBHM_IP_PING_TDO_OBJECT;

#define  ACCESS_BBHM_IP_PING_TDO_OBJECT(p)             \
         ACCESS_CONTAINER(p, BBHM_IP_PING_TDO_OBJECT, Linkage)

#define  PING_SINK_MAX_MESSAGE_SIZE              2048

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support),
 * we have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ANSC_HANDLE
(*PFN_PINGSINK_GET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_PINGSINK_SET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hController
    );

typedef  ANSC_STATUS
(*PFN_PINGSINK_RESET)
    (
        ANSC_HANDLE                 hThisObject
    );

/*
 * DHCP uses UDP as its transport protocol. DHCP messages from a client to a server are sent to
 * the 'DHCP server' port (67), and DHCP messages from a server to a client are sent to the 'DHCP
 * client' port (68). A server with multiple network address (e.g., a multi-homed host) MAY use
 * any of its network addresses in outgoing DHCP messages.
 */
#define  BBHM_IP_PING_SINK_CLASS_CONTENT                                                    \
    /* duplication of the base object class content */                                      \
    ANSC_XSINK_CLASS_CONTENT                                                                \
    /* start of object class content */                                                     \
                                                                                            \
    char                            RecvBuffer[PING_SINK_MAX_MESSAGE_SIZE];                 \
    ULONG                           CurMessageSize;                                         \
    ULONG                           MaxMessageSize;                                         \
    ULONG                           Offset;                                                 \
                                                                                            \
    PFN_PINGSINK_RESET              Reset;                                                  \
    /* end of object class content */                                                       \

typedef  struct
_BBHM_IP_PING_SINK_OBJECT
{
    BBHM_IP_PING_SINK_CLASS_CONTENT
}
BBHM_IP_PING_SINK_OBJECT,  *PBBHM_IP_PING_SINK_OBJECT;

#define  ACCESS_BBHM_IP_PING_SINK_OBJECT(p)             \
         ACCESS_CONTAINER(p, BBHM_IP_PING_SINK_OBJECT, Linkage)

typedef  struct
_BBHM_IP_PING_ECHO_ENTRY
{
    SINGLE_LINK_ENTRY               Linkage;
    USHORT                          SeqId;
    ULONG                           StartTime;
    ULONG                           StopTime;
    ULONG                           PktSize;
    UCHAR                           TTL;
    UCHAR                           ICMPType;
}
BBHM_IP_PING_ECHO_ENTRY,  *PBBHM_IP_PING_ECHO_ENTRY;

#define  ACCESS_BBHM_IP_PING_ECHO_ENTRY(p)             \
         ACCESS_CONTAINER(p, BBHM_IP_PING_ECHO_ENTRY, Linkage)

#endif
