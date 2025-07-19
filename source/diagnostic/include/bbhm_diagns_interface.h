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

    module: bbhm_diagns_interface.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines all the platform-independent
        functions and macros for the Bbhm NSLookup Diagnostic Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Ding Hua

    ---------------------------------------------------------------

    revision:

        02/08/07    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGNS_INTERFACE_
#define  _BBHM_DIAGNS_INTERFACE_


/*
 * This object is derived a virtual base object defined by the underlying framework. We include the
 * interface header files of the base object here to shield other objects from knowing the derived
 * relationship between this object and its base class.
 */
#include "ansc_co_interface.h"
#include "ansc_co_external_api.h"
/*#include "bbhm_properties.h"*/
#include "bbhm_diageo_interface.h"
#include "bbhm_diagns_properties.h"

#define  NS_LOOKUP_XSINK_MAX_MESSAGE_SIZE             2048
#define  NS_LOOKUP_INFO_MAX_HOSTNAME                  256
#define  NS_LOOKUP_INFO_MAX_IPADDRESS                 1000
#define  NS_LOOKUP_ENTRY_MAX_IPADDRESS                10


/***********************************************************
          BBHM NSLOOKUP DIAGNOSTIC OBJECT DEFINITION
***********************************************************/

/*
 * Define some const values that will be used in the object mapper object definition.
 */

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support),
 * we have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ANSC_STATUS
(*PFN_DIAGNS_RESET)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_HANDLE
(*PFN_DIAGNS_GET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_DIAGNS_GET_COMMON)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_DIAGNS_GET_ULONG)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  PUCHAR
(*PFN_DIAGNS_GET_PUCHAR)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_DIAGNS_SET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hContext
    );

typedef  PUCHAR
(*PFN_DIAGNS_GET_ADDR)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_DIAGNS_SET_ADDR)
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      address
    );

typedef  ANSC_STATUS
(*PFN_DIAGNS_ADD_ECHOENTRY)
    (
        ANSC_HANDLE                 hThisObject,
        char*                       DstIpName,
        USHORT                      Index,
        ULONG                       StartTime
    );

typedef  ANSC_STATUS
(*PFN_DIAGNS_ADD_ENTRY)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hENTRY
    );

typedef  ANSC_HANDLE
(*PFN_DIAGNS_GET_ENTRYBYID)
    (
        ANSC_HANDLE                 hThisObject,
        USHORT                      id
    );

typedef  ANSC_STATUS
(*PFN_DIAGNS_SET_STOPTIME)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hQuery,
        ANSC_HANDLE                 hDnsHeader,
        ULONG                       StopTime
    );

typedef  ANSC_STATUS
(*PFN_DIAGNS_CACULATE)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       Num
    );

typedef  ANSC_STATUS
(*PFN_DIAGNS_RECV)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hSinkObject,
        PVOID                       buffer,
        ULONG                       ulSize
    );

typedef  ANSC_STATUS
(*PFN_DIAGNS_SET_STRING)
    (
        ANSC_HANDLE                 hThisObject,
        PUCHAR                      Dst
    );

/*
 *  All diagnostic object specified in BBHM shares some common behaviors: set test parameters,
 *  fire the diagnostic request and a "8 DIAGNOSTICS COMPLETE" is sent out after the test is
 *  done.
 *
 *  These common beahaviors are incorporated into this base object, which the child objects,
 *  like IpPingDiag, WanDslDiag, WanAtmF5Loopback will inherit on.
 */
#define  BBHM_DIAG_NS_LOOKUP_CLASS_CONTENT                                                  \
    /* duplication of the base object class content */                                      \
    BBHM_DIAG_EXEC_CLASS_CONTENT                                                            \
    /* start of object class content */                                                     \
    /* virtual functions start point */                                                     \
    /* virtual functions end point */                                                       \
    BBHM_NS_LOOKUP_PROPERTY         Property;                                               \
    ULONG                           IPProtocol;                                             \
    USHORT                          QueryId;                                                \
    SLIST_HEADER                    EchoTable;                                              \
    SLIST_HEADER                    PqueryTable;                                            \
    ANSC_LOCK                       PqueryTableLock;                                        \
    ANSC_LOCK                       EchoTableLock;                                          \
    ANSC_HANDLE                     hStateTimer;                                            \
    char *                          hSendBuffer;                                            \
    ANSC_HANDLE                     hXsinkObject;                                           \
                                                                                            \
    PFN_DIAGNS_GET_COMMON           Start;                                                  \
    PFN_DIAGNS_GET_COMMON           Stop;                                                   \
    PFN_DIAGNS_GET_COMMON           Expire1;                                                \
    PFN_DIAGNS_GET_COMMON           Expire2;                                                \
    PFN_DIAGNS_ADD_ECHOENTRY        AddEchoEntry;                                           \
    PFN_DIAGNS_GET_COMMON           PopEchoEntry;                                           \
    PFN_DIAGNS_GET_COMMON           Open;                                                   \
    PFN_DIAGNS_ADD_ENTRY            AddPquery;                                              \
    PFN_DIAGNS_GET_ENTRYBYID        GetPqueryById;                                          \
    PFN_DIAGNS_ADD_ENTRY            DelPquery;                                              \
    PFN_DIAGNS_GET_COMMON           DelAllPqueries;                                         \
    PFN_DIAGNS_SET_STOPTIME         SetStopTime;                                            \
    PFN_DIAGNS_GET_COMMON           Close;                                                  \
    PFN_DIAGNS_CACULATE             CalculateResult;                                        \
    PFN_DIAGNS_RECV                 Recv;                                                   \
    PFN_DIAGNS_RECV                 Send;                                                   \
    PFN_DIAGNS_CACULATE             SetControl;                                             \
    PFN_DIAGNS_GET_COMMON           ResetPropertyCounter;                                   \
    PFN_DIAGNS_CACULATE             SetStatus;                                              \
    PFN_DIAGNS_GET_PUCHAR           GetDstIp;                                               \
    PFN_DIAGNS_SET_STRING           SetDstIp;                                               \
    PFN_DIAGNS_GET_ULONG            GetNumPkts;                                             \
    PFN_DIAGNS_CACULATE             SetNumPkts;                                             \
    PFN_DIAGNS_GET_ULONG            GetTimeOut;                                             \
    PFN_DIAGNS_CACULATE             SetTimeOut;                                             \
    PFN_DIAGNS_GET_PUCHAR           GetSrcIp;                                               \
    PFN_DIAGNS_SET_STRING           SetSrcIp;                                               \
    PFN_DIAGNS_GET_ULONG            GetPktsSent;                                            \
    PFN_DIAGNS_CACULATE             SetPktsSent;                                            \
    PFN_DIAGNS_GET_COMMON           ResetProperty;                                          \
    PFN_DIAGNS_GET_ULONG            GetStatus;                                              \
    /* end of object class content */                                                       \

typedef  struct
_BBHM_DIAG_NS_LOOKUP_OBJECT
{
    BBHM_DIAG_NS_LOOKUP_CLASS_CONTENT
}
BBHM_DIAG_NS_LOOKUP_OBJECT,  *PBBHM_DIAG_NS_LOOKUP_OBJECT;

#define  ACCESS_BBHM_DIAG_NS_LOOKUP_OBJECT(p)         ACCESS_CONTAINER(p, BBHM_DIAG_NS_LOOKUP_OBJECT, Linkage)

typedef  struct
_BBHM_NS_LOOKUP_ECHO_ENTRY
{
    SINGLE_LINK_ENTRY               Linkage;
    USHORT                          QueryId;
    ULONG                           StartTime;
    ULONG                           StopTime;
    ULONG                           Status;
    ULONG                           AnswerType;
    char*                           HostNameReturned;
    char*                           IPAddresses;
    char*                           DNSServerIPName;
    ULONG                           ResponsTime;
}
BBHM_NS_LOOKUP_ECHO_ENTRY,  *PBBHM_NS_LOOKUP_ECHO_ENTRY;

#define  ACCESS_BBHM_NS_LOOKUP_ECHO_ENTRY(p)             \
         ACCESS_CONTAINER(p, BBHM_NS_LOOKUP_ECHO_ENTRY, Linkage)

typedef  struct
_BBHM_NS_LOOKUP_QUERY_ENTRY
{
    SINGLE_LINK_ENTRY               Linkage;
    USHORT                          QueryId;
}
BBHM_NS_LOOKUP_QUERY_ENTRY,  *PBBHM_NS_LOOKUP_QUERY_ENTRY;

#define  ACCESS_BBHM_NS_LOOKUP_QUERY_ENTRY(p)            \
         ACCESS_CONTAINER(p, BBHM_NS_LOOKUP_QUERY_ENTRY, Linkage)

#define  BbhmDiagnsFreePquery(tbf_pquery)                                                       \
         {                                                                                  \
            AnscFreeMemory(tbf_pquery);                                                     \
         }

typedef  struct
_BBHM_NS_LOOKUP_ECHO_INFO
{
    ULONG                           Status;
    ULONG                           AnswerType;
    ULONG                           ResponseTime;
    char*                           HostNameReturned[NS_LOOKUP_INFO_MAX_HOSTNAME + 1];
    char*                           IPAddresses[NS_LOOKUP_INFO_MAX_IPADDRESS + 1];
    /*ANSC_IPV4_ADDRESS               DNSServerIP;*/
    char*                           DNSServerName[NS_LOOKUP_INFO_MAX_HOSTNAME + 1];
    ULONG                           ResponsTime;
}
BBHM_NS_LOOKUP_ECHO_INFO,  *PBBHM_NS_LOOKUP_ECHO_INFO;

#endif

