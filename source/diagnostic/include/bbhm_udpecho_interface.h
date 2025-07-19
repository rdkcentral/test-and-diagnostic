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

    module:    bbhm_udpecho_interface.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines all the platform-independent
        functions and macros for the UDP ECHO Server Object.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        06/22/2010    initial revision.

**********************************************************************/


#ifndef  _BBHM_UDPECHO_INTERFACE_
#define  _BBHM_UDPECHO_INTERFACE_


/*
 * This object is derived a virtual base object defined by the underlying framework. We include the
 * interface header files of the base object here to shield other objects from knowing the derived
 * relationship between this object and its base class.
 */
#include "ansc_co_interface.h"
#include "ansc_co_external_api.h"
/*#include "bbhm_properties.h"*/
#include "bbhm_diageo_interface.h"
#include "dslh_definitions_tr143.h"


/***********************************************************
       BBHM UDP ECHO SERVER COMPONENT OBJECT DEFINITION
***********************************************************/
#define  BBHM_UDPECHO_L1_NAME                         "UDPEcho"
#define  BBHM_UDPECHO_RR_NAME_Interface               "Interface"
#define  BBHM_UDPECHO_RR_NAME_Enable                  "Enable"
#define  BBHM_UDPECHO_RR_NAME_SourceIPAddress         "SourceIPAddress"
#define  BBHM_UDPECHO_RR_NAME_UDPPort                 "UDPPort"
#define  BBHM_UDPECHO_RR_NAME_EchoPlusEnabled         "EchoPlusEnabled"

/***********************************************************
      TR143 UDP ECHO SERVER STATS STRUCTURE
***********************************************************/

typedef struct
_DSLH_UDP_ECHO_SERVER_STATS
{
    ULONG                           PacketsReceived;
    ULONG                           PacketsResponded;
    ULONG                           BytesReceived;
    ULONG                           BytesResponded;
    ANSC_UNIVERSAL_TIME             TimeFirstPacketReceived;
    ANSC_UNIVERSAL_TIME             TimeLastPacketReceived;
}
DSLH_UDP_ECHO_SERVER_STATS, *PDSLH_UDP_ECHO_SERVER_STATS;

#define DslhResetUDPEchoServerStats(d_info)                                   \
        {                                                                     \
            AnscZeroMemory(d_info, sizeof(DSLH_UDP_ECHO_SERVER_STATS));       \
        }                                                                     \

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support),
 * we have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */

typedef  ANSC_HANDLE
(*PFN_BBHMUDPECHO_GET_INFO)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMUDPECHO_ACTION)
    (
        ANSC_HANDLE                 hThisObject
    );

#define  BBHM_UDP_ECHOSRV_CLASS_CONTENT                           \
    /* duplication of the base object class content */                    \
    BBHM_DIAG_EXEC_CLASS_CONTENT                                  \
    /* start of object class content */                                \
    BOOL                                bIsServerOn;              \
    BOOL                                bStopServer;              \
    DSLH_TR143_UDP_ECHO_CONFIG          UDPEchoConfig;            \
    DSLH_UDP_ECHO_SERVER_STATS          UDPEchoStats;             \
    PFN_BBHMUDPECHO_GET_INFO            GetConfig;                \
    /* end of object class content */                                  \

typedef  struct
_BBHM_UDP_ECHOSRV_OBJECT
{
    BBHM_UDP_ECHOSRV_CLASS_CONTENT
}
BBHM_UDP_ECHOSRV_OBJECT,  *PBBHM_UDP_ECHOSRV_OBJECT;

#define  ACCESS_BBHM_UDP_ECHOSRV_OBJECT(p)       \
         ACCESS_CONTAINER(p, BBHM_UDP_ECHOSRV_OBJECT, Linkage)


#endif
