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

    module: bbhm_diagns_xsink_interface.h

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


#ifndef  _BBHM_NS_LOOKUP_XSINK_INTERFACE_
#define  _BBHM_NS_LOOKUP_XSINK_INTERFACE_


#define  DIAGNS_XSINK_MAX_MESSAGE_SIZE              2048

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support),
 * we have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ANSC_HANDLE
(*PFN_DIAGNSXSINK_GET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_DIAGNSXSINK_SET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hController
    );

typedef  ANSC_STATUS
(*PFN_DIAGNSXSINK_RESET)
    (
        ANSC_HANDLE                 hThisObject
    );

/*
 * DHCP uses UDP as its transport protocol. DHCP messages from a client to a server are sent to
 * the 'DHCP server' port (67), and DHCP messages from a server to a client are sent to the 'DHCP
 * client' port (68). A server with multiple network address (e.g., a multi-homed host) MAY use
 * any of its network addresses in outgoing DHCP messages.
 */
#define  BBHM_NS_LOOKUP_XSINK_CLASS_CONTENT                                                 \
    /* duplication of the base object class content */                                      \
    ANSC_XSINK_CLASS_CONTENT                                                                \
    /* start of object class content */                                                     \
                                                                                            \
    char                            RecvBuffer[NS_LOOKUP_XSINK_MAX_MESSAGE_SIZE];           \
    ULONG                           CurMessageSize;                                         \
    ULONG                           MaxMessageSize;                                         \
    ULONG                           Offset;                                                 \
                                                                                            \
    PFN_DIAGNSXSINK_RESET           Reset;                                                  \
    /* end of object class content */                                                       \

typedef  struct
_BBHM_NS_LOOKUP_XSINK_OBJECT
{
    BBHM_NS_LOOKUP_XSINK_CLASS_CONTENT
}
BBHM_NS_LOOKUP_XSINK_OBJECT,  *PBBHM_NS_LOOKUP_XSINK_OBJECT;

#define  ACCESS_BBHM_NS_LOOKUP_XSINK_OBJECT(p)              \
         ACCESS_CONTAINER(p, BBHM_NS_LOOKUP_XSINK_OBJECT, Linkage)

#endif

