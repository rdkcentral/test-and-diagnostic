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

    module: bbhm_diagns_tdo_interface.h

        For NSLookup Tool, 
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This file defines the timer that can be
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


#ifndef  _BBHM_NS_LOOKUP_TDO_INTERFACE_
#define  _BBHM_NS_LOOKUP_TDO_INTERFACE_

/***********************************************************
               POEMC TIMER SMO OBJECT DEFINITION
***********************************************************/

#define  BBHM_NS_LOOKUP_TDO_NAME                                "NSLookupTimerDescriptor"
#define  BBHM_NS_LOOKUP_TDO_OID                                 BBHM_DIAG_NS_LOOKUP_OID + 1

/*
 * Define some const values that will be used in the os wrapper object definition.
 */

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support), we
 * have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ULONG
(*PFN_DIAGNSTDO_GET_ULONG)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_DIAGNSTDO_SET_ULONG)
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
#define  BBHM_NS_LOOKUP_TDO_CLASS_CONTENT                                                   \
    /* duplication of the base object class content */                                      \
    ANSC_TIMER_DESCRIPTOR_CLASS_CONTENT                                                     \
                                                                                            \
    ULONG                           Counter;                                                \
    ULONG                           StopTime;                                               \
    PFN_DIAGNSTDO_GET_ULONG         GetCounter;                                             \
    PFN_DIAGNSTDO_SET_ULONG         SetCounter;                                             \
    PFN_DIAGNSTDO_GET_ULONG         GetStopTime;                                            \
    PFN_DIAGNSTDO_SET_ULONG         SetStopTime;                                            \
                                                                                            \
    /* end of object class content */                                                       \

typedef  struct
_BBHM_NS_LOOKUP_TDO_OBJECT
{
    BBHM_NS_LOOKUP_TDO_CLASS_CONTENT
}
BBHM_NS_LOOKUP_TDO_OBJECT,  *PBBHM_NS_LOOKUP_TDO_OBJECT;

#define  ACCESS_BBHM_NS_LOOKUP_TDO_OBJECT(p)             \
         ACCESS_CONTAINER(p, BBHM_NS_LOOKUP_TDO_OBJECT, Linkage)


#endif

