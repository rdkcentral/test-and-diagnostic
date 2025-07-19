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

    module:	bbhm_ifo_dec.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines the base class data structure and
        interface for the Bbhm Diagnostic Execution Control Object.

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


#ifndef  _BBHM_IFO_DEC_
#define  _BBHM_IFO_DEC_


/*
 * This object is derived a virtual base object defined by the underlying framework. We include the
 * interface header files of the base object here to shield other objects from knowing the derived
 * relationship between this object and its base class.
 */
#include "ansc_ifo_interface.h"


/***********************************************************
      BBHM DEVICE BEHAVIOR CONTROL INTERFACE DEFINITION
***********************************************************/

/*
 * Define some const values that will be used in the os wrapper object definition.
 */
#define  BBHM_DEC_INTERFACE_NAME                    "bbhmDiagnosticExecutionControlIf"
#define  BBHM_DEC_INTERFACE_ID                      0

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support), we
 * have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ANSC_STATUS
(*PFN_BBHMDECIF_START0)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

typedef  ANSC_STATUS
(*PFN_BBHMDECIF_STOP0)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDECIF_RETR0)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

typedef  ANSC_STATUS
(*PFN_BBHMDECIF_START1)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulInst1,
        ANSC_HANDLE                 hDslhDiagInfo
    );

typedef  ANSC_STATUS
(*PFN_BBHMDECIF_STOP1)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulInst1
    );

typedef  ANSC_STATUS
(*PFN_BBHMDECIF_RETR1)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulInst1,
        ANSC_HANDLE                 hDslhDiagInfo
    );

typedef  ANSC_STATUS
(*PFN_BBHMDECIF_START2)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulInst1,
        ULONG                       ulInst2,
        ANSC_HANDLE                 hDslhDiagInfo
    );

typedef  ANSC_STATUS
(*PFN_BBHMDECIF_STOP2)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulInst1,
        ULONG                       ulInst2
    );

typedef  ANSC_STATUS
(*PFN_BBHMDECIF_RETR2)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulInst1,
        ULONG                       ulInst2,
        ANSC_HANDLE                 hDslhDiagInfo
    );


/*
 * The BBHM model is designed to be device- and platform-indepedent. We cannot make any assumptions
 * about the capabilities of the underlying device or platform. We define a set of APIs to perform
 * a set of different device-specific actions. For example: rebooting the device is usually consid-
 * ered a device-specific behavior.
 */
#define  BBHM_DEC_INTERFACE_CLASS_CONTENT                                                   \
    /* duplication of the base object class content */                                      \
    ANSCIFO_CLASS_CONTENT                                                                   \
    /* start of object class content */                                                     \
    PFN_BBHMDECIF_START0            IpPingStart;                                            \
    PFN_BBHMDECIF_STOP0             IpPingStop;                                             \
    PFN_BBHMDECIF_RETR0             IpPingRetrResult;                                       \
                                                                                            \
    PFN_BBHMDECIF_START1            WanDslStart;                                            \
    PFN_BBHMDECIF_STOP1             WanDslStop;                                             \
    PFN_BBHMDECIF_RETR1             WanDslRetrResult;                                       \
                                                                                            \
    PFN_BBHMDECIF_START2            AtmF5LoopbackStart;                                     \
    PFN_BBHMDECIF_STOP2             AtmF5LoopbackStop;                                      \
    PFN_BBHMDECIF_RETR2             AtmF5LoopbackRetrResult;                                \
                                                                                            \
    PFN_BBHMDECIF_START0            TraceRouteStart;                                        \
    PFN_BBHMDECIF_STOP0             TraceRouteStop;                                         \
    PFN_BBHMDECIF_RETR0             TraceRouteRetrResult;                                   \
    /* end of object class content */                                                       \

typedef  struct
_BBHM_DEC_INTERFACE
{
    BBHM_DEC_INTERFACE_CLASS_CONTENT
}
BBHM_DEC_INTERFACE,  *PBBHM_DEC_INTERFACE;

#define  ACCESS_BBHM_DEC_INTERFACE(p)               ACCESS_CONTAINER(p, BBHM_DEC_INTERFACE, Linkage)


#endif
