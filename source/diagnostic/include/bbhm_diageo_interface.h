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

    module: bbhm_diageo_interface.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines all the platform-independent
        functions and macros for the Bbhm Diagnostic Executor Object.

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


#ifndef  _BBHM_DIAGEO_INTERFACE_
#define  _BBHM_DIAGEO_INTERFACE_


/*
 * This object is derived a virtual base object defined by the underlying framework. We include the
 * interface header files of the base object here to shield other objects from knowing the derived
 * relationship between this object and its base class.
 */
#include "ansc_co_interface.h"
#include "ansc_co_external_api.h"
/*#include "bbhm_properties.h"*/
#include "bbhm_diag_lib.h"


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
(*PFN_BBHMDIAGEO_GET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_SET_CONTEXT)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hContext
    );

typedef  ANSC_HANDLE
(*PFN_BBHMDIAGEO_GET_IF)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_SET_IF)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hInterface
    );

typedef  ULONG
(*PFN_BBHMDIAGEO_GET_ULONG)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_SET_ULONG)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulValue
    );

typedef  BOOL
(*PFN_BBHMDIAGEO_GET_BOOL)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  char*
(*PFN_BBHMDIAGEO_GET_STRING)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_GET_PROPERTY)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_SET_PROPERTY)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hProperty
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_RESET)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_ENGAGE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_CANCEL)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_SET_DIAG_PARAMS)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    );

typedef  BOOLEAN
(*PFN_BBHMDIAGEO_CHK_STATE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_START_DIAG)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_STOP_DIAG)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_HANDLE
(*PFN_BBHMDIAGEO_GET_RESULT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ULONG
(*PFN_BBHMDIAGEO_GET_RESULT_TS)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_RETR_RESULT)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_START_TIMER)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_STOP_TIMER)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_QUERY_TASK)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDIAGEO_SET_STATE)
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulDiagState
    );


/*
 *  All diagnostic object specified in DSLH shares some common behaviors: set test parameters,
 *  fire the diagnostic request and a "8 DIAGNOSTICS COMPLETE" is sent out after the test is
 *  done.
 *
 *  These common beahaviors are incorporated into this base object, which the child objects,
 *  like IpPingDiag, WanDslDiag, WanAtmF5Loopback will inherit on.
 */
#define  BBHM_DIAG_EXEC_CLASS_CONTENT                                                       \
    /* duplication of the base object class content */                                      \
    ANSCCO_CLASS_CONTENT                                                                    \
    /* start of object class content */                                                     \
    ANSC_LOCK                       AccessLock;                                             \
    BOOL                            bActive;                                                \
    ANSC_HANDLE                     hDslhDiagInfo;                                          \
    ANSC_EVENT                      ResultQueryEvent;                                       \
    ANSC_EVENT                      ResultQueryExitEvent;                                   \
    BOOL                            bResultQueryRunning;                                    \
    ULONG                           ResultTimestamp;                                        \
                                                                                            \
    PFN_BBHMDIAGEO_RESET            Reset;                                                  \
                                                                                            \
    PFN_BBHMDIAGEO_ENGAGE           Engage;                                                 \
    PFN_BBHMDIAGEO_CANCEL           Cancel;                                                 \
                                                                                            \
    PFN_BBHMDIAGEO_SET_DIAG_PARAMS  SetDiagParams;                                          \
    PFN_BBHMDIAGEO_GET_RESULT       GetResult;                                              \
    PFN_BBHMDIAGEO_GET_RESULT_TS    GetResultTimeStamp;                                     \
    PFN_BBHMDIAGEO_SET_STATE        SetDiagState;                                           \
                                                                                            \
    /* virtual functions start point */                                                     \
    PFN_BBHMDIAGEO_SET_DIAG_PARAMS  CopyDiagParams;                                         \
    PFN_BBHMDIAGEO_CHK_STATE        CheckCanStart;                                          \
    PFN_BBHMDIAGEO_START_DIAG       StartDiag;                                              \
    PFN_BBHMDIAGEO_STOP_DIAG        StopDiag;                                               \
    PFN_BBHMDIAGEO_RETR_RESULT      RetrieveResult;                                         \
    /* virtual functions end point */                                                       \
                                                                                            \
    PFN_BBHMDIAGEO_QUERY_TASK       ResultQueryTask;                                        \
                                                                                            \
    /* end of object class content */                                                       \

typedef  struct
_BBHM_DIAG_EXEC_OBJECT
{
    BBHM_DIAG_EXEC_CLASS_CONTENT
}
BBHM_DIAG_EXEC_OBJECT,  *PBBHM_DIAG_EXEC_OBJECT;

#define  ACCESS_BBHM_DIAG_EXEC_OBJECT(p)            ACCESS_CONTAINER(p, BBHM_DIAG_EXEC_OBJECT, Linkage)


#endif

