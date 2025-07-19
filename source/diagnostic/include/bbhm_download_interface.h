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

    module: bbhm_download_interface.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines all the platform-independent
        functions and macros for the Bbhm Download Diagnostics Object.

        Bbhm Diagnostics are defined at TR143

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Jinghua Xu

    ---------------------------------------------------------------

    revision:

        06/01/2011    initial revision.

**********************************************************************/


#ifndef  _BBHM_DOWNLOAD_INTERFACE_
#define  _BBHM_DOWNLOAD_INTERFACE_


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
#include "dslh_definitions_diagnostics.h"


/***********************************************************
       BBHM DOWNLOAD DIAGNOSTICS COMPONENT OBJECT DEFINITION
***********************************************************/
#define  BBHM_DOWNLOAD_L1_NAME                      "DownloadDiag"
#define  BBHM_DOWNLOAD_RR_NAME_Interface            "Interface"
#define  BBHM_DOWNLOAD_RR_NAME_URL                  "DownloadURL"
#define  BBHM_DOWNLOAD_RR_NAME_DSCP                 "DSCP"
#define  BBHM_DOWNLOAD_RR_NAME_EthernetPriority     "EthernetPriority"

/***********************************************************
      TR143 DOWNLOAD DIAGNOSTICS STATS STRUCTURE
***********************************************************/

typedef struct
_DSLH_TR143_DOWNLOAD_DIAG_STATS
{
    ULONG                           DiagStates;
    ULONG                           TestBytesReceived;
    ULONG                           TotalBytesReceived;
    ANSC_UNIVERSAL_TIME             ROMTime;
    ANSC_UNIVERSAL_TIME             BOMTime;
    ANSC_UNIVERSAL_TIME             EOMTime;
    ANSC_UNIVERSAL_TIME             TCPOpenRequestTime;
    ANSC_UNIVERSAL_TIME             TCPOpenResponseTime;
}
DSLH_TR143_DOWNLOAD_DIAG_STATS, *PDSLH_TR143_DOWNLOAD_DIAG_STATS;

#define DslhResetDownloadDiagStats(d_info)                                       \
        {                                                                        \
            AnscZeroMemory(d_info, sizeof(DSLH_TR143_DOWNLOAD_DIAG_STATS));      \
        }                                                                        \
        

/*
 * Since we write all kernel modules in C (due to better performance and lack of compiler support),
 * we have to simulate the C++ object by encapsulating a set of functions inside a data structure.
 */
typedef  ANSC_HANDLE
(*PFN_BBHMDOWNLOAD_GET_INFO)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_BBHMDOWNLOAD_SET_INFO)
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDownloadInfo
    );

typedef  ANSC_STATUS
(*PFN_BBHMDOWNLOAD_ACTION)
    (
        ANSC_HANDLE                 hThisObject
    );

#define BBHM_DOWNLOAD_DIAG_CLASS_CONTENT                                           \
    /* duplication of the base object class content */                                     \
    BBHM_DIAG_EXEC_CLASS_CONTENT                                                   \
    /* start of object class content */                                                  \
    BOOL                                   bDownDiagOn;                             \
    BOOL                                   bStopDownDiag;                           \
    BOOL                                   bDownNotifyNeeded;                       \
    DSLH_TR143_DOWNLOAD_DIAG_INFO          DownloadDiagInfo;                        \
    DSLH_TR143_DOWNLOAD_DIAG_STATS         DownloadDiagStats;                       \
    PFN_BBHMDOWNLOAD_GET_INFO              GetConfig;                               \
    PFN_BBHMDOWNLOAD_ACTION                SetupEnv;                                \
    PFN_BBHMDOWNLOAD_ACTION                CloseEnv;                                \
    /* end of object class content */                                                    \
    
typedef  struct
_BBHM_DOWNLOAD_DIAG_OBJECT
{
    BBHM_DOWNLOAD_DIAG_CLASS_CONTENT
}  
BBHM_DOWNLOAD_DIAG_OBJECT,  *PBBHM_DOWNLOAD_DIAG_OBJECT;

#define  ACCESS_BBHM_DOWNLOAD_DIAG_OBJECT(p)       \
         ACCESS_CONTAINER(p, BBHM_DOWNLOAD_OBJECT, Linkage)


#endif
