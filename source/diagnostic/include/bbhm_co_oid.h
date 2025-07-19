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

    module: bbhm_co_oid.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines the object ids for the Bbhm
        Component Objects.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Xuechen Yang

    ---------------------------------------------------------------

    revision:

        07/09/08    initial revision.

**********************************************************************/


#ifndef  _BBHM_CO_OID_
#define  _BBHM_CO_OID_


/***********************************************************
           GENERAL BBHM FEATURE OBJECTS DEFINITION
***********************************************************/

/*
 * Define the object names for all the Feature Objects that cannot be categorized. Feature Objects
 * are the objects that encapsulate certain features and provide services.
 */
#define  BBHM_FEATURE_OBJECT_OID_BASE               BBHM_COMPONENT_OID_BASE      + 0x1000
#define  BBHM_GENERAL_FO_OID_BASE                   BBHM_FEATURE_OBJECT_OID_BASE + 0x0000

#define  BBHM_SYS_REGISTRY_OID                      BBHM_GENERAL_FO_OID_BASE     + 0x0001
#define  BBHM_FILE_LOADER_OID                       BBHM_GENERAL_FO_OID_BASE     + 0x0002

#define  BBHM_SRV_CONTROLLER_OID                    BBHM_GENERAL_FO_OID_BASE     + 0x0011
#define  BBHM_SYS_CONTROLLER_OID                    BBHM_GENERAL_FO_OID_BASE     + 0x0012
#define  BBHM_WEB_CONTROLLER_OID                    BBHM_GENERAL_FO_OID_BASE     + 0x0013
#define  BBHM_LAN_CONTROLLER_OID                    BBHM_GENERAL_FO_OID_BASE     + 0x0014

#define  BBHM_SYSRO_SIMPLE_OID                      BBHM_GENERAL_FO_OID_BASE     + 0x0021

#define  BBHM_DIAG_EXEC_OID                         BBHM_GENERAL_FO_OID_BASE     + 0x0041
#define  BBHM_DIAG_IP_PING_OID                      BBHM_GENERAL_FO_OID_BASE     + 0x0042
#define  BBHM_DIAG_IP_TRACEROUTE_OID                BBHM_GENERAL_FO_OID_BASE     + 0x0043
#define  BBHM_DIAG_NS_LOOKUP_OID                    BBHM_GENERAL_FO_OID_BASE     + 0x0044
#define  BBHM_DIAG_DOWNLOAD_OID                     BBHM_GENERAL_FO_OID_BASE     + 0x0045
#define  BBHM_DIAG_UPLOAD_OID                       BBHM_GENERAL_FO_OID_BASE     + 0x0046
#define  BBHM_DIAG_UDPECHO_SERVER_OID               BBHM_GENERAL_FO_OID_BASE     + 0x0047

#endif
