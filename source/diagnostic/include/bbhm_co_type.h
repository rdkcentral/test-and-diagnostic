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

    module:	bbhm_co_type.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines the object types for the Bbhm
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


#ifndef  _BBHM_CO_TYPE_
#define  _BBHM_CO_TYPE_


/***********************************************************
            GENERAL BBHM FEATURE OBJECTS DEFINITION
***********************************************************/

/*
 * Define the object names for all the Feature Objects that cannot be categorized. Feature Objects
 * are the objects that encapsulate certain features and provide services.
 */
#define  BBHM_SYS_REGISTRY_TYPE                     ANSC_OBJECT_TYPE_NULL
#define  BBHM_FILE_LOADER_TYPE                      ANSC_OBJECT_TYPE_NULL
#define  BBHM_SRV_CONTROLLER_TYPE                   ANSC_OBJECT_TYPE_NULL
#define  BBHM_SYS_CONTROLLER_TYPE                   ANSC_OBJECT_TYPE_NULL
#define  BBHM_WEB_CONTROLLER_TYPE                   ANSC_OBJECT_TYPE_NULL
#define  BBHM_LAN_CONTROLLER_TYPE                   ANSC_OBJECT_TYPE_NULL


#endif
