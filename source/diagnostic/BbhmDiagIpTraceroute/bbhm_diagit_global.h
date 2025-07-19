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

    module:     bbhm_diagit_global.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This header file includes all the header files required by
        the Bbhm IpTraceroute Diagnostic implementation.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Du Li, Li Shi

    ---------------------------------------------------------------

    revision:

        2009/07/30    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGIT_GLOBAL_
#define  _BBHM_DIAGIT_GLOBAL_


#include "ansc_platform.h"
#include "ansc_oco_interface.h"
#include "ansc_oco_external_api.h"
#include "ansc_tso_interface.h"
#include "ansc_tso_external_api.h"
#include "ansc_socket.h"
#include "ansc_xsocket_external_api.h"

#include "bbhm_co_oid.h"
#include "bbhm_co_name.h"
#include "bbhm_co_type.h"
/*#include "bbhm_properties.h"*/
#include "dslh_definitions_diagnostics.h"

#include "bbhm_diageo_interface.h"
#include "bbhm_diageo_exported_api.h"

#include "bbhm_diagit_interface.h"
#include "bbhm_diagit_exported_api.h"
#include "bbhm_diagit_internal_api.h"

#endif
