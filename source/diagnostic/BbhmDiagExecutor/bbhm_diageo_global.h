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

    module:     bbhm_diageo_global.h

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This header file includes all the header files required by
        the Bbhm Diagnostic Executor implementation.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Ding Hua, Li Shi

    ---------------------------------------------------------------

    revision:

        2007/02/08    initial revision.

**********************************************************************/


#ifndef  _BBHM_DIAGEO_GLOBAL_
#define  _BBHM_DIAGEO_GLOBAL_


#include "ansc_platform.h"
#include "ansc_crypto_interface.h"
#include "ansc_crypto_external_api.h"
#include "ansc_tso_interface.h"
#include "ansc_tso_external_api.h"
#include "ansc_ssto_interface.h"
#include "ansc_ssto_external_api.h"

#include "bbhm_co_oid.h"
#include "bbhm_co_name.h"
#include "bbhm_co_type.h"
/*#include "bbhm_properties.h"*/

#include "bbhm_ifo_dec.h"

/*
#include "bbhm_srvco_interface.h"
#include "bbhm_srvco_exported_api.h"
#include "bbhm_sysco_interface.h"
#include "bbhm_sysco_exported_api.h"
#include "bbhm_lanco_interface.h"
#include "bbhm_lanco_exported_api.h"
*/

#include "dslh_co_oid.h"
#include "dslh_co_name.h"
#include "dslh_co_type.h"
#include "dslh_properties.h"
#include "dslh_definitions_diagnostics.h"
/*#include "dslh_ifo_mso.h"*/

#include "dslh_cpeco_interface.h"
#include "dslh_cpeco_exported_api.h"

/*
#include "poam_irepdo_interface.h"
#include "poam_irepdo_exported_api.h"
*/
#include "poam_irepfo_interface.h"
#include "poam_irepfo_exported_api.h"

#include "slap_definitions.h"
#include "sys_definitions.h"

/*
#include "slap_ifo_poa.h"
#include "slap_ifo_goa.h"
*/
#include "slap_vco_interface.h"
#include "slap_vco_exported_api.h"

/*#include "smeg_event_base.h"
#include "smeg_event_definitions.h"*/

#include "bbhm_diageo_interface.h"
#include "bbhm_diageo_exported_api.h"
#include "bbhm_diageo_internal_api.h"
/*#include "bbhm_diageo_layout.h"*/

#endif
