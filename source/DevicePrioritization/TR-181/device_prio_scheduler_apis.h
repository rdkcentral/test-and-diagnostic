/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 RDK Management
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

#ifndef __DEVICE_PRIO_SCHEDULER_APIS_H
#define __DEVICE_PRIO_SCHEDULER_APIS_H

#ifdef RDK_SCHEDULER_ENABLED

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "scheduler_interface.h"

#define TDM_RDK_LOG_MODULE  "LOG.RDK.TDM"
#define PRIOMAC_DATAFILE    "/nvram/pcs-now-priomac.dat"
#define PRIOMAC_MD5FILE    "/nvram/pcs-now-priomac.dat.md5"
#define PRIO_MAC_DELIM ", "

#define SYSCFG_PRIO_CLIENT_COUNT            "DCPC_PrioClients_Count"
#define SYSCFG_PRIO_CLIENT_MAC_PREFIX       "DCPC_PrioClients_Mac"
#define SYSCFG_PRIO_CLIENT_ACTION_PREFIX    "DCPC_PrioClients_Action"
#define SYSCFG_PRIO_CLIENT_DSCP_PREFIX      "DCPC_PrioClients_DSCP"
#define SYSCFG_PRIO_CLIENT_CONNMARK_PREFIX  "DCPC_PrioClients_Connmark"

int clean_prev_syscfg_params();

int trigger_firewall_restart();

//rdkscheduler callback function
void priomac_operation(char* priomac_str_bundle);

int device_prio_scheduler_init();

#endif //#ifdef RDK_SCHEDULER_ENABLED

#endif
