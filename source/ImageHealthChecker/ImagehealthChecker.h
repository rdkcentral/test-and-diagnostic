/*
 * If not stated otherwise in this file or this component's LICENSE file
 * the following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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

#include <stdio.h>
#include <stdlib.h>
#include  "safec_lib_common.h"
#include <syscfg/syscfg.h>
#include "ccsp_trace.h"
#include "secure_wrapper.h"
#include "ImageHealthChecker_bus_connection.h"
#include <telemetry_busmessage_sender.h>

#define  STR_HLTH "store-health"
#define  BT_CHCK  "bootup-check"

int fnd_cli_diff(int old_val,int new_val);
void report_t2(char * event,char type,char *val);
void get_Clients_Count(char * arg_type,char * ret_buf,int size);
void get_dml_values();
int Iscli_Wap_Pass_Changed(char *arg_type,int old_value,char *curr_pass);
