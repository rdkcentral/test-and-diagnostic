/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
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

#ifndef  __DEVICE_PRIO_WEBCONFIG_APIS_H
#define  __DEVICE_PRIO_WEBCONFIG_APIS_H

#ifdef RDK_SCHEDULER_ENABLED

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "ansc_status.h"
#include "msgpack.h"
#include "webconfig_framework.h"
#include "webconfig_scheduler_doc.h"

#define SUBDOC_COUNT 1
#define PRIO_MAC_SUBDOC "prioritizedmacs"
#define QOS_CLIENT_RULES_ALIAS  "client_qos_rules"

#define MACADDR_SZ  18
#define QOS_RULES_MAX_FIELDS    3
#define QOS_RULE_MAX_BUFFER_SIZE    256

enum {
    QOS_RULE_OK = 3,
    QOS_RULE_EMPTY = 4,
    QOS_RULE_INVALID_MAC = 5,
    QOS_RULE_INVALID_DSCP = 6,
    QOS_RULE_INVALID_ACTION = 7,
    QOS_RULE_INVALID = 8,
    QOS_REMOVED_RULES = 9
};

uint32_t getBlobVersion(char* subdoc);
int setBlobVersion(char* subdoc,uint32_t version);
void webConfigFrameworkInit() ;

pErr process_DCPC_WebConfigRequest(void *Data);
int  get_base64_decodedbuffer(char *pString, char **buffer, int *size);
msgpack_unpack_return get_msgpack_unpack_status(char *decodedbuf, int size);
void freeResources_scheduler_doc(void *arg);

/* Qos rule validation apis*/
int validateQosRule(char* rule);
bool CheckMacHasValidCharacter (char* pMac);
bool Validate_Mac(char* physAddress);
int validateAction(const char *action);
int validateDSCP(int dscp);

#endif //#ifdef RDK_SCHEDULER_ENABLED

#endif

