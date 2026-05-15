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

#ifndef WEBCFG_SELFHEAL_H
#define WEBCFG_SELFHEAL_H

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <syscfg/syscfg.h>
#include <cjson/cJSON.h>
#include <ctype.h>
#include "ccsp_trace.h"
#include "tad_rbus_apis.h"

extern rbusHandle_t g_rbusHandle;

#define WEBCFG_PROPERTIES_FILE "/etc/webconfig.properties"
#define WEBCFG_DECODER_CMD "webcfg_decoder -m /nvram/webconfig_db.bin"

#define MAXCHAR 1024

typedef enum { WEBCFG_FAILURE = 0, WEBCFG_SUCCESS = 1 } WEBCFG_STATUS;

typedef struct SupplementaryDocs {
    char name[128];
    struct SupplementaryDocs *next;
} SupplementaryDocs_t;

typedef struct SubDocSupportMap {
    char name[256];
    char support[8];
    struct SubDocSupportMap *next;
} SubDocSupportMap_t;

void initWebcfgProperties(char *filename);
void setsupportedDocs(const char *value);
void setsupportedVersion(const char *value);
void setsupplementaryDocs(const char *value);
char *getsupportedDocs(void);
char *getsupportedVersion(void);
char *getsupplementaryDocs(void);
WEBCFG_STATUS isSubDocSupported(char *subDoc);
WEBCFG_STATUS isSupplementaryDoc(char *subDoc);
void supplementaryDocs(void);

SubDocSupportMap_t *get_global_sdInfoHead(void);
SupplementaryDocs_t *get_global_spInfoHead(void);
SubDocSupportMap_t * get_global_sdInfoTail(void);
SupplementaryDocs_t * get_global_spInfoTail(void);

void webcfg_subdoc_mismatch_boot_check(void);

#endif /* WEBCFG_SELFHEAL_H */
