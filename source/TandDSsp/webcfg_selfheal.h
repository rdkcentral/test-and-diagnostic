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
#include <syscfg/syscfg.h>
#include <cjson/cJSON.h>
#include <ctype.h>
#include "ccsp_trace.h"
#include "tad_rbus_apis.h"

#ifdef __cplusplus
extern "C" {
#endif

extern rbusHandle_t g_rbusHandle;

#define WEBCFG_PROPERTIES_FILE "/etc/webconfig.properties"
#define MAXCHAR 1024

typedef enum { WEBCFG_FAILURE = 0, WEBCFG_SUCCESS = 1 } WEBCFG_STATUS;

typedef struct SupplementaryDocs {
    char *name;
    struct SupplementaryDocs *next;
} SupplementaryDocs_t;

typedef struct SubDocSupportMap {
    char name[256];
    char support[8];
    struct SubDocSupportMap *next;
} SubDocSupportMap_t;

/* Initialization / Properties */
void initWebcfgProperties(const char *filename);
void setsupportedDocs(char *value);
void setsupportedVersion(char *value);
void setsupplementaryDocs(char *value);
char *getsupportedDocs(void);
char *getsupportedVersion(void);
char *getsupplementaryDocs(void);

/* Supplementary list rebuild */
void supplementaryDocs(void);

/* Queries */
WEBCFG_STATUS isSubDocSupported(const char *subDoc);
WEBCFG_STATUS isSupplementaryDoc(const char *subDoc);

/* Global list accessors */
SubDocSupportMap_t *get_global_sdInfoHead(void);
SupplementaryDocs_t *get_global_spInfoHead(void);
SubDocSupportMap_t *get_global_sdInfoTail(void);
SupplementaryDocs_t *get_global_spInfoTail(void);

/* Self-heal entry */
void webcfg_subdoc_mismatch_boot_check(void);

/* Optional cleanup helpers (useful for tests or managed shutdown) */
void webcfg_free_subdoc_list(void);
void webcfg_free_supplementary_list(void);
void webcfg_properties_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* WEBCFG_SELFHEAL_H */
