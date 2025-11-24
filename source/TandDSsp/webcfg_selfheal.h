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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <syscfg/syscfg.h>
#include <cjson/cJSON.h>
#include "ccsp_trace.h"

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

/**
 * @brief Initialize web configuration properties from a properties file.
 *
 * This function reads configuration values from the specified properties
 * file (for example, WEBCFG_PROPERTIES_FILE) and initializes the internal
 * web configuration state used by other WebConfig helper functions.
 *
 * @param[in] filename
 *     Path to the properties file to be loaded. If NULL or an invalid path
 *     is provided, the behavior is defined by the function implementation
 *     and may result in partial or no initialization.
 *
 * @return void
 *
 * @note Error handling behavior (such as logging, use of defaults, or
 *       leaving configuration unchanged) is implementation-specific. Callers
 *       should rely on subsequent status-returning APIs to determine whether
 *       initialization was successful.
 */
 
void initWebcfgProperties(char *filename);
void setsupportedDocs(char *value);
void setsupportedVersion(char *value);
void setsupplementaryDocs(char *value);
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
