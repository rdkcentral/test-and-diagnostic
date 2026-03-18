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

#include "webcfg_selfheal.h"

static char *supported_bits = NULL;
static char *supported_version = NULL;
static char *supplementary_docs = NULL;

SubDocSupportMap_t *g_sdInfoHead = NULL;
SubDocSupportMap_t *g_sdInfoTail = NULL;
SupplementaryDocs_t *g_spInfoHead = NULL;
SupplementaryDocs_t *g_spInfoTail = NULL;

void setsupplementaryDocs(char *value) {
    if (value != NULL) {
        char *new_value = strdup(value);
        if (new_value == NULL) {
            CcspTraceError(("setsupplementaryDocs: strdup failed\n"));
            return;
        }
        if (supplementary_docs != NULL) {
            free(supplementary_docs);
        }
        supplementary_docs = new_value;
    } else {
        if (supplementary_docs != NULL) {
            free(supplementary_docs);
        }
        supplementary_docs = NULL;
    }
}

void setsupportedDocs(char *value) {
    if (value != NULL) {
        char *new_value = strdup(value);
        if (new_value == NULL) {
            CcspTraceError(("setsupportedDocs: strdup failed\n"));
            return;
        }
        if (supported_bits != NULL) {
            free(supported_bits);
        }
        supported_bits = new_value;
    } else {
        if (supported_bits != NULL) {
            free(supported_bits);
        }
        supported_bits = NULL;
    }
}

void setsupportedVersion(char *value) {
    if (value != NULL) {
        char *new_value = strdup(value);
        if (new_value == NULL) {
            CcspTraceError(("setsupportedVersion: strdup failed\n"));
            return;
        }
        if (supported_version != NULL) {
            free(supported_version);
        }
        supported_version = new_value;
    } else {
        if (supported_version != NULL) {
            free(supported_version);
        }
        supported_version = NULL;
    }
}

char *getsupportedDocs(void) {
    CcspTraceInfo(("The value in supportedbits get is %s\n",
                   supported_bits ? supported_bits : "(null)"));
    return supported_bits;
}

char *getsupportedVersion(void) {
    CcspTraceInfo(("The value in supportedversion get is %s\n",
                   supported_version ? supported_version : "(null)"));
    return supported_version;
}

char *getsupplementaryDocs(void) {
    CcspTraceInfo(("The value in supplementary_docs get is %s\n",
                   supplementary_docs ? supplementary_docs : "(null)"));
    return supplementary_docs;
}

SubDocSupportMap_t *get_global_sdInfoHead(void) {
    SubDocSupportMap_t *tmp = NULL;
    tmp = g_sdInfoHead;
    return tmp;
}

SupplementaryDocs_t *get_global_spInfoHead(void) {
    SupplementaryDocs_t *tmp = NULL;
    tmp = g_spInfoHead;
    return tmp;
}

SubDocSupportMap_t *get_global_sdInfoTail(void)
{
    SubDocSupportMap_t *tmp = NULL;
    tmp = g_sdInfoTail;
    return tmp;
}

SupplementaryDocs_t *get_global_spInfoTail(void)
{
    SupplementaryDocs_t *tmp = NULL;
    tmp = g_spInfoTail;
    return tmp;
}

void initWebcfgProperties(char *filename) {
    FILE *fp = NULL;
    char str[MAXCHAR] = {'\0'};
    char *p, *token;

    CcspTraceInfo(("webcfg properties file path is %s\n", filename));
    fp = fopen(filename, "r");

    if (fp == NULL) {
        CcspTraceError(("Failed to open file %s\n", filename));
        return;
    }

    while (fgets(str, MAXCHAR, fp) != NULL) {
        char *value = NULL;

        if (NULL != (value = strstr(str, "WEBCONFIG_SUPPORTED_DOCS_BIT="))) {
            CcspTraceInfo(("The value stored is %s\n", str));
            value = value + strlen("WEBCONFIG_SUPPORTED_DOCS_BIT=");
            size_t len = strlen(value);
            if (len > 0 && value[len - 1] == '\n') {
                value[len - 1] = '\0';
            }
            setsupportedDocs(value);
            value = NULL;
        }

        if (NULL != (value = strstr(str, "WEBCONFIG_DOC_SCHEMA_VERSION="))) {
            CcspTraceInfo(("The value stored is %s\n", str));
            value = value + strlen("WEBCONFIG_DOC_SCHEMA_VERSION=");
            size_t len = strlen(value);
            if (len > 0 && value[len - 1] == '\n') {
                value[len - 1] = '\0';
            }
            setsupportedVersion(value);
            value = NULL;
        }

        if (strncmp(str, "WEBCONFIG_SUBDOC_MAP", strlen("WEBCONFIG_SUBDOC_MAP")) == 0) {
            p = str;
            token = strtok_r(p, " =", &p);
            token = strtok_r(p, ",", &p);
            
            while (token != NULL) {
                char subdoc[100];
                char *subtoken;
                SubDocSupportMap_t *sdInfo = NULL;
                
                strncpy(subdoc, token, (sizeof(subdoc) - 1));
                subdoc[sizeof(subdoc) - 1] = '\0';
                
                sdInfo = (SubDocSupportMap_t *)malloc(sizeof(SubDocSupportMap_t));
                if (sdInfo == NULL) {
                    fclose(fp);
                    CcspTraceError(("Unable to allocate memory\n"));
                    return;
                }
                memset(sdInfo, 0, sizeof(SubDocSupportMap_t));

                subtoken = strtok(subdoc, ":");
                if (subtoken == NULL) {
                    fclose(fp);
                    free(sdInfo);
                    return;
                }
                strncpy(sdInfo->name, subtoken, (sizeof(sdInfo->name) - 1));
                
                strtok(NULL, ":");
                subtoken = strtok(NULL, ":");
                if (subtoken != NULL) {
                    strncpy(sdInfo->support, subtoken, sizeof(sdInfo->support) - 1);
                }

                token = strtok_r(p, ",", &p);
                sdInfo->next = NULL;

                if (g_sdInfoTail == NULL) {
                    g_sdInfoHead = sdInfo;
                    g_sdInfoTail = sdInfo;
                } else {
                    SubDocSupportMap_t *temp = NULL;
                    temp = get_global_sdInfoTail();
                    temp->next = sdInfo;
                    g_sdInfoTail = sdInfo;
                }
            }
        }

        if (NULL != (value = strstr(str, "WEBCONFIG_SUPPLEMENTARY_DOCS="))) {
            CcspTraceInfo(("The value stored is %s\n", str));
            value = value + strlen("WEBCONFIG_SUPPLEMENTARY_DOCS=");
            size_t len = strlen(value);
            if (len > 0 && value[len - 1] == '\n') {
                value[len - 1] = '\0';
            }
            setsupplementaryDocs(value);
            value = NULL;
            supplementaryDocs();
        }
    }
    fclose(fp);
}

void supplementaryDocs(void) {
    int count = 0;
    char *docs = getsupplementaryDocs();
    if (docs != NULL) {
        char *docs_var = strndup(docs, strlen(docs));
        char *token = strtok(docs_var, ",");

        while (token != NULL) {
            SupplementaryDocs_t *spInfo = (SupplementaryDocs_t *)malloc(sizeof(SupplementaryDocs_t));
            if (spInfo == NULL) {
                CcspTraceError(("Unable to allocate memory for supplementary docs\n"));
                free(docs_var);
                return;
            }
            memset(spInfo, 0, sizeof(SupplementaryDocs_t));
            spInfo->name = strdup(token);
            if (spInfo->name == NULL) { 
                CcspTraceError(("strdup failed for supplementary doc name\n"));
                free(spInfo);
                free(docs_var);
                return;
            }
            spInfo->next = NULL;

            if (g_spInfoTail == NULL) {
                g_spInfoHead = spInfo;
                g_spInfoTail = spInfo;
            } else {
                SupplementaryDocs_t *temp = NULL;
                temp = get_global_spInfoTail();
                temp->next = spInfo;
                g_spInfoTail = spInfo;
            }

            CcspTraceInfo(("The supplementary_doc[%d] is %s\n", count, spInfo->name));
            count++;
            token = strtok(NULL, ",");
        }
        free(docs_var);
    }
}

WEBCFG_STATUS isSubDocSupported(char *subDoc) {
    SubDocSupportMap_t *sd = get_global_sdInfoHead();

    while (sd != NULL) {
        if (strcmp(sd->name, subDoc) == 0) {
            CcspTraceInfo(("The subdoc %s is present\n", sd->name));
            if (strncmp(sd->support, "true", strlen("true")) == 0) {
                CcspTraceInfo(("%s is supported\n", subDoc));
                return WEBCFG_SUCCESS;
            } else {
                CcspTraceInfo(("%s is not supported\n", subDoc));
                return WEBCFG_FAILURE;
            }
        }
        sd = sd->next;
    }
    CcspTraceInfo(("Supported doc bit not found for %s\n", subDoc));
    return WEBCFG_FAILURE;
}

WEBCFG_STATUS isSupplementaryDoc(char *subDoc) {
    SupplementaryDocs_t *sp = get_global_spInfoHead();

    while (sp != NULL) {
        CcspTraceInfo(("Supplementary check for docname %s, subDoc received is %s\n",
                       sp->name, subDoc));
        if (strlen(sp->name) == strlen(subDoc)) {
            if (strncmp(sp->name, subDoc, strlen(subDoc)) == 0) {
                CcspTraceInfo(("subDoc %s is supplementary\n", subDoc));
                return WEBCFG_SUCCESS;
            }
        }
        sp = sp->next;
    }
    return WEBCFG_FAILURE;
}

/* SelfHeal Subdoc Version Mismatch */
static int is_ignored_subdoc(const char *name) {
    if (!name) return 1;
    return (!strcmp(name, "root") ||
            !strcmp(name, "homessid") ||
            !strcmp(name, "privatessid"));
}

static int Get_Component_Version(const char *subdoc, int *ver_out) {
    char key[128], val[64] = {0};

    snprintf(key, sizeof(key), "%s_version", subdoc);
    CcspTraceInfo(("Get_Component_Version: looking up key '%s'\n", key));

    if (syscfg_get(NULL, key, val, sizeof(val)) != 0 || !val[0]) {
        CcspTraceError(("Get_Component_Version: syscfg_get failed or empty for '%s'\n", key));
        return -1;
    }

    *ver_out = atoi(val);
    CcspTraceInfo(("Get_Component_Version: subdoc='%s', value='%s', ver_out=%d\n",
                   subdoc, val, *ver_out));
    return 0;
}

static int Set_Webcfg_ForceReset(const char *reset_list)
{
    rbusError_t err;

    if (g_rbusHandle == NULL)
    {
        CcspTraceError(("%s: g_rbusHandle is NULL, RBUS not initialized\n", __FUNCTION__));
        return -1;
    }

    CcspTraceInfo(("%s: Setting webcfgSubdocForceReset='%s' via RBUS\n",
                   __FUNCTION__, reset_list ? reset_list : "(null)"));

    err = rbus_setStr(g_rbusHandle,
                      "Device.X_RDK_WebConfig.webcfgSubdocForceReset",
                      (char *)reset_list);

    if (err != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s: rbus_setStr failed for webcfgSubdocForceReset, err=%d\n",
                        __FUNCTION__, err));
        return -1;
    }

    CcspTraceInfo(("%s: Successfully set webcfgSubdocForceReset\n", __FUNCTION__));
    return 0;
}

static char *read_pipe_data(FILE *pipe) {
    char buf[4096];
    char *data = NULL;
    size_t len = 0;

    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), pipe);
        if (n > 0) {
            char *tmp = realloc(data, len + n + 1);
            if (!tmp) {
                free(data);
                return NULL;
            }
            data = tmp;
            memcpy(data + len, buf, n);
            len += n;
        }
        if (n < sizeof(buf)) {
            if (ferror(pipe)) {
                free(data);
                return NULL;
            }
            break;
        }
    }
    if (data) {
        data[len] = '\0';
    }
    return data;
}

static cJSON *Load_WebcfgDB_Array(void) {
    CcspTraceInfo(("Executing: webcfg_decoder -m /nvram/webconfig_db.bin\n"));

    char *decoder_argv[] = { "webcfg_decoder", "-m", "/nvram/webconfig_db.bin", NULL };
    FILE *pipe = v_secure_popen("r", "webcfg_decoder", decoder_argv);
    if (!pipe) {
        CcspTraceError(("v_secure_popen failed\n"));
        return NULL;
    }

    char *json = read_pipe_data(pipe);
    v_secure_pclose(pipe);

    if (!json || strlen(json) == 0) {
        CcspTraceError(("Empty output from webcfg_decoder\n"));
        free(json);
        return NULL;
    }

    char *json_start = strchr(json, '{');
    if (!json_start) {
        CcspTraceError(("No '{' found in decoder output\n"));
        free(json);
        return NULL;
    }

    CcspTraceInfo(("Raw JSON first 200 chars: %.200s...\n", json_start));

    cJSON *root = cJSON_Parse(json_start);
    free(json);
    if (!root) {
        CcspTraceError(("cJSON_Parse failed\n"));
        return NULL;
    }

    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "webcfgdb");
    if (!arr || !cJSON_IsArray(arr)) {
        CcspTraceError(("No valid 'webcfgdb' array in JSON\n"));
        cJSON_Delete(root);
        return NULL;
    }

    CcspTraceInfo(("SUCCESS: Found %d subdocs in webcfgdb\n", cJSON_GetArraySize(arr)));
    cJSON *copy = cJSON_Duplicate(arr, 1);
    cJSON_Delete(root);

    return copy;
}

void webcfg_subdoc_mismatch_boot_check(void) {
    CcspTraceInfo(("=== Webconfig selfheal starting ===\n"));
    
    cJSON *arr = Load_WebcfgDB_Array();
    if (!arr) {
        CcspTraceError(("Failed to load webcfgdb\n"));
        return;
    }

    char *reset_list = NULL;
    size_t reset_len = 0;
    int count = 0;

    cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        cJSON *name = cJSON_GetObjectItem(item, "name");
        cJSON *ver = cJSON_GetObjectItem(item, "version");
        if (!cJSON_IsString(name) || !cJSON_IsNumber(ver)) continue;

        const char *subdoc = name->valuestring;
        int db_ver = ver->valueint;

        if (is_ignored_subdoc(subdoc)) continue;
        if (isSubDocSupported((char*)subdoc) != WEBCFG_SUCCESS)
        {
            CcspTraceInfo(("Skipping %s: subdoc not supported in webcfg.properties\n", subdoc));
            continue;
        }

        int comp_ver = -1;
        if (Get_Component_Version(subdoc, &comp_ver) != 0) continue;

        if (comp_ver != db_ver) {
            CcspTraceInfo(("MISMATCH %s: DB=%d COMP=%d\n", subdoc, db_ver, comp_ver));
            count++;
            
            size_t name_len = strlen(subdoc);
            size_t new_size = reset_len + name_len + 2;
            char *tmp = realloc(reset_list, new_size);
            if (tmp == NULL) {
                CcspTraceError(("Memory allocation failed while building reset_list\n"));
                free(reset_list);
                reset_list = NULL;
                break;
            }
            reset_list = tmp;
            snprintf(reset_list + reset_len, new_size - reset_len,
                     "%s%s", reset_len ? "," : "", subdoc);
            reset_len = strlen(reset_list);
        }
    }

    if (reset_list && reset_len > 0) {
        CcspTraceInfo(("FORCE RESET: %s (%d subdocs)\n", reset_list, count));
        Set_Webcfg_ForceReset(reset_list);
    } else {
        CcspTraceInfo(("No mismatches - system healthy\n"));
    }

    free(reset_list);
    cJSON_Delete(arr);
    CcspTraceInfo(("Selfheal complete\n"));
}
