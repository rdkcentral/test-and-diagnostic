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

static void freesubdoclist(void) {
    SubDocSupportMap_t *p = gsdInfoHead;
    while (p) {
        SubDocSupportMap_t *n = p->next;
        free(p);
        p = n;
    }
    gsdInfoHead = gsdInfoTail = NULL;
}

static void freesupplementarylist(void) {
    SupplementaryDocs_t *p = gspInfoHead;
    while (p) {
        SupplementaryDocs_t *n = p->next;
        if (p->name) free(p->name);
        free(p);
        p = n;
    }
    gspInfoHead = gspInfoTail = NULL;
}

static void striptrailingnewline(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    if (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r')) {
        s[len-1] = '\0';
        len--;
        if (len > 0 && (s[len-1] == '\r' || s[len-1] == '\n')) {
            s[len-1] = '\0';
        }
    }
}

void setsupportedDocs(char *value) {
    if (supportedbits) {
        free(supportedbits);
        supportedbits = NULL;
    }
    if (value != NULL) {
        supportedbits = strdup(value);
    }
}

void setsupportedVersion(char *value) {
    if (supportedversion) {
        free(supportedversion);
        supportedversion = NULL;
    }
    if (value != NULL) {
        supportedversion = strdup(value);
    }
}

void setsupplementaryDocs(char *value) {
    if (supplementary_docs) {
        free(supplementary_docs);
        supplementary_docs = NULL;
    }
    if (value != NULL) {
        supplementary_docs = strdup(value);
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
    
    /* FIXED: Clear existing data before reloading */
    freesubdoclist();
    freesupplementarylist();
    
    fp = fopen(filename, "r");
    if (fp == NULL) {
        CcspTraceError(("Failed to open file %s\n", filename));
        return;
    }

    while (fgets(str, MAXCHAR, fp) != NULL) {
        char *value = NULL;

        /* Parse supported docs */
        if (NULL != (value = strstr(str, "WEBCONFIG_SUPPORTED_DOCS_BIT="))) {
            CcspTraceInfo(("The value stored is %s\n", str));
            value = value + strlen("WEBCONFIG_SUPPORTED_DOCS_BIT=");
            striptrailingnewline(value);
            if (value[0] != '\0') {
                setsupportedDocs(value);
            } else {
                setsupportedDocs(NULL);
            }
            value = NULL;
        }

        /* Parse schema version */
        if (NULL != (value = strstr(str, "WEBCONFIG_DOC_SCHEMA_VERSION="))) {
            CcspTraceInfo(("The value stored is %s\n", str));
            value = value + strlen("WEBCONFIG_DOC_SCHEMA_VERSION=");
            striptrailingnewline(value);
            if (value[0] != '\0') {
                setsupportedVersion(value);
            } else {
                setsupportedVersion(NULL);
            }
            value = NULL;
        }

        /* FIXED: Clear subdoc list before parsing new entries */
        if (strncmp(str, "WEBCONFIG_SUBDOC_MAP", strlen("WEBCONFIG_SUBDOC_MAP")) == 0) {
            /* Already cleared at function start, but extra safety */
            freesubdoclist();
            
            p = str;
            token = strtok_r(p, " =", &p);
            token = strtok_r(p, ",", &p);

            while (token != NULL) {
                char subdoc[100];
                char *subtoken;
                SubDocSupportMap_t *sdInfo = NULL;

                strncpy(subdoc, token, (sizeof(subdoc)-1));
                subdoc[sizeof(subdoc)-1] = '\0';

                sdInfo = (SubDocSupportMap_t *)malloc(sizeof(SubDocSupportMap_t));
                if (sdInfo == NULL) {
                    fclose(fp);
                    CcspTraceError(("Unable to allocate memory\n"));
                    freesubdoclist();
                    return;
                }
                memset(sdInfo, 0, sizeof(SubDocSupportMap_t));

                subtoken = strtok(subdoc, ":");
                if (subtoken == NULL) {
                    fclose(fp);
                    free(sdInfo);
                    freesubdoclist();
                    return;
                }
                strncpy(sdInfo->name, subtoken, (sizeof(sdInfo->name)-1));

                strtok(NULL, ":"); // skip bitposition
                subtoken = strtok(NULL, ":"); // support
                if (subtoken != NULL) {
                    strncpy(sdInfo->support, subtoken, sizeof(sdInfo->support)-1);
                }

                token = strtok_r(p, ",", &p);
                sdInfo->next = NULL;

                if (gsdInfoTail == NULL) {
                    gsdInfoHead = gsdInfoTail = sdInfo;
                } else {
                    gsdInfoTail->next = sdInfo;
                    gsdInfoTail = sdInfo;
                }
            }
        }

        /* Parse supplementary docs */
        if (NULL != (value = strstr(str, "WEBCONFIG_SUPPLEMENTARY_DOCS="))) {
            CcspTraceInfo(("The value stored is %s\n", str));
            value = value + strlen("WEBCONFIG_SUPPLEMENTARY_DOCS=");
            striptrailingnewline(value);
            if (value[0] != '\0') {
                setsupplementaryDocs(value);
            } else {
                setsupplementaryDocs(NULL);
            }
            value = NULL;
        }
    }
    fclose(fp);
    
    /* Build supplementary list after parsing */
    supplementaryDocs();
}

void supplementaryDocs(void) {
    int count = 0;
    char *docs = getsupplementaryDocs();
    
    /* FIXED: Clear existing list before rebuilding */
    freesupplementarylist();

    if (docs != NULL) {
        char *docs_var = strndup(docs, strlen(docs));
        if (docs_var == NULL) {
            CcspTraceError(("Unable to allocate memory for supplementary docs copy\n"));
            return;
        }

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
                CcspTraceError(("Unable to allocate memory for supplementary doc name\n"));
                free(spInfo);
                free(docs_var);
                return;
            }

            spInfo->next = NULL;

            if (gspInfoTail == NULL) {
                gspInfoHead = gspInfoTail = spInfo;
            } else {
                gspInfoTail->next = spInfo;
                gspInfoTail = spInfo;
            }

            CcspTraceInfo(("The supplementary_doc[%d] is %s\n", count, spInfo->name));
            count++;
            token = strtok(NULL, ",");
        }
        free(docs_var);
    }
}

WEBCFG_STATUS isSubDocSupported(const char *subDoc) {
    SubDocSupportMap_t *sd = get_global_sdInfoHead();
    while (sd != NULL) {
        if ((strlen(sd->name) == strlen(subDoc)) && (strcmp(sd->name, subDoc) == 0)) {
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
    CcspTraceError(("Supported doc bit not found for %s\n", subDoc));
    return WEBCFG_FAILURE;
}

WEBCFG_STATUS isSupplementaryDoc(const char *subDoc) {
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

void webcfg_free_subdoc_list(void) {
    freesubdoclist();
}

void webcfg_free_supplementary_list(void) {
    freesupplementarylist();
}

void webcfg_properties_cleanup(void) {
    freesubdoclist();
    freesupplementarylist();
    if (supportedbits) {
        free(supportedbits);
        supportedbits = NULL;
    }
    if (supportedversion) {
        free(supportedversion);
        supportedversion = NULL;
    }
    if (supplementary_docs) {
        free(supplementary_docs);
        supplementary_docs = NULL;
    }
}

//SelfHeal Subdoc Version Mismatch
static int is_ignored_subdoc(const char *name) {
    if(!name) return 1;
    return (!strcmp(name, "root") || !strcmp(name, "homessid") || !strcmp(name, "privatessid"));
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

    if(g_rbusHandle == NULL)
    {
        CcspTraceError(("%s: g_rbusHandle is NULL, RBUS not initialized\n", __FUNCTION__));
        return -1;
    }

    CcspTraceInfo(("%s: Setting webcfgSubdocForceReset='%s' via RBUS\n",
                   __FUNCTION__, reset_list ? reset_list : "(null)"));

    err = rbus_setStr(g_rbusHandle,
                      "Device.X_RDK_WebConfig.webcfgSubdocForceReset",
                      (char *)reset_list);

    if(err != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s: rbus_setStr failed for webcfgSubdocForceReset, err=%d\n",
                        __FUNCTION__, err));
        return -1;
    }

    CcspTraceInfo(("%s: Successfully set webcfgSubdocForceReset\n", __FUNCTION__));
    return 0;
}

static char *read_pipe_data(FILE *pipe) {
    char buf[4096], *data = NULL; size_t len = 0;
    while(!feof(pipe)) {
        size_t n = fread(buf, 1, sizeof(buf), pipe);
        if(n) {
            char *tmp = (char *)realloc(data, len + n + 1);
            if (!tmp) {
                free(data);
                return NULL;
            }
            data = tmp;
            memcpy(data + len, buf, n); len += n;
            data[len] = '\0';
        }
    }
    return data; /* may be NULL */
}

static cJSON *Load_WebcfgDB_Array(void) {
    CcspTraceInfo(("Executing: webcfg_decoder -m /nvram/webconfig_db.bin\n"));
    
    FILE *pipe = popen("webcfg_decoder -m /nvram/webconfig_db.bin 2>/dev/null", "r");
    if(!pipe) {
        CcspTraceError(("popen failed\n"));
        return NULL;
    }
    
    char *json = read_pipe_data(pipe);
    int status = pclose(pipe);
    
    CcspTraceInfo(("webcfg_decoder exit status: %d\n", status));
    if(status != 0 || !json || strlen(json) == 0) {
        CcspTraceError(("Empty output or failed: status=%d, len=%lu\n", status, json ? (unsigned long)strlen(json) : 0UL));
        free(json);
        return NULL;
    }
    
    char *json_start = strchr(json, '{');
    if (!json_start) {
        CcspTraceError(("No '{' found in decoder output, cannot parse JSON\n"));
        free(json);
        return NULL;
    }

    CcspTraceInfo(("Raw JSON first 200 chars from first '{': %.200s...\n", json_start));

    cJSON *root = cJSON_Parse(json_start);
    free(json);
    if (!root) {
        CcspTraceError(("cJSON_Parse failed\n"));
        return NULL;
    }
    
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "webcfgdb");
    if(!arr || !cJSON_IsArray(arr)) {
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
    if(!arr) {
        CcspTraceError(("Failed to load webcfgdb\n"));
        return;
    }

    char *reset_list = NULL; size_t reset_len = 0; int count = 0;

    cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        cJSON *name = cJSON_GetObjectItem(item, "name");
        cJSON *ver = cJSON_GetObjectItem(item, "version");
        if(!cJSON_IsString(name) || !cJSON_IsNumber(ver)) continue;

        const char *subdoc = name->valuestring;
        int db_ver = ver->valueint;

        if(is_ignored_subdoc(subdoc)) continue;
        if (isSubDocSupported((char*)subdoc) != WEBCFG_SUCCESS)
        {
            CcspTraceInfo(("Skipping %s: subdoc not supported in webcfg.properties\n", subdoc));
            continue;
        }

        int comp_ver = -1;
        if(Get_Component_Version(subdoc, &comp_ver) != 0) continue;

        if(comp_ver != db_ver) {
            CcspTraceInfo(("MISMATCH %s: DB=%d COMP=%d\n", subdoc, db_ver, comp_ver));
            count++;
            
            size_t name_len = strlen(subdoc);
            size_t extra = name_len + 2; // name + optional comma + '\0'
            char *tmp = (char *)realloc(reset_list, reset_len + extra);
            if (!tmp) {
                CcspTraceError(("Failed to grow reset_list buffer\n"));
                free(reset_list);
                reset_list = NULL;
                cJSON_Delete(arr);
                return;
            }
            reset_list = tmp;

            /* safe: extra includes comma and NUL at most */
            snprintf(reset_list + reset_len, extra, "%s%s", reset_len ? "," : "", subdoc);
            reset_len += (reset_len ? 1 : 0) + name_len;
        }
    }

    if(reset_list && reset_len > 0) {
        CcspTraceInfo(("FORCE RESET: %s (%d subdocs)\n", reset_list, count));
        Set_Webcfg_ForceReset(reset_list);
        free(reset_list);
    } else {
        CcspTraceInfo(("No mismatches - system healthy\n"));
    }

    cJSON_Delete(arr);
    CcspTraceInfo(("Selfheal complete\n"));
}