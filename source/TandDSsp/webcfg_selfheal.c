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
#include "secure_wrapper.h"
#define MAX_DOC_FIELD_LEN   256
#define MAX_SUBDOC_LEN      128

static char supported_bits[MAX_DOC_FIELD_LEN] = {0};
static char supported_version[MAX_DOC_FIELD_LEN] = {0};
static char supplementary_docs[MAX_DOC_FIELD_LEN] = {0};

SubDocSupportMap_t *g_sdInfoHead = NULL;
SubDocSupportMap_t *g_sdInfoTail = NULL;
SupplementaryDocs_t *g_spInfoHead = NULL;
SupplementaryDocs_t *g_spInfoTail = NULL;

static void freeSubDocSupportMap(void)
{
    SubDocSupportMap_t *curr = g_sdInfoHead;

    while (curr) {
        SubDocSupportMap_t *next = curr->next;
        free(curr);
        curr = next;
    }

    g_sdInfoHead = NULL;
    g_sdInfoTail = NULL;
}

static void freeSupplementaryDocsList(void)
{
    SupplementaryDocs_t *curr = g_spInfoHead;

    while (curr) {
        SupplementaryDocs_t *next = curr->next;
        free(curr);
        curr = next;
    }

    g_spInfoHead = NULL;
    g_spInfoTail = NULL;
}

void setsupplementaryDocs(const char *value)
{
    if (value) {
        snprintf(supplementary_docs,
                 sizeof(supplementary_docs),
                 "%s",
                 value);
    } else {
        supplementary_docs[0] = '\0';
    }
}

void setsupportedDocs(const char *value)
{
    if (value) {
        snprintf(supported_bits,
                 sizeof(supported_bits),
                 "%s",
                 value);
    } else {
        supported_bits[0] = '\0';
    }
}

void setsupportedVersion(const char *value)
{
    if (value) {
        snprintf(supported_version,
                 sizeof(supported_version),
                 "%s",
                 value);
    } else {
        supported_version[0] = '\0';
    }
}

char *getsupportedDocs(void)
{
    return supported_bits[0] ? supported_bits : NULL;
}

char *getsupportedVersion(void)
{
    return supported_version[0] ? supported_version : NULL;
}

char *getsupplementaryDocs(void)
{
    return supplementary_docs[0] ? supplementary_docs : NULL;
}

SubDocSupportMap_t *get_global_sdInfoHead(void)
{
    return g_sdInfoHead;
}

SubDocSupportMap_t *get_global_sdInfoTail(void)
{
    return g_sdInfoTail;
}

SupplementaryDocs_t *get_global_spInfoHead(void)
{
    return g_spInfoHead;
}

SupplementaryDocs_t *get_global_spInfoTail(void)
{
    return g_spInfoTail;
}

void initWebcfgProperties(char *filename)
{
    FILE *fp = NULL;
    char str[MAXCHAR] = {'\0'};
    char *p = NULL;
    char *token = NULL;

    freeSubDocSupportMap();
    freeSupplementaryDocsList();

    CcspTraceInfo(("webcfg properties file path is %s\n", filename));

    fp = fopen(filename, "r");

    if (fp == NULL) {
        CcspTraceError(("Failed to open file %s\n", filename));
        return;
    }

    while (fgets(str, MAXCHAR, fp) != NULL) {

        char *value = NULL;

        if ((value = strstr(str,
            "WEBCONFIG_SUPPORTED_DOCS_BIT=")) != NULL) {

            value += strlen("WEBCONFIG_SUPPORTED_DOCS_BIT=");

            size_t len = strlen(value);

            if (len > 0 && value[len - 1] == '\n') {
                value[len - 1] = '\0';
            }

            setsupportedDocs(value);
        }

        if ((value = strstr(str,
            "WEBCONFIG_DOC_SCHEMA_VERSION=")) != NULL) {

            value += strlen("WEBCONFIG_DOC_SCHEMA_VERSION=");

            size_t len = strlen(value);

            if (len > 0 && value[len - 1] == '\n') {
                value[len - 1] = '\0';
            }

            setsupportedVersion(value);
        }

        if (strncmp(str,
                    "WEBCONFIG_SUBDOC_MAP",
                    strlen("WEBCONFIG_SUBDOC_MAP")) == 0) {

            p = str;

            token = strtok_r(p, " =", &p);
            token = strtok_r(p, ",", &p);

            while (token != NULL) {

                char subdoc[MAX_SUBDOC_LEN] = {0};
                char *subtoken = NULL;
                char *saveptr = NULL;

                SubDocSupportMap_t *sdInfo =
                    (SubDocSupportMap_t *)malloc(sizeof(SubDocSupportMap_t));

                if (sdInfo == NULL) {
                    fclose(fp);
                    CcspTraceError(("Unable to allocate memory\n"));
                    return;
                }

                memset(sdInfo, 0, sizeof(SubDocSupportMap_t));

                snprintf(subdoc, sizeof(subdoc), "%s", token);

                subtoken = strtok_r(subdoc, ":", &saveptr);

                if (subtoken == NULL) {
                    free(sdInfo);
                    token = strtok_r(NULL, ",", &p);
                    continue;
                }

                snprintf(sdInfo->name,
                         sizeof(sdInfo->name),
                         "%s",
                         subtoken);

                strtok_r(NULL, ":", &saveptr);

                subtoken = strtok_r(NULL, ":", &saveptr);

                if (subtoken != NULL) {
                    snprintf(sdInfo->support,
                             sizeof(sdInfo->support),
                             "%s",
                             subtoken);
                }

                sdInfo->next = NULL;

                if (g_sdInfoTail == NULL) {
                    g_sdInfoHead = sdInfo;
                    g_sdInfoTail = sdInfo;
                } else {
                    g_sdInfoTail->next = sdInfo;
                    g_sdInfoTail = sdInfo;
                }

                token = strtok_r(NULL, ",", &p);
            }
        }

        if ((value = strstr(str,
            "WEBCONFIG_SUPPLEMENTARY_DOCS=")) != NULL) {

            value += strlen("WEBCONFIG_SUPPLEMENTARY_DOCS=");

            size_t len = strlen(value);

            if (len > 0 && value[len - 1] == '\n') {
                value[len - 1] = '\0';
            }

            setsupplementaryDocs(value);

            supplementaryDocs();
        }
    }

    fclose(fp);
}

void supplementaryDocs(void)
{
    int count = 0;
    char *docs = getsupplementaryDocs();

    freeSupplementaryDocsList();

    if (docs != NULL) {

        char docs_var[MAX_DOC_FIELD_LEN] = {0};

        snprintf(docs_var, sizeof(docs_var), "%s", docs);

        char *saveptr = NULL;
        char *token = strtok_r(docs_var, ",", &saveptr);

        while (token != NULL) {

            SupplementaryDocs_t *spInfo =
                (SupplementaryDocs_t *)malloc(sizeof(SupplementaryDocs_t));

            if (spInfo == NULL) {
                CcspTraceError(("Unable to allocate memory "
                                "for supplementary docs\n"));
                return;
            }

            memset(spInfo, 0, sizeof(SupplementaryDocs_t));

            snprintf(spInfo->name,
                     sizeof(spInfo->name),
                     "%s",
                     token);

            spInfo->next = NULL;

            if (g_spInfoTail == NULL) {
                g_spInfoHead = spInfo;
                g_spInfoTail = spInfo;
            } else {
                g_spInfoTail->next = spInfo;
                g_spInfoTail = spInfo;
            }

            CcspTraceInfo(("The supplementary_doc[%d] is %s\n",
                           count,
                           spInfo->name));

            count++;

            token = strtok_r(NULL, ",", &saveptr);
        }
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

static int Get_Component_Version(const char *subdoc, long long *ver_out) {
    char key[128], val[64] = {0};

    snprintf(key, sizeof(key), "%s_version", subdoc);
    CcspTraceInfo(("Get_Component_Version: looking up key '%s'\n", key));

    if (syscfg_get(NULL, key, val, sizeof(val)) != 0 || !val[0]) {
        CcspTraceError(("Get_Component_Version: syscfg_get failed or empty for '%s'\n", key));
        return -1;
    }
    char *endptr = NULL;
    errno = 0;
    long long v = strtoll(val, &endptr, 10);

    if (errno != 0 || *endptr != '\0') {
        CcspTraceError(("Invalid numeric value for %s_version: %s\n", subdoc, val));
        return -1;
    }

    *ver_out = v;
    CcspTraceInfo(("Get_Component_Version: subdoc='%s', value='%s', ver_out=%lld\n",
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
/*
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
*/

static int read_file_data(const char *path, char **data_out) {
    FILE *fp = NULL;
    char *buffer = NULL;
    long file_size = 0;

    if (data_out == NULL) {
        return -1;
    }
    *data_out = NULL;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    buffer = (char *)malloc((size_t)file_size + 1);
    if (buffer == NULL) {
        fclose(fp);
        return -1;
    }

    if (file_size > 0 && fread(buffer, 1, (size_t)file_size, fp) != (size_t)file_size) {
        free(buffer);
        fclose(fp);
        return -1;
    }

    buffer[file_size] = '\0';
    fclose(fp);
    *data_out = buffer;
    return 0;
}

static cJSON *Load_WebcfgDB_Array(void) {
    /*CcspTraceInfo(("Executing: webcfg_decoder -m /nvram/webconfig_db.bin\n"));

    FILE *pipe = v_secure_popen("r", "webcfg_decoder -m /nvram/webconfig_db.bin");
    if (!pipe) {
        CcspTraceError(("v_secure_popen failed\n"));
        return NULL;
    }

    char *json = read_pipe_data(pipe);
    int pclose_rc = v_secure_pclose(pipe);
    if (pclose_rc != 0) {
        CcspTraceError(("webcfg_decoder exited with rc=%d\n", pclose_rc));
    }
        */

    char tmp_path[64] = {'\0'};
    char *json = NULL;

    if (snprintf(tmp_path, sizeof(tmp_path), "/tmp/webcfg_decoder_%d.json", (int)getpid()) >= (int)sizeof(tmp_path)) {
        CcspTraceError(("Failed to build temp path for webcfg decoder output\n"));
        return NULL;
    }

    remove(tmp_path);

    if ((v_secure_system("%s > %s 2>&1", WEBCFG_DECODER_CMD, tmp_path)) != 0) {
        CcspTraceError(("webcfg_decoder command failed\n"));
        remove(tmp_path);
        return NULL;
    }

    if (read_file_data(tmp_path, &json) != 0) {
        CcspTraceError(("Failed to read decoder output from temp file\n"));
        remove(tmp_path);
        return NULL;
    }

    remove(tmp_path);

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
        long long db_ver = (long long)ver->valuedouble;

        if (is_ignored_subdoc(subdoc)) continue;
        if (isSubDocSupported((char*)subdoc) != WEBCFG_SUCCESS)
        {
            CcspTraceInfo(("Skipping %s: subdoc not supported in webcfg.properties\n", subdoc));
            continue;
        }

        long long comp_ver = -1;
        if (Get_Component_Version(subdoc, &comp_ver) != 0) continue;

        if (db_ver != comp_ver) {
            CcspTraceInfo(("MISMATCH %s: DB=%lld COMP=%lld\n", subdoc, db_ver, comp_ver));
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
        CcspTraceInfo(("No subdoc version mismatches detected\n"));
    }

    free(reset_list);
    cJSON_Delete(arr);
    CcspTraceInfo(("=== Webconfig Selfheal Completed ===\n"));
}
