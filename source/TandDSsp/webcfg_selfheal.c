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

#include <pthread.h>
#include "webcfg_selfheal.h"

extern volatile int g_subdocForceReset_subscribed;
#define MAX_DOC_FIELD_LEN   256
#define MAX_SUBDOC_LEN      128

static char supported_bits[MAX_DOC_FIELD_LEN] = {0};
static char supported_version[MAX_DOC_FIELD_LEN] = {0};
static char supplementary_docs[MAX_DOC_FIELD_LEN] = {0};

static SubDocSupportMap_t *g_sdInfoHead = NULL;
static SubDocSupportMap_t *g_sdInfoTail = NULL;
static SupplementaryDocs_t *g_spInfoHead = NULL;
static SupplementaryDocs_t *g_spInfoTail = NULL;

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

void initWebcfgProperties(const char *filename)
{
    FILE *fp = NULL;
    char str[MAXCHAR] = {'\0'};
    char *p = NULL;
    char *token = NULL;

    freeSubDocSupportMap();
    freeSupplementaryDocsList();
	setsupportedDocs(NULL);
    setsupportedVersion(NULL);
    setsupplementaryDocs(NULL);

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
                    freeSubDocSupportMap();
					freeSupplementaryDocsList();
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
				freeSupplementaryDocsList();
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

WEBCFG_STATUS isSubDocSupported(const char *subDoc) {
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

/* SelfHeal Subdoc Version Mismatch */
static int is_ignored_subdoc(const char *name) {
    if (!name) return 1;
    return (!strcmp(name, "root") ||
            !strcmp(name, "homessid") ||
            !strcmp(name, "privatessid"));
}

static int Get_Component_Version(const char *subdoc, long long *ver_out) {
    char key[128], val[64] = {0};

    if (snprintf(key, sizeof(key), "%s_version", subdoc) >= (int)sizeof(key)) {
        CcspTraceError(("Get_Component_Version: key truncated for subdoc '%s'\n", subdoc));
        return -1;
    }
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

#define FORCERESET_SET_RETRY_COUNT    12
#define FORCERESET_SET_RETRY_DELAY   10

static int Set_Webcfg_ForceReset(const char *reset_list)
{
    rbusError_t err;
    int attempt;

    if (g_rbusHandle == NULL)
    {
        CcspTraceError(("%s: g_rbusHandle is NULL, RBUS not initialized\n", __FUNCTION__));
        return -1;
    }

    CcspTraceInfo(("%s: Setting webcfgSubdocForceReset='%s' via rbus_setStr\n",
                   __FUNCTION__, reset_list ? reset_list : "(null)"));

    for (attempt = 1; attempt <= FORCERESET_SET_RETRY_COUNT; attempt++)
    {
        err = rbus_setStr(g_rbusHandle,
                          "Device.X_RDK_WebConfig.webcfgSubdocForceReset",
                          (char *)reset_list);

        if (err == RBUS_ERROR_SUCCESS)
        {
            CcspTraceInfo(("%s: Successfully set webcfgSubdocForceReset (attempt %d)\n",
                           __FUNCTION__, attempt));
            return 0;
        }

        CcspTraceError(("%s: rbus_setStr failed, err=%d (attempt %d/%d)\n",
                        __FUNCTION__, err, attempt, FORCERESET_SET_RETRY_COUNT));

        if (attempt < FORCERESET_SET_RETRY_COUNT)
            sleep(FORCERESET_SET_RETRY_DELAY);
    }

    CcspTraceError(("%s: All %d attempts failed for webcfgSubdocForceReset\n",
                    __FUNCTION__, FORCERESET_SET_RETRY_COUNT));
    return -1;
}

static cJSON *Load_WebcfgDB_Array(void) {
    const char *bin_path = "/nvram/webconfig_db.bin";
    char *data = NULL;
    size_t len = 0;

    CcspTraceInfo(("Load_WebcfgDB_Array: reading %s directly\n", bin_path));

    FILE *fp = fopen(bin_path, "rb");
    if (!fp) {
        CcspTraceError(("fopen %s failed: %s\n", bin_path, strerror(errno)));
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        CcspTraceError(("fseek SEEK_END failed on %s\n", bin_path));
        fclose(fp);
        return NULL;
    }
    long fsize = ftell(fp);
    if (fsize <= 0) {
        CcspTraceError(("ftell returned %ld for %s\n", fsize, bin_path));
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    data = (char *)malloc((size_t)fsize);
    if (!data) {
        CcspTraceError(("malloc failed for msgpack buffer (%ld bytes)\n", fsize));
        fclose(fp);
        return NULL;
    }

    size_t nread = fread(data, 1, (size_t)fsize, fp);
    if (nread != (size_t)fsize) {
        if (ferror(fp)) {
            CcspTraceError(("fread I/O error on %s: %s\n", bin_path, strerror(errno)));
        } else {
            CcspTraceError(("fread short read on %s: expected %ld, got %zu\n",
                            bin_path, fsize, nread));
        }
        fclose(fp);
        free(data);
        return NULL;
    }
    fclose(fp);
    len = nread;

    /* Decode the top-level msgpack object (mirrors msgPackDecoder logic) */
    msgpack_unpacked msg;
    msgpack_unpacked_init(&msg);
    size_t offset = 0;

    msgpack_unpack_return ret = msgpack_unpack_next(&msg, data, len, &offset);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        CcspTraceError(("msgpack_unpack_next failed with rc=%d\n", (int)ret));
        msgpack_unpacked_destroy(&msg);
        free(data);
        return NULL;
    }

    msgpack_object root_obj = msg.data;
    if (root_obj.type != MSGPACK_OBJECT_MAP) {
        CcspTraceError(("Expected msgpack MAP at root, got type %d\n",
                        (int)root_obj.type));
        msgpack_unpacked_destroy(&msg);
        free(data);
        return NULL;
    }

    /* Locate the "webcfgdb" key in the root map */
    const msgpack_object *db_arr_obj = NULL;
    for (uint32_t i = 0; i < root_obj.via.map.size; i++) {
        const msgpack_object_kv *kv = &root_obj.via.map.ptr[i];
        if (kv->key.type == MSGPACK_OBJECT_STR &&
            kv->key.via.str.size == 8 /* strlen("webcfgdb") */ &&
            strncmp(kv->key.via.str.ptr, "webcfgdb", 8) == 0) {
            db_arr_obj = &kv->val;
            break;
        }
    }

    if (!db_arr_obj || db_arr_obj->type != MSGPACK_OBJECT_ARRAY) {
        CcspTraceError(("No valid 'webcfgdb' array in msgpack\n"));
        msgpack_unpacked_destroy(&msg);
        free(data);
        return NULL;
    }

    /* Build the cJSON array from the msgpack array entries */
    cJSON *arr = cJSON_CreateArray();
    if (!arr) {
        CcspTraceError(("cJSON_CreateArray failed\n"));
        msgpack_unpacked_destroy(&msg);
        free(data);
        return NULL;
    }

    for (uint32_t i = 0; i < db_arr_obj->via.array.size; i++) {
        const msgpack_object *entry = &db_arr_obj->via.array.ptr[i];
        if (entry->type != MSGPACK_OBJECT_MAP) continue;

        const char *name_ptr = NULL;
        size_t      name_mp_len = 0;
        long long   version = 0;
        int has_name = 0, has_ver = 0;

        for (uint32_t j = 0; j < entry->via.map.size; j++) {
            const msgpack_object_kv *kv = &entry->via.map.ptr[j];
            if (kv->key.type != MSGPACK_OBJECT_STR) continue;

            if (kv->key.via.str.size == 4 /* strlen("name") */ &&
                strncmp(kv->key.via.str.ptr, "name", 4) == 0) {
                if (kv->val.type == MSGPACK_OBJECT_STR) {
                    name_ptr    = kv->val.via.str.ptr;
                    name_mp_len = kv->val.via.str.size;
                    has_name    = 1;
                }
            } else if (kv->key.via.str.size == 7 /* strlen("version") */ &&
                       strncmp(kv->key.via.str.ptr, "version", 7) == 0) {
                if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    version = (long long)kv->val.via.u64;
                    has_ver = 1;
                } else if (kv->val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                    version = kv->val.via.i64;
                    has_ver = 1;
                }
            }
        }

        if (!has_name || !has_ver) continue;

        char name_buf[MAX_SUBDOC_LEN];
        size_t copy_len = (name_mp_len < sizeof(name_buf) - 1)
                          ? name_mp_len : sizeof(name_buf) - 1;
        memcpy(name_buf, name_ptr, copy_len);
        name_buf[copy_len] = '\0';

        cJSON *item = cJSON_CreateObject();
        if (!item) {
            CcspTraceError(("cJSON_CreateObject failed for entry %u\n", i));
            continue;
        }
        cJSON_AddStringToObject(item, "name",    name_buf);
        cJSON_AddNumberToObject(item, "version", (double)version);
        cJSON_AddItemToArray(arr, item);
    }

    CcspTraceInfo(("SUCCESS: Found %d subdocs in webcfgdb\n",
                   cJSON_GetArraySize(arr)));

    /* msg holds pointers into data; destroy both together */
    msgpack_unpacked_destroy(&msg);
    free(data);

    return arr;
}

#define SUBDOC_RESET_POLL_SEC       5
#define SUBDOC_RESET_TIMEOUT_SEC    300
#define SUBSCRIBER_WAIT_SEC         120

/*
 * Poll_Webcfg_Rbus_Element() - Poll using rbus_get until the webcfg component
 * has registered Device.X_RDK_WebConfig.webcfgSubdocForceReset.
 * Only RBUS_ERROR_SUCCESS means the element is fully available.
 * Any other error code (DESTINATION_NOT_FOUND, ELEMENT_DOES_NOT_EXIST, etc.)
 * means the component is not ready yet.
 *
 * Returns: 0 on success (webcfg ready), -1 on timeout
 */
static int Poll_Webcfg_Rbus_Element(void)
{
    int elapsed = 0;

    CcspTraceInfo(("%s: Waiting for webcfg component to register "
                   "webcfgSubdocForceReset on rbus...\n", __FUNCTION__));

    while (elapsed < SUBDOC_RESET_TIMEOUT_SEC)
    {
        rbusValue_t val = NULL;
        rbusError_t rc = rbus_get(g_rbusHandle,
                                  "Device.X_RDK_WebConfig.webcfgSubdocForceReset",
                                  &val);
        if (val)
            rbusValue_Release(val);

        if (rc == RBUS_ERROR_SUCCESS)
        {
            CcspTraceInfo(("%s: webcfg component ready after %d seconds\n",
                           __FUNCTION__, elapsed));
            return 0;
        }

        CcspTraceInfo(("%s: webcfg not ready (rbus_get rc=%d), "
                       "retry in %d sec [%d/%d]\n",
                       __FUNCTION__, rc,
                       SUBDOC_RESET_POLL_SEC, elapsed, SUBDOC_RESET_TIMEOUT_SEC));

        sleep(SUBDOC_RESET_POLL_SEC);
        elapsed += SUBDOC_RESET_POLL_SEC;
    }

    CcspTraceError(("%s: Timed out after %d seconds waiting for webcfg\n",
                    __FUNCTION__, SUBDOC_RESET_TIMEOUT_SEC));
    return -1;
}

/*
 * Wait_For_Subscriber_Ready() - Wait until the WebconfigFramework's
 * subscribeSubdocForceReset() has completed its event subscription.
 * The SET handler in the webcfg component only accepts rbus_setStr
 * after the subscriber is connected.
 *
 * Returns: 0 on success, -1 on timeout
 */
static int Wait_For_Subscriber_Ready(void)
{
    int elapsed = 0;

    CcspTraceInfo(("%s: Waiting for subdocForceReset subscriber...\n", __FUNCTION__));

    while (elapsed < SUBSCRIBER_WAIT_SEC)
    {
        if (g_subdocForceReset_subscribed == 1)
        {
            CcspTraceInfo(("%s: Subscriber ready after %d seconds\n",
                           __FUNCTION__, elapsed));
            return 0;
        }

        sleep(SUBDOC_RESET_POLL_SEC);
        elapsed += SUBDOC_RESET_POLL_SEC;
    }

    CcspTraceError(("%s: Timed out after %d seconds waiting for subscriber\n",
                    __FUNCTION__, SUBSCRIBER_WAIT_SEC));
    return -1;
}

static void *webcfg_subdoc_mismatch_boot_check_thread(void *arg)
{
    (void)arg;

    pthread_detach(pthread_self());

    if (Poll_Webcfg_Rbus_Element() != 0)
    {
        CcspTraceError(("webcfg_subdoc_mismatch_boot_check_thread: "
                        "webcfg not ready, skipping check\n"));
        return NULL;
    }

    if (Wait_For_Subscriber_Ready() != 0)
    {
        CcspTraceError(("webcfg_subdoc_mismatch_boot_check_thread: "
                        "subscriber not ready, skipping check\n"));
        return NULL;
    }

    webcfg_subdoc_mismatch_boot_check();
    return NULL;
}

void webcfg_selfheal_start(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, webcfg_subdoc_mismatch_boot_check_thread, NULL) != 0)
    {
        CcspTraceError(("webcfg_selfheal_start: Failed to create thread, "
                        "running synchronously\n"));
        webcfg_subdoc_mismatch_boot_check();
    }
    else
    {
        CcspTraceInfo(("webcfg_selfheal_start: Boot check thread launched\n"));
    }
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
        if (isSubDocSupported(subdoc) != WEBCFG_SUCCESS)
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
