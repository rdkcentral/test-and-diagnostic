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
#include <syscfg/syscfg.h>
#include "webconfig_framework.h"
#include <trower-base64/base64.h>
#include "safec_lib_common.h"
#include "device_prio_webconfig_apis.h"
#include "device_prio_scheduler_apis.h"

int get_base64_decodedbuffer(char *pString, char **buffer, int *size)
{
    int decodeMsgSize = 0;
    char *decodeMsg = NULL;
    if (buffer == NULL || size == NULL || pString == NULL)
        return -1;

    decodeMsgSize = b64_get_decoded_buffer_size(strlen(pString));

    decodeMsg = (char *) malloc(sizeof(char) * decodeMsgSize);

    if (!decodeMsg)
        return -1;

    *size = b64_decode( (const uint8_t*)pString, strlen(pString), (uint8_t *)decodeMsg );
    CcspTraceWarning(("base64 decoded data contains %d bytes\n",*size));

    *buffer = decodeMsg;
    return 0;
}

msgpack_unpack_return get_msgpack_unpack_status(char *decodedbuf, int size)
{

    msgpack_zone mempool;
    msgpack_object deserialized;
    msgpack_unpack_return unpack_ret;

    if (decodedbuf == NULL || !size)
        return MSGPACK_UNPACK_NOMEM_ERROR;

    msgpack_zone_init(&mempool, MSGPACK_ZONE_CHUNK_SIZE);
    unpack_ret = msgpack_unpack(decodedbuf, size, NULL, &mempool, &deserialized);

    switch(unpack_ret)
    {
        case MSGPACK_UNPACK_SUCCESS:
            CcspTraceWarning(("MSGPACK_UNPACK_SUCCESS :%d\n",unpack_ret));
            break;
        case MSGPACK_UNPACK_EXTRA_BYTES:
            CcspTraceWarning(("MSGPACK_UNPACK_EXTRA_BYTES :%d\n",unpack_ret));
            break;
        case MSGPACK_UNPACK_CONTINUE:
            CcspTraceWarning(("MSGPACK_UNPACK_CONTINUE :%d\n",unpack_ret));
            break;
        case MSGPACK_UNPACK_PARSE_ERROR:
            CcspTraceWarning(("MSGPACK_UNPACK_PARSE_ERROR :%d\n",unpack_ret));
            break;
        case MSGPACK_UNPACK_NOMEM_ERROR:
            CcspTraceWarning(("MSGPACK_UNPACK_NOMEM_ERROR :%d\n",unpack_ret));
            break;
        default:
            CcspTraceWarning(("Message Pack decode failed with error: %d\n", unpack_ret));
    }

    msgpack_zone_destroy(&mempool);
    //End of msgpack decoding

    return unpack_ret;
}

/* API to get the subdoc version */
uint32_t getBlobVersion(char* subdoc)
{

	char subdoc_ver[64] = {0}, buf[72] = {0};
	snprintf(buf,sizeof(buf),"%s_version",subdoc);
	if ( syscfg_get( NULL, buf, subdoc_ver, sizeof(subdoc_ver)) == 0 )
	{
		int version = atoi(subdoc_ver);
		return (uint32_t)version;
	}
	return 0;
}

/* API to update the subdoc version */
int setBlobVersion(char* subdoc,uint32_t version)
{

	char subdoc_ver[32] = {0}, buf[72] = {0};
  	snprintf(subdoc_ver,sizeof(subdoc_ver),"%u",version);
  	snprintf(buf,sizeof(buf),"%s_version",subdoc);

 	if(syscfg_set_commit(NULL,buf,subdoc_ver) != 0)
 	{
        CcspTraceError(("syscfg_set failed\n"));
        return -1;
 	}
     	
	return 0;    	 
}

/* API to register all the supported subdocs , versionGet and versionSet are callback functions 
to get and set the subdoc versions in db */
void webConfigFrameworkInit()
{
	char *sub_docs[SUBDOC_COUNT+1]= {PRIO_MAC_SUBDOC,(char *) 0 };
	blobRegInfo *blobData;

	blobData = (blobRegInfo*) malloc(SUBDOC_COUNT * sizeof(blobRegInfo));

	int i;
	memset(blobData, 0, SUBDOC_COUNT * sizeof(blobRegInfo));

	blobRegInfo *blobDataPointer = blobData;


	for (i=0 ; i < SUBDOC_COUNT ; i++ )
	{
		strncpy( blobDataPointer->subdoc_name, sub_docs[i], sizeof(blobDataPointer->subdoc_name)-1);

		blobDataPointer++;
	}

	blobDataPointer = blobData ;

	getVersion versionGet = getBlobVersion;

	setVersion versionSet = setBlobVersion;

	register_sub_docs(blobData,SUBDOC_COUNT,versionGet,versionSet);

}

/* CallBack API to execute DscpControlPerClient Blob request */
pErr process_DCPC_WebConfigRequest(void *Data)
{
    CcspTraceWarning(("%s: called\n", __FUNCTION__));
    pErr execRetVal = NULL;
    execRetVal = (pErr) malloc (sizeof(Err));
    if (execRetVal == NULL )
    {
        CcspTraceError(("%s : malloc failed\n",__FUNCTION__));
        return execRetVal;
    }

    memset(execRetVal,0,sizeof(Err));

    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;

    scheduler_doc_t *sd = (scheduler_doc_t *) Data;

    CcspTraceInfo(("sd->subdoc_name is %s\n", sd->subdoc_name));
    CcspTraceInfo(("sd->version is %lu\n", (long)sd->version));
    CcspTraceInfo(("sd->transaction_id %lu\n",(long) sd->transaction_id));

    if (sd->scheduler_info != NULL) {

        int count = sd->scheduler_info->actions_size;
        // Validate each qos rule
        for (int i=0; i<count; i++) {
            char* rule_set = strdup(sd->scheduler_info->actions[i]);
            if (NULL == rule_set) {
                CcspTraceError(("%s: unable to find qos rule\n", __FUNCTION__));
                execRetVal->ErrorCode = QOS_RULE_EMPTY;
                strncpy(execRetVal->ErrorMsg,"unable to find qos rule",sizeof(execRetVal->ErrorMsg)-1);
                return execRetVal;
            }

            int valid_error = validateQosRule(rule_set);

            if (QOS_RULE_OK != valid_error) {
                CcspTraceError(("%s: qos rule validation failed\n", __FUNCTION__));
            
                execRetVal->ErrorCode = VALIDATION_FALIED;
                if (valid_error == QOS_RULE_INVALID_MAC) {
                    snprintf(execRetVal->ErrorMsg, sizeof(execRetVal->ErrorMsg)-1, "qos rule validation failed invalid mac:%s", rule_set);
                }
                else if (valid_error == QOS_RULE_INVALID_DSCP) {
                    snprintf(execRetVal->ErrorMsg, sizeof(execRetVal->ErrorMsg)-1, "qos rule validation failed invalid dscp:%s", rule_set);
                }
                else if (valid_error == QOS_RULE_INVALID_ACTION) {
                    snprintf(execRetVal->ErrorMsg, sizeof(execRetVal->ErrorMsg)-1, "qos rule validation failed invalid action:%s", rule_set);
                }
                else {
                    snprintf(execRetVal->ErrorMsg, sizeof(execRetVal->ErrorMsg)-1, "qos rule validation failed: %s", rule_set);
                }            
                free(rule_set);
                return execRetVal;
            }

            free(rule_set);
        }

        if (0 == run_schedule(sd->scheduler_info, QOS_CLIENT_RULES_ALIAS)) {
            CcspTraceInfo(("%s: Scheduler started..\n", __FUNCTION__));
            execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
        }
        else {
            CcspTraceInfo(("%s: Failed to start scheduler.\n", __FUNCTION__));
            execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
        }
    }
    else {
        CcspTraceInfo(("%s: Empty scheduler info.\n", __FUNCTION__));
        if (0 == delete_schedule(QOS_CLIENT_RULES_ALIAS)) {
            CcspTraceInfo(("%s: Scheduler stopped.\n", __FUNCTION__));
            priomac_operation(NULL);
            execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
           // strncpy(execRetVal->ErrorMsg,"Removed prioritization of clients",sizeof(execRetVal->ErrorMsg)-1);
            CcspTraceInfo(("%s: Cleaned all device prioritizations.\n", __FUNCTION__));            
        }
        else {
            CcspTraceError(("%s: Failed to stop scheduler.\n", __FUNCTION__));
            execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
            strncpy(execRetVal->ErrorMsg,"Failed to stop scheduler",sizeof(execRetVal->ErrorMsg)-1);
        }
    }

    //No need to destroy scheduler doc
    //will destroy the scheduler doc from freeResources_scheduler_doc by webconfigframework

    return execRetVal;
}

void freeResources_scheduler_doc(void *arg)
{
    CcspTraceInfo((" Entering %s \n",__FUNCTION__));
    execData *blob_exec_data  = (execData*) arg;
    /*CID: 158837 Dereference before null check*/
    if(!blob_exec_data)
       return;
    scheduler_doc_t *s = (scheduler_doc_t *) blob_exec_data->user_data;

    if ( s != NULL )
    {
        scheduler_doc_destroy( s );
        s = NULL;
    }

    if ( blob_exec_data != NULL )
    {
        free(blob_exec_data);
        blob_exec_data = NULL ;
    }
}


int validateQosRule(char* rule) {
    char *token[QOS_RULES_MAX_FIELDS];
    int field_count = 0;

    CcspTraceInfo(("%s: Validating qos rule: %s\n", __FUNCTION__, rule));

    // Tokenize the input line using comma as the delimiter
    char line_copy[QOS_RULE_MAX_BUFFER_SIZE] = {0};
    strncpy(line_copy, rule, sizeof(line_copy));
    line_copy[strlen(rule)] = '\0';

    char *ptr = strtok(line_copy, ",");
    while (ptr != NULL && field_count < QOS_RULES_MAX_FIELDS) {
        token[field_count] = ptr;
        field_count++;
        ptr = strtok(NULL, ",");
    }

    if (field_count == QOS_RULES_MAX_FIELDS) {
        if (Validate_Mac(token[0]) && validateDSCP(atoi(token[1])) && validateAction(token[2])) {
            CcspTraceInfo(("%s: Valid set: Client-MAC: %s, DSCP: %d, ACTION: %s\n", __FUNCTION__, token[0], atoi(token[1]), token[2]));
            return QOS_RULE_OK;
        } else {
            if (!Validate_Mac(token[0])) {
                CcspTraceError(("%s: %s - Invalid MAC address format\n", __FUNCTION__, token[0]));
                return QOS_RULE_INVALID_MAC;
            }
            if (!validateDSCP(atoi(token[1]))) {
                CcspTraceError(("%s: %s - Invalid DSCP value\n", __FUNCTION__, token[1]));
                return QOS_RULE_INVALID_DSCP;
            }
            if (!validateAction(token[2])) {
                CcspTraceError(("%s: %s - Invalid ACTION value\n", __FUNCTION__, token[2]));
                return QOS_RULE_INVALID_ACTION;
            }
        }
    } else {
        CcspTraceError(("%s: Input rule does not have enough fields.\n", __FUNCTION__));
        return QOS_RULE_INVALID;
    }

    return QOS_RULE_INVALID;
}

// Function to validate MAC address format
bool CheckMacHasValidCharacter (char* pMac)
{
    int i;

    for (i = 0; i < 6; i++)
    {
        if ((isxdigit(pMac[0])) &&
            (isxdigit(pMac[1])) &&
            (pMac[2] == ((i == 5) ? 0 : ':')))
        {
            pMac += 3;
        }
        else
        {
            return false;
        }
    }

    return true;
}

bool Validate_Mac(char* physAddress)
{
    bool bvalid = false;
    if(!physAddress || \
            0 == strcmp(physAddress, "00:00:00:00:00:00"))
    {
        return false;
    }

    if(strlen(physAddress) != MACADDR_SZ-1)
    {
        return false;
    }

    bvalid = CheckMacHasValidCharacter(physAddress);
    
    return bvalid;
}

// Function to validate ACTION field
int validateAction(const char *action) {
    return (strcmp(action, "MARK_UPSTREAM") == 0 ||
            strcmp(action, "MARK_DOWNSTREAM") == 0 ||
            strcmp(action, "MARK_BOTH") == 0);
}

// Function to validate DSCP field
int validateDSCP(int dscp) {
    return (dscp >= 0 && dscp <= 63);
}
