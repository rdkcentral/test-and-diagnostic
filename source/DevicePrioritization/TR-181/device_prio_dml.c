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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "device_prio_dml.h"
#include "device_prio_apis.h"

#ifdef RDK_SCHEDULER_ENABLED
#include "device_prio_webconfig_apis.h"
#endif //#ifdef RDK_SCHEDULER_ENABLED

LONG
DscpControl_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
	UNREFERENCED_PARAMETER(hInsContext);

	if (strcmp(pParamName, "ActiveRules") == 0)
    {
		if (!DevicePrio_Get_Parameter_Struct_Value(DP_QOS_ACTIVE_RULES, pValue)) {
			CcspTraceError(("%s for parameter '%s' failed.\n", __FUNCTION__, pParamName));
			return 1;
		}
		*pUlSize = strlen(pValue) + 1;
		return 0;
	}

	CcspTraceWarning(("%s:Unsupported parameter '%s'\n", __FUNCTION__, pParamName));
    return 1;
}

BOOL
DscpControl_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);

#ifdef RDK_SCHEDULER_ENABLED	
    if (strcmp(pParamName, "Data") == 0)
    {
		if(pString != NULL)	
        {
            CcspTraceInfo(("---------------start of b64 decode--------------\n"));

            char * decodeMsg = NULL;
            int size =0;
	    	int retval = 0;
	    	msgpack_unpack_return unpack_ret = MSGPACK_UNPACK_SUCCESS;
            retval = get_base64_decodedbuffer(pString, &decodeMsg, &size);
			
			if (retval == 0)
			{
				unpack_ret = get_msgpack_unpack_status(decodeMsg,size);
			}
			else
			{
				if (decodeMsg)
				{
					free(decodeMsg);
					decodeMsg = NULL;
				}
				CcspTraceError(("decodeMsg allocation failed\n"));
				return FALSE;
					
			}

	    	CcspTraceInfo(("---------------End of b64 decode--------------\n"));

			if(unpack_ret == MSGPACK_UNPACK_SUCCESS)
			{
				scheduler_doc_t *sd;
				sd = scheduler_doc_convert(decodeMsg, size); //used to process the incoming msgobject

				if( decodeMsg )
				{
					free(decodeMsg);
					decodeMsg = NULL;
				}

				if(sd != NULL)
				{
					CcspTraceInfo(("sd->subdoc_name is %s\n", sd->subdoc_name));
					CcspTraceInfo(("sd->version is %lu\n", (unsigned long)sd->version));
					CcspTraceInfo(("sd->transaction_id %d\n", sd->transaction_id));
					CcspTraceInfo(("Scheduler configuration received\n"));

					execData *execDataSd = NULL ;
					execDataSd = (execData*) malloc (sizeof(execData));

					if ( execDataSd != NULL )
					{
						memset(execDataSd, 0, sizeof(execData));
						execDataSd->txid = sd->transaction_id; 
						execDataSd->version = sd->version; 
						execDataSd->numOfEntries = 0; 

						strncpy(execDataSd->subdoc_name, PRIO_MAC_SUBDOC, sizeof(execDataSd->subdoc_name)-1);
						execDataSd->user_data = (void*) sd ;
						execDataSd->calcTimeout = NULL ;
						execDataSd->executeBlobRequest = process_DCPC_WebConfigRequest;
						execDataSd->rollbackFunc = NULL ;
						execDataSd->freeResources = freeResources_scheduler_doc ;
						PushBlobRequest(execDataSd);
						CcspTraceInfo(("PushBlobRequest complete\n"));
						return TRUE;
					}
					else 
					{
						CcspTraceError(("execData memory allocation failed\n"));
						scheduler_doc_destroy(sd);
						return FALSE;
					}	
				}
				return TRUE;                    
			}
			else
			{
				if ( decodeMsg )
				{
					free(decodeMsg);
					decodeMsg = NULL;
				}
				CcspTraceError(("Corrupted %s msgpack value\n", PRIO_MAC_SUBDOC));
				return FALSE;
			}
			return TRUE;	
		}
        return TRUE;
    }

#endif //#ifdef RDK_SCHEDULER_ENABLED

	CcspTraceWarning(("%s:Unsupported parameter '%s'\n", __FUNCTION__, pParamName));
    return FALSE;
}
