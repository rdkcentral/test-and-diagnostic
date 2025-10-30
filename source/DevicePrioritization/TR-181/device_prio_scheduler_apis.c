/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
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
#include <sysevent/sysevent.h>
#include "syscfg/syscfg.h"
#include "device_prio_scheduler_apis.h"
#include "device_prio_webconfig_apis.h"
#include "device_prio_apis.h"
#include "webconfig_scheduler_doc.h"

extern int sysevent_fd;
extern token_t sysevent_token;

#define MAX_DSCP_CLIENTS_SUPPORTED 100

typedef struct marking {
    char dscp_marking[8];
    unsigned int connmark;
    char direction[32];
} marking_t;

marking_t dscp_marking_table[MAX_DSCP_CLIENTS_SUPPORTED] ;

void updateMarkingStruct(marking_t *marking, char *dscp_marking, unsigned int connmark, char* direction) {
    strncpy(marking->dscp_marking, dscp_marking, sizeof(marking->dscp_marking)-1);
    marking->connmark = connmark;
    strncpy(marking->direction, direction, sizeof(marking->direction)-1);
}

#define DSCP_TO_CONNMARK_MAP_DOES_NOT_EXIST -1
#define DSCP_TO_CONNMARK_MAP_EXIST 0

int checkIfDscpToConnmarkMapExists(char *dscp_marking, unsigned int *connmark, char* direction) {

    if (dscp_marking == NULL || connmark == NULL) {
        CcspTraceError(("%s: Invalid input parameters\n", __FUNCTION__));
        return DSCP_TO_CONNMARK_MAP_DOES_NOT_EXIST;
    }

    for (int i = 0; i < MAX_DSCP_CLIENTS_SUPPORTED; i++) {
        if ( dscp_marking_table[i].connmark == 0 ) {
            break;
        }
        
        else if ( (strcmp(dscp_marking_table[i].dscp_marking, dscp_marking) == 0) && (strcmp(dscp_marking_table[i].direction, direction) == 0) ) {
            *connmark = dscp_marking_table[i].connmark;
            return DSCP_TO_CONNMARK_MAP_EXIST;
        }
    }

    return DSCP_TO_CONNMARK_MAP_DOES_NOT_EXIST;
}

#if 0
void checkIfConnmarkIxists()
{
	char buf[16] = {0}, syscfg_param[64] = {0};
    	int prio_clients_count = 0;
    	unsigned int connmark = 0x800; // Starting bit
    	char cConnMark[32] = {0};
	snprintf(syscfg_param, sizeof(syscfg_param), "%s", SYSCFG_PRIO_CLIENT_COUNT);
	if ( syscfg_get( NULL, syscfg_param, buf, sizeof(buf)) == 0 )
	{
		prio_clients_count = atoi(buf);
        	if (prio_clients_count <= 0 ) {
            		CcspTraceError(("%s:  No clients are prioratized %d, returning\n", __FUNCTION__, prio_clients_count));
            		return ;
        	}
	}
    	else {
        	CcspTraceInfo(("%s: syscfg_get is empty for %s\n", __FUNCTION__, syscfg_param));
        	return ;
    	}   
	for(int i=1; i<=prio_clients_count; i++) 
	{
        	memset(syscfg_param, 0, sizeof(syscfg_param));
        	memset(buf, 0, sizeof(buf));
        	snprintf(syscfg_param, sizeof(syscfg_param), "%s_%d", SYSCFG_PRIO_CLIENT_CONNMARK_PREFIX, i);
        	syscfg_get( NULL, syscfg_param, buf, sizeof(buf));
        	if (buf[0] == '\0')
        	{
            		if ( connmark == 0 ) {
                		CcspTraceError(("Failure: Value exceeded 0xFFFFFFFF.\n"));  
                		return;
            		}            
            		snprintf(syscfg_param, sizeof(syscfg_param), "%s_%d", SYSCFG_PRIO_CLIENT_CONNMARK_PREFIX, prio_clients_count);
            		memset(cConnMark, 0, sizeof(cConnMark));
            		snprintf(cConnMark, sizeof(cConnMark), "0x%X", connmark);
            		if(syscfg_set_commit(NULL, syscfg_param, cConnMark) != 0)
            		{
                		CcspTraceError(("syscfg_set failed for %s\n", syscfg_param));
                		return;
            		}
        	}
        	connmark <<= 1; // Shift left by one position to enable the next bit
    	}
}

#endif 
int clean_prev_syscfg_params() {
    char buf[10] = {0}, syscfg_param[64] = {0};
    int prio_clients_count = 0;

	snprintf(syscfg_param, sizeof(syscfg_param), "%s", SYSCFG_PRIO_CLIENT_COUNT);
	if ( syscfg_get( NULL, syscfg_param, buf, sizeof(buf)) == 0 )
	{
		prio_clients_count = atoi(buf);
        if (prio_clients_count <= 0 ) {
            CcspTraceError(("%s: Invalid prio clients count %d\n", __FUNCTION__, prio_clients_count));
            return -1;
        }
	}
    else {
        CcspTraceInfo(("%s: syscfg_get is empty for %s\n", __FUNCTION__, syscfg_param));
        return -1;
    }

    for(int i=1; i<=prio_clients_count; i++) {

        /*Delete prev mac addresses from syscfg db*/
        memset(syscfg_param, 0, sizeof(syscfg_param));
        snprintf(syscfg_param, sizeof(syscfg_param), "%s_%d", SYSCFG_PRIO_CLIENT_MAC_PREFIX, i);
        if (syscfg_unset(NULL, syscfg_param) != 0) {
            CcspTraceError(("%s: syscfg_unset %s\n", __FUNCTION__, syscfg_param));
            return -1;
        }

        /*Delete prev dscp value from syscfg db*/
        memset(syscfg_param, 0, sizeof(syscfg_param));
        snprintf(syscfg_param, sizeof(syscfg_param), "%s_%d", SYSCFG_PRIO_CLIENT_DSCP_PREFIX, i);
        if (syscfg_unset(NULL, syscfg_param) != 0) {
            CcspTraceError(("%s: syscfg_unset %s\n", __FUNCTION__, syscfg_param));
            return -1;
        }

        /*Delete prev action from syscfg db*/
        memset(syscfg_param, 0, sizeof(syscfg_param));
        snprintf(syscfg_param, sizeof(syscfg_param), "%s_%d", SYSCFG_PRIO_CLIENT_ACTION_PREFIX, i);
        if (syscfg_unset(NULL, syscfg_param) != 0) {
            CcspTraceError(("%s: syscfg_unset %s\n", __FUNCTION__, syscfg_param));
            return -1;
        }

        /*Delete connmark  from syscfg db*/
        memset(syscfg_param, 0, sizeof(syscfg_param));
        snprintf(syscfg_param, sizeof(syscfg_param), "%s_%d", SYSCFG_PRIO_CLIENT_CONNMARK_PREFIX, i);
        if (syscfg_unset(NULL, syscfg_param) != 0) {
            CcspTraceError(("%s: syscfg_unset %s\n", __FUNCTION__, syscfg_param));
            return -1;
        }
    }

    /*Delete prev prio clients count from syscfg db*/
    memset(syscfg_param, 0, sizeof(syscfg_param));
    snprintf(syscfg_param, sizeof(syscfg_param), "%s", SYSCFG_PRIO_CLIENT_COUNT);
    if (syscfg_unset(NULL, syscfg_param) != 0) {
        CcspTraceError(("%s: syscfg_unset %s\n", __FUNCTION__, syscfg_param));
        return -1;
    }

    return 0;
}

int trigger_firewall_restart() {
    CcspTraceInfo(("Restarting firewall.. \n"));
    if (0 > sysevent_fd)
    {
        CcspTraceError(("%s: Failed to execute sysevent_set. sysevent_fd have no value:'%d'\n", __FUNCTION__, sysevent_fd));
        return -1;
    }
    
    if(sysevent_set(sysevent_fd, sysevent_token, "firewall-restart", "", 0) != 0)
    {
        CcspTraceError(("Failed to execute sysevent_set from %s:%d\n", __FUNCTION__, __LINE__));
        return -1;
    }
    return 0;
}

void priomac_operation(char* priomac_str_bundle) {

    int prio_clients_count = 0;
    char mac_address[18];
    char dscp_str[5];
    char action[32];
    char cConnMark[32] = {0};

    char syscfg_param[64] = {0};
    char buf[10] = {0};
    unsigned int connmark = 0x800; // Starting bit
    unsigned int connmark_temp = 0; // Starting bit
    int markingTableIndex = 0;
    memset(dscp_marking_table, 0, sizeof(dscp_marking_table));
    if (0 != clean_prev_syscfg_params()) {
        CcspTraceWarning(("%s: clean_prev_syscfg_params() nothing to clean\n", __FUNCTION__));
    }

    //To remove all prio clients
    if (NULL == priomac_str_bundle) {
        CcspTraceInfo(("%s: Empty priomac bundle \n", __FUNCTION__));
        if(0 != trigger_firewall_restart()) {
            CcspTraceError(("%s: failed firewall restart.\n", __FUNCTION__));
        }
        // Set Qos Active Rules TR181
        if (0 != DevicePrio_Set_QOS_Active_Rules()) {
            CcspTraceError(("%s: Set Qos active rules failed.\n", __FUNCTION__));
        }
        return;
    }

    char *buffer = strdup(priomac_str_bundle); // Create a copy of priomac_str_bundle

    if (NULL == buffer) {
        CcspTraceError(("%s: priomac bundle copy failed.\n", __FUNCTION__));
        return;
    }

    // Start parsing
    char *line = buffer;
    while (1) 
    {
        int num_fields = sscanf(line, "%[^,],%[^,],%31s", mac_address, dscp_str, action);
        if (num_fields == 3) 
        {
            connmark_temp=0;
            /*Increment total number of prio clients count in current schedule*/
            prio_clients_count++;

            /*Set mac address in syscfg db*/
            snprintf(syscfg_param, sizeof(syscfg_param), "%s_%d", SYSCFG_PRIO_CLIENT_MAC_PREFIX, prio_clients_count);
            if(syscfg_set_commit(NULL, syscfg_param, mac_address) != 0)
            {
                CcspTraceError(("syscfg_set failed for %s\n", syscfg_param));
                free(buffer);
                return;
            }
            memset(syscfg_param, 0, sizeof(syscfg_param));
            
            /*Set action in syscfg db*/
            snprintf(syscfg_param, sizeof(syscfg_param), "%s_%d", SYSCFG_PRIO_CLIENT_ACTION_PREFIX, prio_clients_count);
            if(syscfg_set_commit(NULL, syscfg_param, action) != 0)
            {
                CcspTraceError(("syscfg_set failed for %s\n", syscfg_param));
                free(buffer);
                return;
            }
            memset(syscfg_param, 0, sizeof(syscfg_param));

            /*Set Dscp value in syscfg db*/
            snprintf(syscfg_param, sizeof(syscfg_param), "%s_%d", SYSCFG_PRIO_CLIENT_DSCP_PREFIX, prio_clients_count);
            if(syscfg_set_commit(NULL, syscfg_param, dscp_str) != 0)
            {
                CcspTraceError(("syscfg_set failed for %s\n", syscfg_param));
                free(buffer);
                return;
            }

            memset(syscfg_param, 0, sizeof(syscfg_param));

            if (checkIfDscpToConnmarkMapExists(dscp_str, &connmark_temp,action) == DSCP_TO_CONNMARK_MAP_DOES_NOT_EXIST) {
                CcspTraceInfo(("DSCP marking %s does not exist in the table, adding it\n", dscp_str));
                updateMarkingStruct(&dscp_marking_table[markingTableIndex], dscp_str, connmark,action);
                markingTableIndex++;
                connmark_temp = connmark;
                connmark <<= 1; // Shift left by one position to enable the next bit
            }
            else {
                CcspTraceInfo(("DSCP marking %s already exists in the table, connmark is 0x%X\n", dscp_str,connmark_temp));
               // connmark = connmark_temp;
            }
            CcspTraceInfo(("Connmark: 0x%X \n", connmark_temp));
            if ( connmark == 0 ) {
                CcspTraceError(("Failure: Value exceeded 0xFFFFFFFF.\n"));  
                free(buffer);
                return;
            }
                        
            snprintf(syscfg_param, sizeof(syscfg_param), "%s_%d", SYSCFG_PRIO_CLIENT_CONNMARK_PREFIX, prio_clients_count);
            memset(cConnMark, 0, sizeof(cConnMark));
            snprintf(cConnMark, sizeof(cConnMark), "0x%X", connmark_temp);
            if(syscfg_set_commit(NULL, syscfg_param, cConnMark) != 0)
            {
                CcspTraceError(("syscfg_set failed for %s\n", syscfg_param));
                free(buffer);
                return;
            }
        }

        memset(syscfg_param, 0, sizeof(syscfg_param));

        CcspTraceInfo(("%s: 'Client %d' --> Mac:%s, Dscp:%s, Action:%s\n", 
                        __FUNCTION__, prio_clients_count, mac_address, dscp_str, action));

        memset(mac_address, 0, sizeof(mac_address));
        memset(action, 0, sizeof(action));
        memset(dscp_str, 0, sizeof(dscp_str));

        line = strchr(line, '\n'); // Move to the next newline character
        if (line == NULL)
            break;

        line++; // Move past the newline character
    }

    /*Set prio clients count in syscfg db*/
    CcspTraceInfo(("%s: Prio Clients count = %d\n", __FUNCTION__, prio_clients_count));
    snprintf(syscfg_param, sizeof(syscfg_param), "%s", SYSCFG_PRIO_CLIENT_COUNT);
    snprintf(buf, sizeof(buf), "%d", prio_clients_count);
    if(syscfg_set_commit(NULL, syscfg_param, buf) != 0)
    {
        CcspTraceError(("syscfg_set failed for %s\n", syscfg_param));
        free(buffer);
        return;
    }

    free(buffer); // Free the dynamically allocated buffer

    if(0 != trigger_firewall_restart()) {
        CcspTraceError(("%s: failed firewall restart.\n", __FUNCTION__));
        return;
    }

    // Set Qos Active Rules TR181
    if (0 != DevicePrio_Set_QOS_Active_Rules()) {
        CcspTraceError(("%s: Set Qos active rules failed.\n", __FUNCTION__));
        return;
    }

}

int device_prio_scheduler_init() {
    SchedulerData init_data =  {
                                .data_file = PRIOMAC_DATAFILE,
                                .md5_file = PRIOMAC_MD5FILE,
                                .max_actions = 0,
                                .scheduler_action = priomac_operation,
                                .scheduler_action_key = QOS_CLIENT_RULES_ALIAS,
                                .instanceNum = 0
                            };

    SchedulerData data[] = { init_data };

    int data_size = sizeof(data) / sizeof(data[0]);

    return scheduler_init(data, data_size, TDM_RDK_LOG_MODULE);
}
