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

/**************************************************************************

    module: cosa_diagnostic_apis.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

        *  CosaDiagCreate
        *  CosaDiagInitialize
        *  CosaDiagRemove
    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**************************************************************************/
#include "plugin_main_apis.h"
#include "cosa_diagnostic_apis.h"
#include "secure_wrapper.h"
#include "arpa/inet.h"
#include <utctx/utctx.h>
#include <utctx/utctx_api.h>
#include <utapi.h>

#define ARP_CACHE_FILE "/tmp/.tmp_arp_cache"

static void s_parse_arp_cache (char *line, arpHost_t *host_info)
{
    char stub[64], is_static[32];

    /*
     * Sample line
     *   192.168.1.113 dev br0 lladdr 00:23:32:c8:28:d8 REACHABLE
     */
    sscanf(line, "%s %s %s %s %s %s", 
                 host_info->ipaddr,
                 stub,
                 host_info->interface,
                 stub,
                 host_info->macaddr,
                 is_static);
    host_info->is_static = ( 0 == strcmp(is_static, "PERMANENT")) ? TRUE : FALSE;
}

static int _GetARPCacheEntries (int *count, arpHost_t **out_hosts)
{
    char line[512];
    int ct = 0;

    *out_hosts = NULL;

    arpHost_t *hosts = NULL;

    v_secure_system("ip neigh show > " ARP_CACHE_FILE);

    FILE *fp = fopen(ARP_CACHE_FILE, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
           hosts = (arpHost_t *) realloc(hosts, sizeof(arpHost_t) * (ct+1));
           if (NULL == hosts) {
               unlink(ARP_CACHE_FILE);
               fclose(fp); /*RDKB-7460, CID-33311, free unused resources*/
               return ERR_INSUFFICIENT_MEM;
           }
           s_parse_arp_cache(line, &hosts[ct]);
           ct++;
        }
        fclose(fp);
    }
    unlink(ARP_CACHE_FILE);

    *count = ct;
    *out_hosts = hosts;

    return UT_SUCCESS;
}


/**********************************************************************

    caller:     self

    prototype:

        PCOSA_DML_DIAG_ARP_TABLE
        CosaDmlDiagGetARPTablePriv
            (
                ANSC_HANDLE                 hContext,
                PULONG                          pulCount
            )
        Description:
            This routine is to retrieve the complete list of arp table, which is a dynamic table.

        Arguments:
            pulCount  is to receive the actual number of entries.

        Return:
            The pointer to the array of arp table, allocated by callee. If no entry is found, NULL is returned.

**********************************************************************/
PCOSA_DML_DIAG_ARP_TABLE
CosaDmlDiagGetARPTablePriv

    (
        ANSC_HANDLE                 hContext,
        PULONG                      pulCount
    )
{
    arpHost_t *host = NULL;
    PCOSA_DML_DIAG_ARP_TABLE pTable = NULL;
    int i = 0, count;
    unsigned int mac[6];
    *pulCount = 0;
    if( UT_SUCCESS == _GetARPCacheEntries(&count, &host) && count != 0){
        if( NULL != (pTable = (PCOSA_DML_DIAG_ARP_TABLE)AnscAllocateMemory(count * sizeof(COSA_DML_DIAG_ARP_TABLE)))){
             while(i < count){
                strncpy(pTable[i].IPAddress, host[i].ipaddr, sizeof(pTable[i].IPAddress)-1);
		pTable[i].IPAddress[sizeof(pTable[i].IPAddress)-1] = '\0'; //CID 163347: Buffer not null terminated
                sscanf(host[i].macaddr, "%x:%x:%x:%x:%x:%x", &(mac[0]), &(mac[1]), &(mac[2]), &(mac[3]), &(mac[4]), &mac[5]); 
                pTable[i].MACAddress[0] = (UCHAR)mac[0];
                pTable[i].MACAddress[1] = (UCHAR)mac[1];
                pTable[i].MACAddress[2] = (UCHAR)mac[2];
                pTable[i].MACAddress[3] = (UCHAR)mac[3];
                pTable[i].MACAddress[4] = (UCHAR)mac[4];
                pTable[i].MACAddress[5] = (UCHAR)mac[5];
                pTable[i].Static = host[i].is_static;
                i++;
            }
            *pulCount = count;
        }
    }

    /*RDKB-7460,CID-33043, free unused resources*/
    if(host)
    {
        free(host);
    }

    return pTable;
}
