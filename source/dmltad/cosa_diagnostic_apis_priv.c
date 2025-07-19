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

        *  CosaDmlDiagGetARPTablePriv
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


#if (defined(_COSA_SIM_))

static COSA_DML_DIAG_ARP_TABLE   g_diag_arptable[] =
    {
        {
            {
                "\x40\x40\x40\x01"
            },
            {
                "\x01\x00\x0c\x07\x08\x09"
            }
        }
    };


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
    PCOSA_DML_DIAG_ARP_TABLE        pARPTable = NULL;

    pARPTable = (PCOSA_DML_DIAG_ARP_TABLE)AnscAllocateMemory( sizeof(g_diag_arptable) );

    if ( pARPTable )
    {
         AnscCopyMemory(pARPTable, g_diag_arptable, sizeof(g_diag_arptable) );

        *pulCount = sizeof(g_diag_arptable)/sizeof(COSA_DML_DIAG_ARP_TABLE);
    }
    else
    {
        *pulCount = 0;
    }

    return pARPTable;
}

#else

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
    *pulCount = 0;

    return NULL;
}


#endif
