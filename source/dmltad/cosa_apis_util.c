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


/**********************************************************************

    module:	cosa_apis_util.h

        This is base file for all parameters H files.

    ---------------------------------------------------------------

    description:

        This file contains all utility functions for COSA DML API development.

    ---------------------------------------------------------------

    environment:

        COSA independent

    ---------------------------------------------------------------

    author:

        Roger Hu

    ---------------------------------------------------------------

    revision:

        01/30/2011    initial revision.

**********************************************************************/



#include "cosa_apis.h"
#include "plugin_main_apis.h"
#include "safec_lib_common.h"

#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include "ansc_platform.h"
#include <ctype.h>


ANSC_STATUS
CosaUtilStringToHex
    (
        char          *str,
        unsigned char *hex_str
    )
{
    INT   i = 0, index = 0, val = 0;
    CHAR  byte[3]       = {'\0'};

    while(str[i] != '\0')
    {
        byte[0] = str[i];
        byte[1] = str[i+1];
        byte[2] = '\0';
        if(_ansc_sscanf(byte, "%x", &val) != 1)
            break;
	hex_str[index] = val;
        i += 2;
        index++;
    }
    if(index != 8)
        return ANSC_STATUS_FAILURE;

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaSListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCOSA_CONTEXT_LINK_OBJECT   pCosaContext
    )
{
    PCOSA_CONTEXT_LINK_OBJECT       pCosaContextEntry = (PCOSA_CONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pCosaContext->InstanceNumber < pCosaContextEntry->InstanceNumber )
            {
                AnscSListPushEntryByIndex(pListHead, &pCosaContext->Linkage, ulIndex);

                return ANSC_STATUS_SUCCESS;
            }
        }

        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }

    return ANSC_STATUS_SUCCESS;
}

PCOSA_CONTEXT_LINK_OBJECT
CosaSListGetEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        ULONG                       InstanceNumber
    )
{
    PCOSA_CONTEXT_LINK_OBJECT       pCosaContextEntry = (PCOSA_CONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        return NULL;
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pCosaContextEntry->InstanceNumber == InstanceNumber )
            {
                return pCosaContextEntry;
            }
        }
    }

    return NULL;
}

PUCHAR
CosaUtilGetLowerLayers
    (
        PUCHAR                      pTableName,
        PUCHAR                      pKeyword
    )
{

    ULONG                           ulNumOfEntries              = 0;
    ULONG                           i                           = 0;
    ULONG                           j                           = 0;
    ULONG                           ulEntryNameLen              = 256;
    char                            ucEntryParamName[256+12]    = {0};
    char                            ucEntryNameValue[256]       = {0};
    char                            ucEntryFullPath[256]        = {0};
    char                            ucLowerEntryPath[256+21]    = {0};
    UCHAR                           ucLowerEntryName[256+7]     = {0};
    ULONG                           ulEntryInstanceNum          = 0;
    ULONG                           ulEntryPortNum              = 0;
    PUCHAR                          pMatchedLowerLayer          = NULL;
    PANSC_TOKEN_CHAIN               pTableListTokenChain        = (PANSC_TOKEN_CHAIN)NULL;
    PANSC_STRING_TOKEN              pTableStringToken           = (PANSC_STRING_TOKEN)NULL;
    errno_t                         rc                          = -1;

    if ( !pTableName || AnscSizeOfString(pTableName) == 0 ||
         !pKeyword   || AnscSizeOfString(pKeyword) == 0
       )
    {
        return NULL;
    }

    pTableListTokenChain = AnscTcAllocate(pTableName, ",");

    if ( !pTableListTokenChain )
    {
        return NULL;
    }

    while ((pTableStringToken = AnscTcUnlinkToken(pTableListTokenChain)))
    {
        if ( strlen(pTableStringToken->Name) != 0 )
        {
            if (strcmp(pTableStringToken->Name, "Device.Ethernet.Interface.") == 0)
            {
                ulNumOfEntries =       CosaGetParamValueUlong("Device.Ethernet.InterfaceNumberOfEntries");

                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex("Device.Ethernet.Interface.", i);

                    if ( ulEntryInstanceNum )
                    {
                        rc = sprintf_s(ucEntryFullPath, sizeof(ucEntryFullPath) , "Device.Ethernet.Interface.%lu", ulEntryInstanceNum);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }


                        rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName) , "%s.Name", ucEntryFullPath);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }
               
                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             (strcmp(ucEntryNameValue, pKeyword) == 0))
                        {
                            pMatchedLowerLayer =  AnscCloneString(ucEntryFullPath);

                            break;
                        }
                    }
                }
            }
            else if (strcmp(pTableStringToken->Name, "Device.IP.Interface.") == 0)
            {
                ulNumOfEntries =       CosaGetParamValueUlong("Device.IP.InterfaceNumberOfEntries");
                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex("Device.IP.Interface.", i);

                    if ( ulEntryInstanceNum )
                    {
                        rc = sprintf_s(ucEntryFullPath, sizeof(ucEntryFullPath) , "Device.IP.Interface.%lu", ulEntryInstanceNum);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }

                        rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName) , "%s.Name", ucEntryFullPath);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }

                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             (strcmp(ucEntryNameValue, pKeyword) == 0))
                        {
                            pMatchedLowerLayer =  AnscCloneString(ucEntryFullPath);

                            break;
                        }
                    }
                }
            }
            else if (strcmp(pTableStringToken->Name, "Device.USB.Interface.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.HPNA.Interface.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.DSL.Interface.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.WiFi.Radio.") == 0)
            {
                ulNumOfEntries =       CosaGetParamValueUlong("Device.WiFi.RadioNumberOfEntries");

                for (i = 0; i < ulNumOfEntries; i++)
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex("Device.WiFi.Radio.", i);
                    
                    if (ulEntryInstanceNum)
                    {
                        rc = sprintf_s(ucEntryFullPath, sizeof(ucEntryFullPath) , "Device.WiFi.Radio.%lu", ulEntryInstanceNum);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }
                        
                        rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName) , "%s.Name", ucEntryFullPath);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }
                        
                        if (( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                            (strcmp(ucEntryNameValue, pKeyword) == 0))
                        {
                            pMatchedLowerLayer = AnscCloneString(ucEntryFullPath);
                            
                            break;
                        }
                    }
                }
            }
            else if (strcmp(pTableStringToken->Name, "Device.HomePlug.Interface.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.MoCA.Interface.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.UPA.Interface.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.ATM.Link.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.PTM.Link.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.Ethernet.Link.") == 0)
            {
                ulNumOfEntries =       CosaGetParamValueUlong("Device.Ethernet.LinkNumberOfEntries");

                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex("Device.Ethernet.Link.", i);

                    if ( ulEntryInstanceNum )
                    {
                        rc = sprintf_s(ucEntryFullPath, sizeof(ucEntryFullPath) , "Device.Ethernet.Link.%lu", ulEntryInstanceNum);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }

                        rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName) ,"%s.Name", ucEntryFullPath);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }
               
                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             (strcmp(ucEntryNameValue, pKeyword) == 0))
                        {
                            pMatchedLowerLayer =  AnscCloneString(ucEntryFullPath);

                            break;
                        }
                    }
                }
            }
            else if (strcmp(pTableStringToken->Name, "Device.Ethernet.VLANTermination.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.WiFi.SSID.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.Bridging.Bridge.") == 0)
            {
                ulNumOfEntries =  CosaGetParamValueUlong("Device.Bridging.BridgeNumberOfEntries");
                AnscTraceFlow(("----------CosaUtilGetLowerLayers, bridgenum:%lu\n", ulNumOfEntries));
                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex("Device.Bridging.Bridge.", i);
                    AnscTraceFlow(("----------CosaUtilGetLowerLayers, instance num:%lu\n", ulEntryInstanceNum));

                    if ( ulEntryInstanceNum )
                    {
                        rc = sprintf_s(ucEntryFullPath, sizeof(ucEntryFullPath) ,"Device.Bridging.Bridge.%lu", ulEntryInstanceNum);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }
                        rc = sprintf_s(ucLowerEntryPath, sizeof(ucLowerEntryPath) , "%s.PortNumberOfEntries", ucEntryFullPath); 
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }
                        
                        ulEntryPortNum = CosaGetParamValueUlong(ucLowerEntryPath);  
                        AnscTraceFlow(("----------CosaUtilGetLowerLayers, Param:%s,port num:%lu\n",ucLowerEntryPath, ulEntryPortNum));

                        for ( j = 1; j<= ulEntryPortNum; j++) {
                            rc = sprintf_s(ucLowerEntryName, sizeof(ucLowerEntryName) , "%s.Port.%lu", ucEntryFullPath, j);
                            if(rc < EOK)
                            {
                                ERR_CHK(rc);
                            }
                            rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName) ,"%s.Port.%lu.Name", ucEntryFullPath, j);
                            if(rc < EOK)
                            {
                                ERR_CHK(rc);
                            }
                            AnscTraceFlow(("----------CosaUtilGetLowerLayers, Param:%s,Param2:%s\n", ucLowerEntryName, ucEntryParamName));
                        
                            if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                                 (strcmp(ucEntryNameValue, pKeyword ) == 0))
                            {
                                pMatchedLowerLayer =  AnscCloneString(ucLowerEntryName);
                                AnscTraceFlow(("----------CosaUtilGetLowerLayers, J:%lu, LowerLayer:%s\n", j, pMatchedLowerLayer));
                                break;
                            }
                        }
                    }
                }
            }
            else if (strcmp(pTableStringToken->Name, "Device.PPP.Interface.") == 0)
            {
            }
            else if (strcmp(pTableStringToken->Name, "Device.DSL.Channel.") == 0)
            {
            }
            
            if ( pMatchedLowerLayer )
            {
                AnscFreeMemory(pTableStringToken);
                break;
            }
        }

        AnscFreeMemory(pTableStringToken);
    }

    if ( pTableListTokenChain )
    {
        AnscTcFree((ANSC_HANDLE)pTableListTokenChain);
    }

    AnscTraceWarning
        ((
            "CosaUtilGetLowerLayers: %s matched LowerLayer(%s) with keyword %s in the table %s\n",
            pMatchedLowerLayer ? "Found a":"Not find any",
            pMatchedLowerLayer ? (char*)pMatchedLowerLayer : "",
            pKeyword,
            pTableName
        ));

    return pMatchedLowerLayer;
}

/*
    CosaUtilGetFullPathNameByKeyword
    
   Description:
        This funcation serves for searching other pathname  except lowerlayer.
        
    PUCHAR                      pTableName
        This is the Table names divided by ",". For example 
        "Device.Ethernet.Interface., Device.Dhcpv4." 
        
    PUCHAR                      pParameterName
        This is the parameter name which hold the keyword. eg: "name"
        
    PUCHAR                      pKeyword
        This is keyword. eg: "wan0".

    return value
        return result string which need be free by the caller.
*/
PUCHAR
CosaUtilGetFullPathNameByKeyword
    (
        PUCHAR                      pTableName,
        PUCHAR                      pParameterName,
        PUCHAR                      pKeyword
    )
{

    ULONG                           ulNumOfEntries              = 0;
    ULONG                           i                           = 0;
    ULONG                           ulEntryNameLen              = 256;
    char                            ucEntryParamName[256+300]   = {0};
    char                            ucEntryNameValue[256]       = {0};
    UCHAR                           ucTmp[128+920]              = {0};
    char                            ucTmp2[128+400]             = {0};
    char                            ucEntryFullPath[256+300]    = {0};
    PUCHAR                          pMatchedLowerLayer          = NULL;
    ULONG                           ulEntryInstanceNum          = 0;   
    PANSC_TOKEN_CHAIN               pTableListTokenChain        = (PANSC_TOKEN_CHAIN)NULL;
    PANSC_STRING_TOKEN              pTableStringToken           = (PANSC_STRING_TOKEN)NULL;
    PUCHAR                          pString                     = NULL;
    PUCHAR                          pString2                    = NULL;
    errno_t                         rc                          = -1;

    if ( !pTableName || AnscSizeOfString(pTableName) == 0 ||
         !pKeyword   || AnscSizeOfString(pKeyword) == 0   ||
         !pParameterName   || AnscSizeOfString(pParameterName) == 0
       )
    {
        return NULL;
    }

    pTableListTokenChain = AnscTcAllocate(pTableName, ",");

    if ( !pTableListTokenChain )
    {
        return NULL;
    }

    while ((pTableStringToken = AnscTcUnlinkToken(pTableListTokenChain)))
    {
        if ( pTableStringToken->Name )
        {
            /* Get the string XXXNumberOfEntries */
            pString2 = &pTableStringToken->Name[0];
            pString  = pString2;
            for (i = 0;pTableStringToken->Name[i]; i++)
            {
                if ( pTableStringToken->Name[i] == '.' )
                {
                    pString2 = pString;
                    pString  = &pTableStringToken->Name[i+1];
                }
            }

            pString--;
            pString[0] = '\0';
            rc = sprintf_s(ucTmp2, sizeof(ucTmp2) , "%sNumberOfEntries", pString2); 
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
            pString[0] = '.';

            /* Enumerate the entry in this table */
            if ( TRUE )
            {
                pString2--;
                pString2[0]='\0';
                rc = sprintf_s(ucTmp, sizeof(ucTmp) , "%s.%s", pTableStringToken->Name, ucTmp2); 
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }
                pString2[0]='.';
                ulNumOfEntries =       CosaGetParamValueUlong(ucTmp);

                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {
                    ulEntryInstanceNum = CosaGetInstanceNumberByIndex(pTableStringToken->Name, i);

                    if ( ulEntryInstanceNum )
                    {
                        rc = sprintf_s(ucEntryFullPath, sizeof(ucEntryFullPath) , "%s%lu.", pTableStringToken->Name, ulEntryInstanceNum);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }

                        rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName) , "%s%s", ucEntryFullPath, pParameterName);
                        if(rc < EOK)
                        {
                            ERR_CHK(rc);
                        }
               
                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             (strcmp(ucEntryNameValue, pKeyword) == 0))
                        {
                            pMatchedLowerLayer =  AnscCloneString(ucEntryFullPath);

                            break;
                        }
                    }
                }
            }

            if ( pMatchedLowerLayer )
            {
                AnscFreeMemory(pTableStringToken);
                break;
            }
        }

        AnscFreeMemory(pTableStringToken);
    }

    if ( pTableListTokenChain )
    {
        AnscTcFree((ANSC_HANDLE)pTableListTokenChain);
    }

    AnscTraceWarning
        ((
            "CosaUtilGetFullPathNameByKeyword: %s matched parameters(%s) with keyword %s in the table %s(%s)\n",
            pMatchedLowerLayer ? "Found a":"Not find any",
            pMatchedLowerLayer ? (char*)pMatchedLowerLayer : "",
            pKeyword,
            pTableName,
            pParameterName
        ));

    return pMatchedLowerLayer;
}

ANSC_STATUS
CosaUtilGetStaticRouteTable
    (
        UINT                        *count,
        StaticRoute                 **out_sroute
    )
{
	return CosaUtilGetStaticRouteTablePriv(count, out_sroute);
}

int isValidIPv4Address(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result;
}

int isValidIPv6Address(char *ipAddress)
{
    struct sockaddr_in6 sa;
    int result = inet_pton(AF_INET6, ipAddress, &(sa.sin6_addr));
    return result;
}

int isValidFQDN(char *fqdn)
{
    char  tmpFqdn[256] = {'\0'};;
    char  *sep = ".";
    char  *token = NULL;
    int i;
    strncpy(tmpFqdn, fqdn, sizeof(tmpFqdn)-1);
    for (token = strtok(tmpFqdn, sep); (token != NULL); token = strtok(NULL, sep))
    {
        if (!isalpha(token[0]))
        {
            AnscTraceWarning(("isValidFQDN - label does not start with letter\n"));
            return 0;
        }

        for (i=0; i < strlen(token); i++)
        {
            if (!isalpha(token[i]) && !('-' == token[i]) && !isdigit(token[i]))
            {
                AnscTraceWarning(("isValidFQDN - found invalid character '%c'\n", token[i]));
                return 0;
            }
        }

        if (!isalpha(token[i-1]) && !isdigit(token[i-1]))
        {
            AnscTraceWarning(("isValidFQDN - label does not end with letter or digit"));
            return 0;
        }
    }
    return 1;
}

