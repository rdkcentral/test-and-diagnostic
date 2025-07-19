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

    module: cosa_dns_dml.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/14/2011    initial revision.

**************************************************************************/
#include <arpa/inet.h>
#include "ansc_platform.h"
#include "cosa_diagnostic_apis.h"
#include "cosa_dns_dml.h"
#include "plugin_main_apis.h"
#include "bbhm_diagns_interface.h"
#include "ccsp_psm_helper.h"
#include "safec_lib_common.h"
#include "cosa_apis_util.h"

/*#include "cosa_dns_internal.h"*/

/***********************************************************************
 IMPORTANT NOTE:

 According to TR69 spec:
 On successful receipt of a SetParameterValues RPC, the CPE MUST apply
 the changes to all of the specified Parameters atomically. That is, either
 all of the value changes are applied together, or none of the changes are
 applied at all. In the latter case, the CPE MUST return a fault response
 indicating the reason for the failure to apply the changes.

 The CPE MUST NOT apply any of the specified changes without applying all
 of them.

 In order to set parameter values correctly, the back-end is required to
 hold the updated values until "Validate" and "Commit" are called. Only after
 all the "Validate" passed in different objects, the "Commit" will be called.
 Otherwise, "Rollback" will be called instead.

 The sequence in COSA Data Model will be:

 SetParamBoolValue/SetParamIntValue/SetParamUlongValue/SetParamStringValue
 -- Backup the updated values;

 if( Validate_XXX())
 {
     Commit_XXX();    -- Commit the update all together in the same object
 }
 else
 {
     Rollback_XXX();  -- Remove the update at backup;
 }

***********************************************************************/

ANSC_STATUS
COSAGetParamValueByPathName
    (
        void*                       bus_handle,
        parameterValStruct_t        *val,
        ULONG                       *parameterValueLength
    );

/***********************************************************************

 APIs for Object:

    DNS.Diagnostics.


***********************************************************************/
/***********************************************************************

 APIs for Object:

    DNS.Diagnostics.NSLookupDiagnostics.

    *  NSLookupDiagnostics_GetParamBoolValue
    *  NSLookupDiagnostics_GetParamIntValue
    *  NSLookupDiagnostics_GetParamUlongValue
    *  NSLookupDiagnostics_GetParamStringValue
    *  NSLookupDiagnostics_SetParamBoolValue
    *  NSLookupDiagnostics_SetParamIntValue
    *  NSLookupDiagnostics_SetParamUlongValue
    *  NSLookupDiagnostics_SetParamStringValue
    *  NSLookupDiagnostics_Validate
    *  NSLookupDiagnostics_Commit
    *  NSLookupDiagnostics_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        NSLookupDiagnostics_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
NSLookupDiagnostics_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        NSLookupDiagnostics_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
NSLookupDiagnostics_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        NSLookupDiagnostics_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
NSLookupDiagnostics_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject           = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo   = pMyObject->hDiagNSLookInfo;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "DiagnosticsState") == 0)
    {
        pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

        if ( pNSLookupDiagInfo )
        {
            *puLong = pNSLookupDiagInfo->DiagnosticState + 1;
        }
        else
        {
            AnscTraceWarning(("Failed to get NSLookup DiagnosticsState parameter\n!"));

            *puLong = 0;

            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "Timeout") == 0)
    {
        if ( !pNSLookupDiagInfo )
        {
            *puLong = 0;

            return FALSE;
        }

        *puLong = pNSLookupDiagInfo->Timeout;

        return TRUE;
    }

    if (strcmp(ParamName, "NumberOfRepetitions") == 0)
    {
        if ( !pNSLookupDiagInfo )
        {
            *puLong = 0;

            return FALSE;
        }

        *puLong = pNSLookupDiagInfo->NumberOfRepetitions;

        return TRUE;
    }

    if (strcmp(ParamName, "SuccessCount") == 0)
    {
        pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

        if ( pNSLookupDiagInfo )
        {
            *puLong = pNSLookupDiagInfo->SuccessCount;
        }
        else
        {
            AnscTraceWarning(("Failed to get NSLookup SuccessCount parameter\n!"));

            *puLong = 0;

            return FALSE;
        }

        return TRUE;
    }


    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        NSLookupDiagnostics_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
NSLookupDiagnostics_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject           = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo   = pMyObject->hDiagNSLookInfo;
    errno_t rc = -1;

    if ( !pNSLookupDiagInfo )
    {
        return -1;
    }

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Interface") == 0)
    {
        if ( AnscSizeOfString(pNSLookupDiagInfo->Interface) < *pUlSize )
        {
            rc = strcpy_s(pValue, *pUlSize ,pNSLookupDiagInfo->Interface);
            ERR_CHK(rc);
        }
        else
        {
            *pUlSize = AnscSizeOfString(pNSLookupDiagInfo->Interface) + 1;

            return 1;
        }

        return 0;
    }

    if (strcmp(ParamName, "HostName") == 0)
    {
        if ( AnscSizeOfString(pNSLookupDiagInfo->HostName) < *pUlSize )
        {
            rc = strcpy_s(pValue, *pUlSize , pNSLookupDiagInfo->HostName);
            ERR_CHK(rc);
        }
        else
        {
            *pUlSize = AnscSizeOfString(pNSLookupDiagInfo->HostName) + 1;

            return 1;
        }

        return 0;
    }

    if (strcmp(ParamName, "DNSServer") == 0)
    {
        if ( AnscSizeOfString(pNSLookupDiagInfo->DNSServer) < *pUlSize )
        {
            rc = strcpy_s(pValue, *pUlSize , pNSLookupDiagInfo->DNSServer);
            ERR_CHK(rc);
        }
        else
        {
            *pUlSize = AnscSizeOfString(pNSLookupDiagInfo->DNSServer) + 1;

            return 1;
        }
        return 0;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        NSLookupDiagnostics_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
NSLookupDiagnostics_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        NSLookupDiagnostics_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
NSLookupDiagnostics_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        NSLookupDiagnostics_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
NSLookupDiagnostics_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject           = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo   = pMyObject->hDiagNSLookInfo;
    PDSLH_NSLOOKUP_INFO             pDiagInfo           = NULL;

    if ( !pNSLookupDiagInfo )
    {
        return FALSE;
    }

    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "DiagnosticsState") == 0)
    {
        if ( (uValue - 1) == (ULONG)DSLH_DIAG_STATE_TYPE_Requested )
        {
            pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_Requested;
            pNSLookupDiagInfo->bForced = TRUE;
        }
        else
        {
            pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
            pNSLookupDiagInfo->bForced = FALSE;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "Timeout") == 0)
    {
        pDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

        if ( pDiagInfo && pDiagInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Inprogress )
        {
            CosaDmlDiagCancelDiagnostic(DSLH_DIAGNOSTIC_TYPE_NSLookup);
            pDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        }

        pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        pNSLookupDiagInfo->Timeout = uValue;

        return TRUE;
    }

    if (strcmp(ParamName, "NumberOfRepetitions") == 0)
    {
        pDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

        if ( pDiagInfo && pDiagInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Inprogress )
        {
            CosaDmlDiagCancelDiagnostic(DSLH_DIAGNOSTIC_TYPE_NSLookup);
            pDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        }

        pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        pNSLookupDiagInfo->NumberOfRepetitions = uValue;

        return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        NSLookupDiagnostics_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
NSLookupDiagnostics_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject           = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo   = pMyObject->hDiagNSLookInfo;
    PDSLH_NSLOOKUP_INFO             pDiagInfo           = NULL;
    errno_t                         rc                  = -1;

    if ( !pNSLookupDiagInfo )
    {
        return FALSE;
    }

    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "Interface") == 0)
    {
        pDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

        if ( pDiagInfo && pDiagInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Inprogress )
        {
            CosaDmlDiagCancelDiagnostic(DSLH_DIAGNOSTIC_TYPE_NSLookup);
            pDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        }

        pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        rc = strcpy_s(pNSLookupDiagInfo->Interface, sizeof(pNSLookupDiagInfo->Interface) , pString);
        ERR_CHK(rc);
        return TRUE;
    }

    if (strcmp(ParamName, "HostName") == 0)
    {
        pDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

        if ( pDiagInfo && pDiagInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Inprogress )
        {
            CosaDmlDiagCancelDiagnostic(DSLH_DIAGNOSTIC_TYPE_NSLookup);
            pDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        }

        pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        rc = strcpy_s(pNSLookupDiagInfo->HostName, sizeof(pNSLookupDiagInfo->HostName) , pString);
        ERR_CHK(rc);
        return TRUE;
    }

    if (strcmp(ParamName, "DNSServer") == 0)
    {
        pDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

        if ( pDiagInfo && pDiagInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Inprogress )
        {
            CosaDmlDiagCancelDiagnostic(DSLH_DIAGNOSTIC_TYPE_NSLookup);
            pDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        }

        pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        rc = strcpy_s(pNSLookupDiagInfo->DNSServer, sizeof(pNSLookupDiagInfo->DNSServer) , pString);
        ERR_CHK(rc);
        return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        NSLookupDiagnostics_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
NSLookupDiagnostics_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    char*                           p                  = NULL;
    char*                           pDomainName        = NULL;
    ULONG                           ulDNLength         = DSLH_NS_MAX_STRING_LENGTH_Host;
    ULONG                           i                  = 0;
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo  = pMyObject->hDiagNSLookInfo;
    char*                           pAddrName          = NULL;
    errno_t                         rc                 = -1;

    if ( !pNSLookupDiagInfo )
    {
        return FALSE;
    }

    //COSAValidateHierarchyInterface doesn't work now due to incomplete lan device management
    if ( pNSLookupDiagInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Requested || 
         /*COSAValidateHierarchyInterface && */ AnscSizeOfString(pNSLookupDiagInfo->Interface) > 0 )
    {
        // COSAValidateHierarchyInterface depends on the specific target
       if(AnscSizeOfString(pNSLookupDiagInfo->Interface) > 0)
            pAddrName = CosaGetInterfaceAddrByName(pNSLookupDiagInfo->Interface);
       else
           pAddrName = CosaGetInterfaceAddrByName("Device.DeviceInfo.X_COMCAST-COM_WAN_IP");

        if(strcmp(pAddrName,"::") && (isValidIPv4Address(pAddrName) || isValidIPv6Address(pAddrName)))
        {
            rc = strcpy_s(pNSLookupDiagInfo->IfAddr, sizeof(pNSLookupDiagInfo->IfAddr) ,pAddrName);
            ERR_CHK(rc);
            AnscFreeMemory(pAddrName);
        }
        else
        {
            AnscFreeMemory(pAddrName);
            rc = strcpy_s(pReturnParamName, *puLength ,"Interface");
            ERR_CHK(rc);
            pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
            return FALSE;
        }
        /*
        if ( !COSAValidateHierarchyInterface
                (
                    pNSLookupDiagInfo->Interface,
                    DSLH_LAN_LAYER3_INTERFACE | DSLH_WAN_LAYER3_CONNECTION_INTERFACE | DSLH_NULL_STRING_INTERFACE
                ))
        {
            AnscCopyString(pReturnParamName, "Interface");
            return FALSE;
        }
        */
    }

    if ( pNSLookupDiagInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Requested && AnscSizeOfString(pNSLookupDiagInfo->HostName) == 0 )
    {
        AnscCopyString(pReturnParamName, "DiagnosticsState");
        pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
        return FALSE;
    }

    if ( pNSLookupDiagInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Requested || AnscSizeOfString(pNSLookupDiagInfo->HostName) > 0 )
    {
        p = pNSLookupDiagInfo->HostName;

        //check if there is any illegal character
        for(i = 0; i < AnscSizeOfString(p); i++)
        {
            if ( (p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'z') ||
                (p[i] >= 'A' && p[i] <= 'Z') || p[i] == '$' || p[i] == '-' ||
                p[i] == '_' || p[i] == '.' || p[i] == '+' || p[i] == '!' ||
                p[i] == '*' || p[i] == 39 || p[i] == '(' || p[i] == ')' ||
                p[i] == ',' || p[i] == '"' )
            {
                continue;
            }
            else
            {
                rc = strcpy_s(pReturnParamName, *puLength , "HostName");
                ERR_CHK(rc);
                pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
                return FALSE;
            }
        }

        if ( pNSLookupDiagInfo->HostName[0] != '.')
        {
            p = _ansc_strstr(pNSLookupDiagInfo->HostName + 1, "..");

            if ( p )
            {
                for(; p < pNSLookupDiagInfo->HostName + AnscSizeOfString(pNSLookupDiagInfo->HostName); p++)
                {
                    if ( *p != '.' )
                    {
                        rc = strcpy_s(pReturnParamName, *puLength , "HostName");
                        ERR_CHK(rc);
                        pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
                        return FALSE;
                    }
                }
            }
        }
        else
        {
            rc = strcpy_s(pReturnParamName, *puLength , "HostName");
            ERR_CHK(rc);
            pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
            return FALSE;
        }

        pDomainName = AnscAllocateMemory(DSLH_NS_MAX_STRING_LENGTH_Host);

        if ( !pDomainName )
        {
            rc = strcpy_s(pReturnParamName, *puLength , "HostName");
            ERR_CHK(rc);
            pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
            return FALSE;
        }

	/* CID 61647 :  Unchecked return value */
        if ( CosaGetParamValueString
            (
#ifndef     DM_IGD
                "Device.DHCPv4.Server.Pool.1.DomainName",
#else
                "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DomainName",
#endif
                pDomainName,
                &ulDNLength
            ) != 0 )
	{
            AnscTraceWarning(("CosaGetParamValueString failure in NSLookupDiagnostics_Validate"));
	}

        if ( !AnscSizeOfString(pDomainName) )
        {
            if ( pNSLookupDiagInfo->HostName[0] != '.')
            {
                p = _ansc_strchr(pNSLookupDiagInfo->HostName + 1, '.');

                if ( !p )
                {
                    rc = strcpy_s(pReturnParamName, *puLength , "HostName");
                    ERR_CHK(rc);
                    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
                    return FALSE;
                }
                else if ( p[1] == '0' || p[1] == '.' )
                {
                    rc = strcpy_s(pReturnParamName, *puLength , "HostName");
                    ERR_CHK(rc);
                    pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
                    return FALSE;
                }
            }
            else
            {
                rc = strcpy_s(pReturnParamName, *puLength , "HostName");
                ERR_CHK(rc);
                pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
                return FALSE;
            }
        }
        else
        {
            if ( pNSLookupDiagInfo->HostName[0] == '.')
            {
                rc = strcpy_s(pReturnParamName, *puLength , "HostName");
                ERR_CHK(rc);
                pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
                return FALSE;
            }
        }
    }

    if ( pNSLookupDiagInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Requested || AnscSizeOfString(pNSLookupDiagInfo->DNSServer) > 0  )
    {
		/*
		  * if DNSServer is empty then we have to take default DNS Server value Device.DNS.Client.Server.1.DNSServer 
		  */
		if ( 0 == AnscSizeOfString(pNSLookupDiagInfo->DNSServer) )
		{
			parameterValStruct_t varStruct;
			UCHAR	   ucEntryNameValue[128]	= { 0 };
			int ulEntryNameLen;

			varStruct.parameterName  = "Device.DNS.Client.Server.1.DNSServer";
			varStruct.parameterValue = ucEntryNameValue;

			ulEntryNameLen = sizeof(ucEntryNameValue);
			if ( ANSC_STATUS_SUCCESS == COSAGetParamValueByPathName(  g_MessageBusHandle, 
																	   &varStruct,
																	   (ULONG *)&ulEntryNameLen ) 
				)
			{
				rc = strcpy_s( pNSLookupDiagInfo->DNSServer, sizeof(pNSLookupDiagInfo->DNSServer) ,varStruct.parameterValue );
				ERR_CHK(rc);
			}
		}

        //still not clear how to validate dns server
        // we are only validating if the server ip is v4/v6
        if(!isValidIPv4Address(pNSLookupDiagInfo->DNSServer) && !isValidIPv6Address(pNSLookupDiagInfo->DNSServer))
            {
                rc = strcpy_s(pReturnParamName, *puLength , "DNSServer");
                ERR_CHK(rc);
                pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
                return FALSE;
            }
        if(isValidIPv4Address(pNSLookupDiagInfo->DNSServer))
        {
            rc = strcpy_s(pNSLookupDiagInfo->IfAddr, sizeof(pNSLookupDiagInfo->IfAddr) ,CosaGetInterfaceAddrByName("Device.DeviceInfo.X_COMCAST-COM_WAN_IP"));
            ERR_CHK(rc);
        }
        else if(isValidIPv6Address(pNSLookupDiagInfo->DNSServer))
        {
            rc = strcpy_s(pNSLookupDiagInfo->IfAddr, sizeof(pNSLookupDiagInfo->IfAddr) ,CosaGetInterfaceAddrByName("Device.DeviceInfo.X_COMCAST-COM_WAN_IPv6"));
            ERR_CHK(rc);
        }	
    }

    if ( TRUE )
    {
        if ( pNSLookupDiagInfo->Timeout < DSLH_NS_MIN_Timeout )
        {
            rc = strcpy_s(pReturnParamName, *puLength , "Timeout");
            ERR_CHK(rc);
            pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
            return FALSE;
        }
    }

    if ( TRUE )
    {
        if ( pNSLookupDiagInfo->NumberOfRepetitions < DSLH_NS_MIN_NumberOfRepetitions )
        {
            rc = strcpy_s(pReturnParamName, *puLength , "NumberOfRepetitions");
            ERR_CHK(rc);
            pNSLookupDiagInfo->DiagnosticState = DSLH_DIAG_STATE_TYPE_None;
            return FALSE;
        }
    }

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        NSLookupDiagnostics_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
NSLookupDiagnostics_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_FAILURE;
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo  = pMyObject->hDiagNSLookInfo;

    if ( !pNSLookupDiagInfo )
    {
        return returnStatus;
    }

    if ( pNSLookupDiagInfo->DiagnosticState == DSLH_DIAG_STATE_TYPE_Requested )
    {
        returnStatus = CosaDmlDiagScheduleDiagnostic(DSLH_DIAGNOSTIC_TYPE_NSLookup, (ANSC_HANDLE)pNSLookupDiagInfo);
    }
    else
    {
        CosaDmlDiagSetState(DSLH_DIAGNOSTIC_TYPE_NSLookup, DSLH_DIAG_STATE_TYPE_None);
    }

    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        NSLookupDiagnostics_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
NSLookupDiagnostics_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_NSLOOKUP_INFO             pNSLookupInfo      = pMyObject->hDiagNSLookInfo;
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo  = NULL;

    if ( !pNSLookupInfo )
    {
        return ANSC_STATUS_FAILURE;
    }

    pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

    if ( pNSLookupDiagInfo )
    {
        DslhInitNSLookupInfo(pNSLookupInfo);

        pNSLookupInfo->StructSize    = sizeof(DSLH_NSLOOKUP_INFO);
        errno_t rc = -1;

        rc = strcpy_s(pNSLookupInfo->HostName, sizeof(pNSLookupInfo->HostName) , pNSLookupDiagInfo->HostName);
        ERR_CHK(rc);
        rc = strcpy_s(pNSLookupInfo->Interface, sizeof(pNSLookupInfo->Interface) , pNSLookupDiagInfo->Interface);
        ERR_CHK(rc);
        rc = strcpy_s(pNSLookupInfo->DNSServer, sizeof(pNSLookupInfo->DNSServer) , pNSLookupDiagInfo->DNSServer);
        ERR_CHK(rc);

        pNSLookupInfo->bForced = FALSE;
        pNSLookupInfo->Timeout = pNSLookupDiagInfo->Timeout;
        pNSLookupInfo->NumberOfRepetitions = pNSLookupDiagInfo->NumberOfRepetitions;
        pNSLookupInfo->UpdatedAt = pNSLookupDiagInfo->UpdatedAt;
    }
    else
    {
        DslhInitNSLookupInfo(pNSLookupInfo);
    }

    return returnStatus;
}

/***********************************************************************

 APIs for Object:

    DNS.Diagnostics.NSLookupDiagnostics.Result.{i}.

    *  Result_GetEntryCount
    *  Result_GetEntry
    *  Result_IsUpdated
    *  Result_Synchronize
    *  Result_GetParamBoolValue
    *  Result_GetParamIntValue
    *  Result_GetParamUlongValue
    *  Result_GetParamStringValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        Result_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
Result_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo  =  NULL;

    pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

    if ( pNSLookupDiagInfo && pNSLookupDiagInfo->DiagnosticState != DSLH_DIAG_STATE_TYPE_None
         && pNSLookupDiagInfo->DiagnosticState != DSLH_DIAG_STATE_TYPE_Requested )
    {
        return pNSLookupDiagInfo->ResultNumberOfEntries;
    }

    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        Result_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
Result_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo  = NULL;
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pEchoInfo          = (PBBHM_NS_LOOKUP_ECHO_ENTRY   )NULL;

    pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

    if ( pNSLookupDiagInfo )
    {
        pEchoInfo = (PBBHM_NS_LOOKUP_ECHO_ENTRY)pNSLookupDiagInfo->hDiaginfo;
    }

    if ( !pEchoInfo )
    {
        return  (ANSC_HANDLE)NULL;
    }
    else
    {
        *pInsNumber  = nIndex + 1;

        return &pEchoInfo[nIndex];
    }

    return NULL; /* return the handle */
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Result_IsUpdated
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is checking whether the table is updated or not.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     TRUE or FALSE.

**********************************************************************/
BOOL
Result_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_NSLOOKUP_INFO             pNSLookupInfo      = pMyObject->hDiagNSLookInfo;
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo  = NULL;

    if ( !pNSLookupInfo )
    {
        return FALSE;
    }

    pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

    if ( pNSLookupDiagInfo && pNSLookupDiagInfo->UpdatedAt != pNSLookupInfo->UpdatedAt )
    {
        return  TRUE;
    }

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        Result_Synchronize
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to synchronize the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Result_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_NSLOOKUP_INFO             pNSLookupInfo      = pMyObject->hDiagNSLookInfo;
    PDSLH_NSLOOKUP_INFO             pNSLookupDiagInfo  = NULL;

    if ( !pNSLookupInfo )
    {
        return ANSC_STATUS_FAILURE;
    }

    pNSLookupDiagInfo = (PDSLH_NSLOOKUP_INFO)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_NSLookup);

    if ( !pNSLookupDiagInfo )
    {
        AnscTraceWarning(("Failed to get NSLookup backend information!\n"));

        return  ANSC_STATUS_FAILURE;
    }

    pNSLookupInfo->UpdatedAt = pNSLookupDiagInfo->UpdatedAt;

    return  ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Result_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Result_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Result_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Result_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Result_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Result_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pEchoInfo          = (PBBHM_NS_LOOKUP_ECHO_ENTRY)hInsContext;

    if ( !pEchoInfo )
    {
        AnscTraceWarning(("Fail to get result parameters hInsContext!\n"));

        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Status") == 0)
    {
        *puLong = pEchoInfo->Status + 1;

        return TRUE;
    }

    if (strcmp(ParamName, "AnswerType") == 0)
    {
        *puLong = pEchoInfo->AnswerType + 1;

        return TRUE;
    }

    if (strcmp(ParamName, "ResponseTime") == 0)
    {
        *puLong = pEchoInfo->ResponsTime;

        return TRUE;
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        Result_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
Result_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PBBHM_NS_LOOKUP_ECHO_ENTRY      pEchoInfo          = (PBBHM_NS_LOOKUP_ECHO_ENTRY)hInsContext;
    errno_t rc = -1;

    if ( !pEchoInfo )
    {
        AnscTraceWarning(("Fail to get result parameters hInsContext!\n"));

        return -1;
    }

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "HostNameReturned") == 0)
    {
        if ( pEchoInfo->HostNameReturned )
        {
            if ( AnscSizeOfString(pEchoInfo->HostNameReturned) < *pUlSize )
            {
                rc = strcpy_s(pValue, *pUlSize , pEchoInfo->HostNameReturned);
                ERR_CHK(rc);

                return 0;
            }
            else
            {
                *pUlSize = AnscSizeOfString(pEchoInfo->HostNameReturned) + 1;

                return 1;
            }
        }

        return -1;
    }

    if (strcmp(ParamName, "IPAddresses") == 0)
    {
        if ( pEchoInfo->IPAddresses )
        {
            if ( AnscSizeOfString(pEchoInfo->IPAddresses) < *pUlSize )
            {
                rc = strcpy_s(pValue, *pUlSize , pEchoInfo->IPAddresses);
                ERR_CHK(rc);

                return 0;
            }
            else
            {
                *pUlSize = AnscSizeOfString(pEchoInfo->IPAddresses) + 1;

                return 1;
            }
        }

        return -1;
    }

    if (strcmp(ParamName, "DNSServerIP") == 0)
    {
        rc = strcpy_s(pValue, *pUlSize , pEchoInfo->DNSServerIPName);
        ERR_CHK(rc);

        return 0;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}
