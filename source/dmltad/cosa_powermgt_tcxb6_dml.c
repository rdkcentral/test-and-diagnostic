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

#include "ansc_platform.h"
#include "plugin_main_apis.h"
#include "cosa_powermgt_tcxb6_dml.h"
#include "secure_wrapper.h"

/***********************************************************************

 APIs for Object:

    PowerManagement.

    *  PowerManagement_GetParamBoolValue
    *  PowerManagement_SetParamBoolValue
    *  PowerManagement_GetParamUlongValue
    *  PowerManagement_SetParamUlongValue
    *  PowerManagement_Validate
    *  PowerManagement_Commit
    *  PowerManagement_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype

        BOOL
        PowerManagement_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                        bValue
            );

    description:

        This function is called to retrieve BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                        bValue 

    return:     TRUE if succeeded.

**********************************************************************/
BOOL PowerManagement_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                        bValue
    )
{
    CcspTraceInfo(("%s:%d \n",__FUNCTION__,__LINE__));
    if (strcmp(ParamName, "PciEPowerManagement") == 0)
    {
#if defined(_COSA_BCM_ARM_) && defined(_XB6_PRODUCT_REQ_)
       char buff[1024];
       FILE *fp = popen("/bin/cat /sys/module/pcie_aspm/parameters/policy", "r");
        if (fp == NULL) {
            CcspTraceError(("Failed to open file \n" ));
            CcspTraceError(("Check /sys/module/pcie_aspm/parameters/policy is exist \n" ));
            *bValue = 0;
            return TRUE;
        }
        if(fgets(buff,sizeof(buff),fp))
        {
            CcspTraceInfo(("Values are  %s \n",buff));
            if(strstr(buff,"[powersave]")!=NULL)
            {
                *bValue = TRUE;
                CcspTraceError(("PowerSave/PowerManagement is enabled \n"));
            }
            else
            {
                *bValue = FALSE;
                CcspTraceError(("PowerSave/PowerManagement is disabled \n"));
            }
        }
        else
        {
            CcspTraceError(("NO DATA read \n"));
            *bValue = TRUE;
        }
        pclose(fp);
#endif
        return TRUE;
    }


    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype

        BOOL
        PowerManagement_SetParamBoolValue
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
                The buffer of returned BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL PowerManagement_SetParamBoolValue  
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    CcspTraceInfo(("In %s:%d  \n",__FUNCTION__,__LINE__));
    if (strcmp(ParamName, "PciEPowerManagement") == 0)
    {
#if defined(_COSA_BCM_ARM_) && defined(_XB6_PRODUCT_REQ_)
        if ( (int)bValue == 1 ) {
            CcspTraceError(("PowerSave/PowerManagement is enabled \n"));
            v_secure_system("echo 'powersave' > /sys/module/pcie_aspm/parameters/policy");
        } else  { 
            CcspTraceError(("PowerSave/PowerManagement is disabled \n"));
            v_secure_system("echo 'performance' > /sys/module/pcie_aspm/parameters/policy");
        }
#endif
        return TRUE;
    }
    return FALSE;
}


/************************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PowerManagement_Validate
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
                The output length of the param name

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
PowerManagement_Validate
   (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
	PowerManagement_Commit
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
PowerManagement_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        PowerManagement_Rollback
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
PowerManagement_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}



