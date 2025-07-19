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
#include "cosa_thermal_dml.h"
#include "platform_hal.h"

/* using pre defined values for number of fans, hal api to return number of fans may need to be added */
#if defined (_CBR2_PRODUCT_REQ_)
#define NUM_FAN 2
#else
#define NUM_FAN 1
#endif

fanInfo_t fanInfo[NUM_FAN];

/***********************************************************************

 APIs for Object:

    Fan.
    
    *  Fan_GetEntryCount
    *  Fan_GetEntry
    *  Fan_GetParamBoolValue
    *  Fan_GetParamUlongValue
    *  Fan_SetParamBoolValue
    *  Fan_Validate
    *  Fan_Commit
    *  Fan_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        Fan_GetEntryCount
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
Fan_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return NUM_FAN;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        Fan_GetEntry
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
Fan_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    int fanIndex = nIndex;

    if (nIndex < NUM_FAN)
    {

#ifdef FAN_THERMAL_CTR

        fanInfo[fanIndex].fanIndex = nIndex;
        fanInfo[fanIndex].status = platform_hal_getFanStatus(fanIndex);
        fanInfo[fanIndex].speed  = platform_hal_getFanSpeed(fanIndex);
        fanInfo[fanIndex].rotorLock  = platform_hal_getRotorLock(fanIndex);
#endif
#if defined(FAN_THERMAL_CTR) || defined(LIMITED_FAN_WAREHOUSE)
        fanInfo[fanIndex].maxOverride = FALSE; 

#endif

        *pInsNumber  = nIndex + 1;

        return &fanInfo[fanIndex];
    } 
    else
    {
        return NULL;
    }
}

/**********************************************************************

    caller:     owner of this object

    prototype

        BOOL
        Fan_GetParamBoolValue
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
                The buffer of returned BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL Fan_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       bValue
    )
{

#if defined(FAN_THERMAL_CTR) || defined(LIMITED_FAN_WAREHOUSE)
    fanInfo_t         *pFanInfo = (fanInfo_t *)hInsContext;

    if (strcmp(ParamName, "MaxOverride") == 0)
    {
        *bValue = pFanInfo->maxOverride;
        return TRUE;
    }
#endif

#ifdef FAN_THERMAL_CTR

    if (strcmp(ParamName, "Status") == 0)
    {
        *bValue = platform_hal_getFanStatus(pFanInfo->fanIndex);
        return TRUE;
    }
#endif

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype

        BOOL
        Fan_SetParamBoolValue
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
BOOL Fan_SetParamBoolValue  
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
#if defined(FAN_THERMAL_CTR) || defined(LIMITED_FAN_WAREHOUSE)

    fanInfo_t         *pFanInfo = (fanInfo_t *)hInsContext;

    if (strcmp(ParamName, "MaxOverride") == 0)
    {
        platform_hal_setFanMaxOverride( bValue, pFanInfo->fanIndex );
        fanInfo[pFanInfo->fanIndex].maxOverride = bValue;

        return TRUE;
    }
#endif
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype

        BOOL
        Fan_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      pULong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      pULong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Fan_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    )
{

#ifdef FAN_THERMAL_CTR

    fanInfo_t         *pFanInfo = (fanInfo_t *)hInsContext;

    if (strcmp(ParamName, "Speed") == 0)
    {
        *pUlong= platform_hal_getRPM(pFanInfo->fanIndex);
        return TRUE;
    }

    if (strcmp(ParamName, "RotorLock") == 0)
    {
        int rotor;

        rotor = platform_hal_getRotorLock(pFanInfo->fanIndex);
        switch( rotor ) {
            case -1:
                *pUlong = 1; //Not_Applicable
                break;
            case 0:
                *pUlong = 3; //False
                break;
            case 1:
                *pUlong = 2; //True
                break;
            default:
                return FALSE;
        }
        return TRUE;
    }
#endif
    return FALSE;
}




/************************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Fan_Validate
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
Fan_Validate
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
	Fan_Commit
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
Fan_Commit
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
        Fan_Rollback
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
Fan_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}
