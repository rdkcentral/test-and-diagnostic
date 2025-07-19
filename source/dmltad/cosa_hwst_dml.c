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

#include <sys/statvfs.h>
#include "ansc_platform.h"
#include "plugin_main_apis.h"
#include "cosa_hwst_dml.h"
#include "platform_hal.h"
#include "safec_lib_common.h"
#include "secure_wrapper.h"

#define HWSELFTEST_RESULTS_SIZE 2048
#define HWSELFTEST_RESULTS_FILE "/tmp/hwselftest.results"
#define BKP_HWSELFTEST_RESULTS_FILE "/nvram/hwselftest.results"

#define HWSELFTEST_START_MIN_SPACE (200*1024) //200KB

BOOL hwst_runTest = FALSE;

/*
 * This char pointer will save the result of executeTest in case of
 * failures. This is then used when Results parameter is fetched and there
 * are no hwselftest.results file in tmp and nvram directory.
 * Note: The message should start with "Error:"
 */
char *hwExecInfo = NULL;

/***********************************************************************


 APIs for Object:

    X_RDK_hwHealthTest.

    *  hwHealthTest_GetParamBoolValue
    *  hwHealthTest_SetParamBoolValue
    *  hwHealthTest_GetParamStringValue
***********************************************************************/

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
    hwHealthTest_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )

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
hwHealthTest_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "executeTest") == 0)
    {
#ifdef COLUMBO_HWTEST
        *pBool = hwst_runTest;
        AnscTraceFlow(("%s Execute tests : %d \n", __FUNCTION__, *pBool));
        return TRUE;
#else
        *pBool = FALSE;
#endif
    }
    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
    hwHealthTest_SetParamBoolValue
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
hwHealthTest_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "executeTest") == 0)
    {
#ifdef COLUMBO_HWTEST
        AnscTraceFlow(("%s Execute tests : %d \n", __FUNCTION__, bValue));
        FILE* fp = fopen("/tmp/.hwst_run", "r");
        char* clientVer = (char*) malloc(8*sizeof(char));
        /*
         * Clear up the hwExecInfo. This might happen if the trigger came through
         * WebPA and then it did not ask for the results before triggering the
         * test again.
         */
        if(NULL != hwExecInfo)
        {
            free(hwExecInfo);
            hwExecInfo = NULL;
        }
        char version[8] = {'\0'};
        if(NULL != fp)
        {
            if(NULL != clientVer)
            {
		/* CID 163494 :  Unchecked return value from library */
                if ( fscanf(fp, "%7s", clientVer) != 1 )
		{
	             AnscTraceFlow((" read error of client version"));
		}
                strncpy(version,clientVer,sizeof(version)-1);
                free(clientVer);
                clientVer = NULL;
            }
        }

        if(NULL != clientVer)
        {
            free(clientVer);
        }

        if(fp != NULL )
        {
            fclose(fp);
            if(strcmp(version, "0001") && bValue)
            {
                AnscTraceFlow(("Multiple connections not allowed"));
                return FALSE;
            }
        }
        if (bValue && !strcmp(version, "0001"))
        {
            AnscTraceFlow(("Hwselftest is already running, hence returning success\n"));
            return TRUE;
        }
        //Check if there is enough space to atleast start HHT.
        unsigned long long result = 0;
        struct statvfs sfs;
        if(statvfs("/tmp", &sfs) != -1)
        {
            result = (unsigned long long)sfs.f_bsize * sfs.f_bavail;
            AnscTraceWarning(("%llu space left in tmp\n", result));
        }

        hwst_runTest = bValue;
        if(hwst_runTest)
        {
            AnscTraceFlow(("%s Execute tests value is set to true\n", __FUNCTION__));
            fp = fopen(HWSELFTEST_RESULTS_FILE, "r");
            if(NULL != fp)
            {
                fclose(fp);
                if (remove(HWSELFTEST_RESULTS_FILE) == 0)
                    AnscTraceFlow(("%s Deleted results file\n", __FUNCTION__));
            }
            else
            {
                //Make sure that the backup file is deleted. This is checked in
                //HHT code as well, but adding it here.
                fp = fopen(BKP_HWSELFTEST_RESULTS_FILE,"r");
                if(NULL != fp)
                {
                    fclose(fp);
                    if (remove(BKP_HWSELFTEST_RESULTS_FILE) == 0)
                        AnscTraceFlow(("%s Deleted results file from backup location.\n", __FUNCTION__));
                }
                //else: No results file generated. 1st run or maybe last one failed
            }
            //Check for min space after the results file is deleted, so that when someone does
            //a get on Results, the error message can be sent back.
            if (result < HWSELFTEST_START_MIN_SPACE)
            {
                AnscTraceWarning(("Not enough space in DRAM to initiate the Hwselftest. Exit\n"));
                char info[100] = "Error: Not enough space to initiate Hardware Health Test.";
                hwExecInfo = malloc(sizeof(char)*100);
                AnscCopyString(hwExecInfo,info);
                return TRUE;
            }
            AnscTraceWarning(("Command to execute HWST\n"));
            AnscTraceFlow(("Executing Hwselftest..\n"));
            v_secure_system("/usr/bin/hwselftest_run.sh 0001 &");
        }
        else
        {
            AnscTraceFlow(("%s Execute tests value is set to false\n", __FUNCTION__));
        }
        return TRUE;
#else
        hwst_runTest = FALSE;
#endif
    }
    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        hwHealthTest_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue
            );

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue
                The string value buffer;

    return:     0 if succeeded;
                1 unable to read results file;

**********************************************************************/
ULONG
hwHealthTest_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue
    )
{
    if (strcmp(ParamName, "Results") == 0)
    {
#ifdef COLUMBO_HWTEST
        AnscTraceFlow(("%s Results get\n", __FUNCTION__));
        errno_t rc = -1;

        FILE *p = fopen(HWSELFTEST_RESULTS_FILE, "r");
        if (p == NULL)
        {
            AnscTraceWarning(("%s, hwselftest.results not present in tmp. Check nvram\n", __FUNCTION__));
            p = fopen(BKP_HWSELFTEST_RESULTS_FILE,"r");
            if(p == NULL)
            {
                AnscTraceWarning(("%s, hwselftest.results not present in nvram\n", __FUNCTION__));
                //If both primary and backup files are not present, maybe the test did not run. Check if the struc hw
                if(NULL != hwExecInfo)
                {
                    rc = strcpy_s(pValue, 1024 , hwExecInfo);
                    ERR_CHK(rc);
                    hwst_runTest = FALSE;
                }
                else
                {
                    AnscTraceWarning(("hwExecInfo NOT set.\n"));
                    rc = strcpy_s(pValue, 1024 , "");
                    ERR_CHK(rc);
                }

                return 0;
            }
        }

        char hwst_result_string[HWSELFTEST_RESULTS_SIZE] = {'\0'};
        char results_data[HWSELFTEST_RESULTS_SIZE] = {'\0'};
        int offset = 0;
        while(fgets(results_data, HWSELFTEST_RESULTS_SIZE, p) != NULL && results_data[0] != '\n')
        {
            rc = strcpy_s(hwst_result_string + offset, sizeof(hwst_result_string)-offset ,results_data); /* copy input at offset into output */
            ERR_CHK(rc);
            offset += strlen(results_data);               /* advance the offset by the length of the string */
            AnscTraceFlow(("%s Results output string after copying a new line: %s\n", __FUNCTION__, hwst_result_string));
        }
        hwst_runTest = FALSE;
        rc = strcpy_s(pValue, 1024 , hwst_result_string);
        ERR_CHK(rc);
        AnscTraceFlow(("%s Results - Overall result: %s\n", __FUNCTION__, pValue));
        fclose(p);
        return 0;
#endif
    }

    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return -1;
}
