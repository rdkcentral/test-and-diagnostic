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

#include <ctype.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "ansc_platform.h"
#include "plugin_main_apis.h"
#include "ansc_string_util.h"
#include "ccsp_trace.h"
#include "secure_wrapper.h"
#include "cosa_apis_util.h"
#include "platform_hal.h"
#include "safec_lib_common.h"
#include "cosa_rdktest_dml.h"

BOOL isTestEnabled() {
    if (access(filePath, F_OK) == 0) {
        return TRUE; // File exists
    }
    return FALSE; // File does not exist   
}

/***********************************************************************

 APIs for Object:

    Device.X_RDK_AutomationTest.

    *  X_RDK_AutomationTest_GetParamStringValue
    *  X_RDK_AutomationTest_SetParamStringValue

***********************************************************************/
/**********************************************************************
    caller:     owner of this object
    prototype:
        ULONG
        X_RDK_AutomationTest_GetParamStringValue
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
                -1 if not supported.
**********************************************************************/
ULONG
X_RDK_AutomationTest_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    errno_t rc = -1;
    void *handle = NULL;
    char *error = NULL;

    // Check Test enabled
    if (!isTestEnabled()) {
        AnscTraceFlow(("%s : Test not enabled, skipping test\n", __FUNCTION__));
        char* result = "Test not enabled";
        rc = strcpy_s(pValue, *pUlSize, result);
        ERR_CHK(rc);
        return 0;
    }

    // Load the shared library
    handle = dlopen(AUTOMATION_TEST_LIB, RTLD_LAZY);
    if (!handle) {
        AnscTraceFlow(("%s : Library for Automation test is unavailable\n", __FUNCTION__));
        char* result = "Library for Automation test is unavailable";
        rc = strcpy_s(pValue, *pUlSize, result);
        ERR_CHK(rc);
        return 0;
    }
    // Clear any existing error
    dlerror();

    if (strcmp(ParamName, "Run") == 0)
    {
        const char* (*get_test_run)();

        // Get the function pointer
        *(void **) (&get_test_run) = dlsym(handle, "get_test_run");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return -1;
        }

        /* collect value */
        const char* run = get_test_run();
        if (run == NULL) {
            dlclose(handle);
            return -1;
        }
        rc = strcpy_s(pValue, *pUlSize, run);
        ERR_CHK(rc);
        dlclose(handle);
        free((char*)run);
        run = NULL;
        return 0;
    }
    else if (strcmp(ParamName, "Status") == 0)
    {
        const char* (*get_test_status)();

        // Get the function pointer
        *(void **) (&get_test_status) = dlsym(handle, "get_test_status");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return -1;
        }
        /* collect value */
        const char* result = get_test_status();
        if (result == NULL) {
            dlclose(handle);
            return -1;
        }
        rc = strcpy_s(pValue, *pUlSize, result);
        ERR_CHK(rc);
        dlclose(handle);
        free((char*)result);
        result = NULL;
        return 0;
    }
    else if (strcmp(ParamName, "Result") == 0)
    {
        const char* (*get_test_result)();

        // Get the function pointer
        *(void **) (&get_test_result) = dlsym(handle, "get_test_result");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return -1;
        }
        /* collect value */
        const char* result = get_test_result();
        if (result == NULL) {
            dlclose(handle);
            return -1;
        }
        rc = strcpy_s(pValue, *pUlSize, result);
        ERR_CHK(rc);
        dlclose(handle);
        free((char*)result);
        result = NULL;
        return 0;
    }
    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    dlclose(handle);
    return -1;
 }

 /**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        X_RDK_AutomationTest_SetParamStringValue
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
typedef struct {
    void *handle;
    BOOL (*is_test_running)();
} monitorThreadArgs;

// Function to monitor the thread and close the handle
void *monitor_thread(void *args) {
    monitorThreadArgs *threadArgs = (monitorThreadArgs *)args;

    // Wait for the thread in the shared library to complete
    while (threadArgs->is_test_running()) {
        sleep(5); // Poll every 5 second
    }

    // Close the shared library handle
    dlclose(threadArgs->handle);
    free(threadArgs);
    return NULL;
}

BOOL
X_RDK_AutomationTest_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    void *handle = NULL;
    char *error = NULL;

    if(strcmp(ParamName, "Run") == 0)
    {
        // Check Test enabled
        if (!isTestEnabled()) {
            AnscTraceWarning(("%s : Test not enabled, skipping test\n", __FUNCTION__));
            return FALSE;
        }

        // Load the shared library
        handle = dlopen(AUTOMATION_TEST_LIB, RTLD_LAZY);
        if (!handle) {
            AnscTraceFlow(("%s : Library for Automation test is unavailable\n",__FUNCTION__));
            return FALSE;
        }
    
        BOOL (*is_test_running)();

        // Clear any existing error
        dlerror();

        // Get the function pointer
        *(void **) (&is_test_running) = dlsym(handle, "is_test_running");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return FALSE;
        }

        if( pString != NULL )
        {
            if (strcasecmp(pString, "DHCPClientv4") == 0 ) {
                int (*Trigger_dhcpClientv4test)();
                // Get the function pointer
                *(void **) (&Trigger_dhcpClientv4test) = dlsym(handle, "Trigger_dhcpClientv4test");
                if ((error = dlerror()) != NULL)  {
                    fprintf(stderr, "%s\n", error);
                    dlclose(handle);
                    return FALSE;
                }
                if( FALSE == is_test_running() ) {
                    int status = Trigger_dhcpClientv4test();
                    if( status != 0 ) {
                        AnscTraceWarning(("%s : Failed to start DHCPClientv4 test\n", __FUNCTION__));
                        dlclose(handle);
                        return FALSE;
                    }
                } else {
                    AnscTraceWarning(("%s : Automation test is already running\n", __FUNCTION__));
                    dlclose(handle);
                    return FALSE;
                }
            }
            else if (strcasecmp(pString, "DHCPClientv6") == 0 ) {
                int (*Trigger_dhcpClientv6test)();
                // Get the function pointer
                *(void **) (&Trigger_dhcpClientv6test) = dlsym(handle, "Trigger_dhcpClientv6test");
                if ((error = dlerror()) != NULL)  {
                    fprintf(stderr, "%s\n", error);
                    dlclose(handle);
                    return FALSE;
                }
                if( FALSE == is_test_running() ) {
                    int status = Trigger_dhcpClientv6test();
                    if( status != 0 ) {
                        AnscTraceWarning(("%s : Failed to start DHCPClientv6 test\n", __FUNCTION__));
                        dlclose(handle);
                        return FALSE;
                    }
                } else {
                    AnscTraceWarning(("%s : Automation test is already running\n", __FUNCTION__));
                    dlclose(handle);
                    return FALSE;
                }
            }
            else if (strncasecmp(pString, "FlowManager|", 12) == 0) {
                int (*TriggerFlowManagerTest)(char*);
                // Get the function pointer
                *(void **) (&TriggerFlowManagerTest) = dlsym(handle, "TriggerFlowManagerTest");
                if ((error = dlerror()) != NULL)  {
                    fprintf(stderr, "%s\n", error);
                    dlclose(handle);
                    return FALSE;
                }
                AnscTraceFlow(("Input string: %s\n", pString));
                if( FALSE == is_test_running() ) {
                    char *input = pString + 12; // Move past "FlowManager|"
                    int status = TriggerFlowManagerTest(input);
                    if( status != 0 ) {
                        AnscTraceWarning(("%s : Failed to start FlowManager test\n", __FUNCTION__));
                        dlclose(handle);
                        return FALSE;
                    }
                } else {
                    AnscTraceWarning(("%s : Automation test is already running\n", __FUNCTION__));
                    dlclose(handle);
                    return FALSE;
                }
            }
            else if (strcasecmp(pString, "SpeedTestXLE") == 0 ) {
                int (*Trigger_SpeedTestXLE)();
                // Get the function pointer
                *(void **) (&Trigger_SpeedTestXLE) = dlsym(handle, "Trigger_SpeedTestXLE");
                if ((error = dlerror()) != NULL)  {
                    fprintf(stderr, "%s\n", error);
                    dlclose(handle);
                    return FALSE;
                }
                if( FALSE == is_test_running() ) {
                    int status = Trigger_SpeedTestXLE();
                    if( status != 0 ) {
                        AnscTraceWarning(("%s : Failed to start SpeedTest XLE test\n", __FUNCTION__));
                        dlclose(handle);
                        return FALSE;
                    }
                } else {
                    AnscTraceWarning(("%s : Automation test is already running\n", __FUNCTION__));
                    dlclose(handle);
                    return FALSE;
                }
            }
            else if (strncasecmp(pString, "logUpload|", 10) == 0) {
                int (*Trigger_logUpload)(char*);
                // Get the function pointer (POSIX-recommended pattern)
                void *func_ptr = dlsym(handle, "Trigger_logUpload");
                Trigger_logUpload = (int (*)(char*))func_ptr;
                if ((error = dlerror()) != NULL)  {
                    fprintf(stderr, "%s\n", error);
                    dlclose(handle);
                    return FALSE;
                }
                AnscTraceFlow(("Input string: %s\n", pString));
                if( FALSE == is_test_running() ) {
                    char *input = pString + strlen("logUpload|"); // Move past "logUpload|"
                    int status = Trigger_logUpload(input);
                    if( status != 0 ) {
                        AnscTraceWarning(("%s : Failed to start logUpload test\n", __FUNCTION__));
                        dlclose(handle);
                        return FALSE;
                    }
                } else {
                    AnscTraceWarning(("%s : Automation test is already running\n", __FUNCTION__));
                    dlclose(handle);
                    return FALSE;
                }
            }
            else if (strncasecmp(pString, "fileUpload|", 10) == 0) {
                int (*Trigger_fileUpload)(char*);
                // Get the function pointer (POSIX-recommended pattern)
                void *func_ptr = dlsym(handle, "Trigger_fileUpload");
                Trigger_fileUpload = (int (*)(char*))func_ptr;
                if ((error = dlerror()) != NULL)  {
                    fprintf(stderr, "%s\n", error);
                    dlclose(handle);
                    return FALSE;
                }
                AnscTraceFlow(("Input string: %s\n", pString));
                if( FALSE == is_test_running() ) {
                    char *input = pString + strlen("fileUpload|"); // Move past "fileUpload|"
                    int status = Trigger_fileUpload(input);
                    if( status != 0 ) {
                        AnscTraceWarning(("%s : Failed to start fileUpload test\n", __FUNCTION__));
                        dlclose(handle);
                        return FALSE;
                    }
                } else {
                    AnscTraceWarning(("%s : Automation test is already running\n", __FUNCTION__));
                    dlclose(handle);
                    return FALSE;
                }
            }
            else {
                AnscTraceWarning(("%s : Invalid test name '%s'\n", __FUNCTION__, pString));
                dlclose(handle);
                return FALSE;
            } 
            // Create a detached thread to monitor the test and close the handle
            pthread_t monitorThread;
            monitorThreadArgs *threadArgs = (monitorThreadArgs *)malloc(sizeof(monitorThreadArgs));
            threadArgs->handle = handle;
            threadArgs->is_test_running = is_test_running;
            if (pthread_create(&monitorThread, NULL, monitor_thread, threadArgs) != 0) {
                AnscTraceWarning(("%s : Failed to create thread to monitor\n", __FUNCTION__));
                free(threadArgs);
                dlclose(handle);
                return FALSE;
            }
            pthread_detach(monitorThread);
            return TRUE;
        }
        else {
            AnscTraceWarning(("%s : Invalid input string\n", __FUNCTION__));
            dlclose(handle);
            return FALSE;
        }           
    }
    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}