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
    } else {
        return FALSE; // File does not exist
    }
}

/***********************************************************************

 APIs for Object:

    X_RDK_Test.DHCPClientv4Test.

    *  DHCPClientv4Test_GetParamBoolValue
    *  DHCPClientv4Test_SetParamBoolValue
    *  DHCPClientv4Test_GetParamStringValue
***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DHCPClientv4Test_GetParamBoolValue
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
DHCPClientv4Test_GetParamBoolValue
	(
	    ANSC_HANDLE                 hInsContext,
	    char*                       ParamName,
	    BOOL*                       pBool
	)
{
    void *handle = NULL;
    char *error = NULL;

    /* check the parameter name and return the corresponding value */
	if (strcmp(ParamName, "Run") == 0)
    {
        // Check Test enabled
        if (!isTestEnabled()) {
            AnscTraceFlow(("%s : Test not enabled, skipping test\n", __FUNCTION__));
            return FALSE;
        }
        BOOL (*is_dhcpClientv4Test_running)();
        // Load the shared library
        handle = dlopen(DHCP_CLIENT_LIB, RTLD_LAZY);
        if (!handle) {
            AnscTraceFlow(("%s : Library for DHCPClient test is unavailable\n", __FUNCTION__));
            return FALSE;
        }
        // Clear any existing error
        dlerror();

        // Get the function pointer
        *(void **) (&is_dhcpClientv4Test_running) = dlsym(handle, "is_dhcpClientv4Test_running");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return FALSE;
        }

        /* collect value */
        *pBool = is_dhcpClientv4Test_running();
        dlclose(handle);
	    return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        ULONG
        DHCPClientv4Test_GetParamStringValue
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
DHCPClientv4Test_GetParamStringValue
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

    if (strcmp(ParamName, "Result") == 0)
    {
        // Check Test enabled
        if (!isTestEnabled()) {
            AnscTraceFlow(("%s : Test not enabled, skipping test\n", __FUNCTION__));
            char* result = "Test not enabled";
            rc = strcpy_s(pValue, *pUlSize, result);
            ERR_CHK(rc);
            return 0;
        }

        const char* (*get_dhcpClientv4Test_result)();
        // Load the shared library
        handle = dlopen(DHCP_CLIENT_LIB, RTLD_LAZY);
        if (!handle) {
            AnscTraceFlow(("%s : Library for DHCPClient test is unavailable\n", __FUNCTION__));
            char* result = "Library for DHCPClient test is unavailable";
            rc = strcpy_s(pValue, *pUlSize, result);
            ERR_CHK(rc);
            return 0;
        }
        // Clear any existing error
        dlerror();

        // Get the function pointer
        *(void **) (&get_dhcpClientv4Test_result) = dlsym(handle, "get_dhcpClientv4Test_result");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return -1;
        }
        /* collect value */
        const char* result = get_dhcpClientv4Test_result();
        if (result == NULL) {
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
    return -1;
 }

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DHCPClientv4Test_SetParamBoolValue
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
typedef struct {
    void *handle;
    BOOL (*is_dhcpClientv4Test_running)();
} v4ThreadArgs;

// Function to monitor the thread and close the handle
void *monitor_v4thread(void *args) {
    v4ThreadArgs *threadArgs = (v4ThreadArgs *)args;

    // Wait for the thread in the shared library to complete
    while (threadArgs->is_dhcpClientv4Test_running()) {
        sleep(5); // Poll every 5 second
    }

    // Close the shared library handle
    dlclose(threadArgs->handle);
    free(threadArgs);
    return NULL;
}

BOOL
DHCPClientv4Test_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    void *handle = NULL;
    char *error = NULL;

    if(strcmp(ParamName, "Run") == 0)
    {
        // Check Test enabled
        if (!isTestEnabled()) {
            AnscTraceFlow(("%s : Test not enabled, skipping test\n", __FUNCTION__));
            return FALSE;
        }

        int (*Trigger_dhcpClientv4test)();
        BOOL (*is_dhcpClientv4Test_running)();

        // Load the shared library
        handle = dlopen(DHCP_CLIENT_LIB, RTLD_LAZY);
        if (!handle) {
            AnscTraceFlow(("%s : Library for DHCPClient test is unavailable\n",__FUNCTION__));
            return FALSE;
        }

        // Clear any existing error
        dlerror();

        // Get the function pointer
        *(void **) (&Trigger_dhcpClientv4test) = dlsym(handle, "Trigger_dhcpClientv4test");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return FALSE;
        }

        // Get the function pointer
        *(void **) (&is_dhcpClientv4Test_running) = dlsym(handle, "is_dhcpClientv4Test_running");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return FALSE;
        }

        if( bValue )
        {
			if( FALSE == is_dhcpClientv4Test_running() )
			{
			    int status = Trigger_dhcpClientv4test();
                if( status != 0 ) {
                    AnscTraceWarning(("%s : Failed to start DHCPClientv4 test\n", __FUNCTION__));
                    dlclose(handle);
                    return FALSE;
                }
                // Create a detached thread to monitor the test and close the handle
                pthread_t monitorThread;
                v4ThreadArgs *threadArgs = (v4ThreadArgs *)malloc(sizeof(v4ThreadArgs));
                threadArgs->handle = handle;
                threadArgs->is_dhcpClientv4Test_running = is_dhcpClientv4Test_running;

                if (pthread_create(&monitorThread, NULL, monitor_v4thread, threadArgs) != 0) {
                    AnscTraceWarning(("%s : Failed to create thread to monitor DHCPClientv4 test\n", __FUNCTION__));
                    free(threadArgs);
                    dlclose(handle);
                    return FALSE;
                }
                pthread_detach(monitorThread);
			}
			else
			{
				AnscTraceFlow(("%s : DHCPClientv4 test is already running\n", __FUNCTION__));
                dlclose(handle);
            }
            return TRUE;
		}
        dlclose(handle);
    }
    return FALSE;
}

/***********************************************************************

 APIs for Object:

    X_RDK_Test.DHCPClientv6Test.

    *  DHCPClientv6Test_GetParamBoolValue
    *  DHCPClientv6Test_SetParamBoolValue
    *  DHCPClientv6Test_GetParamStringValue
***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DHCPClientv6Test_GetParamBoolValue
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
DHCPClientv6Test_GetParamBoolValue
	(
	    ANSC_HANDLE                 hInsContext,
	    char*                       ParamName,
	    BOOL*                       pBool
	)
{
    void *handle = NULL;
    char *error = NULL;

    // Check Test enabled
    if (!isTestEnabled()) {
        AnscTraceFlow(("%s : Test not enabled, skipping test\n", __FUNCTION__));
        return FALSE;
    }

    /* check the parameter name and return the corresponding value */
	if (strcmp(ParamName, "Run") == 0)
    {
        BOOL (*is_dhcpClientv6Test_running)();
        // Load the shared library
        handle = dlopen(DHCP_CLIENT_LIB, RTLD_LAZY);
        if (!handle) {
            AnscTraceFlow(("%s : Library for DHCPClient test is unavailable\n", __FUNCTION__));
            return FALSE;
        }
        // Clear any existing error
        dlerror();

        // Get the function pointer
        *(void **) (&is_dhcpClientv6Test_running) = dlsym(handle, "is_dhcpClientv6Test_running");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return FALSE;
        }

        /* collect value */
        *pBool = is_dhcpClientv6Test_running();
        dlclose(handle);
	    return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        ULONG
        DHCPClientv6Test_GetParamStringValue
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
DHCPClientv6Test_GetParamStringValue
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
    if (strcmp(ParamName, "Result") == 0)
    {
        // Check Test enabled
        if (!isTestEnabled()) {
            AnscTraceFlow(("%s : Test not enabled, skipping test\n", __FUNCTION__));
            char* result = "Test not enabled";
            rc = strcpy_s(pValue, *pUlSize, result);
            ERR_CHK(rc);
            return 0;
        }

        const char* (*get_dhcpClientv6Test_result)();
        // Load the shared library
        handle = dlopen(DHCP_CLIENT_LIB, RTLD_LAZY);
        if (!handle) {
            AnscTraceFlow(("%s : Library for DHCPClient test is unavailable\n", __FUNCTION__));
            char* result = "Library for DHCPClient test is unavailable";
            rc = strcpy_s(pValue, *pUlSize, result);
            ERR_CHK(rc);
            return 0;
        }
        // Clear any existing error
        dlerror();

        // Get the function pointer
        *(void **) (&get_dhcpClientv6Test_result) = dlsym(handle, "get_dhcpClientv6Test_result");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return -1;
        }
        /* collect value */
        const char* result = get_dhcpClientv6Test_result();
        rc = strcpy_s(pValue, *pUlSize, result);
        ERR_CHK(rc);
        dlclose(handle);
        free((char*)result);
        result = NULL;
        return 0;
    }
    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
 }

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DHCPClientv4Test_SetParamBoolValue
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

 typedef struct {
    void *handle;
    BOOL (*is_dhcpClientv6Test_running)();
} v6ThreadArgs;

// Function to monitor the thread and close the handle
void *monitor_v6thread(void *args) {
    v6ThreadArgs *threadArgs = (v6ThreadArgs *)args;

    // Wait for the thread in the shared library to complete
    while (threadArgs->is_dhcpClientv6Test_running()) {
        sleep(5); // Poll every 5 second
    }

    // Close the shared library handle
    dlclose(threadArgs->handle);
    free(threadArgs); // Free the allocated memory for thread arguments
    return NULL;
}

BOOL
DHCPClientv6Test_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    void *handle = NULL;
    char *error = NULL;
    if(strcmp(ParamName, "Run") == 0)
    {
        // Check Test enabled
        if (!isTestEnabled()) {
            AnscTraceFlow(("%s : Test not enabled, skipping test\n", __FUNCTION__));
            return FALSE;
        }

        int (*Trigger_dhcpClientv6test)();
        BOOL (*is_dhcpClientv6Test_running)();

        // Load the shared library
        handle = dlopen(DHCP_CLIENT_LIB, RTLD_LAZY);
        if (!handle) {
            AnscTraceFlow(("%s : Library for DHCPClient test is unavailable\n", __FUNCTION__));
            return FALSE;
        }

        // Clear any existing error
        dlerror();

        // Get the function pointer
        *(void **) (&Trigger_dhcpClientv6test) = dlsym(handle, "Trigger_dhcpClientv6test");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return FALSE;
        }

        // Get the function pointer
        *(void **) (&is_dhcpClientv6Test_running) = dlsym(handle, "is_dhcpClientv6Test_running");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return FALSE;
        }

        if( bValue )
        {
			if( FALSE == is_dhcpClientv6Test_running() )
			{
			    int status = Trigger_dhcpClientv6test();
                if( status != 0 ) {
                    AnscTraceWarning(("%s : Failed to start DHCPClientv6 test\n", __FUNCTION__));
                    dlclose(handle);
                    return FALSE;
                }
                // Create a detached thread to monitor the test and close the handle
                pthread_t monitorThread;
                v6ThreadArgs *threadArgs = (v6ThreadArgs *)malloc(sizeof(v6ThreadArgs));
                threadArgs->handle = handle;
                threadArgs->is_dhcpClientv6Test_running = is_dhcpClientv6Test_running;

                if (pthread_create(&monitorThread, NULL, monitor_v6thread, threadArgs) != 0) {
                    AnscTraceWarning(("%s : Failed to create thread to monitor DHCPClientv6 test\n", __FUNCTION__));
                    free(threadArgs);
                    dlclose(handle);
                    return FALSE;
                }
                pthread_detach(monitorThread);
			}
			else
			{
				AnscTraceFlow(("%s : DHCPClientv6 test is already running\n",__FUNCTION__));
                dlclose(handle);
            }
            return TRUE;
		}
        dlclose(handle);
    }
    return TRUE;
}

/***********************************************************************

 APIs for Object:

    X_RDK_Test.FlowManagerTest.

    *  FlowManagerTest_GetParamStringValue
    *  FlowManagerTest_SetParamStringValue

***********************************************************************/
/**********************************************************************
    caller:     owner of this object
    prototype:
        ULONG
        FlowManagerTest_GetParamStringValue
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
FlowManagerTest_GetParamStringValue
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
    if (strcmp(ParamName, "Run") == 0)
    {
        // Check Test enabled
        if (!isTestEnabled()) {
            AnscTraceFlow(("%s : Test not enabled, skipping test\n", __FUNCTION__));
            char* result = "Test not enabled";
            rc = strcpy_s(pValue, *pUlSize, result);
            ERR_CHK(rc);
            return 0;
        }

        const char* (*get_flowManagerTest_run)();
        // Load the shared library
        handle = dlopen(FLOW_MANAGER_LIB, RTLD_LAZY);
        if (!handle) {
            AnscTraceFlow(("%s : Library for FlowManager test is unavailable\n", __FUNCTION__));
            char* result = "Library for FlowManager test is unavailable";
            rc = strcpy_s(pValue, *pUlSize, result);
            ERR_CHK(rc);
            return 0;
        }
        // Clear any existing error
        dlerror();

        // Get the function pointer
        *(void **) (&get_flowManagerTest_run) = dlsym(handle, "get_flowManagerTest_run");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return -1;
        }

        /* collect value */
        const char* run = get_flowManagerTest_run();
        if (run == NULL) {
            return -1;
        }
        rc = strcpy_s(pValue, *pUlSize, run);
        ERR_CHK(rc);
        dlclose(handle);
        free((char*)run);
        run = NULL;
        return 0;
    }
    else if (strcmp(ParamName, "Result") == 0)
    {
        const char* (*get_flowManagerTest_result)();
        // Load the shared library
        handle = dlopen(FLOW_MANAGER_LIB, RTLD_LAZY);
        if (!handle) {
            AnscTraceFlow(("%s : Library for FlowManager test is unavailable\n", __FUNCTION__));
            char* result = "Library for FlowManager test is unavailable";
            rc = strcpy_s(pValue, *pUlSize, result);
            ERR_CHK(rc);
            return 0;
        }
        // Clear any existing error
        dlerror();

        // Get the function pointer
        *(void **) (&get_flowManagerTest_result) = dlsym(handle, "get_flowManagerTest_result");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return -1;
        }
        /* collect value */
        const char* result = get_flowManagerTest_result();
        if (result == NULL) {
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
    return -1;
 }

 /**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        FlowManagerTest_SetParamStringValue
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
    BOOL (*is_flowManagerTest_running)();
} fmThreadArgs;

// Function to monitor the thread and close the handle
void *monitor_fmthread(void *args) {
    fmThreadArgs *threadArgs = (fmThreadArgs *)args;

    // Wait for the thread in the shared library to complete
    while (threadArgs->is_flowManagerTest_running()) {
        sleep(5); // Poll every 5 second
    }

    // Close the shared library handle
    dlclose(threadArgs->handle);
    free(threadArgs);
    return NULL;
}

BOOL
FlowManagerTest_SetParamStringValue
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
            AnscTraceFlow(("%s : Test not enabled, skipping test\n", __FUNCTION__));
            return FALSE;
        }

        int (*TriggerFlowManagerTest)(char*);
        BOOL (*is_flowManagerTest_running)();

        // Load the shared library
        handle = dlopen(FLOW_MANAGER_LIB, RTLD_LAZY);
        if (!handle) {
            AnscTraceFlow(("%s : Library for FlowManager test is unavailable\n",__FUNCTION__));
            return TRUE;
        }

        // Clear any existing error
        dlerror();

        // Get the function pointer
        *(void **) (&TriggerFlowManagerTest) = dlsym(handle, "TriggerFlowManagerTest");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return FALSE;
        }

        // Get the function pointer
        *(void **) (&is_flowManagerTest_running) = dlsym(handle, "is_flowManagerTest_running");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            dlclose(handle);
            return FALSE;
        }

        if( pString != NULL)
        {
            // Validate mandatory fields (srcip and dstip)
            if (strstr(pString, "srcip=") == NULL || strstr(pString, "dstip=") == NULL) {
                AnscTraceWarning(("%s : Missing mandatory fields (srcip or dstip).\n", __FUNCTION__));
                dlclose(handle);
                return FALSE;
            }

            AnscTraceFlow(("Input string: %s\n", pString));

			if( FALSE == is_flowManagerTest_running() )
			{
			    int status = TriggerFlowManagerTest(pString);
                if( status != 0 ) {
                    AnscTraceWarning(("%s : Failed to start FlowManager test\n", __FUNCTION__));
                    dlclose(handle);
                    return FALSE;
                }
                // Create a detached thread to monitor the test and close the handle
                pthread_t monitorThread;
                fmThreadArgs *threadArgs = (fmThreadArgs *)malloc(sizeof(fmThreadArgs));
                threadArgs->handle = handle;
                threadArgs->is_flowManagerTest_running = is_flowManagerTest_running;

                if (pthread_create(&monitorThread, NULL, monitor_fmthread, threadArgs) != 0) {
                    AnscTraceWarning(("%s : Failed to create thread to monitor FlowManager test\n", __FUNCTION__));
                    free(threadArgs);
                    dlclose(handle);
                    return FALSE;
                }
                pthread_detach(monitorThread);
			}
			else
			{
				AnscTraceFlow(("%s : FlowManager test is already running\n", __FUNCTION__));
                dlclose(handle);
                return FALSE;
            }
            return TRUE;
		}
        dlclose(handle);
    }
    return FALSE;
}



