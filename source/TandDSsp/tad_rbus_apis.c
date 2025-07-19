/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributedTestDiagnosticLogInit, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include "ccsp_trace.h"
#include "tad_rbus_apis.h"

rbusHandle_t g_rbusHandle;

/***********************************************************************

  tadRbusInit(): Initialize Rbus and data elements for Test&Diagnostic

 ***********************************************************************/
rbusError_t tadRbusInit()
{
	int rc = RBUS_ERROR_SUCCESS;

	if(RBUS_ENABLED != rbus_checkStatus())
    {
		CcspTraceError(("%s: RBUS not available. Events are not supported\n", __FUNCTION__));
		return RBUS_ERROR_NOT_INITIALIZED;
    }

	rc = rbus_open(&g_rbusHandle, TAD_COMPONENT_NAME);
	if (rc != RBUS_ERROR_SUCCESS)
	{
		CcspTraceError(("Test&Diagnostic rbus initialization failed\n"));
		rc = RBUS_ERROR_NOT_INITIALIZED;
		return rc;
	}

	return rc;
}

/***********************************************************************

  tadTerminate(): Terminate Rbus for TestDiagnostics

 ***********************************************************************/
rbusError_t tadTerminate()
{
	int rc = rbus_close(g_rbusHandle);
	return rc;
}
