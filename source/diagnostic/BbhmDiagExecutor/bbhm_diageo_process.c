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

    module:     bbhm_diageo_states.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the processing functions
        of the Bbhm Diagnostic Executor Object.

        *   BbhmDiageoCheckCanStart
        *   BbhmDiageoStartDiag
        *   BbhmDiageoStopDiag
        *   BbhmDiageoRetrieveResult
        *   BbhmDiageoResultQueryTask

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Ding Hua, Li Shi

    ---------------------------------------------------------------

    revision:

        2007/02/08    initial revision.

**********************************************************************/


#include "bbhm_diageo_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOLEAN
        BbhmDiageoCheckCanStart
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to check if a new diagnostic process
        can start.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

BOOLEAN
BbhmDiageoCheckCanStart
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_EXEC_OBJECT          pMyObject       = (PBBHM_DIAG_EXEC_OBJECT)hThisObject;
    BOOLEAN                         bCanStart       = FALSE;

    AnscAcquireLock(&pMyObject->AccessLock);

    if ( pMyObject->bResultQueryRunning )
    {
        bCanStart = FALSE;
    }
    else
    {
        bCanStart = TRUE;
    }

    AnscReleaseLock(&pMyObject->AccessLock);

    return  bCanStart;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiageoStartDiag
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to start the diagnostic process. As
        the base class, this object doesn't do anything else but
        start the result query task.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_STATUS
BbhmDiageoStartDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_EXEC_OBJECT          pMyObject       = (PBBHM_DIAG_EXEC_OBJECT)hThisObject;
    PDSLH_DIAG_INFO_BASE            pDiagInfo       = (PDSLH_DIAG_INFO_BASE  )pMyObject->hDslhDiagInfo;

    AnscAcquireLock(&pMyObject->AccessLock);

    pDiagInfo->DiagnosticState      = DSLH_DIAG_STATE_TYPE_Inprogress;
    pMyObject->bResultQueryRunning  = TRUE;

    AnscResetEvent(&pMyObject->ResultQueryEvent);

    AnscReleaseLock(&pMyObject->AccessLock);

    AnscSpawnTask2
            (
                pMyObject->ResultQueryTask,
                (ANSC_HANDLE)pMyObject,
                "BbhmDiagTask",
                ANSC_TASK_PRIORITY_NORMAL
            );

    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiageoStopDiag
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to stop the diagnostic process.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_STATUS
BbhmDiageoStopDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiageoRetrieveResult
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve the diagnostic result.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_STATUS
BbhmDiageoRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiageoResultQueryTask
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This task runs to query the diagnostic result periodically.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     object state.

**********************************************************************/

ANSC_STATUS
BbhmDiageoResultQueryTask
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;
    PBBHM_DIAG_EXEC_OBJECT          pMyObject           = (PBBHM_DIAG_EXEC_OBJECT     )hThisObject;
    PDSLH_DIAG_INFO_BASE            pDiagInfo           = NULL;
    BOOLEAN                         bQueryDone          = FALSE;

    AnscTraceFlow(("BbhmDiageoResultQueryTask ...\n"));

    do
    {
        returnStatus = pMyObject->RetrieveResult((ANSC_HANDLE)pMyObject);

        if ( returnStatus == ANSC_STATUS_SUCCESS )
        {
            pDiagInfo  = (PDSLH_DIAG_INFO_BASE)pMyObject->hDslhDiagInfo;
            bQueryDone = TRUE;

            if ( (pDiagInfo->DiagnosticState != DSLH_DIAG_STATE_TYPE_Inprogress)
                  && (pDiagInfo->DiagnosticState != DSLH_DIAG_STATE_TYPE_Requested) )
            {
                pMyObject->ResultTimestamp = AnscGetTickInSeconds();
                break;
            }
        }
        else
        {
            /* internal error occurs, quit immediatelly */
            break;
        }

        AnscWaitEvent(&pMyObject->ResultQueryEvent, 1000);
    }
    while ( pMyObject->bResultQueryRunning );

    if ( TRUE/*pDiagInfo->RequestType == DSLH_DIAGNOSTIC_REQUEST_TYPE_Acs*/ )
    {
        /* Always notify the initiator */
        CcspTraceInfo(("BbhmDiageoResultQueryTask -- notify initiator.....\n"));

        /* send out the notification */
        if ( ANSC_STATUS_SUCCESS != CosaSendDiagCompleteSignal() )
        {
            AnscTraceWarning(("Failed to send event for diagnostics completion.\n"));
        }
    }

    AnscAcquireLock(&pMyObject->AccessLock);

    AnscTraceFlow(("BbhmDiageoResultQueryTask -- quiting...\n"));

    /*
     *  stop the diagnostic process
     */
    pMyObject->bResultQueryRunning  = FALSE;

    if ( !bQueryDone )
    {
        pMyObject->StopDiag((ANSC_HANDLE)pMyObject);
    }

    AnscSetEvent(&pMyObject->ResultQueryExitEvent);

    AnscReleaseLock(&pMyObject->AccessLock);

    AnscTraceFlow(("BbhmDiageoStartDiag -- exit...\n"));

    return  ANSC_STATUS_SUCCESS;
}
