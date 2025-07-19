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

        This module implements the advanced state-access functions
        of the Bbhm Diagnostic Executor Object.

        *   BbhmDiageoSetDiagParams
        *   BbhmDiageoGetResult
        *   BbhmDiageoGetResultTimeStamp
        *   BbhmDiageoCopyDiagParams
        *   BbhmDiageoSetDiagState
        *   BbhmDiageoReset

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

        ANSC_STATUS
        BbhmDiageoSetDiagParams
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDslhDiagInfo
            );

    description:

        This function is called to set the diagnostic parameters. If
        the diagnostic process is ongoing, it will be stopped first.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDslhDiagInfo
                The pointer points to the diagnostic parameters.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiageoSetDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{
    PBBHM_DIAG_EXEC_OBJECT          pMyObject    = (PBBHM_DIAG_EXEC_OBJECT)hThisObject;
    PDSLH_DIAG_INFO_BASE            pDiagInfo    = (PDSLH_DIAG_INFO_BASE  )pMyObject->hDslhDiagInfo;
    PDSLH_DIAG_INFO_BASE            pNewDiagInfo = (PDSLH_DIAG_INFO_BASE  )hDslhDiagInfo;

    if ( !pMyObject->CheckCanStart((ANSC_HANDLE)pMyObject) )
    {
        AnscTraceFlow(("BbhmDiageoSetDiagParams -- cannot start diag, last one is probably still ongoing...\n"));

        return  ANSC_STATUS_PENDING;
    }

    /*
     *  Do not shutdown the query task, as the background diagnostic may still be ongoing
     *

    if ( pMyObject->bResultQueryRunning )
    {
        AnscResetEvent(&pMyObject->ResultQueryExitEvent);

        pMyObject->bResultQueryRunning = FALSE;
        AnscPulseEvent(&pMyObject->ResultQueryEvent);

        AnscReleaseLock(&pMyObject->AccessLock);

        AnscWaitEvent (&pMyObject->ResultQueryExitEvent);

        AnscAcquireLock(&pMyObject->AccessLock);
    }
     */

    AnscAcquireLock(&pMyObject->AccessLock);

    if ( pDiagInfo == NULL )
    {
        pDiagInfo = (PDSLH_DIAG_INFO_BASE)AnscAllocateMemory(pNewDiagInfo->StructSize);

        if ( pDiagInfo == NULL )
        {
            AnscTrace("BbhmDiageoSetDiagParams -- insufficient resources!\n");

            AnscReleaseLock(&pMyObject->AccessLock);

            return  ANSC_STATUS_RESOURCES;
        }
        else
        {
            pMyObject->hDslhDiagInfo = (ANSC_HANDLE)pDiagInfo;
            pDiagInfo->StructSize    = pNewDiagInfo->StructSize;
        }
    }

    if ( pNewDiagInfo->StructSize != pDiagInfo->StructSize )
    {
        AnscTrace
            (
                "BbhmDiageoSetDiagParams -- invalid structure size, src/dst = %lu/%lu!!!\n",
                pDiagInfo->StructSize,
                pNewDiagInfo->StructSize
            );

        AnscReleaseLock(&pMyObject->AccessLock);

        return  ANSC_STATUS_FAILURE;
    }
    else
    {
        pMyObject->CopyDiagParams((ANSC_HANDLE)pMyObject, hDslhDiagInfo);

        AnscReleaseLock(&pMyObject->AccessLock);

        return  ANSC_STATUS_SUCCESS;
    }
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        BbhmDiageoSetDiagParams
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to return the pointer to the complete
        diagnostic result.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_HANDLE
BbhmDiageoGetResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_EXEC_OBJECT          pMyObject    = (PBBHM_DIAG_EXEC_OBJECT)hThisObject;
    
    return  pMyObject->hDslhDiagInfo;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        BbhmDiageoGetResultTimeStamp
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to return the timestamp when
        the latest diagnostic result was generated.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ULONG
BbhmDiageoGetResultTimeStamp
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DIAG_EXEC_OBJECT          pMyObject    = (PBBHM_DIAG_EXEC_OBJECT)hThisObject;
    
    return  pMyObject->ResultTimestamp;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiageoSetDiagParams
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDslhDiagInfo
            );

    description:

        This function is called to set the diagnostic parameters. If
        the diagnostic process is ongoing, it will be stopped first.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiageoCopyDiagParams
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{
    
    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiageoSetDiagState
            (
                ANSC_HANDLE                 hThisObject,
                ULONG                            ulDiagState
            );

    description:

        This function is called to set the diagnostic parameters. If
        the diagnostic process is ongoing, it will be stopped first.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiageoSetDiagState
    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulDiagState
    )
{
    PBBHM_DIAG_EXEC_OBJECT          pMyObject    = (PBBHM_DIAG_EXEC_OBJECT)hThisObject;
    PDSLH_DIAG_INFO_BASE            pDiagInfo    = (PDSLH_DIAG_INFO_BASE  )pMyObject->hDslhDiagInfo;

    /* CID: 135532 Data race condition */
    AnscAcquireLock(&pMyObject->AccessLock);
    pDiagInfo->DiagnosticState = ulDiagState;
    AnscReleaseLock(&pMyObject->AccessLock);

    return  ANSC_STATUS_SUCCESS;
}



/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDiageoReset
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to reset object states.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDiageoReset
    (
        ANSC_HANDLE                 hThisObject
    )
{
    
    return  ANSC_STATUS_SUCCESS;
}
