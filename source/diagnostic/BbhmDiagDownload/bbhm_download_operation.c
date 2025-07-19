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

    module:  bbhm_download_operation.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced operation functions
        of the Bbhm Download Diagnostics Object.

        *   BbhmDownloadEngage
        *   BbhmDownloadCancel
        *   BbhmDownloadSetupEnv
        *   BbhmDownloadCloseEnv

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Jinghua Xu

    ---------------------------------------------------------------

    revision:

        06/01/2011    initial revision.

**********************************************************************/


#include "bbhm_download_global.h"


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDownloadEngage
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to engage the object activity.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDownloadEngage
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DOWNLOAD_DIAG_OBJECT      pMyObject    = (PBBHM_DOWNLOAD_DIAG_OBJECT)hThisObject;

    if ( pMyObject->bActive )
    {
        return  ANSC_STATUS_SUCCESS;
    }

    returnStatus = pMyObject->SetupEnv((ANSC_HANDLE)pMyObject);

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        return  returnStatus;
    }

    pMyObject->bActive = TRUE;

    return  returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDownloadCancel
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to cancel the object activity.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDownloadCancel
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DOWNLOAD_DIAG_OBJECT      pMyObject    = (PBBHM_DOWNLOAD_DIAG_OBJECT)hThisObject;

    if ( !pMyObject->bActive )
    {
        return  ANSC_STATUS_SUCCESS;
    }


    pMyObject->bActive = FALSE;

    returnStatus = pMyObject->CloseEnv((ANSC_HANDLE)pMyObject);

    return  returnStatus;
}



/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDownloadSetupEnv
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to setup the operating environment.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDownloadSetupEnv
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus        = ANSC_STATUS_SUCCESS;

#if 0   
    PBBHM_DOWNLOAD_DIAG_OBJECT      pMyObject           = (PBBHM_DOWNLOAD_DIAG_OBJECT)hThisObject;
    PBBHM_SRV_CONTROLLER_OBJECT     pBbhmSrvController  = (PBBHM_SRV_CONTROLLER_OBJECT)pMyObject->hBbhmSrvController;
    PDSLH_CPE_CONTROLLER_OBJECT     pDslhCpeController  = (PDSLH_CPE_CONTROLLER_OBJECT)pBbhmSrvController->GetDslhCpeController((ANSC_HANDLE)pBbhmSrvController);
    ANSC_HANDLE                     hSysRoot            = NULL;

    /* get the system root folder */
    hSysRoot = pDslhCpeController->pSysIraIf->OpenFolder(
                pDslhCpeController->pSysIraIf->hOwnerContext,
                (ANSC_HANDLE)NULL,
                "/Configuration/Provision"
                );

    if ( !hSysRoot )
    {
        returnStatus =  ANSC_STATUS_ACCESS_DENIED;
        goto EXIT1;
    }

    /* get the WmpProcessor folder */
    pMyObject->hIrepFoDownload = pDslhCpeController->pSysIraIf->OpenFolder(
                                    pDslhCpeController->pSysIraIf->hOwnerContext,
                                    hSysRoot,
                                    BBHM_DOWNLOAD_L1_NAME
                                    );

    if ( !pMyObject->hIrepFoDownload )
    {
        returnStatus = ANSC_STATUS_ACCESS_DENIED;

        goto EXIT1;
    }

    /******************************************************************
                GRACEFUL ROLLBACK PROCEDURES AND EXIT DOORS
    ******************************************************************/


    EXIT1:

    if ( hSysRoot )
    {
        pDslhCpeController->pSysIraIf->CloseFolder(
            pDslhCpeController->pSysIraIf->hOwnerContext,
            hSysRoot
            );
    }
#endif

    return  returnStatus;
}
 
 
/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDownloadCloseEnv
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to close the operating environment.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDownloadCloseEnv
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;

#if 0
    PBBHM_DOWNLOAD_DIAG_OBJECT      pMyObject          = (PBBHM_DOWNLOAD_DIAG_OBJECT)hThisObject;
    PBBHM_SRV_CONTROLLER_OBJECT     pBbhmSrvController = (PBBHM_SRV_CONTROLLER_OBJECT)pMyObject->hBbhmSrvController;
    PDSLH_CPE_CONTROLLER_OBJECT     pDslhCpeController = (PDSLH_CPE_CONTROLLER_OBJECT)pBbhmSrvController->GetDslhCpeController((ANSC_HANDLE)pBbhmSrvController);

    if ( pMyObject->hIrepFoDownload )
    {
       returnStatus = pDslhCpeController->pSysIraIf->CloseFolder(
                        pDslhCpeController->pSysIraIf->hOwnerContext,
                        pMyObject->hIrepFoDownload
                        );
    }

    pMyObject->hIrepFoDownload = (ANSC_HANDLE)NULL;

#endif

    return  returnStatus;
}



