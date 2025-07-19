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

    module:	bbhm_udpecho_action.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced policy-access functions
        of the Bbhm UDP Echo Server Object
        *   dslhUdpechoGetDiagInterfaceIPAddress
        *   dslhUdpechoGetDiagInterface
        *   bbhmUdpechoStartUdpEchoTask
        *   BbhmUdpechoStartDiag
        *   BbhmUdpechoStopDiag
        *   BbhmUdpechoGetResult
        *   BbhmUdpechoRetrieveResult
        *   BbhmUdpechoGetConfig
        *   BbhmUdpechoSetConfig

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        06/25/2010    initial revision.

**********************************************************************/


#include "bbhm_udpecho_global.h"
#include "ansc_xsocket_external_api.h"
#include "safec_lib_common.h"

#define  ECHO_MAX_MESSAGE                               255     /* Longest string to echo */
#define  UDP_ECHO_POLL_INTERVAL_MS                      5000    /* 5 seconds */

#define  UDP_HEADER_LENGTH                              8

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        bbhmUdpechoStartUdpEchoTask
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to start UDP Echo Server

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/
ANSC_STATUS
bbhmUdpechoStartUdpEchoTask
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus       			= ANSC_STATUS_SUCCESS;
    PBBHM_UDP_ECHOSRV_OBJECT        pMyObject          			= (PBBHM_UDP_ECHOSRV_OBJECT  )hThisObject;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo       			= (PDSLH_TR143_UDP_ECHO_CONFIG)&pMyObject->UDPEchoConfig;
    XSKT_SOCKET                     aSocket            			= XSKT_SOCKET_INVALID_SOCKET;
    char                            pMsg[ECHO_MAX_MESSAGE + 8]  = { 0 };
    ULONG                           uMsgSize             		= ECHO_MAX_MESSAGE;
    int                             s_result             		= 0;
    BOOL                            bFirst               		= TRUE;
    /*xskt_socket_addr_in             local_addr;*/
    xskt_addrinfo*                  pxskt_local_addrinfo 		= NULL;
    xskt_addrinfo*                  pxskt_src_addrinfo   		= NULL;
    ansc_fd_set                     read_fd_set;
    ansc_timeval                    timeval;
    /*xskt_socket_addr_in             client_addr;*/
    xskt_addrinfo                   xskt_hints          		= {0};
    USHORT                          usPort              		= 0;
    char                            port[6]             		= {0};
    int                             iReturn             		= 0;
    char                            address[NI_MAXHOST]         = {0}; /*RDKB-7455, CID-33431, buffer should be of NI_MAXHOST length*/
    char                            srcIP[NI_MAXHOST]  = {0};

    if ( !pMyObject->bActive )
    {
        return  ANSC_STATUS_FAILURE;
    }

    /* make sure previous server is off */
    while( pMyObject->bIsServerOn )
    {
        AnscSleep(500);  /* half second */

        if( !pMyObject->bActive )
        {
            returnStatus = ANSC_STATUS_FAILURE;

            goto EXIT1;
        }
    }

    /* init socket wrapper */
    AnscStartupXsocketWrapper((ANSC_HANDLE)pMyObject);

    /* start the UDP Echo Server */
    pMyObject->bIsServerOn      = TRUE;
    DslhResetUDPEchoServerStats((&pMyObject->UDPEchoStats));

    /* get the diag interface and IP address */
    /*
    if ( AnscSizeOfString(pUdpEchoInfo->Interface) )
    {
        AnscCopyString(pInterface, pUdpEchoInfo->Interface);
    }

    uLocalIP   = dslhUdpechoGetDiagInterfaceIPAddress(hThisObject,pInterface);
    */

    if ( TRUE )
    {
        xskt_hints.ai_family   = AF_UNSPEC;
        /*xskt_hints.ai_socktype = XSKT_SOCKET_STREAM;*/
        xskt_hints.ai_flags    = AI_CANONNAME;

        usPort = pUdpEchoInfo->UDPPort;
        errno_t rc = -1;
        rc = sprintf_s(port, sizeof(port) , "%d", usPort);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }

        CcspTraceInfo(("!!! Host Port: %s !!!\n", port));
        CcspTraceInfo(("!!! Host Name: %s !!!\n", pUdpEchoInfo->IfAddrName));

        if ( _xskt_getaddrinfo
                (
                    pUdpEchoInfo->SourceIPName,
                    NULL,
                    &xskt_hints,
                    &pxskt_src_addrinfo
                )
            )
        {
            CcspTraceError(("getaddrinfo %s returns error!\n", pUdpEchoInfo->SourceIPName));
            return  ANSC_STATUS_FAILURE;

        }

        if (strcmp(pUdpEchoInfo->IfAddrName, "::") == 0)
        {
            if (!pxskt_src_addrinfo)
                return ANSC_STATUS_FAILURE;

            if ( pxskt_src_addrinfo->ai_family == AF_INET )
            {
                if ( _xskt_getaddrinfo
                    (
                        "0.0.0.0",
                        port,
                        &xskt_hints,
                        &pxskt_local_addrinfo
                    )
		   ) 
		{
		   CcspTraceError(("getaddrinfo %s returns error!\n", port));
                   if(pxskt_src_addrinfo)
                      _xskt_freeaddrinfo(pxskt_src_addrinfo);
		   return  ANSC_STATUS_FAILURE;
	        }
            }
            else if ( pxskt_src_addrinfo->ai_family == AF_INET6 )
            {
                if ( _xskt_getaddrinfo
                    (
                        "::",
                        port,
                        &xskt_hints,
                        &pxskt_local_addrinfo
                    )
		   )
		{
		   CcspTraceError(("getaddrinfo %s returns error!\n", port));
                   if(pxskt_src_addrinfo)
                      _xskt_freeaddrinfo(pxskt_src_addrinfo);
                   return  ANSC_STATUS_FAILURE;
                }
            }
        }
        else
        {
            if (  _xskt_getaddrinfo
                     (
                        pUdpEchoInfo->IfAddrName,
                        port,
                        &xskt_hints,
                        &pxskt_local_addrinfo
                     )
               )
            {
                CcspTraceError(("getaddrinfo %s returns error!\n", pUdpEchoInfo->IfAddrName));
		if(pxskt_src_addrinfo)
                   _xskt_freeaddrinfo(pxskt_src_addrinfo);

                return  ANSC_STATUS_FAILURE;
            }
        }

        AnscTrace("!!! after getaddrinfo !!!\n");

        iReturn = _xskt_getnameinfo
                    (
                        pxskt_src_addrinfo->ai_addr,
                        pxskt_src_addrinfo->ai_addrlen,
                        srcIP,
                        NI_MAXHOST,
                        NULL,
                        NI_MAXSERV,
                        NI_NUMERICHOST
                    );

        CcspTraceInfo(("Normalized source ip = %s iReturn = %d \n", srcIP, iReturn));

    }

    if ( pMyObject->bStopServer )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        goto EXIT1;
    }

    /* create the socket */
    aSocket = _xskt_socket(pxskt_local_addrinfo->ai_family, XSKT_SOCKET_DGRAM, 0);

    if ( aSocket == XSKT_SOCKET_INVALID_SOCKET )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        goto EXIT1;
    }

    if ( _xskt_bind(aSocket, pxskt_local_addrinfo->ai_addr, pxskt_local_addrinfo->ai_addrlen) != 0 )
    {
        returnStatus = ANSC_STATUS_FAILURE;

        AnscTrace(("Unable to start the UDP Echo Server, failed at bind().\n"));

        goto  EXIT2;
    }

    while( TRUE )
    {
        /*
         * Since only one socket is included in the fd_set, we only distinguish the result between
         * one and non-one values. If error is detected, we shall close the socket and notify the
         * socket owner immediately.
         */
        /* init the time out */
        XSKT_SOCKET_FD_ZERO(&read_fd_set);
        XSKT_SOCKET_FD_SET ((XSKT_SOCKET)aSocket, &read_fd_set);

        timeval.tv_sec  = (UDP_ECHO_POLL_INTERVAL_MS / 1000);
        timeval.tv_usec = (UDP_ECHO_POLL_INTERVAL_MS % 1000) * 1000;

        s_result = _xskt_select(aSocket + 1, &read_fd_set, NULL, NULL, &timeval);

        if ( s_result == XSKT_SOCKET_ERROR )
        {
            returnStatus = ANSC_STATUS_FAILURE;

            goto  EXIT2;
        }
        else if ( s_result > 0)
        {
            uMsgSize = ECHO_MAX_MESSAGE;

            s_result = _xskt_recvfrom(aSocket, pMsg, uMsgSize, 0,
                                      pxskt_src_addrinfo->ai_addr,
                                      &pxskt_src_addrinfo->ai_addrlen);

            if ( s_result == XSKT_SOCKET_ERROR )
            {
                returnStatus = ANSC_STATUS_FAILURE;

                goto  EXIT2;
            }
            else if ( s_result > 0 )
            {
                CcspTraceInfo(("Receive echo packet!\n"));

                iReturn = _xskt_getnameinfo
                    (
                        pxskt_src_addrinfo->ai_addr,
                        pxskt_src_addrinfo->ai_addrlen,
                        address,
                        NI_MAXHOST,
                        NULL,
                        NI_MAXSERV,
                        NI_NUMERICHOST
                    );

                CcspTraceInfo(("Src Addr: %s \n", pUdpEchoInfo->SourceIPName));
                CcspTraceInfo(("Client Addr: %s \n", address));


                /* check the client ip address */
                if (strcmp(address, srcIP) == 0)
                {
                    if ( bFirst )
                    {
                        AnscGetSystemTime(&pMyObject->UDPEchoStats.TimeFirstPacketReceived);

                        bFirst = FALSE;
                    }

                    AnscGetSystemTime(&pMyObject->UDPEchoStats.TimeLastPacketReceived);
                    pMyObject->UDPEchoStats.PacketsReceived += 1;
                    pMyObject->UDPEchoStats.BytesReceived   += s_result + UDP_HEADER_LENGTH;
                    /* send response back */
                    s_result = _xskt_sendto(aSocket, pMsg, s_result, 0,
                                            pxskt_src_addrinfo->ai_addr,
                                            pxskt_src_addrinfo->ai_addrlen);

                    CcspTraceInfo(("sendto returns %s \n", strerror(errno)));

                    if( s_result > 0)
                    {
                        pMyObject->UDPEchoStats.PacketsResponded += 1;
                        pMyObject->UDPEchoStats.BytesResponded   += s_result + UDP_HEADER_LENGTH;
                    }
                    else
                    {
                        AnscTrace(("Failed to send back UDP Echo response.\n"));
                        returnStatus = ANSC_STATUS_FAILURE;

                        goto  EXIT2;
                    }
                }
                else
                {
                    /* ignore them */
                    CcspTraceWarning(("UDP request from other ip address, ignored.\n"));
                }
            }
        }

        if ( pMyObject->bStopServer )
        {
            goto EXIT2;
        }
    }


EXIT2:

    if ( aSocket != ANSC_SOCKET_INVALID_SOCKET )
    {
        _xskt_closesocket(aSocket);
    }

EXIT1:

    pMyObject->bIsServerOn      = FALSE;
    pMyObject->bStopServer      = FALSE;
    if(pxskt_local_addrinfo)
       _xskt_freeaddrinfo(pxskt_local_addrinfo); //CID: 73443 -Resource leak
    if(pxskt_src_addrinfo)
       _xskt_freeaddrinfo(pxskt_src_addrinfo); //CID: 64519 -Resource leak

    AnscTrace(("The UDP Echo Server stopped...\n"));

    return returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUdpechoStartDiag
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to start UDP Echo Server

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmUdpechoStartDiag

    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_UDP_ECHOSRV_OBJECT        pMyObject    = (PBBHM_UDP_ECHOSRV_OBJECT  )hThisObject;
    
    if ( !pMyObject->bActive )
    {
        return  ANSC_STATUS_FAILURE;
    }

    if ( pMyObject->bIsServerOn )
    {
        return ANSC_STATUS_SUCCESS;
    }

    /* start the UDP Echo Server */
    AnscSpawnTask
        (
            bbhmUdpechoStartUdpEchoTask,
            (ANSC_HANDLE)hThisObject,
            "bbhmUdpechoStartUdpEchoTask"
        );

    return  ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUdpechoStopDiag
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to stop UDP Echo Server

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/
ANSC_STATUS
BbhmUdpechoStopDiag

    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_UDP_ECHOSRV_OBJECT        pMyObject    = (PBBHM_UDP_ECHOSRV_OBJECT  )hThisObject;
    
    if ( !pMyObject->bActive )
    {
        return ANSC_STATUS_FAILURE;
    }

    if ( !pMyObject->bIsServerOn )
    {
        return ANSC_STATUS_SUCCESS;
    }

    pMyObject->bStopServer  = TRUE;

    return returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        BbhmUdpechoGetResult
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to get UDP Echo statistics data.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_HANDLE
BbhmUdpechoGetResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_UDP_ECHOSRV_OBJECT        pMyObject    = (PBBHM_UDP_ECHOSRV_OBJECT)hThisObject;

    return  &pMyObject->UDPEchoStats;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUdpechoRetrieveResult
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve UDP Echo Server result

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmUdpechoRetrieveResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    return  ANSC_STATUS_SUCCESS;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        BbhmUdpechoGetConfig
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to get the UDP Echo Config

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     The current UDP echo server Config

**********************************************************************/

ANSC_HANDLE
BbhmUdpechoGetConfig

    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_UDP_ECHOSRV_OBJECT        pMyObject    = (PBBHM_UDP_ECHOSRV_OBJECT  )hThisObject;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)&pMyObject->UDPEchoConfig;
    PDSLH_TR143_UDP_ECHO_CONFIG     pHandle      = NULL;


    pHandle = (PDSLH_TR143_UDP_ECHO_CONFIG)AnscAllocateMemory(sizeof(DSLH_TR143_UDP_ECHO_CONFIG));

    if ( pHandle != NULL )
    {
        DslhInitUDPEchoConfig(pHandle);
        errno_t rc = -1;

        rc = strcpy_s(pHandle->Interface, sizeof(pHandle->Interface) , pUdpEchoInfo->Interface );
        ERR_CHK(rc);
        rc = strcpy_s(pHandle->IfAddrName, sizeof(pHandle->IfAddrName) , pUdpEchoInfo->IfAddrName);
        ERR_CHK(rc);
        pHandle->Enable               = pUdpEchoInfo->Enable;
        rc = strcpy_s(pHandle->SourceIPName, sizeof(pHandle->SourceIPName) , pUdpEchoInfo->SourceIPName);
        ERR_CHK(rc);
        pHandle->UDPPort              = pUdpEchoInfo->UDPPort;
        pHandle->EchoPlusEnabled      = pUdpEchoInfo->EchoPlusEnabled;
        pHandle->EchoPlusSupported    = pUdpEchoInfo->EchoPlusSupported;
    }

    return pHandle;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUdpechoSetConfig
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDslhDiagInfo
            );

    description:

        This function is called to set the configuration changes.If
        the diagnostic process is ongoing, it will be stopped first.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 hDslhDiagInfo
                The new config information

    return:     The status of operation

**********************************************************************/

ANSC_STATUS
BbhmUdpechoSetConfig

    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{
    PBBHM_UDP_ECHOSRV_OBJECT        pMyObject    = (PBBHM_UDP_ECHOSRV_OBJECT  )hThisObject;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)&pMyObject->UDPEchoConfig;
    PDSLH_TR143_UDP_ECHO_CONFIG     pHandle      = (PDSLH_TR143_UDP_ECHO_CONFIG)hDslhDiagInfo;
    errno_t                         rc           = -1;

    if ( pUdpEchoInfo->Enable && pMyObject->bIsServerOn )
    {
        pMyObject->StopDiag(pMyObject);
    }

    rc = strcpy_s(pUdpEchoInfo->Interface, sizeof(pUdpEchoInfo->Interface) , pHandle->Interface );
    ERR_CHK(rc);
    rc = strcpy_s(pUdpEchoInfo->IfAddrName, sizeof(pUdpEchoInfo->IfAddrName) , pHandle->IfAddrName);
    ERR_CHK(rc);
    pUdpEchoInfo->Enable                     = pHandle->Enable;
    rc = strcpy_s(pUdpEchoInfo->SourceIPName, sizeof(pUdpEchoInfo->SourceIPName) , pHandle->SourceIPName);
    ERR_CHK(rc);
    pUdpEchoInfo->UDPPort                    = pHandle->UDPPort;

#ifdef _ANSC_UDP_ECHO_SERVER_PLUS_SUPPORTED_

    pUdpEchoInfo->EchoPlusEnabled            = pHandle->EchoPlusEnabled;

#endif

    return ANSC_STATUS_SUCCESS;
}

