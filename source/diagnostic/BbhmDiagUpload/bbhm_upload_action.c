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

    module:bbhm_upload_action.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced policy-access functions
        of the Bbhm Upload Diagnostics Object

        *   BbhmUploadGetDiagInterface
        *   bbhmUploadStartDiagTask
        *   BbhmUploadStartDiag
        *   BbhmUploadStopDiag
        *   BbhmUploadGetResult
        *   BbhmUploadRetrieveResult
        *   BbhmUploadGetConfig
        *   BbhmUploadSetConfig
        
    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Jinghua Xu, Chen Lei

    ---------------------------------------------------------------

    revision:

        06/01/2011    initial revision.
        10/16/2001	  Add IPv6 compatibility,
        			  rewrite HTTP parse function.

**********************************************************************/

#include <ctype.h>
#include "bbhm_upload_global.h"
#include "ansc_xsocket_external_api.h"
#include "safec_lib_common.h"


#define  UPLOAD_PORT_FROM_                            5801
#define  UPLOAD_PORT_TO_                              5808

#define  UPLOAD_SINGLE_BUFFER_SIZE                 500000        /* 500 K */

/**********************************************************************

  prototype:

    static int
    GetAddressByDmlPath(const char *path, char *address, ULONG size)

  description:

    Get IP address string by TR-181 data module path

  arguments:
  
    @path should be:
      "Device.IP.Interface.{i}.IPv4Address.{i}" or
      "Device.IP.Interface.{i}.IPv6Address.{i}".
	and {i} is index number.

  Return:
  
    0 if success and -1 on error.

**********************************************************************/

#if 0
static int
GetAddressByDmlPath(const char *path, char *address, ULONG size)
{
	char *addrBuf;

	return -1;
#if 0
	if (!path || _ansc_strlen(path) == 0 || !address)
		return -1;

	/*
	 * Don't use COSAGetParamValueString 
	 */
	if ((addrBuf = CosaGetInterfaceAddrByName(path)) == NULL)
	{
		AnscTraceWarning(("Failed to get IP Addresss for %s\n", path));
		return -1;
	}

	if (_ansc_strcmp(addrBuf, "::") == 0)
	{
		/* it may not an error, but "::" for IPv4 is unsuitable,
		 * and we can just don't bind "::" */
		AnscFreeMemory(addrBuf);
		return -1;
	}

	errno_t rc = -1;
	rc = sprintf_s(address, size, "%s", addrBuf);
	if(rc < EOK)
	{
		ERR_CHK(rc);
	}
	AnscFreeMemory(addrBuf);
#endif
    return 0;
}
#endif

/**********************************************************************

  prototype:

    static int
    ParseHttpURL(const char *url, char **host, char **serv, char **path);

  description:

    Parse HTTP URL to host name, service name and path name.

  arguments:
  
    @host[out], host name or IP address
    @serv[out], service name or port number string
    @path[out], path name, if no PATH in URL use default value "/".

  Return:
  
    0 if success and -1 on error.
 
  Note:
  
    if return 0, don't forget to AnscFreeMemory() 
    *host,*serv and *path if they are not NULL.

**********************************************************************/
static int
ParseHttpURL(const char *url, char **host, char **serv, char **path)
{
	char scheme[16], *ptr;
	int rc, maxlen;
	errno_t safe_rc = -1;

	if (!url || !host || !serv || !path)
		return -1;

	maxlen = strlen(url) + 1;
	*host = *serv = *path = NULL;

	if ((*host = (char*)AnscAllocateMemory(maxlen)) == NULL
			|| (*serv = (char*)AnscAllocateMemory(maxlen)) == NULL
			|| (*path = (char*)AnscAllocateMemory(maxlen)) == NULL)
	{
		goto errout;
	}

	if ((rc = sscanf(url, "%15[^\n:]://%[^\n/?]%[^\n]",
					scheme, *host, *path)) < 2)
	{
		goto errout;
	}

	if (strcasecmp(scheme, "http") != 0)
	{
		goto errout;
	}

	if (rc == 2)
	{
		safe_rc = strcpy_s(*path, maxlen, "/"); /* default value for PATH */
		ERR_CHK(safe_rc);
	}

	/* check if service or port number is in URL */

	/* according to RFC2732, IPv6 address in URL use IPv6reference,
	 * e.g., http://[::FFFF:129.144.52.38]:80/index.html */
	if (**host == '[')
	{
		/* since *host is allcated, we can't change it */
		memmove(*host, (*host) + 1, strlen(*host)); /* include '\0' */

		ptr = *host;
		while (*ptr &&
				(isxdigit(*ptr) || (*ptr == ':')
					|| (*ptr == '%') || (*ptr == '.')))
		{
			ptr++;
		}

		if (*ptr != ']') /* invalid IPv6 address */
			goto errout;
		*ptr++ = '\0';
	}
	else
	{
		ptr = strchr(*host, ':');
	}

	if (ptr && *ptr == ':')
		*ptr++ = '\0';
	else
		ptr = "80";

	safe_rc = sprintf_s(*serv, maxlen, "%s", ptr);
	if(safe_rc < EOK)
	{
		ERR_CHK(safe_rc);
	}

	return 0;

errout:
	if (*host)
		AnscFreeMemory(*host);
	if (*serv)
		AnscFreeMemory(*serv);
	if (*path)
		AnscFreeMemory(*path);
	*host = *serv = *path = NULL;

	return -1;
}

/* XXX: Xsocket has no relate wrapper for inet_pton() and sockaddr_in6{} */
static BOOL
IsIPv6Address(const char *string)
{
	struct sockaddr_in6 sin6;

	if (!string || _ansc_strlen(string) == 0)
		return FALSE;

	if (inet_pton(AF_INET6, string, &sin6.sin6_addr) <= 0)
		return FALSE;

	return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        bbhmUploadStartDiagTask
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to start Upload Diagnostics

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

#if 0
static char http_put_request1[]=
"PUT %s HTTP/1.1\r\n"
"Host: %s\r\n"
"Referer: http://%s\r\n"
"Connection: keep-alive\r\n"
"Content-Type: multipart/form-data; boundary=ZzAaBbCc1234567890\r\n"
"Content-Length: %d\r\n\r\n";

static char http_put_body_begin[]=
"--ZzAaBbCc1234567890\r\n"
"Content-Disposition: form-data; name=\"filename\"; filename=\"f1.txt\"\r\nContent-Type: application/octet-stream\r\n\r\n";

static char http_put_body_end[]=
"\r\n--ZzAaBbCc1234567890--\r\n";
#endif

static char http_put_request2[]=
"PUT %s HTTP/1.1\r\n"
"Host: %s:%s\r\n"
"User-Agent: Mozilla/5.0 Firefox/3.6.4 \r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 \r\n"
"Keep-Alive: 115\r\n"
"Referer: http://%s:%s\r\n"
"Connection: keep-alive\r\n"
"Content-Type: multipart/form-data; boundary=ZzAaBbCc1234567890\r\n"
"Content-Length: %d\r\n\r\n";

static char http_sample_upload_text[] = "Test Upload files. blah blah blah...\r\n";

ANSC_STATUS
bbhmUploadStartDiagTask

    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;
    PBBHM_UPLOAD_DIAG_OBJECT        pMyObject          = (PBBHM_UPLOAD_DIAG_OBJECT)hThisObject;
    PDSLH_TR143_UPLOAD_DIAG_STATS   pStats             = (PDSLH_TR143_UPLOAD_DIAG_STATS)&pMyObject->UploadDiagStats;
    ULONG                           uCount             = 500;  /* half second */
    ULONG                           uBytesSent         = 0;
    XSKT_SOCKET                     aSocket            = XSKT_SOCKET_INVALID_SOCKET;
    int                             s_result           = 0;
    char                            buffer[1024]       = { 0 };
    char*                           send_buffer        = NULL;
    ULONG                           send_size          = 0;
    ULONG                           uTotalMsgSize      = 0;
	char							*pHost			   = NULL;
	char							*pServ			   = NULL;
	char							*pPath			   = NULL;
	xskt_addrinfo					hints;
	xskt_addrinfo					*servInfo		   = NULL;
	xskt_addrinfo					*cliInfo		   = NULL;
	int								tos				   = 0;
	char							ipv6ref[64]		   = {0};
	errno_t							rc 				   = -1;

    if ( !pMyObject->bActive )
    {
        return  ANSC_STATUS_FAILURE;
    }

    pMyObject->bUpNotifyNeeded   = FALSE;

    /* make sure previous diag is done */
    while( pMyObject->bUpDiagOn)
    {
        AnscSleep(uCount);

        if( !pMyObject->bActive)
        {
            returnStatus = ANSC_STATUS_FAILURE;

            goto done;
        }
    }

	/* init socket warpper */
	AnscStartupXsocketWrapper((ANSC_HANDLE)pMyObject);

    /* turn on the diag */
    pMyObject->bUpDiagOn           = TRUE;

    /* reset the stats */
    DslhResetUploadDiagStats((pStats));
	
    pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Requested;

    if ( pMyObject->bStopUpDiag )
    {
        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }

    /* parse the upload http url */
	if (ParseHttpURL(pMyObject->UploadDiagInfo.UploadURL,
			&pHost, &pServ, &pPath) != 0)
	{
		/* if the function fail, memory should not allcated,
		 * but the Pointers' value is uncertain. */
		pHost = pServ = pPath = NULL;

        pMyObject->bUpNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
	}

	/* resolution the HTTP server's hostname/service to sockaddrinfo */
    AnscZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* XXX: xsocket wrapper has no XSKT_SOCKET_AF_UNSPEC */
	hints.ai_socktype = SOCK_STREAM;
	if (_xskt_getaddrinfo(pHost, pServ, &hints, &servInfo) != 0)
	{
		servInfo = NULL;

		pMyObject->bUpNotifyNeeded = TRUE;
		pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;
		
		returnStatus = ANSC_STATUS_FAILURE;
		
		goto done;
	}

	/* create the socket */
	aSocket = (XSKT_SOCKET)_xskt_socket(servInfo->ai_family,
			servInfo->ai_socktype, servInfo->ai_protocol);
	if ( aSocket == XSKT_SOCKET_INVALID_SOCKET )
	{
        pMyObject->bUpNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }

	/* bind local address if need */
#if 0
	if (GetAddressByDmlPath(pMyObject->UploadDiagInfo.Interface,
			localAddr, sizeof(localAddr)) == 0)
#else
	if (_ansc_strlen(pMyObject->UploadDiagInfo.IfAddrName) > 0)
#endif
	{
        AnscZeroMemory(&hints, sizeof(hints));
		hints.ai_family = servInfo->ai_family;
		hints.ai_socktype = servInfo->ai_socktype;

		if ((s_result = _xskt_getaddrinfo(pMyObject->UploadDiagInfo.IfAddrName, "", &hints, &cliInfo)) != 0
				|| _xskt_bind(aSocket, cliInfo->ai_addr, cliInfo->ai_addrlen) != 0)
		{
			if (s_result != 0)
				cliInfo = NULL;

	        pMyObject->bUpNotifyNeeded = TRUE;
	        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

	        returnStatus = ANSC_STATUS_FAILURE;
	        goto done;
		}
	}

	/* DSCP */
	if (pMyObject->UploadDiagInfo.DSCP > 0 && pMyObject->UploadDiagInfo.DSCP < 64)
	{
		/* 6bits DSCP, and 2bits ENC */
		tos = pMyObject->UploadDiagInfo.DSCP << 2;
		
		/* XXX: no XSKT_SOCKET_SOL_IP_TOS or XSKT_SOCKET_IP_TOS
		 * and infact IPPROTO_IP and SOL_XXX is not same level,
		 * so the name XSKT_SOCKET_SOL_IPPROTO_IP is not approciate.*/

		if (servInfo->ai_family == XSKT_SOCKET_AF_INET)
		{
			if (_xskt_setsocketopt(aSocket, XSKT_SOCKET_SOL_IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) != 0)
				AnscTraceWarning(("Fail to set IPv4 DSCP.\n"));
		}
		else if (servInfo->ai_family == XSKT_SOCKET_AF_INET6)
		{
			if (_xskt_setsocketopt(aSocket, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)) != 0)
				AnscTraceWarning(("Fail to set IPv6 DSCP.\n"));
		}
	}

	/* ethernet priority */
	/* TODO: need 802.1d support */

    AnscGetSystemTime(&pStats->TCPOpenRequestTime);
	
	/* connect HTTP server */
	if ( _xskt_connect(aSocket, servInfo->ai_addr, servInfo->ai_addrlen) != 0)
	{
        /* failed to connect the server */
        AnscTraceWarning(("Unable to connect to the http server.\n"));

        pMyObject->bUpNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_NoResponse;

        returnStatus = ANSC_STATUS_FAILURE;

        AnscGetSystemTime(&pStats->TCPOpenResponseTime);
        goto done;
    }
    
    AnscGetSystemTime(&pStats->TCPOpenResponseTime);

    /* record HTTP request time */
    AnscGetSystemTime(&pStats->ROMTime);

    /* calculate the total length */
    uTotalMsgSize = pMyObject->UploadDiagInfo.TestFileLength; 

	/*
	 * according to RFC2396, "host" field in HTTP header for IPv6 address
	 * should be a IPv6 Reference.
	 *
	 *   host		   = hostname | IPv4address | IPv6reference
	 *   ipv6reference = "[" IPv6address "]"
	 */
	if (IsIPv6Address(pHost))
	{
		rc = sprintf_s(ipv6ref, sizeof(ipv6ref), "[%s]", pHost);
		if(rc < EOK)
		{
			ERR_CHK(rc);
		}
		rc = sprintf_s(buffer, sizeof(buffer), http_put_request2, 
				pPath, ipv6ref, pServ, ipv6ref, pServ, uTotalMsgSize);
		if(rc < EOK)
		{
			ERR_CHK(rc);
		}
	}
	else
	{
		rc = sprintf_s(buffer, sizeof(buffer), http_put_request2, 
				pPath, pHost, pServ, pHost, pServ, uTotalMsgSize);
		if(rc < EOK)
		{
			ERR_CHK(rc);
		}
	}

	/* send the HTTP request */
    s_result = _xskt_send(aSocket, buffer, AnscSizeOfString(buffer), 0);

#ifdef _DEBUG
    
	AnscTraceWarning(("******** Upload Request **************\n"));
	AnscTraceWarning((buffer));
	AnscTraceWarning(("\n******************************************\n"));
    
#endif

    if ( s_result == XSKT_SOCKET_ERROR )
    {
        /* failed to send the request */
        AnscTraceWarning(("Failed to send request to the http server.\n"));

        pMyObject->bUpNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }

    pStats->TotalBytesSent = s_result;
    AnscGetSystemTime(&pStats->BOMTime);

    /* allocate the sending message buffer */
    send_buffer = (char*)AnscAllocateMemory(UPLOAD_SINGLE_BUFFER_SIZE + 1);

    if ( send_buffer == NULL )
    {
        /* failed to send the request */
        AnscTraceWarning(("Failed to allocate memory.\n"));

        pMyObject->bUpNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

        returnStatus = ANSC_STATUS_FAILURE;

        goto done;
    }

    rc = strcpy_s(send_buffer, UPLOAD_SINGLE_BUFFER_SIZE + 1 , http_sample_upload_text);
    ERR_CHK(rc);

    /* continue to upload the file */
    uBytesSent = pMyObject->UploadDiagInfo.TestFileLength;

    while( uBytesSent > 0)
    {
        AnscGetSystemTime(&pStats->EOMTime);

        if ( uBytesSent >= UPLOAD_SINGLE_BUFFER_SIZE )
        {
             send_size   = UPLOAD_SINGLE_BUFFER_SIZE;
        }
        else
        {
            send_size   = uBytesSent;
        }

        pStats->TotalBytesSent += send_size;

        s_result    = _xskt_send(aSocket, send_buffer, send_size, 0);

        if ( s_result == XSKT_SOCKET_ERROR )
        {
            /* failed to send the request */
            AnscTraceWarning(("Failed to send request to the http server. code: %d\n", _xskt_get_last_error()));

            pMyObject->bUpNotifyNeeded = TRUE;
            pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_TransferFailed;

            returnStatus = ANSC_STATUS_FAILURE;

            goto done;
        }

        uBytesSent -= send_size;

        if ( pMyObject->bStopUpDiag )
        {
            returnStatus = ANSC_STATUS_FAILURE;

            goto done;
        }
    }

#ifdef _DEBUG
    AnscZeroMemory(buffer, sizeof(buffer));
	if (_xskt_recv(aSocket, buffer, sizeof(buffer) - 1, 0) != -1)
	{
		AnscTraceWarning(("******** Upload Response **************\n"));
		AnscTraceWarning((buffer));
		AnscTraceWarning(("\n******************************************\n"));
	}
#endif

    /* succeeded */
    pMyObject->bUpNotifyNeeded                   = TRUE;
    pStats->DiagStates                           = DSLH_TR143_DIAGNOSTIC_Completed;

done:
	if (aSocket != XSKT_SOCKET_INVALID_SOCKET)
		_xskt_closesocket(aSocket);
	if (send_buffer != NULL)
		AnscFreeMemory(send_buffer);
	if (servInfo)
		_xskt_freeaddrinfo(servInfo);
	if (cliInfo)
		_xskt_freeaddrinfo(cliInfo);
	if (pHost)
		AnscFreeMemory(pHost);
	if (pServ)
		AnscFreeMemory(pServ);
	if (pPath)
		AnscFreeMemory(pPath);

    if ( pMyObject->bUpNotifyNeeded)
    {
		CosaSendDiagCompleteSignal();
    }

    /* if the task is stopped, reset the stats */
    if ( pMyObject->bStopUpDiag)
    {
        DslhResetUploadDiagStats((pStats));        
    }

    pMyObject->UploadDiagInfo.DiagnosticsState = pStats->DiagStates;

	/* clear flags */
    pMyObject->bUpNotifyNeeded   = FALSE;
    pMyObject->bUpDiagOn         = FALSE; 
    pMyObject->bStopUpDiag       = FALSE;

    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUploadStartDiag
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to start Upload Diagnostics

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmUploadStartDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    /* start the diagnostics */
    AnscSpawnTask
        (
            bbhmUploadStartDiagTask,
            (ANSC_HANDLE)hThisObject,
            "bbhmUploadStartDiagTask"
        );

    return  ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUploadStopDiag
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to stop Upload Diagnostics

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/
ANSC_STATUS
BbhmUploadStopDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                   returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_UPLOAD_DIAG_OBJECT      pMyObject    = (PBBHM_UPLOAD_DIAG_OBJECT)hThisObject;

    if ( pMyObject->bUpDiagOn )
    {
        pMyObject->bStopUpDiag = TRUE;
    }
    else
    {
        /* reset the stats */
        DslhResetUploadDiagStats((&pMyObject->UploadDiagStats));        
    }

    return returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        BbhmUploadGetResult
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to get upload Diag statistics data.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_HANDLE
BbhmUploadGetResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_UPLOAD_DIAG_OBJECT        pMyObject    = (PBBHM_UPLOAD_DIAG_OBJECT)hThisObject;

    return  &pMyObject->UploadDiagStats;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUploadRetrieveResult
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve upload Diag statistics data.
        
    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmUploadRetrieveResult
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
        BbhmUploadGetConfig
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to get the Upload Diagnostics Config

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:      The current Upload Diagnostics Config

**********************************************************************/

ANSC_HANDLE

BbhmUploadGetConfig
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_UPLOAD_DIAG_OBJECT        pMyObject   = (PBBHM_UPLOAD_DIAG_OBJECT)hThisObject;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)&pMyObject->UploadDiagInfo;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pHandle     = NULL;

    pHandle = (PDSLH_TR143_UPLOAD_DIAG_INFO)AnscAllocateMemory(sizeof(DSLH_TR143_UPLOAD_DIAG_INFO));

    if ( pHandle != NULL )
    {
        DslhInitUploadDiagInfo(pHandle);
        errno_t rc = -1;

        rc = strcpy_s(pHandle->Interface, sizeof(pHandle->Interface) , pUploadInfo->Interface);
        ERR_CHK(rc);
        rc = strcpy_s(pHandle->UploadURL, sizeof(pHandle->UploadURL) , pUploadInfo->UploadURL);
        ERR_CHK(rc);
        pHandle->DSCP             = pUploadInfo->DSCP;
        pHandle->EthernetPriority = pUploadInfo->EthernetPriority;
        pHandle->TestFileLength   = pUploadInfo->TestFileLength;
        pHandle->DiagnosticsState = pUploadInfo->DiagnosticsState;
    }

    return pHandle;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUploadSetInfo
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hUploadInfo
            );

    description:

        This function is called to set the Upload Diagnostics Config

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                     hUploadInfo
                The updated Upload Diagnostics Config

    return:     The status of the operation;

**********************************************************************/

ANSC_STATUS
BbhmUploadSetConfig
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDslhDiagInfo
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_UPLOAD_DIAG_OBJECT        pMyObject   = (PBBHM_UPLOAD_DIAG_OBJECT)hThisObject;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)&pMyObject->UploadDiagInfo;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pHandle     = (PDSLH_TR143_UPLOAD_DIAG_INFO)hDslhDiagInfo;


    pMyObject->StopDiag(pMyObject);

    errno_t rc = -1;
    rc = strcpy_s(pUploadInfo->Interface, sizeof(pUploadInfo->Interface) , pHandle->Interface);
    ERR_CHK(rc);
    rc = strcpy_s(pUploadInfo->UploadURL, sizeof(pUploadInfo->UploadURL) , pHandle->UploadURL);
    ERR_CHK(rc);
    pUploadInfo->DSCP             = pHandle->DSCP;
    pUploadInfo->EthernetPriority = pHandle->EthernetPriority;
    pUploadInfo->TestFileLength   = pHandle->TestFileLength;
    pUploadInfo->DiagnosticsState = pHandle->DiagnosticsState;
    rc = strcpy_s(pUploadInfo->IfAddrName, sizeof(pUploadInfo->IfAddrName) , pHandle->IfAddrName);
    ERR_CHK(rc);

    return returnStatus;
}

ANSC_STATUS
BbhmUploadSetDiagState

    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulDiagState
    )
{
    PBBHM_UPLOAD_DIAG_OBJECT        pMyObject    = (PBBHM_UPLOAD_DIAG_OBJECT)hThisObject;
    PDSLH_TR143_UPLOAD_DIAG_STATS   pStats       = (PDSLH_TR143_UPLOAD_DIAG_STATS)&pMyObject->UploadDiagStats;

    pStats->DiagStates = ulDiagState;

    if ( DSLH_TR143_DIAGNOSTIC_Requested != ulDiagState )    
    {
       pMyObject->UploadDiagInfo.DiagnosticsState = ulDiagState;
    }

    return  ANSC_STATUS_SUCCESS;
}

