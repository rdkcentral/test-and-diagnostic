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

    module:bbhm_download_action.c

        For Broadband Home Manager Model Implementation (BBHM),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the advanced policy-access functions
        of the Bbhm Download Diagnostics Object

        *   BbhmDownloadGetDiagInterface
        *   bbhmDownloadStartDiagTask
        *   BbhmDownloadStartDiag
        *   BbhmDownloadStopDiag
        *   BbhmDownloadGetResult
        *   BbhmDownloadRetrieveResult        
        *   BbhmDownloadGetConfig
        *   BbhmDownloadSetConfig
        
    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Jinghua Xu, Chen Lei

    ---------------------------------------------------------------

    revision:

        06/01/2011    initial revision.
		10/15/2011	  Add IPv6 compatibility, 
					  rewrite HTTP parse function.

**********************************************************************/

#include <ctype.h>
#include "bbhm_download_global.h"
#include "ansc_xsocket_external_api.h"
#include "safec_lib_common.h"


#define  DOWNLOAD_PORT_FROM_                            5701
#define  DOWNLOAD_PORT_TO_                              5708

#define  DOWNLOAD_SINGLE_BUFFER_SIZE                 500000        /* 500 K */

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
	return -1;
#if 0
	char *addrBuf;
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

	_ansc_snprintf(address, size, "%s", addrBuf);
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
        bbhmDownloadStartDiagTask
        
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to start Download Diagnostics

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/
#if 0
static char http_get_request1[]=
"GET %s HTTP/1.1\r\n"
"Host: %s\r\n"
"User-Agent: Mozilla/5.0 Firefox/3.6.4\r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
"Accept-Language: en-us,en;q=0.5\r\n"
"Accept-Charset: x-gbk,utf-8;q=0.7,*;q=0.7\r\n"
"Keep-Alive: 115\r\n"
"Connection: keep-alive\r\n\r\n";
#endif

static char http_get_request2[]=
"GET %s HTTP/1.1\r\n"
"Host: %s:%s\r\n"
"User-Agent: Mozilla/5.0 Firefox/3.6.4\r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
"Accept-Encoding: gzip,deflate\r\n"
"Accept-Charset: x-gbk,utf-8;q=0.7,*;q=0.7\r\n"
"Keep-Alive: 115\r\n"
"Connection: keep-alive\r\n\r\n";

ANSC_STATUS
bbhmDownloadStartDiagTask

    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;
    PBBHM_DOWNLOAD_DIAG_OBJECT      pMyObject          = (PBBHM_DOWNLOAD_DIAG_OBJECT)hThisObject;
    PDSLH_TR143_DOWNLOAD_DIAG_STATS pStats             = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)&pMyObject->DownloadDiagStats;
    char                            ipv6ref[64]        = {0};
    char*                           pHost              = NULL;
    char*                           pServ              = NULL;
    char*                           pPath              = NULL;
    ULONG                           uCount             = 500;  /* half second */
    XSKT_SOCKET                     aSocket            = XSKT_SOCKET_INVALID_SOCKET;
    int                             s_result           = 0;
    char                            buffer[1024]       = { 0 };
    ULONG                           ulSize             = 0;
    char*                           recv_buffer        = NULL;
    ULONG                           recv_size          = 0;
	int								tos				   = 0;
    xskt_addrinfo                   hints;
    xskt_addrinfo                   *servInfo   	   = NULL;
    xskt_addrinfo                   *cliInfo    	   = NULL;
    errno_t                         rc                 = -1;

    if ( !pMyObject->bActive )
    {
        return  ANSC_STATUS_FAILURE;
    }

    pMyObject->bDownNotifyNeeded = FALSE;

    /* make sure previous diag is done */
    while( pMyObject->bDownDiagOn )
    {
        AnscSleep(uCount);

        if ( !pMyObject->bActive )
        {
            returnStatus = ANSC_STATUS_FAILURE;

            goto done;
        }
    }

    /* init socket wrapper */
    AnscStartupXsocketWrapper((ANSC_HANDLE)pMyObject);

    /* turn on the diag */
    pMyObject->bDownDiagOn         = TRUE;
    
    /* reset the stats */
    DslhResetDownloadDiagStats((pStats));

    pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Requested;

    if ( pMyObject->bStopDownDiag )
    {
        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }

    /* parse the download http url */
    if (ParseHttpURL(pMyObject->DownloadDiagInfo.DownloadURL,
                &pHost, &pServ, &pPath) != 0)
    {
		/* if the function fail, memory should not allcated, 
		 * but the the Pointer's value is uncertain */
		pHost = pServ = pPath = NULL;
		
        pMyObject->bDownNotifyNeeded = TRUE;
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

        pMyObject->bDownNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }

    /* create the socket */
    aSocket = (XSKT_SOCKET)_xskt_socket(servInfo->ai_family, 
    		servInfo->ai_socktype, servInfo->ai_protocol);
    if ( aSocket == XSKT_SOCKET_INVALID_SOCKET )
    {
        pMyObject->bDownNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }

	/* bind local address if need */
#if 0
    if (GetAddressByDmlPath(pMyObject->DownloadDiagInfo.Interface, 
			localAddr, sizeof(localAddr)) == 0)
#else
	if (_ansc_strlen(pMyObject->DownloadDiagInfo.IfAddrName) > 0)
#endif
	{
        AnscZeroMemory(&hints, sizeof(hints));
		hints.ai_family = servInfo->ai_family;
		hints.ai_socktype = servInfo->ai_socktype;

		if ((s_result = _xskt_getaddrinfo(pMyObject->DownloadDiagInfo.IfAddrName, "", &hints, &cliInfo)) != 0
				|| _xskt_bind(aSocket, cliInfo->ai_addr, cliInfo->ai_addrlen) != 0)
		{
			if (s_result != 0)
				cliInfo = NULL;
			
	        pMyObject->bDownNotifyNeeded = TRUE;
	        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

	        returnStatus = ANSC_STATUS_FAILURE;
	        goto done;
	    }
	}
	
	/* DSCP */
	if (pMyObject->DownloadDiagInfo.DSCP > 0 && pMyObject->DownloadDiagInfo.DSCP < 64)
	{
		/* 6bits DSCP, and 2bits ENC */
		tos = pMyObject->DownloadDiagInfo.DSCP << 2;
		
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
    if ( _xskt_connect(aSocket, servInfo->ai_addr, servInfo->ai_addrlen) != 0 )
    {
        /* failed to connect the server */
        AnscTraceWarning(("Unable to connect to the http server.\n"));

        pMyObject->bDownNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_NoResponse;

        returnStatus = ANSC_STATUS_FAILURE;

        AnscGetSystemTime(&pStats->TCPOpenResponseTime);
        
        goto done;
    }
    
    AnscGetSystemTime(&pStats->TCPOpenResponseTime);

    /* record HTTP request time */
    AnscGetSystemTime(&pStats->ROMTime);

	/*
	 * according to RFC2396, "host" field in HTTP header for IPv6 addresss 
	 * should be a IPv6 Reference. 
	 * 
	 * 	 host		   = hostname | IPv4address | IPv6reference
	 *   ipv6reference = "[" IPv6address "]"
	 */
	if (IsIPv6Address(pHost))
	{
		rc = sprintf_s(ipv6ref, sizeof(ipv6ref), "[%s]", pHost);
		if(rc < EOK)
		{
			ERR_CHK(rc);
		}
		rc = sprintf_s(buffer, sizeof(buffer) ,http_get_request2, pPath, ipv6ref, pServ);
		if(rc < EOK)
		{
			ERR_CHK(rc);
		}
	}
	else
	{
		rc = sprintf_s(buffer, sizeof(buffer) , http_get_request2, pPath, pHost, pServ);
		if(rc < EOK)
		{
			ERR_CHK(rc);
		}
	}

	/* send the HTTP request */
    ulSize   = AnscSizeOfString(buffer);
    s_result = _xskt_send(aSocket, buffer, (int)ulSize, 0);

#ifdef _DEBUG

    AnscTraceWarning(("******** Download Request **************\n"));
    AnscTraceWarning((buffer));
    AnscTraceWarning(("\n******************************************\n"));

#endif

    if ( s_result == XSKT_SOCKET_ERROR || s_result < (int)ulSize )
    {
        /* failed to send the request */
        AnscTraceWarning(("Failed to send request to the http server.\n"));

        pMyObject->bDownNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }

    /* receive the response */
    recv_buffer = (char*)AnscAllocateMemory(DOWNLOAD_SINGLE_BUFFER_SIZE + 1);

    if ( recv_buffer == NULL )
    {
        /* failed to send the request */
        AnscTraceWarning(("Failed to allocate memory.\n"));

        pMyObject->bDownNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }

    recv_size   = DOWNLOAD_SINGLE_BUFFER_SIZE;
    s_result    = _xskt_recv(aSocket, recv_buffer, recv_size, 0);

    AnscGetSystemTime(&pStats->BOMTime);
    recv_buffer[recv_size] = '\0'; //CID -135416: String not null terminated

    /* check whether it succededd or not */
    if ( s_result <= 0 || _ansc_strstr(recv_buffer, "HTTP/1.1 2") != recv_buffer )
    {
        /* failed to receive the request */
        AnscTraceWarning(("Failed to recv or not 200 OK.\n"));

        pMyObject->bDownNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_TransferFailed;

        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }

    while(s_result > 0)
    {
#if 0 // _DEBUG --This piece of code breaks for binary files and work for text files.
		recv_buffer[s_result] = '\0'; /* allocated one more byte, so no problem */
		AnscTraceWarning(("%s", recv_buffer));
#endif

        AnscGetSystemTime(&pStats->EOMTime);
        pStats->TestBytesReceived += s_result;
        if ( pMyObject->bStopDownDiag )
        {
            returnStatus = ANSC_STATUS_FAILURE;
            goto done;
        }

        recv_size   = DOWNLOAD_SINGLE_BUFFER_SIZE;
        s_result    = _xskt_recv(aSocket, recv_buffer, recv_size, 0);

        if ( s_result < 0 )
        {
            /* failed to receive the request */
            AnscTraceWarning(("Failed to recv packet.\n"));

            pMyObject->bDownNotifyNeeded = TRUE;
            pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_TransferFailed;

            returnStatus = ANSC_STATUS_FAILURE;
            goto done;
        }
    }

    /* succeeded */
    pMyObject->bDownNotifyNeeded = TRUE;
    pStats->DiagStates           = DSLH_TR143_DIAGNOSTIC_Completed;

done:
    /* clear resources if need */
    if (aSocket != XSKT_SOCKET_INVALID_SOCKET)
        _xskt_closesocket(aSocket);
    if (recv_buffer != NULL)
        AnscFreeMemory(recv_buffer);
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
    
    if ( pMyObject->bDownNotifyNeeded )
    {
        CosaSendDiagCompleteSignal();
    }

    /* if the task is stopped, reset the stats */
    if ( pMyObject->bStopDownDiag )
    {
        DslhResetDownloadDiagStats((&pMyObject->DownloadDiagStats));        
    }

    pMyObject->DownloadDiagInfo.DiagnosticsState = pStats->DiagStates;
        
    /* clear flags */
    pMyObject->bDownNotifyNeeded   = FALSE;
    pMyObject->bDownDiagOn         = FALSE; 
    pMyObject->bStopDownDiag       = FALSE;

    return returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS        
        BbhmDownloadStartDiag
        
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to start Download Diagnostics

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDownloadStartDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    /* start the diagnostics */
    AnscSpawnTask
        (
            bbhmDownloadStartDiagTask,
            (ANSC_HANDLE)hThisObject,
            "bbhmDownloadStartDiagTask"
        );

    return  ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDownloadStopDiag
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to stop Download Diagnostics

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/
ANSC_STATUS
BbhmDownloadStopDiag
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBBHM_DOWNLOAD_DIAG_OBJECT      pMyObject    = (PBBHM_DOWNLOAD_DIAG_OBJECT)hThisObject;

    if ( pMyObject->bDownDiagOn )
    {
        pMyObject->bStopDownDiag = TRUE;
    }
    else
    {
        /* reset the stats */
        DslhResetDownloadDiagStats((&pMyObject->DownloadDiagStats));        
    }

    return returnStatus;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        BbhmDownloadGetResult
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to get download Diag statistics data.

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_HANDLE
BbhmDownloadGetResult
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DOWNLOAD_DIAG_OBJECT      pMyObject    = (PBBHM_DOWNLOAD_DIAG_OBJECT)hThisObject;

    return  &pMyObject->DownloadDiagStats;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDownloadRetrieveResult
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to retrieve download Diag statistics data.
        
    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:     status of operation.

**********************************************************************/

ANSC_STATUS
BbhmDownloadRetrieveResult
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
        BbhmDownloadGetConfig
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function is called to get the Download Diagnostics Config

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

    return:      The current Download Diagnostics Config

**********************************************************************/

ANSC_HANDLE

BbhmDownloadGetConfig
    (
        ANSC_HANDLE                 hThisObject
    )
{
    PBBHM_DOWNLOAD_DIAG_OBJECT     pMyObject     = (PBBHM_DOWNLOAD_DIAG_OBJECT)hThisObject;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)&pMyObject->DownloadDiagInfo;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO pHandle       = NULL;

    pHandle = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)AnscAllocateMemory(sizeof(DSLH_TR143_DOWNLOAD_DIAG_INFO));

    if ( pHandle != NULL )
    {
        DslhInitDownloadDiagInfo(pHandle);
        errno_t rc = -1;

        rc = strcpy_s(pHandle->Interface, sizeof(pHandle->Interface) , pDownloadInfo->Interface);
        ERR_CHK(rc);
        rc = strcpy_s(pHandle->DownloadURL, sizeof(pHandle->DownloadURL) , pDownloadInfo->DownloadURL);
        ERR_CHK(rc);
        pHandle->DSCP                 = pDownloadInfo->DSCP;
        pHandle->EthernetPriority     = pDownloadInfo->EthernetPriority;
        pHandle->DiagnosticsState     = pDownloadInfo->DiagnosticsState;
    }

    return pHandle;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmDownloadSetConfig
            (
                ANSC_HANDLE                 hThisObject,
                ANSC_HANDLE                 hDownloadInfo
            );

    description:

        This function is called to set the Download Diagnostics Config

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                     hDownloadInfo
                The updated Download Diagnostics Config

    return:     The status of the operation;

**********************************************************************/

ANSC_STATUS
BbhmDownloadSetConfig
    (
        ANSC_HANDLE                 hThisObject,
        ANSC_HANDLE                 hDownloadInfo
    )
{
    ANSC_STATUS                     returnStatus  = ANSC_STATUS_SUCCESS;
    PBBHM_DOWNLOAD_DIAG_OBJECT      pMyObject     = (PBBHM_DOWNLOAD_DIAG_OBJECT)hThisObject;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)&pMyObject->DownloadDiagInfo;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pHandle       = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)hDownloadInfo;


    pMyObject->StopDiag(pMyObject);

/*
    if ( pDownloadInfo->Interface )
    {
        AnscFreeMemory(pDownloadInfo->Interface);
    }

    if ( pDownloadInfo->DownloadURL )
    {
        AnscFreeMemory(pDownloadInfo->DownloadURL);
    }
*/
    errno_t rc = -1;
    rc = strcpy_s(pDownloadInfo->Interface, sizeof(pDownloadInfo->Interface) ,pHandle->Interface);
    ERR_CHK(rc);
    rc = strcpy_s(pDownloadInfo->DownloadURL, sizeof(pDownloadInfo->DownloadURL) , pHandle->DownloadURL);
    ERR_CHK(rc);
    pDownloadInfo->DSCP             = pHandle->DSCP;
    pDownloadInfo->EthernetPriority = pHandle->EthernetPriority;
    pDownloadInfo->DiagnosticsState = pHandle->DiagnosticsState;
    rc = strcpy_s(pDownloadInfo->IfAddrName, sizeof(pDownloadInfo->IfAddrName) , pHandle->IfAddrName);
    ERR_CHK(rc);

    return returnStatus;
}

ANSC_STATUS
BbhmDownloadSetDiagState

    (
        ANSC_HANDLE                 hThisObject,
        ULONG                       ulDiagState
    )
{
    PBBHM_DOWNLOAD_DIAG_OBJECT      pMyObject    = (PBBHM_DOWNLOAD_DIAG_OBJECT)hThisObject;
    PDSLH_TR143_DOWNLOAD_DIAG_STATS pStats       = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)&pMyObject->DownloadDiagStats;

    pStats->DiagStates = ulDiagState;
    
    if ( DSLH_TR143_DIAGNOSTIC_Requested != ulDiagState )    
    {
       pMyObject->DownloadDiagInfo.DiagnosticsState = ulDiagState;
    }
    
    return  ANSC_STATUS_SUCCESS;
}

