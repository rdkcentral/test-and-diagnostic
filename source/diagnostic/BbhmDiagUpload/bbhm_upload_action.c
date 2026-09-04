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
#include <errno.h>
#include <stdio.h>
#include <sys/time.h>
#include "bbhm_upload_global.h"
#include "bbhm_upload_auto_tfl.h"
#include "ansc_xsocket_external_api.h"
#include "safec_lib_common.h"


#define  UPLOAD_PORT_FROM_                            5801
#define  UPLOAD_PORT_TO_                              5808

#define  UPLOAD_SINGLE_BUFFER_SIZE                 500000        /* 500 K */
#define  HTTP_RESPONSE_OK_STRING                  "HTTP/1.1 200 OK"
#define  HTTP_RESPONSE_REDIRECTION_STRING         "HTTP/1.1 301"

/*
 * Reuse one 500KB send buffer across Upload runs. Alloc/free every Requested
 * (bUpDiagOn), so a process-lifetime buffer is safe.
 */
static char* s_uploadSendBuffer = NULL;

/* RDKB SRU DM path for upload speed (Mbps). If empty/0, fallback to GPON NominalBitRateUpstream. */
#define  PPPMgr_COMPONENT_NAME                    "eRT.com.cisco.spvtg.ccsp.pppmanager"
#define  PPPMgr_DBUS_PATH                         "/com/cisco/spvtg/ccsp/pppmanager"
#define  RDKB_SRU_UPLOAD_SPEED_DM                 "Device.PPP.Interface.1.X_T_ONLINE_DE_SRU"

extern PBBHM_UPLOAD_DIAG_OBJECT g_DiagUploadObj;

pthread_cond_t  UploadDiagCond             =       PTHREAD_COND_INITIALIZER;
pthread_mutex_t UploadDiagMutex            =       PTHREAD_MUTEX_INITIALIZER;

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
"Content-Length: %lu\r\n\r\n";

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
"Content-Length: %lu\r\n\r\n";

static char http_sample_upload_text[] = "Test Upload files. blah blah blah...\r\n";


static char http_head_request[]=
"HEAD %s HTTP/1.1\r\n"
"Host: %s:%s\r\n\r\n";

#define LOCATION "Location: "
#define LOCATION_SCANF_FMT "%255[^\r\n]"  /* DSLH_TR143_MAX_STRING_LENGTH - 1 */

static int checkIfTheURLIsValid(XSKT_SOCKET sock, char *header_data,int header_len, char **redirectionUrl)
{
    int s_result = 0;
    char rUrl[DSLH_TR143_MAX_STRING_LENGTH] = {0};
    char buffer[2048] = {0};
    struct timeval timeout;
    errno_t rc = -1;

    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    if (_xskt_setsocketopt(sock, XSKT_SOCKET_SOL_SOCKET, ANSC_SOCKET_SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) < 0)
    {
        CcspTraceError(("Setsockopt for send timeout -- failed !!\n"));
        return -1;
    }

    if (_xskt_setsocketopt(sock, XSKT_SOCKET_SOL_SOCKET, ANSC_SOCKET_SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0)
    {
        CcspTraceError(("Setsockopt for receive timeout -- failed !!\n"));
        return -1;
    }

#ifdef _DEBUG
    AnscTraceWarning(("******** HEAD Upload Request **************\n"));
    AnscTraceWarning((header_data));
    AnscTraceWarning(("\n******************************************\n"));
#endif

    if(header_data != NULL)
    {
        s_result = _xskt_send(sock, header_data, header_len, 0);
    }

    if(s_result == XSKT_SOCKET_ERROR)
    {
            AnscTraceWarning(("Failed to send http head request\n"));
            return -1;
    }
    else
    {
            *redirectionUrl = NULL;
            AnscTraceWarning(("Successfully sent the request\n"));
            s_result = _xskt_recv(sock, buffer, sizeof(buffer) - 1, 0);
            if(( s_result != -1) && (s_result > 0))
            {
#ifdef _DEBUG
                    AnscTraceWarning(("******** HEAD Upload Response **************\n"));
                    AnscTraceWarning((buffer));
                    AnscTraceWarning(("\n******************************************\n"));
#endif
                    if(_ansc_strstr(buffer, HTTP_RESPONSE_OK_STRING) != NULL )
                    {
                            AnscTraceWarning(("Received 200 Ok Response\n"));
                            return 0;
                    }
                    else if(_ansc_strstr(buffer, HTTP_RESPONSE_REDIRECTION_STRING) != NULL)
		    {
			    AnscTraceWarning(("Received 301 Redirection response\n"));
			    char *res_buffer = _ansc_strstr(buffer, LOCATION);
			    if (res_buffer != NULL)
			    {
                                   res_buffer += _ansc_strlen(LOCATION);
                                   while (*res_buffer == ' ' || *res_buffer == '\t')
                                       res_buffer++;

                                   if (sscanf(res_buffer, LOCATION_SCANF_FMT, rUrl) == 1 && rUrl[0] != '\0')
				   {
					*redirectionUrl = (char*)AnscAllocateMemory(DSLH_TR143_MAX_STRING_LENGTH);
					if (*redirectionUrl !=  NULL)
					{
					    rc = strcpy_s(*redirectionUrl, DSLH_TR143_MAX_STRING_LENGTH, rUrl);
					    if (rc < EOK)
					    {
					        AnscFreeMemory(*redirectionUrl);
					        *redirectionUrl = NULL;
					        return -1;
					    }
					    AnscTraceWarning(("Redirection URL is %s\n", *redirectionUrl));
					    return 0;
					}
				   }
			    }
		    }
	     }
	     else
	     {
		AnscTraceWarning(("Failure in receiving the response\n"));
		return -1;
	     }
            return -1;
       }
}

/**********************************************************************

  prototype:

    static void
    updateTestFileLength(PDSLH_TR143_UPLOAD_DIAG_INFO pUploadInfo)

  description:

    Priority: 1) SRU>0  2) WebPA/DM manual  3) auto TFL / reuse
**********************************************************************/
static void
updateTestFileLength(PDSLH_TR143_UPLOAD_DIAG_INFO pUploadInfo)
{
    ULONG       uploadSpeedKbps = 0;
    ULONG       uploadSpeedBps  = 0;
    ULONG       testFileLength  = 0;
    ANSC_STATUS sruStatus       = ANSC_STATUS_FAILURE;

    if (pUploadInfo == NULL)
        return;

    /* 1) SRU */
    sruStatus = Tad_GetParamValues(PPPMgr_COMPONENT_NAME, PPPMgr_DBUS_PATH,
            RDKB_SRU_UPLOAD_SPEED_DM, &uploadSpeedKbps);

    if (ANSC_STATUS_SUCCESS == sruStatus && uploadSpeedKbps > 0)
    {
        AutoTfl_Reset();

        uploadSpeedBps = uploadSpeedKbps * 1000;
        CcspTraceInfo(("updateTestFileLength: got UploadSpeed %lu bps based on SRU DM\n", uploadSpeedBps));

        testFileLength = (ULONG)((((unsigned long long)uploadSpeedBps) * 3) / 4);
        if (testFileLength < UPLOAD_TFL_DEFAULT_BYTES)
            testFileLength = UPLOAD_TFL_DEFAULT_BYTES;

        pUploadInfo->TestFileLength = testFileLength;
        CcspTraceInfo(("updateTestFileLength: TestFileLength=%lu bytes\n", pUploadInfo->TestFileLength));
        return;
    }

    /* 2) WebPA/DM */
    if (AutoTfl_TryManual(pUploadInfo))
        return;

    /* 3) Auto TFL / reuse */
    AutoTfl_Start(pUploadInfo);
}

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
    char                            buffer[2048]       = { 0 };
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
    BOOL                            head_validated     = FALSE;
    ULONG                           initialTxBytes     = 0;
    ULONG                           finalTxBytes       = 0;
    struct timeval                  startTime;
    struct timeval                  currentTime;
    unsigned long long              ullStartTimeInMs   = 0;
    unsigned long long              ullCurrentTimeInMs = 0;
    unsigned long long              ullDurationInMs    = 0;
    char                            PrevDiagState[DEF_SIZE]     = {0};
    char                            CurrDiagState[DEF_SIZE]     = {0};
    char                            bufferState[DEF_SIZE_128]   = {0};

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

    /* turn on indicator to identify it test is started or not, if not already set */
    if (!pMyObject->bUpDiagOn)
    {
        pMyObject->bUpDiagOn           = TRUE;
    }

    /* reset the stats */
    DslhResetUploadDiagStats((pStats));
	
    pStats->TimeBasedTestDuration = (DOUBLE)pMyObject->UploadDiagInfo.TimeBasedTestDuration;
    pStats->TimeBasedTestMeasurementOffset = pMyObject->UploadDiagInfo.TimeBasedTestMeasurementOffset;

    getDiagnosticState(DSLH_DIAGNOSTIC_TYPE_Upload, PrevDiagState);
    pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Requested;

    getDiagnosticState(DSLH_DIAGNOSTIC_TYPE_Upload, CurrDiagState);
    snprintf(bufferState, sizeof(bufferState), "%d,%s,%s,ccsp_string", CCSP_COMPONENT_ID_NOTIFY_COMP, CurrDiagState, PrevDiagState);

    Notify_change("Device.IP.Diagnostics.UploadDiagnostics.DiagnosticsState", bufferState);
    getDiagnosticState(DSLH_DIAGNOSTIC_TYPE_Upload, PrevDiagState);

    if ( pMyObject->bStopUpDiag )
    {
        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }

     retry :

        pHost = pServ = pPath = NULL;
    /* parse the upload http url */
	if (ParseHttpURL(pMyObject->UploadDiagInfo.UploadURL,
			&pHost, &pServ, &pPath) != 0)
	{
		/* if the function fail, memory should not allcated, but the Pointers' value is uncertain. */
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

    {
        struct timeval timeout;

        timeout.tv_sec = (long)pMyObject->UploadDiagInfo.TimeBasedTestDuration;
        timeout.tv_usec = 0;

        if (_xskt_setsocketopt(aSocket, XSKT_SOCKET_SOL_SOCKET, ANSC_SOCKET_SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) < 0)
        {
            CcspTraceError(("Setsockopt for send timeout -- failed !!\n"));
            goto done;
        }

        if (_xskt_setsocketopt(aSocket, XSKT_SOCKET_SOL_SOCKET, ANSC_SOCKET_SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0)
        {
            CcspTraceError(("Setsockopt for receive timeout -- failed !!\n"));
            goto done;
        }
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


    if (!head_validated)
    {
       int ret = -1;
       char *redirectionUrl = NULL;


	if (IsIPv6Address(pHost))
        {
                _ansc_snprintf(ipv6ref, sizeof(ipv6ref), "[%s]", pHost);
                _ansc_snprintf(buffer, sizeof(buffer), http_head_request,
                                pPath, ipv6ref, pServ);
        }
        else
        {
                _ansc_snprintf(buffer, sizeof(buffer), http_head_request,
                                pPath, pHost, pServ);
        }


	ret = checkIfTheURLIsValid(aSocket, buffer ,sizeof(buffer), &redirectionUrl);

        if (ret == 0)
        {
            head_validated = TRUE;

            if (redirectionUrl)
	    {
                 _ansc_snprintf(pMyObject->UploadDiagInfo.UploadURL,sizeof(pMyObject->UploadDiagInfo.UploadURL),"%s",redirectionUrl);
                AnscFreeMemory(redirectionUrl);
	    }
	    if (aSocket != XSKT_SOCKET_INVALID_SOCKET)
		    _xskt_closesocket(aSocket);
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
	    goto retry;
        }

        pMyObject->bUpNotifyNeeded = TRUE;
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_InitConnectionFailed;

        returnStatus = ANSC_STATUS_FAILURE;

        goto done;
    }

    /* calculate the total length */
    updateTestFileLength(&pMyObject->UploadDiagInfo);
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

    /* TR-143: ROMTime = time when client sends the PUT command */
    AnscGetSystemTime(&pStats->ROMTime);

    pStats->TestBytesSent = s_result;
    /* TR-143: BOMTime = time when first data packet is sent. For HTTP, first packet is the PUT request (headers). */
    AnscGetSystemTime(&pStats->BOMTime);

    /*
     * TR-143: TimeBasedTestDuration window uses wall time sampled immediately after BOMTime
     * (same clock family as loop gettimeofday), so the send loop budget aligns to BOM.
     * Same boundary behavior as bbhm_download_action.c (e.g. default 10s test window).
     */
    if (0 != gettimeofday(&startTime, NULL))
    {
        CcspTraceError(("Failed to get the time of a day \n"));
        returnStatus = ANSC_STATUS_FAILURE;
        goto done;
    }
    ullStartTimeInMs =
        (unsigned long long)startTime.tv_sec * 1000ULL
        + (unsigned long long)(startTime.tv_usec / 1000);

    /* TR-143: Sample interface stats at BOMTime for TotalBytesSent calculation */
    if (ANSC_STATUS_FAILURE == Tad_GetParamValues(PAM_COMPONENT_NAME, PAM_DBUS_PATH, INTERFACE_STATS_Tx_BYTES, &initialTxBytes))
    {
        CcspTraceError(("%s: Failed to get the initial Tx byte count\n", __FUNCTION__));
    }
    CcspTraceWarning(("initialTxBytes = %lu\n", initialTxBytes));

    /* allocate once and reuse across Upload diagnostics */
    if ( s_uploadSendBuffer == NULL )
    {
        s_uploadSendBuffer = (char*)AnscAllocateMemory(UPLOAD_SINGLE_BUFFER_SIZE + 1);
    }
    send_buffer = s_uploadSendBuffer;

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

    /*
     * Time-based window: ullStartTimeInMs was taken immediately after BOMTime (above).
     * Do not start another send after TimeBasedTestDuration from that anchor.
     * SO_SNDTIMEO in the loop is remaining_ms so a single send cannot block past the window.
     * (Initial socket SO_SNDTIMEO remains full TimeBasedTestDuration for connect/send/PUT headers.)
     */
    {
        unsigned long long const ullTestWindowMs =
            (unsigned long long)pStats->TimeBasedTestDuration * 1000ULL;
        unsigned long long prev_sndto_ms = (unsigned long long)-1;

        while (uBytesSent > 0)
        {
            if (0 != gettimeofday(&currentTime, NULL))
            {
                CcspTraceError(("Failed to get the time of a day \n"));
                returnStatus = ANSC_STATUS_FAILURE;
                goto done;
            }

            ullCurrentTimeInMs =
                (unsigned long long)currentTime.tv_sec * 1000ULL
                + (unsigned long long)(currentTime.tv_usec / 1000);
            ullDurationInMs = ullCurrentTimeInMs - ullStartTimeInMs;

            if (ullDurationInMs >= ullTestWindowMs)
            {
                break;
            }

            if ( pMyObject->bStopUpDiag )
            {
                returnStatus = ANSC_STATUS_FAILURE;
                goto done;
            }

            send_size = (uBytesSent >= UPLOAD_SINGLE_BUFFER_SIZE) ? UPLOAD_SINGLE_BUFFER_SIZE : uBytesSent;

            {
                unsigned long long remaining_ms = ullTestWindowMs - ullDurationInMs;

                if (remaining_ms != prev_sndto_ms)
                {
                    struct timeval tv;

                    prev_sndto_ms = remaining_ms;
                    tv.tv_sec = (long)(remaining_ms / 1000);
                    tv.tv_usec = (long)((remaining_ms % 1000) * 1000);
                    if (_xskt_setsocketopt(aSocket, XSKT_SOCKET_SOL_SOCKET, ANSC_SOCKET_SO_SNDTIMEO,
                            (const char *)&tv, sizeof(tv)) < 0)
                    {
                        CcspTraceError(("Setsockopt for send loop timeout -- failed !!\n"));
                        goto done;
                    }
                }
            }

            s_result = _xskt_send(aSocket, send_buffer, (int)send_size, 0);

            if ( s_result < 0 )
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    if (0 != gettimeofday(&currentTime, NULL))
                    {
                        CcspTraceError(("Failed to get the time of a day \n"));
                        returnStatus = ANSC_STATUS_FAILURE;
                        goto done;
                    }
                    ullCurrentTimeInMs =
                        (unsigned long long)currentTime.tv_sec * 1000ULL
                        + (unsigned long long)(currentTime.tv_usec / 1000);
                    ullDurationInMs = ullCurrentTimeInMs - ullStartTimeInMs;
                    if (ullDurationInMs >= ullTestWindowMs)
                    {
                        break;
                    }
                }

                AnscTraceWarning(("Failed to send request to the http server. code: %d\n", _xskt_get_last_error()));

                pMyObject->bUpNotifyNeeded = TRUE;
                pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_TransferFailed;

                returnStatus = ANSC_STATUS_FAILURE;

                goto done;
            }

            if (s_result == 0)
            {
                AnscTraceWarning(("send returned 0 unexpectedly.\n"));
                pMyObject->bUpNotifyNeeded = TRUE;
                pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_TransferFailed;
                returnStatus = ANSC_STATUS_FAILURE;
                goto done;
            }

            pStats->TestBytesSent += (ULONG)s_result;
            uBytesSent -= (ULONG)s_result;
        }
    }


         AnscZeroMemory(buffer, sizeof(buffer));
	if (_xskt_recv(aSocket, buffer, sizeof(buffer) - 1, 0) != -1)
	{
		AnscTraceWarning(("******** Upload Response **************\n"));
		AnscTraceWarning((buffer));
		AnscTraceWarning(("\n******************************************\n"));
	}

        if (_ansc_strstr(buffer, HTTP_RESPONSE_OK_STRING) == NULL)
        {
            // failed to receive the request
            AnscTraceWarning(("Failed to receive 200 Ok Response after uploading the data\n"));

            pMyObject->bUpNotifyNeeded = TRUE;
            pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_TransferFailed;

            goto done;
        }

    /* TR-143: EOMTime = time when HTTP successful response code is received */
    AnscGetSystemTime(&pStats->EOMTime);

    /* Capture final interface stats AFTER recv: kernel has flushed our data to the wire by now,
     * so erouter0 BytesSent reflects all upload bytes. Reading before recv caused undercount
     * (send() buffers in kernel, interface counter updates when packets actually leave). */
    if (ANSC_STATUS_FAILURE == Tad_GetParamValues(PAM_COMPONENT_NAME, PAM_DBUS_PATH, INTERFACE_STATS_Tx_BYTES, &finalTxBytes))
    {
        CcspTraceError(("%s: Failed to get the final Tx byte count\n", __FUNCTION__));
    }
    CcspTraceInfo(("finalTxBytes = %lu\n", finalTxBytes));

    pMyObject->bUpNotifyNeeded = TRUE;

    if (finalTxBytes >= initialTxBytes)
    {
        /* succeeded */
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Completed;
    }
    else if (pStats->TestBytesSent > 0)
    {
        /*
         * Device.IP.Interface.*.Stats.BytesSent can wrap or reset; delta is unusable.
         * Complete using TestBytesSent for TotalBytesSent.
         */
        CcspTraceWarning(("Interface BytesSent decreased (wrap/reset); using TestBytesSent for TotalBytesSent (initial %lu final %lu).\n",
                initialTxBytes, finalTxBytes));
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Completed;
    }
    else
    {
        CcspTraceError(("Interface stats invalid (finalTxBytes %lu < initialTxBytes %lu) \n", finalTxBytes, initialTxBytes));
        pStats->DiagStates = DSLH_TR143_DIAGNOSTIC_Error_Internal;
    }

done:

    if (pStats->DiagStates == DSLH_TR143_DIAGNOSTIC_Completed)
    {
        pStats->TimeBasedTestDuration = CalculateTimeDifference((USER_SYSTEM_TIME*)&pStats->EOMTime, (USER_SYSTEM_TIME*)&pStats->BOMTime);
        pStats->TimeBasedTestMeasurementOffset = (ULONG)CalculateTimeDifference((USER_SYSTEM_TIME*)&pStats->BOMTime, (USER_SYSTEM_TIME*)&pStats->ROMTime);

        if (finalTxBytes >= initialTxBytes)
        {
            pStats->TotalBytesSent = finalTxBytes - initialTxBytes;
        }
        else
        {
            pStats->TotalBytesSent = pStats->TestBytesSent;
        }
        CcspTraceWarning(("TotalTxBytes = %lu TestBytesSent = %lu\n", pStats->TotalBytesSent, pStats->TestBytesSent));
        Notify_change("UploadDownloadSpeedStatus","UploadCompleted");

        getDiagnosticState(DSLH_DIAGNOSTIC_TYPE_Upload, CurrDiagState);
        snprintf(bufferState, sizeof(bufferState), "%d,%s,%s,ccsp_string", CCSP_COMPONENT_ID_NOTIFY_COMP, CurrDiagState, PrevDiagState);
        Notify_change("Device.IP.Diagnostics.UploadDiagnostics.DiagnosticsState", bufferState);
    }
    else if((pStats->DiagStates != DSLH_TR143_DIAGNOSTIC_None) && (pStats->DiagStates != DSLH_TR143_DIAGNOSTIC_Requested) && (pStats->DiagStates != DSLH_TR143_DIAGNOSTIC_Canceled))
    {
        Notify_change("UploadDownloadSpeedStatus","Error_Occured");

        getDiagnosticState(DSLH_DIAGNOSTIC_TYPE_Upload, CurrDiagState);
        snprintf(bufferState, sizeof(bufferState), "%d,%s,%s,ccsp_string", CCSP_COMPONENT_ID_NOTIFY_COMP, CurrDiagState, PrevDiagState);
        Notify_change("Device.IP.Diagnostics.UploadDiagnostics.DiagnosticsState", bufferState);
    }

	if (aSocket != XSKT_SOCKET_INVALID_SOCKET)
		_xskt_closesocket(aSocket);
	if (send_buffer != NULL)
		send_buffer = NULL;
    /* keep s_uploadSendBuffer for reuse; do not free here */
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
        pthread_mutex_lock(&UploadDiagMutex);
        pMyObject->bStopUpDiag       = FALSE;
        pthread_cond_signal(&UploadDiagCond);
        pthread_mutex_unlock(&UploadDiagMutex);
    }

    pMyObject->UploadDiagInfo.DiagnosticsState = pStats->DiagStates;

	/* clear flags */
    pMyObject->bUpNotifyNeeded   = FALSE;
    pMyObject->bUpDiagOn         = FALSE;

    AutoTfl_Finish(pMyObject, pStats);

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
        pHandle->TimeBasedTestDuration = pUploadInfo->TimeBasedTestDuration;
        pHandle->TimeBasedTestMeasurementOffset = pUploadInfo->TimeBasedTestMeasurementOffset;
        pHandle->DiagnosticsState = pUploadInfo->DiagnosticsState;
    }

    return pHandle;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_STATUS
        BbhmUploadSetConfig
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
    pUploadInfo->TimeBasedTestDuration = pHandle->TimeBasedTestDuration;
    pUploadInfo->TimeBasedTestMeasurementOffset = pHandle->TimeBasedTestMeasurementOffset;
    pUploadInfo->DiagnosticsState = pHandle->DiagnosticsState;
    rc = strcpy_s(pUploadInfo->IfAddrName, sizeof(pUploadInfo->IfAddrName) , pHandle->IfAddrName);
    ERR_CHK(rc);

    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

       ANSC_STATUS
       BbhmUploadSetDiagState
           (
               ANSC_HANDLE                 hThisObject,
               ULONG                       ulDiagState
            );

    description:

        This function is called to set the Upload Diagnostics State

    argument:   ANSC_HANDLE                 hThisObject
                This handle is actually the pointer of this object
                itself.

                ANSC_HANDLE                 ulDiagState
               The Disgnostic State being set.

    return:     The status of the operation;

**********************************************************************/

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

