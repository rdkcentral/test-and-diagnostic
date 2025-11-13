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


/**************************************************************************

    module: cosa_ip_dml.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/17/2011    initial revision.

**************************************************************************/

#include <ctype.h>
#include "ansc_platform.h"
#include "cosa_diagnostic_apis.h"
#include "plugin_main_apis.h"
#include "cosa_ip_dml.h"
#include "diag.h"
#include "ansc_string_util.h"
#include <syscfg/syscfg.h>
#include "ccsp_trace.h"
#include "secure_wrapper.h"
#include "cosa_apis_util.h"

#ifdef EMMC_DIAG_SUPPORT
#include "platform_hal.h"
#include "ccsp_hal_emmc.h"
#endif
#include "safec_lib_common.h"

#ifdef WAN_FAILOVER_SUPPORTED
#include "sysevent/sysevent.h"
#endif

#define REFRESH_INTERVAL 120
#define SPEEDTEST_ARG_SIZE 4096
#define TIME_NO_NEGATIVE(x) ((long)(x) < 0 ? 0 : (x))
#define SPEEDTEST_AUTH_SIZE 4096
#define SPEEDTEST_VERSION_LOG_FILE "/tmp/.speedtest-client-version.log"
#define SPEEDTEST_VERSION_SIZE 32
#define SPEEDTEST_SERVER_KEY_SIZE	1024
#define SPEEDTEST_SERVER_USERNAME_PASS_SIZE	12


#ifndef ROUTEHOPS_HOST_STRING
#define ROUTEHOPS_HOST_STRING		"Host"
#endif

#if defined(_HUB4_PRODUCT_REQ_)
#define DEVICE_MAC                   "Device.DeviceInfo.X_COMCAST-COM_WAN_MAC"
#else
#define DEVICE_MAC                   "Device.DeviceInfo.X_COMCAST-COM_CM_MAC"
#endif

#ifndef _COSA_SIM_
BOOL CosaIpifGetSetSupported(char * pParamName);
#endif

//SpeedTest
BOOL g_enable_speedtest = FALSE;
BOOL g_run_speedtest = FALSE;
BOOL g_is_pingtest_running = FALSE;

char g_argument_speedtest[SPEEDTEST_ARG_SIZE + 1] ;
char g_authentication_speedtest[SPEEDTEST_AUTH_SIZE + 1] = {0};
char g_clientversion_speedtest[SPEEDTEST_VERSION_SIZE + 1] = {0};
int g_clienttype_speedtest = 1;
int g_status_speedtest = 0;



extern  COSAGetParamValueByPathNameProc     g_GetParamValueByPathNameProc;
extern  ANSC_HANDLE                         bus_handle;

static int validate_hostname (char *host, char *wrapped_host, size_t sizelimit)
{
    errno_t rc;

    /* check if host doesn't hold null or whitespaces */
    if (AnscValidStringCheck(host) != TRUE)
        return -1;

    /*
       'host' must contain IPv4, IPv6, or a FQDN.
    */
    if (isValidIPv4Address(host))
    {
        AnscTraceWarning(("validate_hostname - isValidIPv4Address success '%s'\n", host));
        goto done;
    }
    else if(isValidIPv6Address(host))
    {
        AnscTraceWarning(("validate_hostname - isValidIPv6Address success '%s'\n", host));
        goto done;
    }
    else if(isValidFQDN(host))
    {
        AnscTraceWarning(("validate_hostname - isValidFQDN success '%s'\n", host));
        goto done;
    }
    else
    {
        AnscTraceWarning(("validate_hostname - Invalidhostname configured '%s'\n", host));
        return -1;
    }
done:
    rc = sprintf_s(wrapped_host, sizelimit, "'%s'", host);
    if (rc < EOK)
    {
        ERR_CHK(rc);
    }

    return 0;
}


/***********************************************************************
 IMPORTANT NOTE:

 According to TR69 spec:
 On successful receipt of a SetParameterValues RPC, the CPE MUST apply
 the changes to all of the specified Parameters atomically. That is, either
 all of the value changes are applied together, or none of the changes are
 applied at all. In the latter case, the CPE MUST return a fault response
 indicating the reason for the failure to apply the changes.

 The CPE MUST NOT apply any of the specified changes without applying all
 of them.

 In order to set parameter values correctly, the back-end is required to
 hold the updated values until "Validate" and "Commit" are called. Only after
 all the "Validate" passed in different objects, the "Commit" will be called.
 Otherwise, "Rollback" will be called instead.

 The sequence in COSA Data Model will be:

 SetParamBoolValue/SetParamIntValue/SetParamUlongValue/SetParamStringValue
 -- Backup the updated values;

 if( Validate_XXX())
 {
     Commit_XXX();    -- Commit the update all together in the same object
 }
 else
 {
     Rollback_XXX();  -- Remove the update at backup;
 }

***********************************************************************/


/***********************************************************************

 APIs for Object:

    IP.Diagnostics.


***********************************************************************/

#if !defined (RESOURCE_OPTIMIZATION)

/***********************************************************************

 APIs for Object:

    IP.Diagnostics.X_CISCO_COM_ARP.

    *  X_CISCO_COM_ARP_GetParamBoolValue
    *  X_CISCO_COM_ARP_GetParamIntValue
    *  X_CISCO_COM_ARP_GetParamUlongValue
    *  X_CISCO_COM_ARP_GetParamStringValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        X_CISCO_COM_ARP_GetParamBoolValue
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
X_CISCO_COM_ARP_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        X_CISCO_COM_ARP_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
X_CISCO_COM_ARP_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        X_CISCO_COM_ARP_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
X_CISCO_COM_ARP_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        X_CISCO_COM_ARP_GetParamStringValue
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
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
X_CISCO_COM_ARP_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/***********************************************************************

 APIs for Object:

    IP.Diagnostics.X_CISCO_COM_ARP.Table.{i}.

    *  ARPTable_GetEntryCount
    *  ARPTable_GetEntry
    *  ARPTable_GetParamBoolValue
    *  ARPTable_GetParamIntValue
    *  ARPTable_GetParamUlongValue
    *  ARPTable_GetParamStringValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        ARPTable_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
ARPTable_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject           = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    ULONG                           entryCount          = pMyObject->ArpEntryCount;

    return entryCount;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        ARPTable_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
ARPTable_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject           = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PCOSA_DML_DIAG_ARP_TABLE        pArpTable           = (PCOSA_DML_DIAG_ARP_TABLE)pMyObject->pArpTable;
    
    *pInsNumber  = nIndex + 1;

    return (ANSC_HANDLE)&pArpTable[nIndex]; /* return the handle */
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ARPTable_IsUpdated
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is checking whether the table is updated or not.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     TRUE or FALSE.

**********************************************************************/
BOOL
ARPTable_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject           = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    BOOL                            bIsUpdated   = TRUE;

    /*
        We can use one rough granularity interval to get whole table in case
        that the updating is too frequent.
        */
    if ( ( AnscGetTickInSeconds() - pMyObject->PreviousVisitTime ) < COSA_DML_DIAG_ARP_TABLE_ACCESS_INTERVAL )
    {
        bIsUpdated  = FALSE;
    }
    else
    {
        pMyObject->PreviousVisitTime =  AnscGetTickInSeconds();
        bIsUpdated  = TRUE;
    }

    return bIsUpdated;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        ARPTable_Synchronize
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to synchronize the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
ARPTable_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    ANSC_STATUS                     returnStatus      = ANSC_STATUS_FAILURE;
    PCOSA_DATAMODEL_DIAG            pMyObject         = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PCOSA_DML_DIAG_ARP_TABLE        pArpTable         = (PCOSA_DML_DIAG_ARP_TABLE)pMyObject->pArpTable;
    ULONG                           entryCount        = pMyObject->ArpEntryCount;
    PCOSA_DML_DIAG_ARP_TABLE        pArpTable2        = NULL;

    pArpTable2         = CosaDmlDiagGetARPTable(NULL,&entryCount);
    if ( !pArpTable2 )
    {
        /* Get Error, we don't del link because next time, it may be successful */
        return ANSC_STATUS_FAILURE;
    }

    if ( pArpTable )
    {
        AnscFreeMemory(pArpTable);
    }

    pMyObject->pArpTable     = pArpTable2;
    pMyObject->ArpEntryCount = entryCount;

    returnStatus =  ANSC_STATUS_SUCCESS;

    return returnStatus;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ARPTable_GetParamBoolValue
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
ARPTable_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    PCOSA_DML_DIAG_ARP_TABLE        pArpTable           = (PCOSA_DML_DIAG_ARP_TABLE)hInsContext;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Static") == 0)
    {
        /* collect value */
        *pBool    =  pArpTable->Static;

        return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ARPTable_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ARPTable_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        ARPTable_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
ARPTable_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    /* check the parameter name and return the corresponding value */

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        ARPTable_GetParamStringValue
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
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
ARPTable_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PCOSA_DML_DIAG_ARP_TABLE        pArpTable           = (PCOSA_DML_DIAG_ARP_TABLE)hInsContext;
    errno_t rc = -1;


    /* check the parameter name and return the corresponding value */

    if (strcmp(ParamName, "IPAddress") == 0)
    {
        /* collect value */
        rc = strcpy_s(pValue, *pUlSize ,pArpTable->IPAddress);
        ERR_CHK(rc);

        return 0;
    }

    if (strcmp(ParamName, "MACAddress") == 0)
    {
        /* collect value */
        if ( sizeof(pArpTable->MACAddress) <= *pUlSize)
        {
            rc = sprintf_s
                (
                    pValue, *pUlSize ,
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    pArpTable->MACAddress[0],
                    pArpTable->MACAddress[1],
                    pArpTable->MACAddress[2],
                    pArpTable->MACAddress[3],
                    pArpTable->MACAddress[4],
                    pArpTable->MACAddress[5]
                );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
            return 0;
        }
        else
        {
            *pUlSize = sizeof(pArpTable->MACAddress);
            return 1;
        }
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

#endif

/***********************************************************************

 APIs for Object:

    IP.Diagnostics.X_RDKCENTRAL-COM_PingTest.

    *  X_RDKCENTRAL_COM_PingTest_GetParamBoolValue
    *  X_RDKCENTRAL_COM_PingTest_GetParamStringValue
    *  X_RDKCENTRAL_COM_PingTest_SetParamBoolValue
    *  X_RDKCENTRAL_COM_PingTest_Validate
    *  X_RDKCENTRAL_COM_PingTest_Commit
    *  X_RDKCENTRAL_COM_PingTest_Rollback

***********************************************************************/
void COSAIP_pingtest_ProcessThread_Start( void )
{
	pthread_t pingtestthread;
	pthread_create( &pingtestthread, NULL, COSAIP_pingtest_ProcessThread, NULL );
}

void *COSAIP_pingtest_ProcessThread( void *arg )
{
	diag_pingtest_device_details_t *pingtest_devdet = diag_pingtest_getdevicedetails( );
	diag_state_t	state;
	diag_err_t		err_return;
	diag_cfg_t		cfg;
	diag_stat_t 	statis;
	char 			tmp_hostname[ 257 ]  = { 0 };
	int i = 0,j = 0;
	errno_t rc = -1;

	//Detach the thread from loop
    pthread_detach( pthread_self( ) );

	if ( CCSP_SUCCESS != COSA_IP_diag_Startpingtest( ) )
	{
		AnscTraceFlow(( "<%s> Failed to execute PING Test\n", __FUNCTION__ ));
		g_is_pingtest_running = FALSE;
		return NULL;
	}

	//ping test process thread
	while( 1 ) 
	{
		//Get the current state of ping test
		err_return = diag_getstate( DIAG_MD_PING, &state );
		if ( err_return != DIAG_ERR_OK )
		break;

		/* wait till ping test complete or error state */
		if( DIAG_ST_COMPLETE == state || DIAG_ST_ERROR == state )
		{
			break;
		}

		// wait for 1 sec of previous query
		sleep( 1 );
	}

	if( err_return != DIAG_ERR_OK )
	{
		AnscTraceFlow(( "<%s> Failed to execute PING Test\n", __FUNCTION__ ));
		g_is_pingtest_running = 0;
		return NULL;
	}

//For future requirement if need
#if 0
	/* Get the ping test status */
    char pingtestresult[ 64 ] = { 0 };
    diag_err_t		err;
	switch( state )
	{
		case DIAG_ST_NONE:
		{
			sprintf( pingtestresult, "%s", "None" );
		}
		break; /* DIAG_ST_NONE	*/

		case DIAG_ST_COMPLETE:
		{
			sprintf( pingtestresult, "%s", "Complete" );			
		}
		break; /* DIAG_ST_COMPLETE  */
		
		case DIAG_ST_ERROR:
		{
			diag_geterr(DIAG_MD_PING, &err);
			
			switch ( err ) 
			{
				case DIAG_ERR_RESOLVE:
					sprintf( pingtestresult, "%s", "Error_CannotResolveHostName" );			
					break; /* DIAG_ERR_RESOLVE */
				case DIAG_ERR_INTERNAL:
					sprintf( pingtestresult, "%s", "Error_Internal" );			
					break; /* DIAG_ERR_INTERNAL */
				case DIAG_ERR_OTHER:
				default:
					sprintf( pingtestresult, "%s", "Error_Other" );			
					break; /* DIAG_ERR_OTHER | default */
			}
		}
		break; /* DIAG_ST_ERROR */
		default:
			break;
	}
#endif /* 0 */

	/* Get the ping test configuration */
	if (diag_getcfg(DIAG_MD_PING, &cfg) != DIAG_ERR_OK)
	    return NULL;

	/* Get the ping test results */
	diag_getstatis(DIAG_MD_PING, &statis);

	//Fill Device Details it's already not filled case
	COSA_IP_diag_FillDeviceDetails( );

	/*
	  * Remove first and last charecter from host name
	  * if host name is 'www.google.com' then we have to display like 
	  * www.google.com
	  */
	rc = sprintf_s( tmp_hostname, sizeof(tmp_hostname) , "%s", "NULL" );
	if(rc < EOK)
	{
		ERR_CHK(rc);
	}

	/* CID: 67228 Copy of overlapping memory */
        if( cfg.host[ 0 ] != '\0' )
	{
            for(i= 0;i<strlen(cfg.host);i++) 
	    {
                if (cfg.host[i] == '\'')
                    continue;

                tmp_hostname[j++] = cfg.host[i];
            }
            tmp_hostname[j++] = '\0';
	}

       AnscTraceFlow(( "DeviceId:%s;CmMac:%s;PartnerId:%s;DeviceModel:%s;Endpoint:%s;Attempts:%d;SuccessCount:%d;AvgRtt:%.2f\n",
					( pingtest_devdet->DeviceID[ 0 ] != '\0' ) ? pingtest_devdet->DeviceID : "NULL",
					( pingtest_devdet->ecmMAC[ 0 ] != '\0' ) ? pingtest_devdet->ecmMAC : "NULL",										
					( pingtest_devdet->PartnerID[ 0 ] != '\0' ) ? pingtest_devdet->PartnerID : "NULL",										
					( pingtest_devdet->DeviceModel[ 0 ] != '\0' ) ? pingtest_devdet->DeviceModel : "NULL", 				
					tmp_hostname,
					cfg.cnt,
					statis.u.ping.success,
					statis.u.ping.rtt_avg ));

	g_is_pingtest_running = 0;
	
	return NULL;
}

void COSA_IP_diag_FillDeviceDetails( void )
{
	diag_pingtest_device_details_t *pingtest_devdet = diag_pingtest_getdevicedetails( );
	errno_t rc = -1;

	/* Get CM MAC if already having NULL */
	if( '\0' == pingtest_devdet->ecmMAC[ 0 ] )
	{
		rc = memset_s( pingtest_devdet->ecmMAC, sizeof( pingtest_devdet->ecmMAC ) , 0, sizeof( pingtest_devdet->ecmMAC ));
		ERR_CHK(rc);

		COSA_IP_diag_getGetParamValue(DEVICE_MAC, pingtest_devdet->ecmMAC,
					      sizeof( pingtest_devdet->ecmMAC ));
	}

	/* Get Serial number if already having NULL */
	if( '\0' == pingtest_devdet->DeviceID[ 0 ] )
	{
		rc = memset_s( pingtest_devdet->DeviceID, sizeof( pingtest_devdet->DeviceID ) , 0, sizeof( pingtest_devdet->DeviceID ));
		ERR_CHK(rc);

		COSA_IP_diag_getGetParamValue( "Device.DeviceInfo.SerialNumber", 
									  pingtest_devdet->DeviceID,
									  sizeof( pingtest_devdet->DeviceID ));
	}

	/* Get ModelName if already having NULL */
	if( '\0' == pingtest_devdet->DeviceModel[ 0 ] )
	{
		rc = memset_s( pingtest_devdet->DeviceModel, sizeof( pingtest_devdet->DeviceModel ), 0, sizeof( pingtest_devdet->DeviceModel ));
		ERR_CHK(rc);

		COSA_IP_diag_getGetParamValue( "Device.DeviceInfo.ModelName", 
									  pingtest_devdet->DeviceModel,
									  sizeof( pingtest_devdet->DeviceModel ));
	}
}

int	COSA_IP_diag_Startpingtest( void )
{
	CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
	parameterValStruct_t   param_val[ 1 ]    = {{ "Device.IP.Diagnostics.IPPing.DiagnosticsState", "Requested", ccsp_string }};
	char				   component[ 256 ]  = "eRT.com.cisco.spvtg.ccsp.tdm";
	char				   bus[256]		     = "/com/cisco/spvtg/ccsp/tdm";
	char*				   faultParam 	     = NULL;
	int 				   ret			     = 0;	

	ret = CcspBaseIf_setParameterValues(  bus_handle,
										  component,
										  bus,
										  0,
										  0,
										  param_val,
										  1,
										  TRUE,
										  &faultParam
										  );
			
	if( ( ret != CCSP_SUCCESS ) && \
		( faultParam )
	  )
	{
	    AnscTraceWarning(("%s -- failed to set parameter %s\n", __FUNCTION__, param_val[ 0 ].parameterName));
		bus_info->freefunc( faultParam );
	}

	return ret;
}

void COSA_IP_diag_getGetParamValue( char *ParamName, char *ParamValue, int size )
{
    ANSC_STATUS   retval  = ANSC_STATUS_FAILURE;

	if( ( NULL != ParamName ) && \
		( NULL != ParamValue ) && \
		( size > 0 ) 
	)
	{
		parameterValStruct_t	ParamStruct = { 0 };
		
		ParamStruct.parameterName	= ParamName;
		ParamStruct.parameterValue  = ParamValue;
		
		AnscTraceFlow(("%s - retrieve param %s\n", __FUNCTION__, ParamName));
		
		retval = g_GetParamValueByPathNameProc( bus_handle, &ParamStruct, (ULONG *)&size);
		
		if ( retval != ANSC_STATUS_SUCCESS )
		{
			AnscTraceWarning(("%s -- failed to retrieve parameter %s\n", __FUNCTION__, ParamName));
		}
	}
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        X_RDKCENTRAL_COM_PingTest_GetParamBoolValue
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
X_RDKCENTRAL_COM_PingTest_GetParamBoolValue
	(
	    ANSC_HANDLE                 hInsContext,
	    char*                       ParamName,
	    BOOL*                       pBool
	)
{
    /* check the parameter name and return the corresponding value */
	if (strcmp(ParamName, "Run") == 0)
    {
	    *pBool = g_is_pingtest_running;
	    return TRUE;
    } 

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        X_RDKCENTRAL_COM_PingTest_SetParamBoolValue
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
BOOL
X_RDKCENTRAL_COM_PingTest_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    /* check the parameter name and set the corresponding value */
	if (strcmp(ParamName, "Run") == 0)
    {
		if( bValue )
		{
			if( FALSE == g_is_pingtest_running )
			{
				AnscTraceFlow(("%s Run Pingtest : %d \n",__FUNCTION__, bValue));
				g_is_pingtest_running = bValue;

				/* Start the PING test as a thread */
				COSAIP_pingtest_ProcessThread_Start( );
			}
			else
			{
				AnscTraceFlow(("%s Pingtest is already running : %d\n",__FUNCTION__, g_is_pingtest_running));
			}
		}
		
		return TRUE;
	 }

    /*AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        X_RDKCENTRAL_COM_PingTest_GetParamStringValue
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
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
X_RDKCENTRAL_COM_PingTest_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    diag_pingtest_device_details_t	*devdetails = diag_pingtest_getdevicedetails( );
    errno_t rc = -1;

	//Fill Device Details it's already not filled case
	COSA_IP_diag_FillDeviceDetails( );

    if (strcmp(ParamName, "PartnerID") == 0)
    {
		if ( *pUlSize < AnscSizeOfString( devdetails->PartnerID ) )
		{
			*pUlSize = AnscSizeOfString( devdetails->PartnerID ) + 1;
			return 1;
		}

		rc = strcpy_s( pValue, *pUlSize ,devdetails->PartnerID );
		ERR_CHK(rc);
		return 0;
    }

    if (strcmp(ParamName, "ecmMAC") == 0)
    {
		if ( *pUlSize < AnscSizeOfString( devdetails->ecmMAC ) )
		{
			*pUlSize = AnscSizeOfString( devdetails->ecmMAC ) + 1;
			return 1;
		}

		rc = strcpy_s( pValue, *pUlSize ,devdetails->ecmMAC );
		ERR_CHK(rc);
		return 0;
    }

    if (strcmp(ParamName, "DeviceID") == 0)
    {
		if ( *pUlSize < AnscSizeOfString( devdetails->DeviceID ) )
		{
			*pUlSize = AnscSizeOfString( devdetails->DeviceID ) + 1;
			return 1;
		}

		rc = strcpy_s( pValue, *pUlSize ,devdetails->DeviceID );
		ERR_CHK(rc);
		return 0;
    }

    if (strcmp(ParamName, "DeviceModel") == 0)
    {
		if ( *pUlSize < AnscSizeOfString( devdetails->DeviceModel ) )
		{
			*pUlSize = AnscSizeOfString( devdetails->DeviceModel ) + 1;
			return 1;
		}

		rc = strcpy_s( pValue, *pUlSize ,devdetails->DeviceModel );
		ERR_CHK(rc);
		return 0;
    }

    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        X_RDKCENTRAL_COM_PingTest_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
X_RDKCENTRAL_COM_PingTest_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        X_RDKCENTRAL_COM_PingTest_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
X_RDKCENTRAL_COM_PingTest_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        X_RDKCENTRAL_COM_PingTest_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
X_RDKCENTRAL_COM_PingTest_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    IP.Diagnostics.IPPing.

    *  IPPing_GetParamBoolValue
    *  IPPing_GetParamIntValue
    *  IPPing_GetParamUlongValue
    *  IPPing_GetParamStringValue
    *  IPPing_SetParamBoolValue
    *  IPPing_SetParamIntValue
    *  IPPing_SetParamUlongValue
    *  IPPing_SetParamStringValue
    *  IPPing_Validate
    *  IPPing_Commit
    *  IPPing_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        IPPing_GetParamBoolValue
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
IPPing_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        IPPing_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPPing_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        IPPing_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPPing_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    diag_state_t                    state;
    diag_err_t                      err;
    diag_cfg_t                      cfg;
    diag_stat_t                     statis;

    if (diag_getstate(DIAG_MD_PING, &state) != DIAG_ERR_OK
            || diag_getcfg(DIAG_MD_PING, &cfg) != DIAG_ERR_OK
            || diag_getstatis(DIAG_MD_PING, &statis) != DIAG_ERR_OK
            || diag_geterr(DIAG_MD_PING, &err) != DIAG_ERR_OK)
        return FALSE;

    if (strcmp(ParamName, "DiagnosticsState") == 0)
    {
        switch (state) {
            case DIAG_ST_NONE:
                *puLong = DSLH_DIAG_STATE_TYPE_None + 1;
                break;
            case DIAG_ST_ACTING:
                *puLong = DSLH_DIAG_STATE_TYPE_Requested + 1;
                break;
            case DIAG_ST_COMPLETE:
                *puLong = DSLH_DIAG_STATE_TYPE_Complete + 1;
                break;
            case DIAG_ST_ERROR:
                switch (err) {
                    case DIAG_ERR_RESOLVE:
                        *puLong = DSLH_DIAG_STATE_TYPE_PING_Error_HostName + 1;
                        break;
                    case DIAG_ERR_INTERNAL:
                        *puLong = DSLH_DIAG_STATE_TYPE_PING_Error_Internal + 1;
                        break;
                    case DIAG_ERR_OTHER:
                    default:
                        *puLong = DSLH_DIAG_STATE_TYPE_PING_Error_Other + 1;
                        break;
                }
                break;
            default:
                return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "NumberOfRepetitions") == 0)
        *puLong = cfg.cnt;
    else if (strcmp(ParamName, "Timeout") == 0)
        *puLong = cfg.timo;
    else if (strcmp(ParamName, "DataBlockSize") == 0)
        *puLong = cfg.size;
    else if (strcmp(ParamName, "DSCP") == 0)
        *puLong = cfg.tos >> 2;
    else if (strcmp(ParamName, "SuccessCount") == 0)
        *puLong = statis.u.ping.success;
    else if (strcmp(ParamName, "FailureCount") == 0)
        *puLong = statis.u.ping.failure;
    else if (strcmp(ParamName, "AverageResponseTime") == 0)
        *puLong = statis.u.ping.rtt_avg;
    else if (strcmp(ParamName, "MinimumResponseTime") == 0)
        *puLong = statis.u.ping.rtt_min;
    else if (strcmp(ParamName, "MaximumResponseTime") == 0)
        *puLong = statis.u.ping.rtt_max;
    else
        return FALSE;

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        IPPing_GetParamStringValue
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
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
IPPing_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    diag_cfg_t                      cfg;
    errno_t rc = -1;

    if (diag_getcfg(DIAG_MD_PING, &cfg) != DIAG_ERR_OK)
        return -1;

    if (strcmp(ParamName, "Interface") == 0)
    {
        /*
         *  Revert to TR-181 definition -- object reference
         *
        if (*pUlSize <= strlen(cfg.ifname))
        {
            *pUlSize = strlen(cfg.ifname) + 1;
            return 1;
        }

        strncpy(pValue, cfg.ifname, *pUlSize);
         */
        if ( *pUlSize <= _ansc_strlen(cfg.Interface) )
        {
            *pUlSize = _ansc_strlen(cfg.Interface) + 1;
            return 1;
        }

        rc = strcpy_s(pValue, *pUlSize , cfg.Interface);
        ERR_CHK(rc);
        return 0;
    }

    if (strcmp(ParamName, "Host") == 0)
    {
        if (*pUlSize <= strlen(cfg.host))
        {
            *pUlSize = strlen(cfg.host) + 1;
            return 1;
        }

        rc = strcpy_s(pValue, *pUlSize , cfg.host);
        ERR_CHK(rc);
        return 0;
    }
   
    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        IPPing_SetParamBoolValue
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
BOOL
IPPing_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        IPPing_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPPing_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        IPPing_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
IPPing_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    diag_cfg_t                      cfg;
    #define MIN 1
    #define MAX 4
    if (diag_getcfg(DIAG_MD_PING, &cfg) != DIAG_ERR_OK)
        return FALSE;

    if (strcmp(ParamName, "DiagnosticsState") == 0) {
        if (uValue == DSLH_DIAG_STATE_TYPE_Requested + 1) {
            if (diag_start(DIAG_MD_PING) != 0)
                return FALSE;
            return TRUE;
        }
        else if (uValue == DSLH_DIAG_STATE_TYPE_Canceled + 1) {
            if (diag_stop(DIAG_MD_PING) != 0)
                return FALSE;
            return TRUE;
        }
        return FALSE;
    }

    if (strcmp(ParamName, "NumberOfRepetitions") == 0)
    {
        if((uValue<MIN) || (uValue>MAX))
            return FALSE;
        else
            cfg.cnt = uValue;
    }
    else if (strcmp(ParamName, "Timeout") == 0)
        cfg.timo = uValue;
    else if (strcmp(ParamName, "DataBlockSize") == 0)
    {
        cfg.size = uValue;
        if (syscfg_set_u_commit (NULL, "selfheal_ping_DataBlockSize", cfg.size) != 0)
        {
            AnscTraceWarning(("syscfg_set failed\n"));
        }
    }
    else if (strcmp(ParamName, "DSCP") == 0)
        cfg.tos = uValue << 2;
    else
        return FALSE;

    if (diag_setcfg(DIAG_MD_PING, &cfg) != DIAG_ERR_OK)
        return FALSE;

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        IPPing_SetParamStringValue
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
BOOL
IPPing_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    diag_cfg_t cfg;
    errno_t rc = -1;

    if (diag_getcfg(DIAG_MD_PING, &cfg) != DIAG_ERR_OK)
        return FALSE;

    if (strcmp(ParamName, "Interface") == 0)
    {
        if (pString[0] == 0)
        {
            /* empty string is OK */
        }
        else if (AnscValidStringCheck(pString) != TRUE) /* fail if pString contains <space> or any of <>&|'" */
        {
            return FALSE;
        }

        rc = sprintf_s(cfg.Interface, sizeof(cfg.Interface), "%s", pString);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }

        /*
         *  Fill in cfg.ifname based on Interface - Device.IP.Interface.<n>
         */
        {
            ANSC_STATUS             retval  = ANSC_STATUS_FAILURE;
            char                    IfNameParamName[DIAG_CFG_REF_STRING_LENGTH+1+5];
            parameterValStruct_t    ParamVal;
            int                     size = sizeof(cfg.ifname);

            if (cfg.Interface[0] == 0)
            {
                /* If an empty string is specified, use "Device.IP.Interface.1" as the interface */
                ParamVal.parameterName = "Device.IP.Interface.1.Name";
            }
            else
            {
                rc = sprintf_s(IfNameParamName, sizeof(IfNameParamName), "%s.Name", cfg.Interface);
                if (rc < EOK)
                {
                    ERR_CHK(rc);
                }

                ParamVal.parameterName = IfNameParamName;
            }

            ParamVal.parameterValue = cfg.ifname;

            AnscTraceFlow(("%s - retrieve param %s\n", __FUNCTION__, IfNameParamName));

            retval = g_GetParamValueByPathNameProc(bus_handle, &ParamVal, (ULONG *)&size);

            if ( retval != ANSC_STATUS_SUCCESS )
            {
                AnscTraceWarning(("%s -- failed to retrieve parameter %s\n", __FUNCTION__, IfNameParamName));
            }
            else
            {
                AnscTraceFlow(("%s -- Interface.Name is %s\n", __FUNCTION__, cfg.ifname));
            }
        }
    }
    else if (strcmp(ParamName, "Host") == 0)
    {
        char wrapped_host[256];

        if (validate_hostname(pString, wrapped_host, sizeof(wrapped_host)) != 0)
            return FALSE;

        rc = sprintf_s(cfg.host, sizeof(cfg.host), "%s", wrapped_host);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
    }
    else
        return FALSE;

    if (diag_setcfg(DIAG_MD_PING, &cfg) != DIAG_ERR_OK)
        return FALSE;

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        IPPing_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
IPPing_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        IPPing_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
IPPing_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        IPPing_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
IPPing_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    IP.Diagnostics.TraceRoute.

    *  TraceRoute_GetParamBoolValue
    *  TraceRoute_GetParamIntValue
    *  TraceRoute_GetParamUlongValue
    *  TraceRoute_GetParamStringValue
    *  TraceRoute_SetParamBoolValue
    *  TraceRoute_SetParamIntValue
    *  TraceRoute_SetParamUlongValue
    *  TraceRoute_SetParamStringValue
    *  TraceRoute_Validate
    *  TraceRoute_Commit
    *  TraceRoute_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        TraceRoute_GetParamBoolValue
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
TraceRoute_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        TraceRoute_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
TraceRoute_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        TraceRoute_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
TraceRoute_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    diag_state_t                    state;
    diag_err_t                      err;
    diag_cfg_t                      cfg;
    diag_stat_t                     statis;

    if (diag_getstate(DIAG_MD_TRACERT, &state) != DIAG_ERR_OK
            || diag_getcfg(DIAG_MD_TRACERT, &cfg) != DIAG_ERR_OK
            || diag_getstatis(DIAG_MD_TRACERT, &statis) != DIAG_ERR_OK
            || diag_geterr(DIAG_MD_TRACERT, &err) != DIAG_ERR_OK)
        return FALSE;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "DiagnosticsState") == 0)
    {
        switch (state) {
            case DIAG_ST_NONE:
                *puLong = DSLH_DIAG_STATE_TYPE_None + 1;
                break;
            case DIAG_ST_ACTING:
                *puLong = DSLH_DIAG_STATE_TYPE_Requested + 1;
                break;
            case DIAG_ST_COMPLETE:
                *puLong = DSLH_DIAG_STATE_TYPE_Complete + 1;
                break;
            case DIAG_ST_ERROR:
                switch (err) {
                case DIAG_ERR_RESOLVE:
                    *puLong = DSLH_DIAG_STATE_TYPE_TRAC_Error_HostName + 1;
                    break;
                case DIAG_ERR_MAXHOPS:
                    *puLong = DSLH_DIAG_STATE_TYPE_TRAC_Error_MaxHopCount + 1;
                    break;
                case DIAG_ERR_OTHER:
                default:
                    /*
                     * voilate TR-181 has only two error state,
                     * but There really some other errors.
                     * Since UI using TR-181 values, we have to return one of them.
                     */
                    *puLong = DSLH_DIAG_STATE_TYPE_TRAC_Error_MaxHopCount + 1;
                    break;
                }
                break;
            default:
                return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "NumberOfTries") == 0)
        *puLong = cfg.cnt;
    else if (strcmp(ParamName, "Timeout") == 0)
        *puLong = cfg.timo;
    else if (strcmp(ParamName, "DataBlockSize") == 0)
        *puLong = cfg.size;
    else if (strcmp(ParamName, "DSCP") == 0)
        *puLong = cfg.tos >> 2;
    else if (strcmp(ParamName, "MaxHopCount") == 0)
        *puLong = cfg.maxhop;
    else if (strcmp(ParamName, "ResponseTime") == 0)
        *puLong = statis.u.tracert.resptime;

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        TraceRoute_GetParamStringValue
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
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
TraceRoute_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    diag_cfg_t                      cfg;
    errno_t rc = -1;

    if (diag_getcfg(DIAG_MD_TRACERT, &cfg) != DIAG_ERR_OK)
        return -1;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Interface") == 0)
    {
        /*
         *  Revert to TR-181 definition -- object reference
         *
        if (*pUlSize <= strlen(cfg.ifname))
        {
            *pUlSize = strlen(cfg.ifname) + 1;
            return 1;
        }

        snprintf(pValue, *pUlSize, "%s", cfg.ifname);
         */
        if ( *pUlSize <= _ansc_strlen(cfg.Interface) )
        {
            *pUlSize = _ansc_strlen(cfg.Interface) + 1;
            return 1;
        }

        rc = strcpy_s(pValue, *pUlSize , cfg.Interface);
        ERR_CHK(rc);
        return 0;
    }

    if (strcmp(ParamName, "Host") == 0)
    {
        if (*pUlSize <= strlen(cfg.host))
        {
            *pUlSize = strlen(cfg.host) + 1;
            return 1;
        }

        rc = sprintf_s(pValue, *pUlSize , "%s", cfg.host);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        return 0;
    }

    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        TraceRoute_SetParamBoolValue
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
BOOL
TraceRoute_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        TraceRoute_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
TraceRoute_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        TraceRoute_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
TraceRoute_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    diag_cfg_t                      cfg;

    if (strcmp(ParamName, "DiagnosticsState") == 0)
    {
        if (uValue == DSLH_DIAG_STATE_TYPE_Requested + 1)
        {
            if (diag_start(DIAG_MD_TRACERT) == DIAG_ERR_OK)
            {
                return TRUE;
            }
        }
        else if (uValue == DSLH_DIAG_STATE_TYPE_TRAC_Canceled + 1)
        {
            if (diag_stop(DIAG_MD_TRACERT) == DIAG_ERR_OK)
            {
                return TRUE;
            }
        }
        return FALSE;
    }

    if (diag_getcfg(DIAG_MD_TRACERT, &cfg) != DIAG_ERR_OK)
        return FALSE;

    if (strcmp(ParamName, "NumberOfTries") == 0)
        cfg.cnt = uValue;
    else if (strcmp(ParamName, "Timeout") == 0)
        cfg.timo = uValue;
    else if (strcmp(ParamName, "DataBlockSize") == 0)
        cfg.size = uValue;
    else if (strcmp(ParamName, "DSCP") == 0)
        cfg.tos = uValue << 2;
    else if (strcmp(ParamName, "MaxHopCount") == 0)
        cfg.maxhop = uValue;
    else
        return FALSE;

    if (diag_setcfg(DIAG_MD_TRACERT, &cfg) != DIAG_ERR_OK)
        return FALSE;

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        TraceRoute_SetParamStringValue
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
BOOL
TraceRoute_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    diag_cfg_t                      cfg;
    errno_t rc = -1;

    if (diag_getcfg(DIAG_MD_TRACERT, &cfg) != DIAG_ERR_OK)
        return FALSE;
   
    if (strcmp(ParamName, "Interface") == 0)
    {
        if (pString[0] == 0)
        {
            /* empty string is OK */
        }
        else if (AnscValidStringCheck(pString) != TRUE) /* fail if pString contains <space> or any of <>&|'" */
        {
            return FALSE;
        }

        rc = sprintf_s(cfg.Interface, sizeof(cfg.Interface), "%s", pString);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }

        /*
         *  Fill in cfg.ifname based on Interface - Device.IP.Interface.<n>
         */
        {
            ANSC_STATUS             retval  = ANSC_STATUS_FAILURE;
            char                    IfNameParamName[DIAG_CFG_REF_STRING_LENGTH+1+5];
            parameterValStruct_t    ParamVal;
            int                     size = sizeof(cfg.ifname);

            if (cfg.Interface[0] == 0)
            {
                /* If an empty string is specified, use "Device.IP.Interface.1" as the interface */
                ParamVal.parameterName = "Device.IP.Interface.1.Name";
            }
            else
            {
                rc = sprintf_s(IfNameParamName, sizeof(IfNameParamName), "%s.Name", cfg.Interface);
                if (rc < EOK)
                {
                    ERR_CHK(rc);
                }

                ParamVal.parameterName = IfNameParamName;
            }

            ParamVal.parameterValue = cfg.ifname;

            AnscTraceFlow(("%s - retrieve param %s\n", __FUNCTION__, IfNameParamName));

            retval = g_GetParamValueByPathNameProc(bus_handle, &ParamVal, (ULONG *)&size);

            if ( retval != ANSC_STATUS_SUCCESS )
            {
                AnscTraceWarning(("%s -- failed to retrieve parameter %s\n", __FUNCTION__, IfNameParamName));
            }
            else
            {
                AnscTraceFlow(("%s -- Interface.Name is %s\n", __FUNCTION__, cfg.ifname));
            }
        }
    }
    else if (strcmp(ParamName, "Host") == 0)
    {
        char wrapped_host[256];

        if (validate_hostname(pString, wrapped_host, sizeof(wrapped_host)) != 0)
            return FALSE;

        rc = sprintf_s(cfg.host, sizeof(cfg.host), "%s", wrapped_host);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
    }
    else
        return FALSE;

    if (diag_setcfg(DIAG_MD_TRACERT, &cfg) != DIAG_ERR_OK)
        return FALSE;

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        TraceRoute_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
TraceRoute_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        TraceRoute_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
TraceRoute_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        TraceRoute_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
TraceRoute_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/***********************************************************************

 APIs for Object:

    IP.Diagnostics.TraceRoute.RouteHops.{i}.

    *  RouteHops_GetEntryCount
    *  RouteHops_GetEntry
    *  RouteHops_IsUpdated
    *  RouteHops_Synchronize
    *  RouteHops_GetParamBoolValue
    *  RouteHops_GetParamIntValue
    *  RouteHops_GetParamUlongValue
    *  RouteHops_GetParamStringValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        RouteHops_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
RouteHops_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    diag_stat_t stat;

    if (diag_getstatis(DIAG_MD_TRACERT, &stat) != DIAG_ERR_OK)
        return 0;
    return stat.u.tracert.nhop;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        RouteHops_GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
RouteHops_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    diag_stat_t stat;

    if (diag_getstatis(DIAG_MD_TRACERT, &stat) != DIAG_ERR_OK)
        return NULL;
    if (nIndex >= stat.u.tracert.nhop)
        return NULL;
    *pInsNumber  = nIndex + 1;
    return &stat.u.tracert.hops[nIndex];
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RouteHops_IsUpdated
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is checking whether the table is updated or not.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     TRUE or FALSE.

**********************************************************************/
BOOL
RouteHops_IsUpdated
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return  TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        RouteHops_Synchronize
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to synchronize the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
RouteHops_Synchronize
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RouteHops_GetParamBoolValue
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
RouteHops_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RouteHops_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
RouteHops_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RouteHops_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
RouteHops_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    tracert_hop_t                   *hop = (tracert_hop_t *)hInsContext;

    if (!hop)
        return FALSE;

    if (strcmp(ParamName, "ErrorCode") == 0)
    {
        *puLong = hop->icmperr;
        return TRUE;
    }

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        RouteHops_GetParamStringValue
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
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
RouteHops_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    tracert_hop_t                   *hop = (tracert_hop_t *)hInsContext;
    errno_t rc = -1;

    if (!hop)
        return FALSE;

    if (strcmp(ParamName, "Host") == 0)
    {
        if (strlen(hop->host) >= *pUlSize) {
            *pUlSize = strlen(hop->host) + 1;
            return 1;
        }

        rc = sprintf_s(pValue, *pUlSize , "%s", hop->host);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        return 0;
    }
    if (strcmp(ParamName, "HostAddress") == 0)
    {
        if (strlen(hop->addr) >= *pUlSize) {
            *pUlSize = strlen(hop->addr) + 1;
            return 1;
        }

        rc = sprintf_s(pValue, *pUlSize , "%s", hop->addr);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        return 0;
    }
    if (strcmp(ParamName, "RTTimes") == 0)
    {
        if (strlen(hop->rtts) >= *pUlSize) {
            *pUlSize = strlen(hop->rtts) + 1;
            return 1;
        }

        rc = sprintf_s(pValue, *pUlSize , "%s", hop->rtts);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        return 0;
    }

    return -1;
}

#if !defined (RESOURCE_OPTIMIZATION)
/***********************************************************************


 APIs for Object:

    IP.Diagnostics.DownloadDiagnostics.

    *  DownloadDiagnostics_GetParamBoolValue
    *  DownloadDiagnostics_GetParamIntValue
    *  DownloadDiagnostics_GetParamUlongValue
    *  DownloadDiagnostics_GetParamStringValue
    *  DownloadDiagnostics_SetParamBoolValue
    *  DownloadDiagnostics_SetParamIntValue
    *  DownloadDiagnostics_SetParamUlongValue
    *  DownloadDiagnostics_SetParamStringValue
    *  DownloadDiagnostics_Validate
    *  DownloadDiagnostics_Commit
    *  DownloadDiagnostics_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DownloadDiagnostics_GetParamBoolValue
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
DownloadDiagnostics_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DownloadDiagnostics_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DownloadDiagnostics_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DownloadDiagnostics_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DownloadDiagnostics_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo      = pMyObject->hDiagDownloadInfo;
    PDSLH_TR143_DOWNLOAD_DIAG_STATS pDownloadDiagStats = NULL;


    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "DiagnosticsState") == 0)
    {
        pDownloadDiagStats = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)CosaDmlDiagGetResults
                                (
                                    DSLH_DIAGNOSTIC_TYPE_Download
                                );

        if ( pDownloadDiagStats )
        {
            *puLong = pDownloadDiagStats->DiagStates + 1;
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get DiagnosticsState\n!"));

            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "DSCP") == 0)
    {
        if ( pDownloadInfo )
        {
            *puLong = pDownloadInfo->DSCP;
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get DSCP \n!"));
            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "EthernetPriority") == 0)
    {
        if ( pDownloadInfo )
        {
            *puLong = pDownloadInfo->EthernetPriority;
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get EthernetPriority \n!"));
            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "TestBytesReceived") == 0)
    {
        pDownloadDiagStats = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)CosaDmlDiagGetResults
                                (
                                    DSLH_DIAGNOSTIC_TYPE_Download
                                );

        if ( pDownloadDiagStats )
        {
            *puLong = pDownloadDiagStats->TestBytesReceived;
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get TestBytesReceived\n!"));

            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "TotalBytesReceived") == 0)
    {
        pDownloadDiagStats = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)CosaDmlDiagGetResults
                                (
                                    DSLH_DIAGNOSTIC_TYPE_Download
                                );


        if ( pDownloadDiagStats )
        {
            *puLong = pDownloadDiagStats->TotalBytesReceived;
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get TotalBytesReceived\n!"));

            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        DownloadDiagnostics_GetParamStringValue
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
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
DownloadDiagnostics_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo      = pMyObject->hDiagDownloadInfo;
    PDSLH_TR143_DOWNLOAD_DIAG_STATS pDownloadDiagStats = NULL;
    PANSC_UNIVERSAL_TIME            pTime              = NULL;
    char                            pBuf[128]          = { 0 };
    errno_t                         rc                 = -1;


    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Interface") == 0)
    {
        if ( pDownloadInfo )
        {
            rc = strcpy_s(pValue, *pUlSize , pDownloadInfo->Interface);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get Interface\n!"));
            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "DownloadURL") == 0)
    {
        if ( pDownloadInfo )
        {
            rc = strcpy_s(pValue, *pUlSize ,pDownloadInfo->DownloadURL);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get DownloadURL \n!"));
            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "ROMTime") == 0)
    {
        pDownloadDiagStats = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)CosaDmlDiagGetResults
                                (
                                    DSLH_DIAGNOSTIC_TYPE_Download
                                );

        if ( pDownloadDiagStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pDownloadDiagStats->ROMTime;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }

            rc = strcpy_s(pValue, *pUlSize, pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get ROMTime\n!"));

            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "BOMTime") == 0)
    {
        pDownloadDiagStats = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)CosaDmlDiagGetResults
                                (
                                    DSLH_DIAGNOSTIC_TYPE_Download
                                );

        if ( pDownloadDiagStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pDownloadDiagStats->BOMTime;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }

            rc = strcpy_s(pValue, *pUlSize ,pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get BOMTime\n!"));

            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "EOMTime") == 0)
    {
        pDownloadDiagStats = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)CosaDmlDiagGetResults
                                (
                                    DSLH_DIAGNOSTIC_TYPE_Download
                                );

        if ( pDownloadDiagStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pDownloadDiagStats->EOMTime;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }

            rc = strcpy_s(pValue, *pUlSize, pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get EOMTime\n!"));

            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "TCPOpenRequestTime") == 0)
    {
        pDownloadDiagStats = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)CosaDmlDiagGetResults
                                (
                                    DSLH_DIAGNOSTIC_TYPE_Download
                                );

        if ( pDownloadDiagStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pDownloadDiagStats->TCPOpenRequestTime;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }

            rc = strcpy_s(pValue, *pUlSize, pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get TCPOpenRequestTime\n!"));

            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "TCPOpenResponseTime") == 0)
    {
        pDownloadDiagStats = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)CosaDmlDiagGetResults
                                (
                                    DSLH_DIAGNOSTIC_TYPE_Download
                                );
        if ( pDownloadDiagStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pDownloadDiagStats->TCPOpenResponseTime;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }

            rc = strcpy_s(pValue, *pUlSize, pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get TCPOpenResponseTime\n!"));

            return -1;
        }

        return 0;
    }

	if (strcmp(ParamName, "DownloadTransports") == 0)
	{
		if (!pValue || !pUlSize)
			return -1;

		if (*pUlSize < AnscSizeOfString("HTTP") + 1)
		{
			*pUlSize = AnscSizeOfString("HTTP") + 1;
			return 1;
		}

		rc = strcpy_s(pValue, *pUlSize, "HTTP");
		ERR_CHK(rc);
		return 0;
	}

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DownloadDiagnostics_SetParamBoolValue
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
BOOL
DownloadDiagnostics_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DownloadDiagnostics_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DownloadDiagnostics_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DownloadDiagnostics_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DownloadDiagnostics_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo      = pMyObject->hDiagDownloadInfo;

	/* according to TR-181, set writable params other than DiagnosticsState,
	 * must set DiagnosticsState to "NONE". */
	pDownloadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_None;

    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "DiagnosticsState") == 0)
    {
        uValue--;
        if ( uValue != (ULONG)DSLH_TR143_DIAGNOSTIC_Requested )
        {
            return FALSE;
        }

        pDownloadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_Requested;
        return TRUE;
    }

    if (strcmp(ParamName, "DSCP") == 0)
    {
        pDownloadInfo->DSCP= uValue;
        return TRUE;
    }

    if (strcmp(ParamName, "EthernetPriority") == 0)
    {
        pDownloadInfo->EthernetPriority = uValue;
        return TRUE;
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DownloadDiagnostics_SetParamStringValue
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
BOOL
DownloadDiagnostics_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo      = pMyObject->hDiagDownloadInfo;

	/* according to TR-181, set writable params other than DiagnosticsState,
	 * must set DiagnosticsState to "NONE". */
	pDownloadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_None;
	errno_t rc = -1;

    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "Interface") == 0)
    {
        rc = strcpy_s(pDownloadInfo->Interface, sizeof(pDownloadInfo->Interface) , pString);
        ERR_CHK(rc);
        return TRUE;
    }

    if (strcmp(ParamName, "DownloadURL") == 0)
    {
        if ( !pString || !(*pString) )
        {
            return FALSE;
        }

        rc = strcpy_s(pDownloadInfo->DownloadURL, sizeof(pDownloadInfo->DownloadURL) , pString);
        ERR_CHK(rc);
        return TRUE;
    }

    /*AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DownloadDiagnostics_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
DownloadDiagnostics_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo      = pMyObject->hDiagDownloadInfo;

    if ( pDownloadInfo->DiagnosticsState == DSLH_TR143_DIAGNOSTIC_Requested
      && !AnscSizeOfString(pDownloadInfo->DownloadURL) )
    {
        errno_t rc = -1;
        rc = strcpy_s(pReturnParamName, *puLength ,"DownloadURL");
        ERR_CHK(rc);
        return FALSE;
    }

    return  TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        DownloadDiagnostics_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
DownloadDiagnostics_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo      = pMyObject->hDiagDownloadInfo;
	char*							pAddrName			= NULL;
    errno_t rc = -1;

    if ( pDownloadInfo->DiagnosticsState != DSLH_TR143_DIAGNOSTIC_Requested )
    {
        pDownloadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_None;
    }

	if ((pAddrName = CosaGetInterfaceAddrByName(pDownloadInfo->Interface)) != NULL
			&& _ansc_strcmp(pAddrName, "::") != 0)
	{
		rc = strcpy_s(pDownloadInfo->IfAddrName, sizeof(pDownloadInfo->IfAddrName) ,pAddrName);
		ERR_CHK(rc);
	}
	else
	{
		pDownloadInfo->IfAddrName[0] = '\0';
	}
	if (pAddrName)
		AnscFreeMemory(pAddrName);

    CosaDmlDiagScheduleDiagnostic
                    (
                        DSLH_DIAGNOSTIC_TYPE_Download,
                        (ANSC_HANDLE)pDownloadInfo
                    );

    return 0;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        DownloadDiagnostics_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
DownloadDiagnostics_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject          = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadInfo      = pMyObject->hDiagDownloadInfo;
    PDSLH_TR143_DOWNLOAD_DIAG_INFO  pDownloadPreInfo   = NULL;

    if ( !pDownloadInfo )
    {
        return ANSC_STATUS_FAILURE;
    }

    DslhInitDownloadDiagInfo(pDownloadInfo);

    pDownloadPreInfo = (PDSLH_TR143_DOWNLOAD_DIAG_INFO)CosaDmlDiagGetConfigs
                        (
                            DSLH_DIAGNOSTIC_TYPE_Download
                        );

    if ( pDownloadPreInfo )
    {
        errno_t rc = -1;
        rc = strcpy_s(pDownloadInfo->Interface, sizeof(pDownloadInfo->Interface) , pDownloadPreInfo->Interface);
        ERR_CHK(rc);
        rc = strcpy_s(pDownloadInfo->DownloadURL, sizeof(pDownloadInfo->DownloadURL) ,pDownloadPreInfo->DownloadURL);
        ERR_CHK(rc);
        pDownloadInfo->DSCP             = pDownloadPreInfo->DSCP;
        pDownloadInfo->EthernetPriority = pDownloadPreInfo->EthernetPriority;
        pDownloadInfo->DiagnosticsState = pDownloadPreInfo->DiagnosticsState;
    }
    else
    {
       AnscTraceWarning(("Download Diagnostics---Failed to get previous configuration!\n"));
    }

    return 0;
}


/***********************************************************************

 APIs for Object:

    IP.Diagnostics.UploadDiagnostics.

    *  UploadDiagnostics_GetParamBoolValue
    *  UploadDiagnostics_GetParamIntValue
    *  UploadDiagnostics_GetParamUlongValue
    *  UploadDiagnostics_GetParamStringValue
    *  UploadDiagnostics_SetParamBoolValue
    *  UploadDiagnostics_SetParamIntValue
    *  UploadDiagnostics_SetParamUlongValue
    *  UploadDiagnostics_SetParamStringValue
    *  UploadDiagnostics_Validate
    *  UploadDiagnostics_Commit
    *  UploadDiagnostics_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UploadDiagnostics_GetParamBoolValue
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
UploadDiagnostics_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UploadDiagnostics_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
UploadDiagnostics_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UploadDiagnostics_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
UploadDiagnostics_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject        = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo      = pMyObject->hDiagUploadInfo;
    PDSLH_TR143_UPLOAD_DIAG_STATS   pUploadDiagStats = NULL;


    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "DiagnosticsState") == 0)
    {
        pUploadDiagStats = (PDSLH_TR143_UPLOAD_DIAG_STATS)CosaDmlDiagGetResults
                            (
                                DSLH_DIAGNOSTIC_TYPE_Upload
                            );

        if ( pUploadDiagStats )
        {
            *puLong = pUploadDiagStats->DiagStates + 1;
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get DiagnosticsState\n!"));

            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "DSCP") == 0)
    {
        if ( pUploadInfo )
        {
            *puLong = pUploadInfo->DSCP;
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get DSCP \n!"));
            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "EthernetPriority") == 0)
    {
        if ( pUploadInfo )
        {
            *puLong = pUploadInfo->EthernetPriority;
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get EthernetPriority \n!"));
            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "TestFileLength") == 0)
    {
        if ( pUploadInfo )
        {
            *puLong = pUploadInfo->TestFileLength;
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get TestFileLength \n!"));
            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "TotalBytesSent") == 0)
    {
        pUploadDiagStats = (PDSLH_TR143_UPLOAD_DIAG_STATS)CosaDmlDiagGetResults
                            (
                                DSLH_DIAGNOSTIC_TYPE_Upload
                            );

        if ( pUploadDiagStats )
        {
            *puLong = pUploadDiagStats->TotalBytesSent;
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get TotalBytesSent\n!"));

            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        UploadDiagnostics_GetParamStringValue
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
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
UploadDiagnostics_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject        = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo      = pMyObject->hDiagUploadInfo;
    PDSLH_TR143_UPLOAD_DIAG_STATS   pUploadDiagStats = NULL;
    PANSC_UNIVERSAL_TIME            pTime            = NULL;
    char                            pBuf[128]        = { 0 };
    errno_t                         rc               = -1;


    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Interface") == 0)
    {
        if ( pUploadInfo )
        {
            rc = strcpy_s(pValue, *pUlSize ,pUploadInfo->Interface);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get Interface \n!"));
            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "UploadURL") == 0)
    {
        if ( pUploadInfo )
        {
            rc = strcpy_s(pValue, *pUlSize , pUploadInfo->UploadURL);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get UploadURL \n!"));
            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "ROMTime") == 0)
    {
        pUploadDiagStats = (PDSLH_TR143_UPLOAD_DIAG_STATS)CosaDmlDiagGetResults
                            (
                                DSLH_DIAGNOSTIC_TYPE_Upload
                            );

        if ( pUploadDiagStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pUploadDiagStats->ROMTime;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
           rc = strcpy_s(pValue, *pUlSize , pBuf);
           ERR_CHK(rc);
        }
       else
       {
            AnscTraceWarning(("Upload Diagnostics---Failed to get ROMTime\n!"));

            return -1;
       }

       return 0;
    }

    if (strcmp(ParamName, "BOMTime") == 0)
    {
        pUploadDiagStats = (PDSLH_TR143_UPLOAD_DIAG_STATS)CosaDmlDiagGetResults
                            (
                                DSLH_DIAGNOSTIC_TYPE_Upload
                            );

        if ( pUploadDiagStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pUploadDiagStats->BOMTime;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
            rc = strcpy_s(pValue, *pUlSize ,pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get BOMTime\n!"));

            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "EOMTime") == 0)
    {
        pUploadDiagStats = (PDSLH_TR143_UPLOAD_DIAG_STATS)CosaDmlDiagGetResults
                            (
                                DSLH_DIAGNOSTIC_TYPE_Upload
                            );

        if ( pUploadDiagStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pUploadDiagStats->EOMTime;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }

            rc = strcpy_s(pValue, *pUlSize , pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get EOMTime\n!"));

            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "TCPOpenRequestTime") == 0)
    {
        pUploadDiagStats = (PDSLH_TR143_UPLOAD_DIAG_STATS)CosaDmlDiagGetResults
                            (
                                DSLH_DIAGNOSTIC_TYPE_Upload
                            );

        if ( pUploadDiagStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pUploadDiagStats->TCPOpenRequestTime;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
            rc = strcpy_s(pValue, *pUlSize , pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get TCPOpenRequestTime\n!"));

            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "TCPOpenResponseTime") == 0)
    {
        pUploadDiagStats = (PDSLH_TR143_UPLOAD_DIAG_STATS)CosaDmlDiagGetResults
                            (
                                DSLH_DIAGNOSTIC_TYPE_Upload
                            );

        if ( pUploadDiagStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pUploadDiagStats->TCPOpenResponseTime;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
            rc = strcpy_s(pValue, *pUlSize ,pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get TCPOpenResponseTime\n!"));

            return -1;
        }

        return 0;
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UploadDiagnostics_SetParamBoolValue
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
BOOL
UploadDiagnostics_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UploadDiagnostics_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
UploadDiagnostics_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UploadDiagnostics_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
UploadDiagnostics_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject        = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo      = pMyObject->hDiagUploadInfo;

	/* according to TR-181, set writable params other than DiagnosticsState,
	 * must set DiagnosticsState to "NONE". */
	pUploadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_None;

    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "DiagnosticsState") == 0)
    {
        uValue--;
        if ( uValue != (ULONG)DSLH_TR143_DIAGNOSTIC_Requested )
        {
            return FALSE;
        }

        pUploadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_Requested;
        return TRUE;
    }

    if (strcmp(ParamName, "DSCP") == 0)
    {
        pUploadInfo->DSCP = uValue;
        return TRUE;
    }

    if (strcmp(ParamName, "EthernetPriority") == 0)
    {
        pUploadInfo->EthernetPriority = uValue;
        return TRUE;
    }

    if (strcmp(ParamName, "TestFileLength") == 0)
    {
        if ( uValue == 0 )
        {
            return FALSE;
        }

        pUploadInfo->TestFileLength = uValue;
        return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UploadDiagnostics_SetParamStringValue
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
BOOL
UploadDiagnostics_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject        = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo      = pMyObject->hDiagUploadInfo;
    errno_t rc = -1;

	/* according to TR-181, set writable params other than DiagnosticsState,
	 * must set DiagnosticsState to "NONE". */
	pUploadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_None;

    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "Interface") == 0)
    {
        rc = strcpy_s(pUploadInfo->Interface, sizeof(pUploadInfo->Interface) , pString);
        ERR_CHK(rc);
        return TRUE;
    }

    if (strcmp(ParamName, "UploadURL") == 0)
    {
        if ( !pString || !(*pString) )
        {
            return FALSE;
        }

        rc = strcpy_s(pUploadInfo->UploadURL, sizeof(pUploadInfo->UploadURL) , pString);
        ERR_CHK(rc);
        return TRUE;
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UploadDiagnostics_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
UploadDiagnostics_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo  = pMyObject->hDiagUploadInfo;

    if ( pUploadInfo->DiagnosticsState == DSLH_TR143_DIAGNOSTIC_Requested
       && !AnscSizeOfString(pUploadInfo->UploadURL) )
    {
        errno_t rc = -1;
        rc = strcpy_s(pReturnParamName, *puLength , "UploadURL");
        ERR_CHK(rc);
        return FALSE;
    }
    return  TRUE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        UploadDiagnostics_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
UploadDiagnostics_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject    = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo  = pMyObject->hDiagUploadInfo;
	char*							pAddrName			= NULL;
	errno_t                         rc           = -1;

    if ( pUploadInfo->DiagnosticsState != DSLH_TR143_DIAGNOSTIC_Requested )
    {
        pUploadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_None;
    }

	if ((pAddrName = CosaGetInterfaceAddrByName(pUploadInfo->Interface)) != NULL
			&& _ansc_strcmp(pAddrName, "::") != 0)
	{
		rc = strcpy_s(pUploadInfo->IfAddrName, sizeof(pUploadInfo->IfAddrName) , pAddrName);
		ERR_CHK(rc);
	}
	else
	{
		pUploadInfo->IfAddrName[0] = '\0' ;
	}
	if (pAddrName)
		AnscFreeMemory(pAddrName);


    CosaDmlDiagScheduleDiagnostic
                    (
                        DSLH_DIAGNOSTIC_TYPE_Upload,
                        (ANSC_HANDLE)pUploadInfo
                    );

    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        UploadDiagnostics_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
UploadDiagnostics_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject        = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadInfo      = pMyObject->hDiagUploadInfo;
    PDSLH_TR143_UPLOAD_DIAG_INFO    pUploadPreInfo   = NULL;
    errno_t rc = -1;

    if ( !pUploadInfo )
    {
        return ANSC_STATUS_FAILURE;
    }

    DslhInitUploadDiagInfo(pUploadInfo);

    pUploadPreInfo = (PDSLH_TR143_UPLOAD_DIAG_INFO)CosaDmlDiagGetConfigs
                        (
                            DSLH_DIAGNOSTIC_TYPE_Upload
                        );

    if ( pUploadPreInfo )
    {
        rc = strcpy_s(pUploadInfo->Interface, sizeof(pUploadInfo->Interface) , pUploadPreInfo->Interface);
        ERR_CHK(rc);
        rc = strcpy_s(pUploadInfo->UploadURL, sizeof(pUploadInfo->UploadURL) , pUploadPreInfo->UploadURL);
        ERR_CHK(rc);
        pUploadInfo->DSCP                 = pUploadPreInfo->DSCP;
        pUploadInfo->EthernetPriority     = pUploadPreInfo->EthernetPriority;
        pUploadInfo->TestFileLength       = pUploadPreInfo->TestFileLength;
        pUploadInfo->DiagnosticsState     = pUploadPreInfo->DiagnosticsState;
    }
    else
    {
        AnscTraceWarning(("Upload Diagnostics---Failed to get previous configuration!\n"));
    }

    return 0;
}


/***********************************************************************

 APIs for Object:

    IP.Diagnostics.UDPEchoConfig.

    *  UDPEchoConfig_GetParamBoolValue
    *  UDPEchoConfig_GetParamIntValue
    *  UDPEchoConfig_GetParamUlongValue
    *  UDPEchoConfig_GetParamStringValue
    *  UDPEchoConfig_SetParamBoolValue
    *  UDPEchoConfig_SetParamIntValue
    *  UDPEchoConfig_SetParamUlongValue
    *  UDPEchoConfig_SetParamStringValue
    *  UDPEchoConfig_Validate
    *  UDPEchoConfig_Commit
    *  UDPEchoConfig_Rollback

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UDPEchoConfig_GetParamBoolValue
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
UDPEchoConfig_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = pMyObject->hDiagUdpechoSrvInfo;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Enable") == 0)
    {
        if ( pUdpEchoInfo )
        {
            *pBool = pUdpEchoInfo->Enable;
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get Enable \n!"));
            *pBool = FALSE;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "EchoPlusEnabled") == 0)
    {
        if ( pUdpEchoInfo )
        {
            *pBool = pUdpEchoInfo->EchoPlusEnabled;
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get EchoPlusEnabled \n!"));
            *pBool = FALSE;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "EchoPlusSupported") == 0)
    {
        if ( pUdpEchoInfo )
        {
            *pBool = pUdpEchoInfo->EchoPlusSupported;
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get EchoPlusSupported \n!"));
            *pBool = FALSE;
            return FALSE;
        }

        return TRUE;
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UDPEchoConfig_GetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int*                        pInt
            );

    description:

        This function is called to retrieve integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int*                        pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
UDPEchoConfig_GetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int*                        pInt
    )
{
    /* check the parameter name and return the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UDPEchoConfig_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
UDPEchoConfig_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = pMyObject->hDiagUdpechoSrvInfo;
    PDSLH_UDP_ECHO_SERVER_STATS     pUdpEchoStats = NULL;

    /* check the parameter name and return the corresponding value */

    if (strcmp(ParamName, "UDPPort") == 0)
    {
        if ( pUdpEchoInfo )
        {
            *puLong = pUdpEchoInfo->UDPPort;
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get UDPPort \n!"));
            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "PacketsReceived") == 0)
    {
        pUdpEchoStats = (PDSLH_UDP_ECHO_SERVER_STATS)CosaDmlDiagGetResults
                        (
                            DSLH_DIAGNOSTIC_TYPE_UdpEcho
                        );

        if ( pUdpEchoStats )
        {
            *puLong = pUdpEchoStats->PacketsReceived;
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get PacketsReceived\n!"));

            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "PacketsResponded") == 0)
    {
        pUdpEchoStats = (PDSLH_UDP_ECHO_SERVER_STATS)CosaDmlDiagGetResults
                        (
                            DSLH_DIAGNOSTIC_TYPE_UdpEcho
                        );

        if ( pUdpEchoStats )
        {
            *puLong = pUdpEchoStats->PacketsResponded;
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get PacketsResponded\n!"));

            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }

    if (strcmp(ParamName, "BytesReceived") == 0)
    {
        if ( pUdpEchoInfo && pUdpEchoInfo->Enable)
        {
            pUdpEchoStats = (PDSLH_UDP_ECHO_SERVER_STATS)CosaDmlDiagGetResults
                        (
                            DSLH_DIAGNOSTIC_TYPE_UdpEcho
                        );

            if ( pUdpEchoStats )
            {
                *puLong = pUdpEchoStats->BytesReceived;
            }
            else
            {
                AnscTraceWarning(("UDP echo Diagnostics---Failed to get BytesReceived\n!"));

                *puLong = 0;
                return FALSE;
           }
        }  else 
        {
              AnscTraceWarning(("UDP echo Diagnostics---Not enabled\n!"));
        }
        return TRUE;
    }

    if (strcmp(ParamName, "BytesResponded") == 0)
    {
        pUdpEchoStats = (PDSLH_UDP_ECHO_SERVER_STATS)CosaDmlDiagGetResults
                        (
                            DSLH_DIAGNOSTIC_TYPE_UdpEcho
                        );

        if ( pUdpEchoStats )
        {
            *puLong = pUdpEchoStats->BytesResponded;
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get BytesResponded\n!"));

            *puLong = 0;
            return FALSE;
        }

        return TRUE;
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        UDPEchoConfig_GetParamStringValue
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
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
UDPEchoConfig_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = pMyObject->hDiagUdpechoSrvInfo;
    PDSLH_UDP_ECHO_SERVER_STATS     pUdpEchoStats = NULL;
    PANSC_UNIVERSAL_TIME            pTime         = NULL;
    char                            pBuf[128]     = { 0 };
    errno_t                         rc            = -1;


    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Interface") == 0)
    {
        if ( pUdpEchoInfo )
        {
            rc = strcpy_s(pValue, *pUlSize , pUdpEchoInfo->Interface);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get Interface\n!"));
            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "SourceIPAddress") == 0)
    {
        if ( pUdpEchoInfo )
        {
            rc = strcpy_s(pValue, *pUlSize , pUdpEchoInfo->SourceIPName);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get SourceIPAddress \n!"));
            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "TimeFirstPacketReceived") == 0)
    {
        pUdpEchoStats = (PDSLH_UDP_ECHO_SERVER_STATS)CosaDmlDiagGetResults
                            (
                                DSLH_DIAGNOSTIC_TYPE_UdpEcho
                            );

        if ( pUdpEchoStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pUdpEchoStats->TimeFirstPacketReceived;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }
            rc = strcpy_s(pValue, *pUlSize , pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get TimeFirstPacketReceived\n!"));

            return -1;
        }

        return 0;
    }

    if (strcmp(ParamName, "TimeLastPacketReceived") == 0)
    {
        pUdpEchoStats = (PDSLH_UDP_ECHO_SERVER_STATS)CosaDmlDiagGetResults
                            (
                                DSLH_DIAGNOSTIC_TYPE_UdpEcho
                            );

        if ( pUdpEchoStats )
        {
            pTime = (PANSC_UNIVERSAL_TIME)&pUdpEchoStats->TimeLastPacketReceived;

            rc = sprintf_s
            (
                pBuf, sizeof(pBuf),
                "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d.%.3d000",
                pTime->Year,
                pTime->Month,
                pTime->DayOfMonth,
                pTime->Hour,
                pTime->Minute,
                pTime->Second,
                pTime->MilliSecond
            );
            if(rc < EOK)
            {
                ERR_CHK(rc);
            }

            rc = strcpy_s(pValue, *pUlSize , pBuf);
            ERR_CHK(rc);
        }
        else
        {
            AnscTraceWarning(("UDP echo Diagnostics---Failed to get TimeLastPacketReceived\n!"));

            return -1;
        }

        return 0;
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UDPEchoConfig_SetParamBoolValue
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
BOOL
UDPEchoConfig_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = pMyObject->hDiagUdpechoSrvInfo;

    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "Enable") == 0)
    {
        pUdpEchoInfo->Enable = bValue;
        return TRUE;
    }

    if (strcmp(ParamName, "EchoPlusEnabled") == 0)
    {
        pUdpEchoInfo->EchoPlusEnabled = bValue;
        return TRUE;
    }

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UDPEchoConfig_SetParamIntValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                int                         iValue
            );

    description:

        This function is called to set integer parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                int                         iValue
                The updated integer value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
UDPEchoConfig_SetParamIntValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        int                         iValue
    )
{
    /* check the parameter name and set the corresponding value */

    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UDPEchoConfig_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
UDPEchoConfig_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = pMyObject->hDiagUdpechoSrvInfo;
    
    /* check the parameter name and set the corresponding value */

    if (strcmp(ParamName, "UDPPort") == 0)
    {
        if ( uValue == 0 )
        {
            return FALSE;
        }

        pUdpEchoInfo->UDPPort = uValue;
        return TRUE;
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UDPEchoConfig_SetParamStringValue
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
BOOL
UDPEchoConfig_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = pMyObject->hDiagUdpechoSrvInfo;
    errno_t rc = -1;


    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "Interface") == 0)
    {
        rc = strcpy_s(pUdpEchoInfo->Interface, sizeof(pUdpEchoInfo->Interface) , pString);
        ERR_CHK(rc);
        return TRUE;
    }

    if (strcmp(ParamName, "SourceIPAddress") == 0)
    {
        rc = strcpy_s(pUdpEchoInfo->SourceIPName, sizeof(pUdpEchoInfo->SourceIPName) , pString);
        ERR_CHK(rc);
        return TRUE;
    }


    /* AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        UDPEchoConfig_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
UDPEchoConfig_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = pMyObject->hDiagUdpechoSrvInfo;
    char*                           pAddrName     = NULL;
    errno_t rc = -1;

    if (AnscSizeOfString(pUdpEchoInfo->Interface))    
    {
        pAddrName = CosaGetInterfaceAddrByName(pUdpEchoInfo->Interface);
        if (_ansc_strcmp(pAddrName, "::"))
        {
            rc = strcpy_s(pUdpEchoInfo->IfAddrName, sizeof(pUdpEchoInfo->IfAddrName) ,pAddrName);
            ERR_CHK(rc);
            AnscFreeMemory(pAddrName);
        }
        else
        {
            rc = strcpy_s(pReturnParamName, *puLength ,"Interface");
            ERR_CHK(rc);
            AnscFreeMemory(pAddrName);
            return FALSE;  
        }
    }
    else
    {
        rc = strcpy_s(pUdpEchoInfo->IfAddrName, sizeof(pUdpEchoInfo->IfAddrName) ,"::");
        ERR_CHK(rc);
    }


    if ( pUdpEchoInfo->EchoPlusEnabled && !pUdpEchoInfo->EchoPlusSupported )
    {
        rc = strcpy_s(pReturnParamName, *puLength , "EchoPlusEnabled");
        ERR_CHK(rc);
        return FALSE;
    }

    if ( pUdpEchoInfo->Enable && (strlen(pUdpEchoInfo->SourceIPName) == 0) )
    {
        rc = strcpy_s(pReturnParamName, *puLength , "SourceIPAddress");
        ERR_CHK(rc);
        return FALSE;
    }

    if ( pUdpEchoInfo->Enable && (pUdpEchoInfo->UDPPort == 0) )
    {
        rc = strcpy_s(pReturnParamName, *puLength , "UDPPort");
        ERR_CHK(rc);
        return FALSE;
    }

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        UDPEchoConfig_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
UDPEchoConfig_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject     = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo  = pMyObject->hDiagUdpechoSrvInfo;

    CosaDmlDiagScheduleDiagnostic
                (
                    DSLH_DIAGNOSTIC_TYPE_UdpEcho,
                    (ANSC_HANDLE)pUdpEchoInfo
                );

    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        UDPEchoConfig_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
UDPEchoConfig_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PCOSA_DATAMODEL_DIAG            pMyObject       = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoInfo    = pMyObject->hDiagUdpechoSrvInfo;
    PDSLH_TR143_UDP_ECHO_CONFIG     pUdpEchoPreInfo = NULL;

    if ( !pUdpEchoInfo )
    {
        return ANSC_STATUS_FAILURE;
    }

    DslhInitUDPEchoConfig(pUdpEchoInfo);

    pUdpEchoPreInfo = (PDSLH_TR143_UDP_ECHO_CONFIG)CosaDmlDiagGetConfigs
                    (
                        DSLH_DIAGNOSTIC_TYPE_UdpEcho
                    );

    if ( pUdpEchoPreInfo )
    {
        errno_t rc = -1;
        rc = strcpy_s(pUdpEchoInfo->Interface, sizeof(pUdpEchoInfo->Interface) ,pUdpEchoPreInfo->Interface);
        ERR_CHK(rc);
        pUdpEchoInfo->Enable               = pUdpEchoPreInfo->Enable;
        rc = strcpy_s(pUdpEchoInfo->SourceIPName, sizeof(pUdpEchoInfo->SourceIPName) ,pUdpEchoPreInfo->SourceIPName);
        ERR_CHK(rc);
        pUdpEchoInfo->UDPPort              = pUdpEchoPreInfo->UDPPort;
        pUdpEchoInfo->EchoPlusEnabled      = pUdpEchoPreInfo->EchoPlusEnabled;
        pUdpEchoInfo->EchoPlusSupported    = pUdpEchoPreInfo->EchoPlusSupported;
    }
    else
    {
        AnscTraceWarning(("UDP echo Diagnostics---Failed to get previous configuration!\n"));
    }

    return 0;
}
#endif

/***********************************************************************


 APIs for Object:

    IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.

    *  SpeedTest_GetParamBoolValue
    *  SpeedTest_GetParamBoolValue
    *  SpeedTest_GetParamStringValue
    *  SpeedTest_SetParamStringValue
    *  SpeedTest_GetParamUlongValue
    *  SpeedTest_SetParamUlongValue
  
***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SpeedTest_GetParamBoolValue
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
SpeedTest_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Enable_Speedtest") == 0)
    {
	    AnscTraceFlow(("%s Enable_Speedtest : %d\n",  __FUNCTION__, g_enable_speedtest));
	    *pBool = g_enable_speedtest;
	    return TRUE;
    } else
    if (strcmp(ParamName, "Run") == 0)
    {
	    AnscTraceFlow(("%s Speedtest Run : %d \n", __FUNCTION__, g_run_speedtest));
	    *pBool = g_run_speedtest;
	    return TRUE;
    } else
    	AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SpeedTest_SetParamBoolValue
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
BOOL
SpeedTest_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "Enable_Speedtest") == 0)
    {
        AnscTraceFlow(("%s Enable Speedtest : %d \n", __FUNCTION__, bValue));
        g_enable_speedtest = bValue;
        return TRUE;
    }
    else if (strcmp(ParamName, "Run") == 0)
    {
        AnscTraceFlow(("%s Run Speedtest : %d \n",__FUNCTION__, bValue));
        g_run_speedtest = bValue;
        return TRUE;
    }

    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName)); 
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SpeedTest_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
SpeedTest_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
	
    if ( g_enable_speedtest == FALSE && g_run_speedtest == TRUE )
    {
        errno_t rc = -1;
        rc = strcpy_s(pReturnParamName,  *puLength ,"Run");
        ERR_CHK(rc);
        g_run_speedtest = FALSE;
        return FALSE; 
    }

    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        SpeedTest_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
SpeedTest_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    char previous[8];

    syscfg_get(NULL, "enable_speedtest", previous, sizeof(previous));

    if (strcmp(previous, g_enable_speedtest ? "true" : "false") != 0)
    {
        if (syscfg_set_commit(NULL, "enable_speedtest", g_enable_speedtest ? "true" : "false") != 0)
        {
            AnscTraceWarning(("%s syscfg_set failed  for Enable_Speedtest\n",__FUNCTION__));
            return 1;
        }
    }

    if ((g_enable_speedtest == TRUE) && (g_run_speedtest == TRUE))
    {
        AnscTraceFlow(("Executing Speedtest..\n"));
        v_secure_system("/usr/ccsp/tad/speedtest.sh &");
        g_run_speedtest = FALSE;
    }

    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        SpeedTest_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
SpeedTest_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    char buf[128] = {0} ;

    if((syscfg_get( NULL, "enable_speedtest", buf, sizeof(buf)) == 0 ) && (buf[0] != '\0') )
    {
            g_enable_speedtest = (!strcmp(buf, "true")) ? TRUE : FALSE;
    }

    g_run_speedtest = FALSE;

    return 0;
}

/***********************************************************************


 APIs for Object:

    IP.Diagnostics.X_RDK_SpeedTest.

    *  RDK_SpeedTest_GetParamUlongValue
    *  RDK_SpeedTest_SetParamUlongValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RDK_SpeedTest_GetParamUlongValue
            (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    )

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      pUlong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.


**********************************************************************/
BOOL
RDK_SpeedTest_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    )
{
/*Need to add _SCER11BEL_PRODUCT_REQ_ only if we see log flooding in TDMlog.txt.0, like  RDKB-50881 */

#if !defined(_SR213_PRODUCT_REQ_) && !defined (_WNXL11BWL_PRODUCT_REQ_)//SHARMAN-1777 and LTE-2347
    char TO_buf[4]={0};
    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "SubscriberUnPauseTimeOut") == 0)
    {
            if((syscfg_get( NULL, "Speedtest_SubUnPauseTimeOut", TO_buf, sizeof(TO_buf)) == 0 ) && (TO_buf[0] != '\0') )
            {
                *pUlong = atoi(TO_buf);
                return TRUE;
            }
            else
            {
                AnscTraceWarning(("!!! %s syscfg_get SubscriberUnPauseTimeOut Failed \n", __FUNCTION__));
            }
    }
    else
    {
        AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    }
#else
    *pUlong = 0;
    return TRUE;
#endif
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RDK_SpeedTest_SetParamUlongValue
            (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       ulong
    );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                      ulong
                The updated ULONG value;

    return:     TRUE if succeeded.


**********************************************************************/

BOOL
RDK_SpeedTest_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       ulong
    )
{
    if (strcmp(ParamName, "SubscriberUnPauseTimeOut") == 0)
    {
        AnscTraceFlow(("%s SubscriberUnPauseTimeOut value : %lu \n",__FUNCTION__, ulong));
        if (ulong >= 1 && ulong <= 180 )
        {
            if (syscfg_set_u_commit(NULL, "Speedtest_SubUnPauseTimeOut", ulong) != 0)
            {
                AnscTraceWarning(("%s syscfg_set failed\n",__FUNCTION__));
            }
            return TRUE;
        }
        else
        {
            AnscTraceWarning(("%s Invalid Timeout Range '%lu'\n",__FUNCTION__, ulong));
            return FALSE;
        }
    }
    else
    {
        AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    }

    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        SpeedTest_GetParamStringValue
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
                Usually size of 256 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
SpeedTest_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    int len = strlen(g_argument_speedtest);
    FILE *filePtr = NULL;
    char strClientVersionBuf[512] = {0};
    int  byteCount = 0;
    errno_t rc = -1;
    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Argument") == 0)
    {
        if (  *pUlSize > SPEEDTEST_ARG_SIZE )
        {
		AnscTraceFlow(("SpeedTest Argument get : %s : len :%d: *pUlSize:%lu: \n",g_argument_speedtest,len,*pUlSize));
		/******   SafeC has a limitation of changes not more than 4k. 
		 * Here size of g_argument_speedtest is approx 4k. So no changes has  been done******/
		AnscCopyString(pValue, g_argument_speedtest);
		return 0;
        } else
	{
		AnscTraceWarning(("SpeedTest Argument get :  Incorrect size: %s: current_string_size:%d:  size of buffer :%lu: \n",g_argument_speedtest,len, *pUlSize));

                *pUlSize = SPEEDTEST_ARG_SIZE+1;
		return 1;

	}
    }
    else if (strcmp(ParamName, "Authentication") == 0)
    {
        if (  *pUlSize > SPEEDTEST_AUTH_SIZE )
        {
                AnscTraceFlow(("SpeedTest Authentication get : %s : len :%d: *pUlSize:%lu: \n",g_authentication_speedtest,len,*pUlSize));
                /******   SafeC has a limitation of changes not more than 4k. 
                * Here size of g_authentication_speedtest is approx 4k. So no changes has  been done******/
                AnscCopyString(pValue, g_authentication_speedtest);
                return 0;
        } else
        {
                AnscTraceWarning(("SpeedTest Authentication get :  Incorrect size: %s: current_string_size:%d:  size of buffer :%lu: \n",g_authentication_speedtest,len, *pUlSize));

                *pUlSize = SPEEDTEST_AUTH_SIZE+1;
                return 1;

        }
    }
    else if (strcmp(ParamName, "ClientVersion") == 0)
    {
        if (!strcmp(g_clientversion_speedtest,""))
        {
            filePtr = fopen(SPEEDTEST_VERSION_LOG_FILE, "r");
            if (filePtr != NULL)
            {
                byteCount = fread(strClientVersionBuf, 1, (sizeof(strClientVersionBuf) - 1), filePtr);
                strClientVersionBuf[byteCount-1] = '\0';
            }
            else
            {
                AnscTraceFlow(( "<%s> syscfg_get failed to parse log file for ClientVersion\n", __FUNCTION__ ));
                return 1;
            }
            if (!strcmp(strClientVersionBuf, ""))
            {
                AnscTraceWarning(("%s syscfg_get failed ClientVersion is set to Null \n",__FUNCTION__));
		fclose(filePtr); //CID: 175400 Resource leak
                return 1;
            }
            else
            {
                char *token = strtok(strClientVersionBuf, " \n");
                while( token != NULL )
                {
                    if(!strcmp(token,"version:"))
                    {
                        rc = strcpy_s(strClientVersionBuf, sizeof(strClientVersionBuf) ,token+9);
                        ERR_CHK(rc);
                        if( strClientVersionBuf[strlen(strClientVersionBuf)-1] == '\n' )
                        {
                            strClientVersionBuf[strlen(strClientVersionBuf)-1] = '\0';
                        }
                        break;
                    }
                    token = strtok(NULL, " \n");
                }
                rc = strcpy_s(g_clientversion_speedtest, sizeof(g_clientversion_speedtest) ,strClientVersionBuf);
                ERR_CHK(rc);
                rc = strcpy_s(pValue, *pUlSize , g_clientversion_speedtest);
                ERR_CHK(rc);
		fclose(filePtr); //CID: 175400 Resource leak
                return 0;
            }
        }
        else
        {
            rc = strcpy_s(pValue, *pUlSize , g_clientversion_speedtest);
            ERR_CHK(rc);
	    /* CID 175410: Unchecked return value from library */
            if (remove(SPEEDTEST_VERSION_LOG_FILE) !=0)
	    {
		AnscTraceWarning(("removing file is failed \n"));
            }
            return 0;
        }
    }
    else
    {
        AnscTraceWarning(("SpeedTest Argument/Authentication/ClientVersion get :Unsupported parameter '%s'\n", ParamName));
        return -1;
    }
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SpeedTest_SetParamStringValue
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
BOOL
SpeedTest_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    int len = strlen(pString);
    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "Argument") == 0)
    {
	if ( len <= (SPEEDTEST_ARG_SIZE ) ){
		AnscTraceFlow(("SpeedTest Argument set : %s : string len : %d: \n",pString,len));
		/******   SafeC has a limitation of changes not more than 4k. 
		 * Here size of both  g_argument_speedtest &  g_authentication_speedtest are of approx 4k.
		  So no changes has  been done******/
		AnscCopyString(g_argument_speedtest, pString);
		return TRUE;
	} else
	{
		AnscTraceWarning(("SpeedTest Argument set : string too long:  %s : string len : %d: \n",pString,len));
		return FALSE;
	}
    }
    else if (strcmp(ParamName, "Authentication") == 0)
    {
        if ( len <= (SPEEDTEST_AUTH_SIZE ) ){
                AnscTraceFlow(("SpeedTest Authentication set : %s : string len : %d: \n",pString,len));
                AnscCopyString(g_authentication_speedtest, pString);
                return TRUE;
        } else
        {
                AnscTraceWarning(("SpeedTest Authentication set : string too long:  %s : string len : %d: \n",pString,len));
                return FALSE;
        }
    } else
    {
     AnscTraceWarning(("SpeedTest Argument/Authentication set : Unsupported parameter '%s'\n", ParamName));
    }
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
	SpeedTest_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    )

    description:

        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      pUlong
                The buffer of returned ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
SpeedTest_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    )
{
    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "ClientType") == 0)
    {
            AnscTraceFlow(("%s ClientType SpeedTest : %d\n",  __FUNCTION__, g_clienttype_speedtest));
            *pUlong = g_clienttype_speedtest;
            return TRUE;
    } else
    if (strcmp(ParamName, "Status") == 0)
    {
            //AnscTraceFlow(("%s Status Speedtest : %d \n", __FUNCTION__, g_status_speedtest));
            *pUlong = g_status_speedtest;
            return TRUE;
    }
    else
        AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
	SpeedTest_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       ulong
    );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                      ulong
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SpeedTest_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       ulong
    )
{
    /* check the parameter name and set the corresponding value */
    if (strcmp(ParamName, "ClientType") == 0)
    {
        AnscTraceFlow(("%s ClientType Speedtest : %lu \n", __FUNCTION__, ulong));
        g_clienttype_speedtest = ulong;
        return TRUE;
    }
    else if (strcmp(ParamName, "Status") == 0)
    {
        AnscTraceFlow(("%s Status Speedtest : %lu \n",__FUNCTION__, ulong));
        g_status_speedtest = ulong;
        return TRUE;
    }
    else
    	AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}



BOOL
SpeedTestServer_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
	PCOSA_DATAMODEL_DIAG		pMyObject 	= (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
	PCOSA_DML_DIAG_SPEEDTEST_SERVER 	pSpeedTestServer		= (PCOSA_DML_DIAG_SPEEDTEST_SERVER)pMyObject->pSpeedTestServer;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Capability") == 0)
    {
		*pBool = 	pSpeedTestServer->Capability ;		
		return TRUE;
    }

    return FALSE;
}



ULONG
SpeedTestServer_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
	PCOSA_DATAMODEL_DIAG		pMyObject 	= (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
	PCOSA_DML_DIAG_SPEEDTEST_SERVER 	pSpeedTestServer		= (PCOSA_DML_DIAG_SPEEDTEST_SERVER)pMyObject->pSpeedTestServer;
	errno_t rc = -1;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "Key") == 0)
    {    
		rc = strcpy_s(pValue, *pUlSize ,pSpeedTestServer->Key);
		ERR_CHK(rc);
		return 0;
	}

	if (strcmp(ParamName, "Username") == 0)
	{
		rc = strcpy_s(pValue, *pUlSize , pSpeedTestServer->Username);
		ERR_CHK(rc);
		return 0;
	}

	if (strcmp(ParamName, "Password") == 0)
	{
		rc = strcpy_s(pValue, *pUlSize ,pSpeedTestServer->Password);
		ERR_CHK(rc);
		return 0;
	}

    return -1;
}


BOOL
SpeedTestServer_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
	PCOSA_DATAMODEL_DIAG		pMyObject 	= (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
	PCOSA_DML_DIAG_SPEEDTEST_SERVER 	pSpeedTestServer		= (PCOSA_DML_DIAG_SPEEDTEST_SERVER)pMyObject->pSpeedTestServer;

	int len = strlen(pString);
	errno_t rc = -1;

  /* check the parameter name and set the corresponding value */
	if (strcmp(ParamName, "Key") == 0)
	{
		if(len < SPEEDTEST_SERVER_KEY_SIZE)
		{
			rc = strcpy_s(pSpeedTestServer->Key, sizeof(pSpeedTestServer->Key) , pString);
			ERR_CHK(rc);
			return TRUE;
		}
		else
        {
              AnscTraceWarning(("SpeedTest Server Key set : string too long:  %s : string len : %d: \n",pString,len));
              return FALSE;
        }
	}
	
	if (strcmp(ParamName, "Username") == 0)
	{	
		if(len <= SPEEDTEST_SERVER_USERNAME_PASS_SIZE)
		{
			rc = strcpy_s(pSpeedTestServer->Username, sizeof(pSpeedTestServer->Username) , pString);
			ERR_CHK(rc);
			pSpeedTestServer->Username[len] = '\0'; //CID 74640: Out-of-bounds write
			return TRUE;
		}		
		else
        {
              AnscTraceWarning(("SpeedTest Server User Name set : string too long:  %s : string len : %d: \n",pString,len));
              return FALSE;
        }
	}
	
	
	if (strcmp(ParamName, "Password") == 0)
	{		
		if(len <= SPEEDTEST_SERVER_USERNAME_PASS_SIZE)
		{
			rc = strcpy_s(pSpeedTestServer->Password, sizeof(pSpeedTestServer->Password) ,pString);
			ERR_CHK(rc);
			pSpeedTestServer->Password[len] = '\0'; //CID 59296: Out-of-bounds write
			return TRUE;
		}		
		else
        {
              AnscTraceWarning(("SpeedTest Server Password set : string too long:  %s : string len : %d: \n",pString,len));
              return FALSE;
        }
	}
	
return FALSE;

}

#ifdef EMMC_DIAG_SUPPORT
ULONG
eMMCFlashDiag_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    int ret = 0;
    eSTMGRDeviceInfo DeviceInfo ;
    eSTMGRHealthInfo* pHealthInfo = (eSTMGRHealthInfo*)malloc(sizeof(eSTMGRHealthInfo));
    if (!pHealthInfo) {
        CcspTraceError(("Memory allocation failed for HealthInfo\n"));
        return 1;
    }

    memset(&DeviceInfo, 0, sizeof(DeviceInfo));
    memset(pHealthInfo, 0, sizeof(eSTMGRHealthInfo));

    ret = CcspHalEmmcGetHealthInfo (pHealthInfo);
    if (ret != 0)
    {
        CcspTraceError(("CcspHalEmmcGetHealthInfo returned with error %d\n", ret));
        free(pHealthInfo);
        return 1;
    }

    ret = CcspHalEmmcGetDeviceInfo (&DeviceInfo);
    if (ret != 0)
    {
        CcspTraceError(("CcspHalEmmcGetDeviceInfo returned with error %d\n", ret));
        return 1;
    }

    if (strcmp(ParamName, "Manufacturer") == 0)
    {
        AnscCopyString( pValue, DeviceInfo.m_manufacturer );
        *pUlSize = AnscSizeOfString( DeviceInfo.m_manufacturer);
    }

    else if (strcmp(ParamName, "FirmwareVersion") == 0)
    {
        AnscCopyString( pValue, DeviceInfo.m_firmwareVersion);
        *pUlSize = AnscSizeOfString( DeviceInfo.m_firmwareVersion );
    }

    else if (strcmp(ParamName, "DeviceID") == 0)
    {
        AnscCopyString( pValue, DeviceInfo.m_deviceID);
        *pUlSize = AnscSizeOfString( DeviceInfo.m_deviceID );
    }

    else if (strcmp(ParamName, "SerialNumber") == 0)
    {
        AnscCopyString( pValue, DeviceInfo.m_serialNumber);
        *pUlSize = AnscSizeOfString( DeviceInfo.m_serialNumber );
    }

    else if (strcmp(ParamName, "Model") == 0)
    {
        AnscCopyString( pValue, DeviceInfo.m_model);
        *pUlSize = AnscSizeOfString( DeviceInfo.m_model );
    }

    else if (strcmp(ParamName, "HwVersion") == 0)
    {
        AnscCopyString( pValue, DeviceInfo.m_hwVersion);
        *pUlSize = AnscSizeOfString( DeviceInfo.m_hwVersion );
    }

    else if (strcmp(ParamName, "Capacity") == 0)
    {
        if (DeviceInfo.m_capacity == 0)
        {
            pValue = NULL;
        }
        else
        {
            snprintf(pValue, 128,"%llu",DeviceInfo.m_capacity);
        }
    }

    else if (strcmp(ParamName, "LifeElapsedA") == 0)
    {
        AnscCopyString( pValue, pHealthInfo->m_lifetimesList.m_diagnostics[0].m_value );
        *pUlSize = AnscSizeOfString( pHealthInfo->m_lifetimesList.m_diagnostics[0].m_value );
    }

    else if (strcmp(ParamName, "LifeElapsedB") == 0)
    {
        AnscCopyString( pValue, pHealthInfo->m_lifetimesList.m_diagnostics[1].m_value );
        *pUlSize = AnscSizeOfString( pHealthInfo->m_lifetimesList.m_diagnostics[1].m_value );
    }

    else if (strcmp(ParamName, "PreEOLStateEUDA") == 0)
    {
        AnscCopyString( pValue, pHealthInfo->m_healthStatesList.m_diagnostics[1].m_value );
        *pUlSize = AnscSizeOfString( pHealthInfo->m_healthStatesList.m_diagnostics[1].m_value );
    }

    else if (strcmp(ParamName, "PreEOLStateSystem") == 0)
    {
        AnscCopyString( pValue, pHealthInfo->m_healthStatesList.m_diagnostics[0].m_value );
        *pUlSize = AnscSizeOfString( pHealthInfo->m_healthStatesList.m_diagnostics[0].m_value );
    }

    else if (strcmp(ParamName, "PreEOLStateMLC") == 0)
    {
        AnscCopyString( pValue, pHealthInfo->m_healthStatesList.m_diagnostics[2].m_value );
        *pUlSize = AnscSizeOfString( pHealthInfo->m_healthStatesList.m_diagnostics[2].m_value );
    }

    else if (strcmp(ParamName, "DeviceTemperature") == 0)
    {
        AnscCopyString( pValue, pHealthInfo->m_healthStatesList.m_diagnostics[3].m_value );
        *pUlSize = AnscSizeOfString( pHealthInfo->m_healthStatesList.m_diagnostics[3].m_value );
    }

    else if (strcmp(ParamName, "UncorrectableECC") == 0)
    {
        AnscCopyString( pValue, pHealthInfo->m_healthStatesList.m_diagnostics[4].m_value );
        *pUlSize = AnscSizeOfString( pHealthInfo->m_healthStatesList.m_diagnostics[4].m_value );
    }

    else
    {
        CcspTraceError(("Requested parameter not available as part of emmc diag\n"));
        return -1;
    }
    free(pHealthInfo);
    return 0;
}

BOOL
eMMCFlashDiag_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    int ret = 0;

    eSTMGRHealthInfo* pHealthInfo = (eSTMGRHealthInfo*)malloc(sizeof(eSTMGRHealthInfo));
    if (!pHealthInfo) {
        CcspTraceError(("Memory allocation failed\n"));
        return FALSE;
    }
    memset(pHealthInfo, 0, sizeof(eSTMGRHealthInfo));

    
    ret = CcspHalEmmcGetHealthInfo(pHealthInfo);
    if (ret != 0)
    {
        CcspTraceError(("CcspHalEmmcGetHealthInfo returned with error %d\n", ret));
        free(pHealthInfo);
        return FALSE;
    }
    if (strcmp(ParamName, "Operational") == 0)
    {
        *pBool = pHealthInfo->m_isOperational;
        free(pHealthInfo);
        return TRUE;
    }
    else if (strcmp(ParamName, "Healthy") == 0)
    {
        *pBool = pHealthInfo->m_isHealthy;
        free(pHealthInfo);
        return TRUE;
    }
    free(pHealthInfo);
    return FALSE;
}
#endif

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        X_RDKCENTRAL-COM_RxTxStats_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue
            );

    description:

        This function is called to retrieve string parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue
                The string value buffer;

    return:     0 if succeeded;
                1 unable to read results file;

**********************************************************************/
ULONG
X_RDKCENTRAL_COM_RxTxStats_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(pUlSize);
    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;
    errno_t                         rc           = -1;
    int                             ind          = -1;

    rc = strcmp_s("InterfaceList", strlen("InterfaceList"), ParamName, &ind );
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        /* collect value */
        rc = strcpy_s(pValue, sizeof(pRxTXStats->Interfacelist), pRxTXStats->Interfacelist);
        if (rc != EOK)
        {
            ERR_CHK(rc);
            return -1;
        }
        *pUlSize = AnscSizeOfString(pValue);
        return 0;
    }

    rc = strcmp_s("PortList", strlen("PortList"), ParamName, &ind );
    ERR_CHK(rc);
    if((!ind) && (rc == EOK))
    {
        /* collect value */
        rc = strcpy_s(pValue, sizeof(pRxTXStats->Portlist), pRxTXStats->Portlist);
        if (rc != EOK)
        {
            ERR_CHK(rc);
            return -1;
        }
        *pUlSize = AnscSizeOfString(pValue);
        return 0;
    }

    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return 1;
}

BOOL
X_RDKCENTRAL_COM_RxTxStats_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{

    UNREFERENCED_PARAMETER(pUlSize);
    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;
    errno_t                    rc           = -1;

    /* check the parameter name and return the corresponding value */
    if (strcmp(ParamName, "InterfaceList") == 0)
    {
        rc = memset_s(pRxTXStats->Interfacelist, sizeof(pRxTXStats->Interfacelist), 0, sizeof(pRxTXStats->Interfacelist));
        ERR_CHK(rc);
        rc = strcpy_s(pRxTXStats->Interfacelist, sizeof(pRxTXStats->Interfacelist), pValue);
        ERR_CHK(rc);
        CcspTraceInfo(("[%s] SET RxTx Stats Interfacelist:[ %s ]\n",__FUNCTION__,pRxTXStats->Interfacelist));
        return TRUE;
    }

    if (strcmp(ParamName, "PortList") == 0)
    {
        rc = memset_s(pRxTXStats->Portlist, sizeof(pRxTXStats->Portlist), 0, sizeof(pRxTXStats->Portlist));
        ERR_CHK(rc);
        rc = strcpy_s(pRxTXStats->Portlist, sizeof(pRxTXStats->Portlist), pValue);
        ERR_CHK(rc);
        CcspTraceInfo(("[%s] SET RxTx Stats Portlist:[ %s ]\n",__FUNCTION__,pRxTXStats->Portlist));
        return TRUE;
    }

    AnscTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        X_RDKCENTRAL_COM_RxTxStats_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation.

                ULONG*                      puLength
                The output length of the param name.

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
X_RDKCENTRAL_COM_RxTxStats_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        X_RDKCENTRAL_COM_RxTxStats_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
X_RDKCENTRAL_COM_RxTxStats_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{

    char Interfacelist[RXTX_INTFLIST_SZ]={0};
    char Portlist[RXTX_PORTLIST_SZ]={0};
    errno_t rc = -1;

    PCOSA_DATAMODEL_DIAG        pMyObject   = (PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag;
    PCOSA_DML_DIAG_RXTX_STATS     pRxTXStats   = (PCOSA_DML_DIAG_RXTX_STATS) pMyObject->pRxTxStats;

    if (syscfg_set_commit(NULL, "rxtxstats_interface_list", pRxTXStats->Interfacelist) != 0)
    {
        AnscTraceWarning(("%s syscfg_set failed  for Rx stats interface list\n",__FUNCTION__));
        /*Rollback to previous value if any*/
        if((syscfg_get( NULL, "rxtxstats_interface_list", Interfacelist, sizeof(Interfacelist)) == 0)
                && (Interfacelist[0] != '\0') )
        {
            AnscTraceWarning(("%s Roll back Interfacelist to previous value %s\n",__FUNCTION__,Interfacelist));
            rc = strcpy_s(pRxTXStats->Interfacelist, sizeof(pRxTXStats->Interfacelist), Interfacelist);
            ERR_CHK(rc);
        }
        return 1;
    }

    if (syscfg_set_commit(NULL, "rxtxstats_port_list", pRxTXStats->Portlist) != 0)
    {
        AnscTraceWarning(("%s syscfg_set failed  for Rx stats port list\n",__FUNCTION__));
        /*Rollback to previous value if any*/
        if((syscfg_get( NULL, "rxtxstats_port_list", Portlist, sizeof(Portlist)) == 0)
                && (Portlist[0] != '\0') )
        {
            AnscTraceWarning(("%s Roll back Portlist to previous value %s\n",__FUNCTION__,Portlist));
            rc = strcpy_s(pRxTXStats->Portlist, sizeof(pRxTXStats->Portlist), Portlist);
            ERR_CHK(rc);
        }
        return 1;
    }

    return 0;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        SpeedTest_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
X_RDKCENTRAL_COM_RxTxStats_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return 0;
}

