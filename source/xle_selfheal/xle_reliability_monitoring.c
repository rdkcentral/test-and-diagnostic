/*********************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
******************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <rbus/rbus.h>
#include "sysevent/sysevent.h"
#include "safec_lib_common.h"
#include "ccsp_psm_helper.h"
#include <ccsp_base_api.h>
#include "ccsp_memory.h"
#include <syscfg/syscfg.h>
#include "xle_reliability_monitoring.h"

rbusHandle_t g_rbusHandle;

extern int            sysevent_fd ;
extern token_t        sysevent_token;

rbusError_t xle_selfheal_rbus_init()
{
    int rc = RBUS_ERROR_SUCCESS;
    xle_log("[xle_self_heal] calling %s ...\n", __FUNCTION__);
    if(RBUS_ENABLED == rbus_checkStatus())
    {
        xle_log("[xle_self_heal] RBUS enabled \n");
    }
    else
    {
        xle_log("[xle_self_heal] RBUS is not initialised \n");
        return RBUS_ERROR_BUS_ERROR;
    }

    rc = rbus_open(&g_rbusHandle, XLE_SELFHEAL_COMP);
    if (rc != RBUS_ERROR_SUCCESS)
    {
        xle_log("[xle_self_heal] RBUS Initialization failed\n");
        rc = RBUS_ERROR_NOT_INITIALIZED;
        return rc;
    }
    xle_log("[xle_self_heal] RBUS Initialization success\n");
    return rc;
}

int rbus_getStringValue(char* value, char* path)
{
    int rc = 0;
    rbusValue_t strVal = NULL;

    xle_log("[xle_self_heal] %s: calling rbus get for %s\n", __FUNCTION__, path);

    rc = rbus_get(g_rbusHandle, path, &strVal);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        xle_log("[xle_self_heal] rbus_get failed for [%s] with error [%d]\n", path, rc);
        if(strVal != NULL)
        {
            rbusValue_Release(strVal);
        }
        return 1;
    }

    snprintf(value, 128, (char *)rbusValue_GetString(strVal, NULL));
    xle_log("[xle_self_heal] value of %s is %s\n", path, value);
    rbusValue_Release(strVal);
    return 0;
}

int rbus_setStringValue(char* value, char* path)
{
    int rc = 0;
    rbusValue_t strVal;

    xle_log("[xle_self_heal] %s: calling rbus get for %s\n", __FUNCTION__, path);
    rbusValue_Init(&strVal);
    rbusValue_SetString(strVal, value);
    rc = rbus_set(g_rbusHandle, path, strVal, NULL);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        xle_log("[xle_self_heal] rbus_get failed for [%s] with error [%d]\n", path, rc);
        if(strVal != NULL)
        {
            rbusValue_Release(strVal);
        }
        return 1;
    }

    snprintf(value, 128, (char *)rbusValue_GetString(strVal, NULL));
    xle_log("[xle_self_heal] value of %s is %s\n", path, value);
    rbusValue_Release(strVal);
    return 0;
}

int rbus_getUInt32Value(ULONG* value, char* path)
{
    int rc = 0;
    rbusValue_t uintVal = NULL;

    xle_log("[xle_self_heal] %s: calling rbus get for %s\n", __FUNCTION__, path);

    rc = rbus_get(g_rbusHandle, path, &uintVal);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        xle_log("[xle_self_heal] rbus_get failed for [%s] with error [%d]\n",  path, rc);
        if(uintVal != NULL)
        {
            rbusValue_Release(uintVal);
        }
        return 1;
    }

    *value = rbusValue_GetUInt32(uintVal);
    xle_log("[xle_self_heal] value of %s is %lu\n", path, *value);
    rbusValue_Release(uintVal);
    return 0;
}

//create /tmp/.ntp_tried_timesyncfromGW when device ntpd is restarted once to sync from primary gateway
void create_ntp_restart_File()
{
    // Attempt to create the file
    FILE *fd = fopen(NTP_STARTED_ONCE_GW_TIMESYNC, "wx");
    if (fd != NULL) {
        // File created successfully
        fclose(fd);
        xle_log("[xle_self_heal] File %s created successfully\n", NTP_STARTED_ONCE_GW_TIMESYNC);
    } else {
        // File already exists or another error occurred
        if (errno == EEXIST) {
            xle_log("[xle_self_heal] File %s already exists\n", NTP_STARTED_ONCE_GW_TIMESYNC);
        } else {
            xle_log("[xle_self_heal] Failed to create %s file\n", NTP_STARTED_ONCE_GW_TIMESYNC);
        }
    }
}


int ntpd_selfheal_sync_primary() {
    FILE *fp;
    char buffer[128] = {0};
    unsigned long uptime_seconds = 0;

    // Open the /proc/uptime file
    fp = fopen("/proc/uptime", "r");
    if (fp == NULL) {
        xle_log("[xle_self_heal] Error opening /proc/uptime");
        return 1;
    }
    // Read the uptime in seconds
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        sscanf(buffer, "%lu", &uptime_seconds);
    }
    fclose(fp);

    // Check if uptime is greater than 10 minutes (600 seconds)
    if (uptime_seconds > 600) {
        xle_log("[xle_self_heal] uptime is greater than 10 minutes, proceeding with ntpd selfheal\n");
        FILE *file = fopen(TIME_SYNC_FROM_LTE, "r");
        if (file != NULL) {
            xle_log("[xle_self_heal] %s file exists\n", TIME_SYNC_FROM_LTE);
            fclose(file);
            sysevent_set(sysevent_fd, sysevent_token, "ntpd-syncTimeFromPrimary", "", 0);
            xle_log("[xle_self_heal] time synced from LTE. Do not sync time from Primary GW \n");
        } else {
            xle_log("[xle_self_heal] %s file is also not found , syncing time from primary gateway\n",TIME_SYNC_FROM_LTE);
            sysevent_set(sysevent_fd, sysevent_token, "ntpd-syncTimeFromPrimary", "syncfromPrimaryGateway", 0);
        }
	create_ntp_restart_File();
        sysevent_set(sysevent_fd, sysevent_token, "ntpd-restart", "", 0);
    } else {
        xle_log("[xle_self_heal] Uptime is less than 10 minutes\n");
        xle_log("[xle_self_heal] Skipping ntpd selfheal\n");
    }
    return 0;
}

