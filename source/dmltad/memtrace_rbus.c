#include <rbus/rbus.h>
#include "safec_lib_common.h"
#include "ccsp_trace.h"
#include "ansc_platform.h"
#include <secure_wrapper.h>
#include <syscfg/syscfg.h>

#define BUF_64 64

char const* GetParamName(char const* path)
{
    char const* p = path + strlen(path);
    while(p > path && *(p-1) != '.')
        p--;
    return p;
}

rbusError_t MemTraceRbusInit(void);
bool ReadProcessListFromBucketStatus(const char* color, char* outBuf, size_t outBufSize);

BOOL MemTrace_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       bValue
    );
BOOL MemTrace_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    );
BOOL
MemTrace_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    );
BOOL
MemTrace_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    );
ULONG
MemTrace_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    );

rbusError_t MemTrace_GetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t MemTrace_GetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t MemTrace_SetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);
rbusError_t MemTrace_GetUlongHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t MemTrace_SetUlongHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);

rbusHandle_t g_rbusHandle;
#define MT_COMPONENT_NAME "MemTraceRbus"
#define MT_NUM_OF_RBUS_PARAMS  sizeof(memtrace_RbusDataElements)/sizeof(memtrace_RbusDataElements[0])

rbusDataElement_t memtrace_RbusDataElements[] = {
    {"Device.Diagnostics.MemTrace.Enable", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetBoolHandler, MemTrace_SetBoolHandler, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.Interval", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetUlongHandler, MemTrace_SetUlongHandler, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.RSSThreshold", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetUlongHandler, MemTrace_SetUlongHandler, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.InitialSnapshotUptime", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetUlongHandler, MemTrace_SetUlongHandler, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.ProcessesInCodeGreen", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetStringHandler, NULL, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.ProcessesInCodeYellow", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetStringHandler, NULL, NULL, NULL, NULL, NULL}},
    {"Device.Diagnostics.MemTrace.ProcessesInCodeRed", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetStringHandler, NULL, NULL, NULL, NULL, NULL}},
};

rbusError_t MemTraceRbusInit()
{
    int rc = RBUS_ERROR_SUCCESS;
    CcspTraceDebug(("In %s\n", __FUNCTION__));
    if(RBUS_ENABLED == rbus_checkStatus())
    {
        CcspTraceInfo(("RBUS enabled, Proceed with MemTrace\n"));
    }
    else
    {
        CcspTraceError(("RBUS is NOT ENABLED, Can't Proceed with MemTrace\n"));
        return RBUS_ERROR_BUS_ERROR;
    }

    rc = rbus_open(&g_rbusHandle, MT_COMPONENT_NAME);
    if (rc != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("MemTrace RBUS Initialization failed\n"));
        rc = RBUS_ERROR_NOT_INITIALIZED;
        return rc;
    }

    // Register data elements
    rc = rbus_regDataElements(g_rbusHandle, MT_NUM_OF_RBUS_PARAMS, memtrace_RbusDataElements);

    if (rc != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("MemTrace rbus register data elements failed\n"));
        rc = rbus_close(g_rbusHandle);
        return rc;
    }
    CcspTraceDebug(("Out %s\n", __FUNCTION__));
    return rc;
}

/**
 * @brief Reads the process list for a given bucket color from /tmp/bucket_status.txt.
 *
 * This function opens the `/tmp/bucket_status.txt` file, searches for a line starting
 * with the specified `color` followed by a colon (e.g., "RED:pid1,pid2,pid3"), and
 * copies the associated process list into the provided output buffer.
 *
 * @param[in]  color       The color name (e.g., "RED", "GREEN", "BLUE") to search for in the status file.
 * @param[out] outBuf      Pointer to the output buffer where the resulting process list will be stored.
 * @param[in]  outBufSize  The size of the output buffer in bytes. The resulting string will be null-terminated.
 *
 * @return
 * - `1` if the matching color is found and the process list is successfully written to `outBuf`.
 * - `0` if the file cannot be opened or the matching color is not found.
 *
 * @note
 * - The `/tmp/bucket_status.txt` file is expected to have lines in the format:
 *   @code
 *   RED:proc1,proc2,proc3
 *   GREEN:proc4,proc5
 *   @endcode
 * - If the process list exceeds `outBufSize - 1` characters, it will be truncated.
 * - Trailing newline characters in the file are removed from the stored process list.
 *
 * @warning
 * - Ensure `outBuf` is a valid pointer and `outBufSize` is sufficient to store the expected process list.
 * - Thread safety is not guaranteed. If multiple threads call this function, external synchronization is needed.
 */

bool ReadProcessListFromBucketStatus(const char* color, char* outBuf, size_t outBufSize)
{
    FILE* fp = fopen("/tmp/bucket_status.txt", "r");
    if (!fp) {
        return false;
    }
    char line[4096];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, color, strlen(color)) == 0 && line[strlen(color)] == ':') {
            // Found the line for the color
            char* processes = line + strlen(color) + 1; // Skip "COLOR:"
            // Remove trailing newline if present
            size_t len = strlen(processes);
            if (len > 0 && processes[len - 1] == '\n') {
                processes[len - 1] = '\0';
            }
            strncpy(outBuf, processes, outBufSize - 1);
            outBuf[outBufSize - 1] = '\0';
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

/**********************************************************************
    caller:     owner of this object
    prototype
        BOOL
        MemTrace_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       bValue
            );
    description:
        This function is called to retrieve BOOL parameter value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                BOOL*                       bValue
                The buffer of returned BOOL value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL MemTrace_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       bValue
    )
{
    char res[BUF_64] = {0};
    if ( strcmp(ParamName, "Enable") == 0 )
    {
        if(syscfg_get(NULL, "MemTrace_Enable", res, sizeof(res)) != 0) {
            CcspTraceWarning(("%s: Failed to get MemTrace_Enable from syscfg db\n", __FUNCTION__));
            return FALSE;
        }
        if (res[0] == '1')
            *bValue = TRUE;
        else
            *bValue = FALSE;

        return TRUE;
    }
    return FALSE;
}

/**********************************************************************
    caller:     owner of this object
    prototype
        BOOL
        MemTrace_SetParamBoolValue
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
                The buffer of returned BOOL value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL MemTrace_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    int ret = 0;
    if ( strcmp(ParamName, "Enable") == 0 )
    {
        if ( bValue )
        {
            char buf[2] = {0};
            if ( syscfg_get(NULL, "MemTrace_Enable", buf, sizeof(buf)) == 0 && buf[0] == '1' )
            {
                CcspTraceInfo(("%s: MemTrace is already enabled\n", __FUNCTION__));
                return TRUE;
            }
            else
            {
                CcspTraceInfo(("%s: Starting memtraced service\n", __FUNCTION__));
                ret = v_secure_system("systemctl start memtraced");
                if(ret != 0)
                {
                      CcspTraceWarning(("%s - Failed to start memtraced service\n", __FUNCTION__));
                      return FALSE;
                }
                else
                {
                    if (syscfg_set_commit(NULL, "MemTrace_Enable", "1") != 0) {
                        CcspTraceWarning(("%s: Failed to set MemTrace_Enable in syscfg db\n", __FUNCTION__));
                        return FALSE;
                    }
                    CcspTraceInfo(("%s: memtraced service started\n", __FUNCTION__));
                    return TRUE;
                }
            }
        }
        else
        {
            // Disable and stop MemTrace
            CcspTraceInfo(("%s: Stopping memtraced service\n", __FUNCTION__));

            // Stop the monitoring script
            ret = v_secure_system("systemctl stop memtraced");
            if(ret != 0)
            {
                CcspTraceWarning(("%s - Failed to stop memtraced service\n",__FUNCTION__ ));
            }

            // Clean up bucket status file
            v_secure_system("rm -f /tmp/bucket_status.txt");

            if (syscfg_set_commit(NULL, "MemTrace_Enable", "0") != 0) {
                CcspTraceWarning(("%s: Failed to set MemTrace_Enable in syscfg db\n", __FUNCTION__));
                return FALSE;
            }

            CcspTraceInfo(("%s: memtraced service stopped\n", __FUNCTION__));
            return TRUE;
        }
    }
    return FALSE;
}

/**********************************************************************
    caller:     owner of this object
    prototype
        BOOL
        MemTrace_GetParamUlongValue
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
MemTrace_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    char res[BUF_64] = {0};
    char *ptr = NULL;
    if( (strcmp(ParamName, "Interval") == 0) || (strcmp(ParamName, "RSSThreshold") == 0) || (strcmp(ParamName, "InitialSnapshotUptime") == 0) )
    {
        if (strcmp(ParamName, "Interval") == 0) {
            if(syscfg_get(NULL, "MemTrace_Interval", res, sizeof(res)) != 0) {
                CcspTraceWarning(("%s: Failed to get MemTrace_Interval from syscfg db\n", __FUNCTION__));
                return FALSE;
            }
        }
        else if (strcmp(ParamName, "RSSThreshold") == 0) {
            if(syscfg_get(NULL, "MemTrace_RSSThreshold", res, sizeof(res)) != 0) {
                CcspTraceWarning(("%s: Failed to get MemTrace_RSSThreshold from syscfg db\n", __FUNCTION__));
                return FALSE;
            }
        }
        else if (strcmp(ParamName, "InitialSnapshotUptime") == 0) {
            if(syscfg_get(NULL, "MemTrace_InitialSnapshotUptime", res, sizeof(res)) != 0) {
                CcspTraceWarning(("%s: Failed to get MemTrace_InitialSnapshotUptime from syscfg db\n", __FUNCTION__));
                return FALSE;
            }
        }
        *puLong = strtoul(res, &ptr, 10);
        return TRUE;
    }
    return FALSE;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        BOOL
        MemTrace_SetParamUlongValue
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
MemTrace_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    if( (strcmp(ParamName, "Interval") == 0) || (strcmp(ParamName, "RSSThreshold") == 0) || (strcmp(ParamName, "InitialSnapshotUptime") == 0) )
    {
        char res[24] = {0};
        snprintf(res, sizeof(res), "%lu", uValue);
        if (strcmp(ParamName, "Interval") == 0) {
            if (syscfg_set_commit(NULL, "MemTrace_Interval", res) != 0) {
                CcspTraceWarning(("%s: Failed to set MemTrace_Interval in syscfg db\n", __FUNCTION__));
                return FALSE;
            }
            CcspTraceInfo(("%s - setting Interval of %s seconds\n", __FUNCTION__, res));
            v_secure_system("systemctl restart memtraced");
        }
        else if (strcmp(ParamName, "RSSThreshold") == 0) {
            if (syscfg_set_commit(NULL, "MemTrace_RSSThreshold", res) != 0) {
                CcspTraceWarning(("%s: Failed to set MemTrace_RSSThreshold in syscfg db\n", __FUNCTION__));
                return FALSE;
            }
            CcspTraceInfo(("%s - setting RSSThreshold of %s kB\n", __FUNCTION__, res));
            v_secure_system("systemctl restart memtraced");
        }
        else if (strcmp(ParamName, "InitialSnapshotUptime") == 0) {
            if (syscfg_set_commit(NULL, "MemTrace_InitialSnapshotUptime", res) != 0) {
                CcspTraceWarning(("%s: Failed to set MemTrace_InitialSnapshotUptime in syscfg db\n", __FUNCTION__));
                return FALSE;
            }
            CcspTraceInfo(("%s - setting InitialSnapshotUptime of %s seconds\n", __FUNCTION__, res));
        }
    }
    else
    {
        return FALSE;
    }
    return TRUE;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        BOOL
        MemTrace_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );
    description:
        This function is called to get string value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pValue,
                The parameter value;
                ULONG                       pUlSize
                The string length;
    return:     ULONG Size of the returned string.
**********************************************************************/
ULONG
MemTrace_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    (void) hInsContext;
    // Check if MemTrace is enabled
    // Only return process lists if the feature is actually running
    char enableCheck[BUF_64] = {0};
    BOOL isEnabled = FALSE;

    if(syscfg_get(NULL, "MemTrace_Enable", enableCheck, sizeof(enableCheck)) != 0) {
        CcspTraceWarning(("%s: Failed to get MemTrace_Enable from syscfg db\n", __FUNCTION__));
        isEnabled = FALSE;
    }
    atoi(enableCheck) == 1 ? (isEnabled = TRUE) : (isEnabled = FALSE);

    // If not enabled, return empty string
    if (!isEnabled)
    {
        CcspTraceInfo(("%s: MemTrace is disabled, returning empty process list\n", __FUNCTION__));
        if (pValue)
        {
            *pValue = '\0';
        }
        return 1;
    }

    // Feature is enabled, read from bucket status file
    if (strcmp(ParamName, "ProcessesInCodeYellow") == 0) {
        if (ReadProcessListFromBucketStatus("YELLOW", pValue, *pUlSize)) {
            return 0;
        }
    } else if (strcmp(ParamName, "ProcessesInCodeGreen") == 0) {
        if (ReadProcessListFromBucketStatus("GREEN", pValue, *pUlSize)) {
            return 0;
        }
    } else if (strcmp(ParamName, "ProcessesInCodeRed") == 0) {
        if (ReadProcessListFromBucketStatus("RED", pValue, *pUlSize)) {
            return 0;
        }
    } else {
        CcspTraceWarning(("%s - MemTrace has no bucket list\n", __FUNCTION__));
        return 1;
    }
    return 1;
}

rbusError_t MemTrace_GetStringHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    CcspTraceDebug(("In %s\n", __FUNCTION__));
    errno_t rc = 0;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val;
    char value[4096] = {0};
    unsigned long ulSize = sizeof(value);

    CcspTraceInfo(("Called %s for [%s]\n", __FUNCTION__, propName));

    rbusValue_Init(&val);

    rc = MemTrace_GetParamStringValue(NULL, param, value, &ulSize);
    free(param);
    if(rc != 0)
    {
        CcspTraceError(("[%s]: MemTrace_GetParamStringValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_SetString(val, value);
    rbusProperty_SetValue(property, val);
    rbusValue_Release(val);
    CcspTraceDebug(("Out %s\n", __FUNCTION__));
    return RBUS_ERROR_SUCCESS;
}

rbusError_t MemTrace_GetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    BOOL rc = FALSE;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    BOOL value = FALSE;
    rbusValue_t val;

    if (!param)
    {
        CcspTraceError(("[%s]: failed to allocate param name\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_Init(&val);
    rc = MemTrace_GetParamBoolValue(NULL, param, &value);
    free(param);
    if(rc != TRUE)
    {
        rbusValue_Release(val);
        CcspTraceError(("[%s]: MemTrace_GetParamBoolValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_SetBoolean(val, value ? true : false);
    rbusProperty_SetValue(property, val);
    rbusValue_Release(val);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t MemTrace_SetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    BOOL rc = FALSE;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val = rbusProperty_GetValue(property);
    BOOL bValue = FALSE;

    if (!param || !val)
    {
        free(param);
        CcspTraceError(("[%s]: invalid input for bool set\n", __FUNCTION__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    bValue = rbusValue_GetBoolean(val) ? TRUE : FALSE;
    rc = MemTrace_SetParamBoolValue(NULL, param, bValue);
    free(param);
    if(rc != TRUE)
    {
        CcspTraceError(("[%s]: MemTrace_SetParamBoolValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }
    return RBUS_ERROR_SUCCESS;
}

rbusError_t MemTrace_GetUlongHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    BOOL rc = FALSE;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    ULONG value = 0;
    rbusValue_t val;

    if (!param)
    {
        CcspTraceError(("[%s]: failed to allocate param name\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_Init(&val);
    rc = MemTrace_GetParamUlongValue(NULL, param, &value);
    free(param);
    if(rc != TRUE)
    {
        rbusValue_Release(val);
        CcspTraceError(("[%s]: MemTrace_GetParamUlongValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusValue_SetUInt32(val, (uint32_t)value);
    rbusProperty_SetValue(property, val);
    rbusValue_Release(val);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t MemTrace_SetUlongHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    BOOL rc = FALSE;
    char const* propName = rbusProperty_GetName(property);
    char* param = strdup(GetParamName(propName));
    rbusValue_t val = rbusProperty_GetValue(property);
    ULONG value = 0;

    if (!param || !val)
    {
        free(param);
        CcspTraceError(("[%s]: invalid input for ulong set\n", __FUNCTION__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    value = (ULONG)rbusValue_GetUInt32(val);
    rc = MemTrace_SetParamUlongValue(NULL, param, value);
    free(param);
    if(rc != TRUE)
    {
        CcspTraceError(("[%s]: MemTrace_SetParamUlongValue failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    return RBUS_ERROR_SUCCESS;
}
