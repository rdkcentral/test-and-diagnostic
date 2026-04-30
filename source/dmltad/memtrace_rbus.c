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

rbusError_t MemTrace_GetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t MemTrace_SetBoolHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);

rbusHandle_t g_rbusHandle;
#define MT_COMPONENT_NAME "MemTraceEnableRbus"
#define MT_NUM_OF_RBUS_PARAMS  sizeof(memtrace_RbusDataElements)/sizeof(memtrace_RbusDataElements[0])

rbusDataElement_t memtrace_RbusDataElements[] = {
    {"Device.Diagnostics.MemTrace.Enable", RBUS_ELEMENT_TYPE_PROPERTY, {MemTrace_GetBoolHandler, MemTrace_SetBoolHandler, NULL, NULL, NULL, NULL}},
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
                if (syscfg_set_commit(NULL, "MemTrace_Enable", "1") != 0) {
                    CcspTraceWarning(("%s: Failed to set MemTrace_Enable in syscfg db\n", __FUNCTION__));
                    return FALSE;
                }
                CcspTraceInfo(("%s: Starting memtraced service\n", __FUNCTION__));
                ret = v_secure_system("systemctl start memtraced");
                if(ret != 0)
                {
                      CcspTraceWarning(("%s - Failed to start memtraced service\n", __FUNCTION__));
                      return FALSE;
                }
                else
                {
                    CcspTraceInfo(("%s: memtraced service started\n", __FUNCTION__));
                    return TRUE;
                }
            }
        }
        else
        {
            if (syscfg_set_commit(NULL, "MemTrace_Enable", "0") != 0) {
                CcspTraceWarning(("%s: Failed to set MemTrace_Enable in syscfg db\n", __FUNCTION__));
                return FALSE;
            }
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

            CcspTraceInfo(("%s: memtraced service stopped\n", __FUNCTION__));
            return TRUE;
        }
    }
    return FALSE;
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
