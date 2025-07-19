#include <stdio.h>
#include "cosa_warehousediag_rbus_apis.h"
#include "cosa_warehousediag_rbus_handler_apis.h"

// Define WHDIAG_EXTENDED_DML_SUPPORT macro to experiment with additional WHDIAG DMLs
// #define WHDIAG_EXTENDED_DML_SUPPORT

extern rbusHandle_t rbus_handle_whd;

rbusDataElement_t WarehouseDiag_Feature_RbusDataElements[] =
{
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Enable", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Enable", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Enable", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Status", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Status", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Status", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LTE.Status", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LTE.Imei", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LTE.Iccid", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LTE.FirmwareVersion", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.Enable", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Fan.Speed", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Fan.State", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.Enable", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.Color", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.State", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.SSID", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.SSID", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.SSID", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.BSSID", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.BSSID", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.BSSID", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, NULL, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Password", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Password", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Password", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
#ifdef WHDIAG_EXTENDED_DML_SUPPORT
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.Interval", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Bandwidth", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Bandwidth", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Bandwidth", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Sideband", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.Mode", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.TransmitChannel", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.TransmitLength", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.TransmitPattern", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
#endif
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Channel", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Channel", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} },
    { "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Channel", RBUS_ELEMENT_TYPE_PROPERTY, {WAREHOUSEDIAG_GetHandler, WAREHOUSEDIAG_SetHandler, NULL, NULL, NULL, NULL} }
};

rbusError_t WAREHOUSEDIAG_Reg_Elements()
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    int rc = RBUS_ERROR_SUCCESS;

    if(RBUS_ENABLED == rbus_checkStatus())
    {
        CcspTraceInfo(("RBUS enabled, Proceed with Warehouse Diagnostics rbus registration\n"));
    }
    else
    {
        CcspTraceError(("RBUS is NOT ENABLED, Can't Proceed with Warehouse Diagnostics rbus registration\n"));
        return RBUS_ERROR_BUS_ERROR;
    }
    if (rbus_handle_whd == NULL)
    {
        rc = rbus_open(&rbus_handle_whd, "WarehouseDiagnostics");
        if (rc != RBUS_ERROR_SUCCESS)
        {
            rbus_handle_whd = NULL;
            CcspTraceError(("rbus initialization failed\n"));
            rc = RBUS_ERROR_NOT_INITIALIZED;
            return rc;
        }
    }
    if (rbus_handle_whd != NULL)
    {
        rc = rbus_regDataElements(rbus_handle_whd, ARRAY_SZ(WarehouseDiag_Feature_RbusDataElements), WarehouseDiag_Feature_RbusDataElements);
        if (rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("rbus register data elements failed\n"));
            return rc;
        }
    }
    return rc;
}

rbusError_t WAREHOUSEDIAG_UnReg_Elements()
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    int rc = RBUS_ERROR_SUCCESS;

    if (rbus_handle_whd != NULL)
    {
        rc = rbus_unregDataElements(rbus_handle_whd, ARRAY_SZ(WarehouseDiag_Feature_RbusDataElements), WarehouseDiag_Feature_RbusDataElements);
        if (rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("rbus unregister data elements failed\n"));
            return rc;
        }
        rc = rbus_close(rbus_handle_whd);
        rbus_handle_whd = NULL;
        if (rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceError(("rbus close failed\n"));
            return rc;
        }
    }
    return rc;
}
