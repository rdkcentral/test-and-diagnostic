#include "cosa_warehousediag_rbus_apis.h"
#include "cosa_warehousediag_rbus_handler_apis.h"

extern PWAREHOUSE_DIAG_GLOBAL_CTXT_INFO g_pWarehouseDiag;

rbusError_t WAREHOUSEDIAG_GetHandler(rbusHandle_t handle, rbusProperty_t property,
                                                        rbusGetHandlerOptions_t* opts)
{
    char const* name;
    rbusValue_t value;
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    errno_t rc = -1;
    LEDColor color;
    LEDState state;
    int bright;
    int interval;

    rbusValue_Init(&value);

    name = rbusProperty_GetName(property);
    CcspTraceInfo(("Inside %s with name %s\n", __FUNCTION__, name));
    if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Enable") == 0)
    {
        rbusValue_SetBoolean(value, g_pWarehouseDiag->WiFi_2_4gEnable);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Enable") == 0)
    {
        rbusValue_SetBoolean(value, g_pWarehouseDiag->WiFi_5glEnable);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Enable") == 0)
    {
        rbusValue_SetBoolean(value, g_pWarehouseDiag->WiFi_5ghEnable);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Status") == 0)
    {
        get_wifi_bss(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gStatus);
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_2_4gStatus);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Status") == 0)
    {
        get_wifi_bss(WIFI_5G_LOW, g_pWarehouseDiag->WiFi_5glStatus);
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_5glStatus);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Status") == 0)
    {
        get_wifi_bss(WIFI_5G_HIGH, g_pWarehouseDiag->WiFi_5ghStatus);
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_5ghStatus);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LTE.Status") == 0)
    {
        getLTEStatus(g_pWarehouseDiag->LTEStatus);
        rbusValue_SetString(value, g_pWarehouseDiag->LTEStatus);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LTE.Imei") == 0)
    {
        getLTEImei(g_pWarehouseDiag->LTEImei);
        rbusValue_SetString(value, g_pWarehouseDiag->LTEImei);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LTE.Iccid") == 0)
    {
        getLTEIccid(g_pWarehouseDiag->LTEIccid);
        rbusValue_SetString(value, g_pWarehouseDiag->LTEIccid);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LTE.FirmwareVersion") == 0)
    {
        getLTEFirmwareVersion(g_pWarehouseDiag->LTEFirmwareVersion);
        rbusValue_SetString(value, g_pWarehouseDiag->LTEFirmwareVersion);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.Enable") == 0)
    {
        rbusValue_SetBoolean(value, g_pWarehouseDiag->BluetoothEnable);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Fan.Speed") == 0)
    {
        g_pWarehouseDiag->FanSpeed = getFanSpeed();
        rbusValue_SetUInt32(value, g_pWarehouseDiag->FanSpeed);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Fan.State") == 0)
    {
        rc = strcpy_s(g_pWarehouseDiag->FanState, sizeof(g_pWarehouseDiag->FanState), getFanState());
        ERR_CHK(rc);
        rbusValue_SetString(value, g_pWarehouseDiag->FanState);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.Enable") == 0)
    {
        rbusValue_SetBoolean(value, g_pWarehouseDiag->LEDEnable);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.Color") == 0)
    {
        if (g_pWarehouseDiag->LEDEnable)
        {
            if (getLed(&color, &bright, &state, &interval) == 0)
            {
                rc = strcpy_s(g_pWarehouseDiag->LEDColor, sizeof(g_pWarehouseDiag->LEDColor), getLEDColorName(color));
                ERR_CHK(rc);
            }
            else
            {
                CcspTraceError(("%s: getLed Failed\n", __FUNCTION__));
            }
        }
        rbusValue_SetString(value, g_pWarehouseDiag->LEDColor);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.State") == 0)
    {
        if (g_pWarehouseDiag->LEDEnable)
        {
            if (getLed(&color, &bright, &state, &interval) == 0)
            {
                rc = strcpy_s(g_pWarehouseDiag->LEDState, sizeof(g_pWarehouseDiag->LEDState), getLEDStateName(state));
                ERR_CHK(rc);
            }
            else
            {
                CcspTraceError(("%s: getLed Failed\n", __FUNCTION__));
            }
        }
        rbusValue_SetString(value, g_pWarehouseDiag->LEDState);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.Interval") == 0)
    {
        if (g_pWarehouseDiag->LEDEnable)
        {
            if (getLed(&color, &bright, &state, &interval) == 0)
            {
                if (state == BLINK)
                {
                    g_pWarehouseDiag->LEDInterval = interval;
                }
            }
            else
            {
                CcspTraceError(("%s: getLed Failed\n", __FUNCTION__));
            }
        }
        rbusValue_SetUInt32(value, g_pWarehouseDiag->LEDInterval);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.SSID") == 0)
    {
        if (g_pWarehouseDiag->WiFi_2_4gEnable)
        {
            get_wifi_ssid(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID);
        }
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_2_4gSSID);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.SSID") == 0)
    {
        if (g_pWarehouseDiag->WiFi_5glEnable)
        {
            get_wifi_ssid(WIFI_5G_LOW, g_pWarehouseDiag->WiFi_5glSSID);
        }
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_5glSSID);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.SSID") == 0)
    {
        if (g_pWarehouseDiag->WiFi_5ghEnable)
        {
            get_wifi_ssid(WIFI_5G_HIGH, g_pWarehouseDiag->WiFi_5ghSSID);
        }
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_5ghSSID);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.BSSID") == 0)
    {
        get_wifi_bssid(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gBSSID);
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_2_4gBSSID);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.BSSID") == 0)
    {
        get_wifi_bssid(WIFI_5G_LOW, g_pWarehouseDiag->WiFi_5glBSSID);
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_5glBSSID);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.BSSID") == 0)
    {
        get_wifi_bssid(WIFI_5G_HIGH, g_pWarehouseDiag->WiFi_5ghBSSID);
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_5ghBSSID);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Password") == 0)
    {
        if (g_pWarehouseDiag->WiFi_2_4gEnable)
        {
            get_wifi_psk(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gPassword);
        }
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_2_4gPassword);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Password") == 0)
    {
        if (g_pWarehouseDiag->WiFi_5glEnable)
        {
            get_wifi_psk(WIFI_5G_LOW, g_pWarehouseDiag->WiFi_5glPassword);
        }
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_5glPassword);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Password") == 0)
    {
        if (g_pWarehouseDiag->WiFi_5ghEnable)
        {
            get_wifi_psk(WIFI_5G_HIGH, g_pWarehouseDiag->WiFi_5ghPassword);
        }
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_5ghPassword);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Bandwidth") == 0)
    {
        rbusValue_SetUInt32(value, g_pWarehouseDiag->WiFi_2_4gBandwidth);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Bandwidth") == 0)
    {
        rbusValue_SetUInt32(value, g_pWarehouseDiag->WiFi_5glBandwidth);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Bandwidth") == 0)
    {
        rbusValue_SetUInt32(value, g_pWarehouseDiag->WiFi_5ghBandwidth);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Channel") == 0)
    {
        if (g_pWarehouseDiag->WiFi_2_4gEnable)
        {
            get_wifi_channel(WIFI_2_4G, &g_pWarehouseDiag->WiFi_2_4gChannel);
        }
        rbusValue_SetUInt32(value, g_pWarehouseDiag->WiFi_2_4gChannel);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Channel") == 0)
    {
        if (g_pWarehouseDiag->WiFi_5glEnable)
        {
            get_wifi_channel(WIFI_5G_LOW, &g_pWarehouseDiag->WiFi_5glChannel);
        }
        rbusValue_SetUInt32(value, g_pWarehouseDiag->WiFi_5glChannel);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Channel") == 0)
    {
        if (g_pWarehouseDiag->WiFi_5ghEnable)
        {
            get_wifi_channel(WIFI_5G_HIGH, &g_pWarehouseDiag->WiFi_5ghChannel);
        }
        rbusValue_SetUInt32(value, g_pWarehouseDiag->WiFi_5ghChannel);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Sideband") == 0)
    {
        rbusValue_SetString(value, g_pWarehouseDiag->WiFi_2_4gSideband);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.Mode") == 0)
    {
        rbusValue_SetString(value, g_pWarehouseDiag->BluetoothMode);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.TransmitChannel") == 0)
    {
        rbusValue_SetUInt32(value, g_pWarehouseDiag->BluetoothTransmitChannel);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.TransmitLength") == 0)
    {
        rbusValue_SetUInt32(value, g_pWarehouseDiag->BluetoothTransmitLength);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.TransmitPattern") == 0)
    {
        rbusValue_SetUInt32(value, g_pWarehouseDiag->BluetoothTransmitPattern);
    }
    else
    {
        ret = RBUS_ERROR_INVALID_INPUT;
    }
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return ret;
}

rbusError_t WAREHOUSEDIAG_SetHandler(rbusHandle_t handle, rbusProperty_t property,
                                                        rbusSetHandlerOptions_t* opts)
{
    char const* name;
    rbusValue_t value;
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    name = rbusProperty_GetName(property);
    value = rbusProperty_GetValue(property);
    CcspTraceInfo(("Inside %s with name %s\n", __FUNCTION__, name));
    if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Enable") == 0)
    {
        bool WiFi_2_4gEnable = rbusValue_GetBoolean(value);
        if (WiFi_2_4gEnable == g_pWarehouseDiag->WiFi_2_4gEnable)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->WiFi_2_4gEnable = WiFi_2_4gEnable;
        if (g_pWarehouseDiag->WiFi_2_4gEnable)
        {
            if (g_pWarehouseDiag->WiFi_2_4gBandwidth == 40)
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, g_pWarehouseDiag->WiFi_2_4gSideband[0]);
            }
            else
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, ' ');
            }
        }
        else
        {
            disableWiFi(WIFI_2_4G);
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Enable") == 0)
    {
        bool WiFi_5glEnable = rbusValue_GetBoolean(value);
        if (WiFi_5glEnable == g_pWarehouseDiag->WiFi_5glEnable)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->WiFi_5glEnable = WiFi_5glEnable;
        if (g_pWarehouseDiag->WiFi_5glEnable)
        {
            applyWiFiParameters(WIFI_5G_LOW, g_pWarehouseDiag->WiFi_5glSSID, g_pWarehouseDiag->WiFi_5glPassword, g_pWarehouseDiag->WiFi_5glChannel, g_pWarehouseDiag->WiFi_5glBandwidth, ' ');
        }
        else
        {
            disableWiFi(WIFI_5G_LOW);
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Enable") == 0)
    {
        bool WiFi_5ghEnable = rbusValue_GetBoolean(value);
        if (WiFi_5ghEnable == g_pWarehouseDiag->WiFi_5ghEnable)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->WiFi_5ghEnable = WiFi_5ghEnable;
        if (g_pWarehouseDiag->WiFi_5ghEnable)
        {
            applyWiFiParameters(WIFI_5G_HIGH, g_pWarehouseDiag->WiFi_5ghSSID, g_pWarehouseDiag->WiFi_5ghPassword, g_pWarehouseDiag->WiFi_5ghChannel, g_pWarehouseDiag->WiFi_5ghBandwidth, ' ');
        }
        else
        {
            disableWiFi(WIFI_5G_HIGH);
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.Enable") == 0)
    {
        bool BluetoothEnable = rbusValue_GetBoolean(value);
        if (BluetoothEnable == g_pWarehouseDiag->BluetoothEnable)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->BluetoothEnable = BluetoothEnable;
        if (g_pWarehouseDiag->BluetoothEnable)
        {
            if (strcmp(g_pWarehouseDiag->BluetoothMode, "TRANSMIT") == 0)
            {
                bleBeaconEnable(true);
                bleTransmitModeUpdate(g_pWarehouseDiag->BluetoothTransmitChannel, g_pWarehouseDiag->BluetoothTransmitLength, g_pWarehouseDiag->BluetoothTransmitPattern);
            }
            else if (strcmp(g_pWarehouseDiag->BluetoothMode, "BEACON") == 0)
            {
                bleBeaconEnable(false); // reset TRANSMIT mode
                bleBeaconEnable(true);
            }
        }
        else
        {
            bleBeaconEnable(false);
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Fan.Speed") == 0)
    {
        int FanSpeed = rbusValue_GetUInt32(value);
        if (FanSpeed < 0 || FanSpeed > MAX_BRIGHTNESS)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (FanSpeed == g_pWarehouseDiag->FanSpeed)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->FanSpeed = FanSpeed;
        setFanSpeed(g_pWarehouseDiag->FanSpeed);
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.Enable") == 0)
    {
        bool LEDEnable = rbusValue_GetBoolean(value);
        if (LEDEnable == g_pWarehouseDiag->LEDEnable)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->LEDEnable = LEDEnable;
        if (g_pWarehouseDiag->LEDEnable)
        {
            setLed(getLEDColor(g_pWarehouseDiag->LEDColor), MAX_BRIGHTNESS, getLEDState(g_pWarehouseDiag->LEDState), g_pWarehouseDiag->LEDInterval);
        }
        else
        {
            setLedOff();
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.Color") == 0)
    {
        const char* LEDColor = rbusValue_GetString(value, NULL);
        if ((strcmp(LEDColor, "RED") != 0) && (strcmp(LEDColor, "WHITE") != 0))
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        rc = strcmp_s(g_pWarehouseDiag->LEDColor, sizeof(g_pWarehouseDiag->LEDColor), LEDColor, &ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            return RBUS_ERROR_SUCCESS;
        }
        rc = strcpy_s(g_pWarehouseDiag->LEDColor, sizeof(g_pWarehouseDiag->LEDColor), LEDColor);
        ERR_CHK(rc);
        if (g_pWarehouseDiag->LEDEnable)
        {
            setLed(getLEDColor(g_pWarehouseDiag->LEDColor), MAX_BRIGHTNESS, getLEDState(g_pWarehouseDiag->LEDState), g_pWarehouseDiag->LEDInterval);
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.State") == 0)
    {
        const char* LEDState = rbusValue_GetString(value, NULL);
        if ((strcmp(LEDState, "SOLID") != 0) && (strcmp(LEDState, "BLINK") != 0))
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        rc = strcmp_s(g_pWarehouseDiag->LEDState, sizeof(g_pWarehouseDiag->LEDState), LEDState, &ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            return RBUS_ERROR_SUCCESS;
        }
        rc = strcpy_s(g_pWarehouseDiag->LEDState, sizeof(g_pWarehouseDiag->LEDState), LEDState);
        ERR_CHK(rc);
        if (g_pWarehouseDiag->LEDEnable)
        {
            setLed(getLEDColor(g_pWarehouseDiag->LEDColor), MAX_BRIGHTNESS, getLEDState(g_pWarehouseDiag->LEDState), g_pWarehouseDiag->LEDInterval);
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.LED.Interval") == 0)
    {
        int LEDInterval = rbusValue_GetUInt32(value);
        if (LEDInterval < 0)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (LEDInterval == g_pWarehouseDiag->LEDInterval)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->LEDInterval = LEDInterval;
        if (g_pWarehouseDiag->LEDEnable)
        {
            setLed(getLEDColor(g_pWarehouseDiag->LEDColor), MAX_BRIGHTNESS, getLEDState(g_pWarehouseDiag->LEDState), g_pWarehouseDiag->LEDInterval);
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.SSID") == 0)
    {
        const char* WiFi_2_4gSSID = rbusValue_GetString(value, NULL);
        if (strlen(WiFi_2_4gSSID) > MAX_SSID_LEN)
        {
            CcspTraceError(("%s: 2.4g SSID length exceeds maximum length\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (!isValidSSID(WiFi_2_4gSSID))
        {
            CcspTraceError(("%s: 2.4g SSID is empty or contains invalid special characters\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (preservedNameSSID(WiFi_2_4gSSID))
        {
            CcspTraceError(("%s: 2.4g SSID contains preserved names\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        rc = strcmp_s(g_pWarehouseDiag->WiFi_2_4gSSID, sizeof(g_pWarehouseDiag->WiFi_2_4gSSID), WiFi_2_4gSSID, &ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            CcspTraceInfo(("%s : 2.4g SSID is same as existing\n", __FUNCTION__));
            return RBUS_ERROR_SUCCESS;
        }
        rc = strcpy_s(g_pWarehouseDiag->WiFi_2_4gSSID, sizeof(g_pWarehouseDiag->WiFi_2_4gSSID), WiFi_2_4gSSID);
        ERR_CHK(rc);
        if (g_pWarehouseDiag->WiFi_2_4gEnable)
        {
            if (g_pWarehouseDiag->WiFi_2_4gBandwidth == 40)
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, g_pWarehouseDiag->WiFi_2_4gSideband[0]);
            }
            else
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, ' ');
            }
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.SSID") == 0)
    {
        const char* WiFi_5glSSID = rbusValue_GetString(value, NULL);
        if (strlen(WiFi_5glSSID) > MAX_SSID_LEN)
        {
            CcspTraceError(("%s: 5gl SSID length exceeds maximum length\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (!isValidSSID(WiFi_5glSSID))
        {
            CcspTraceError(("%s: 5gl SSID is empty or contains invalid special characters\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (preservedNameSSID(WiFi_5glSSID))
        {
            CcspTraceError(("%s: 5gl SSID contains preserved names\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        rc = strcmp_s(g_pWarehouseDiag->WiFi_5glSSID, sizeof(g_pWarehouseDiag->WiFi_5glSSID), WiFi_5glSSID, &ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            CcspTraceInfo(("%s : 5gl SSID is same as existing\n", __FUNCTION__));
            return RBUS_ERROR_SUCCESS;
        }
        rc = strcpy_s(g_pWarehouseDiag->WiFi_5glSSID, sizeof(g_pWarehouseDiag->WiFi_5glSSID), WiFi_5glSSID);
        ERR_CHK(rc);
        if (g_pWarehouseDiag->WiFi_5glEnable)
        {
            applyWiFiParameters(WIFI_5G_LOW, g_pWarehouseDiag->WiFi_5glSSID, g_pWarehouseDiag->WiFi_5glPassword, g_pWarehouseDiag->WiFi_5glChannel, g_pWarehouseDiag->WiFi_5glBandwidth, ' ');
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.SSID") == 0)
    {
        const char* WiFi_5ghSSID = rbusValue_GetString(value, NULL);
        if (strlen(WiFi_5ghSSID) > MAX_SSID_LEN)
        {
            CcspTraceError(("%s: 5gh SSID length exceeds maximum length\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (!isValidSSID(WiFi_5ghSSID))
        {
            CcspTraceError(("%s: 5gh SSID is empty or contains invalid special characters\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (preservedNameSSID(WiFi_5ghSSID))
        {
            CcspTraceError(("%s: 5gh SSID contains preserved names\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        rc = strcmp_s(g_pWarehouseDiag->WiFi_5ghSSID, sizeof(g_pWarehouseDiag->WiFi_5ghSSID), WiFi_5ghSSID, &ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            CcspTraceInfo(("%s : 5gh SSID is same as existing\n", __FUNCTION__));
            return RBUS_ERROR_SUCCESS;
        }
        rc = strcpy_s(g_pWarehouseDiag->WiFi_5ghSSID, sizeof(g_pWarehouseDiag->WiFi_5ghSSID), WiFi_5ghSSID);
        ERR_CHK(rc);
        if (g_pWarehouseDiag->WiFi_5ghEnable)
        {
            applyWiFiParameters(WIFI_5G_HIGH, g_pWarehouseDiag->WiFi_5ghSSID, g_pWarehouseDiag->WiFi_5ghPassword, g_pWarehouseDiag->WiFi_5ghChannel, g_pWarehouseDiag->WiFi_5ghBandwidth, ' ');
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Password") == 0)
    {
        const char* WiFi_2_4gPassword = rbusValue_GetString(value, NULL);
        if (strlen(WiFi_2_4gPassword) < MIN_PASSPHRASE_LEN)
        {
            CcspTraceError(("%s: 2.4g Password length less than minimum length\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (strlen(WiFi_2_4gPassword) > MAX_PASSPHRASE_LEN)
        {
            CcspTraceError(("%s: 2.4g Password length exceeds maximum length\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        rc = strcmp_s(g_pWarehouseDiag->WiFi_2_4gPassword, sizeof(g_pWarehouseDiag->WiFi_2_4gPassword), WiFi_2_4gPassword, &ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            CcspTraceInfo(("%s : 2.4g Password is same as existing\n", __FUNCTION__));
            return RBUS_ERROR_SUCCESS;
        }
        rc = strcpy_s(g_pWarehouseDiag->WiFi_2_4gPassword, sizeof(g_pWarehouseDiag->WiFi_2_4gPassword), WiFi_2_4gPassword);
        ERR_CHK(rc);
        if (g_pWarehouseDiag->WiFi_2_4gEnable)
        {
            if (g_pWarehouseDiag->WiFi_2_4gBandwidth == 40)
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, g_pWarehouseDiag->WiFi_2_4gSideband[0]);
            }
            else
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, ' ');
            }
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Password") == 0)
    {
        const char* WiFi_5glPassword = rbusValue_GetString(value, NULL);
        if (strlen(WiFi_5glPassword) < MIN_PASSPHRASE_LEN)
        {
            CcspTraceError(("%s: 5gl Password length less than minimum length\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (strlen(WiFi_5glPassword) > MAX_PASSPHRASE_LEN)
        {
            CcspTraceError(("%s: 5gl Password length exceeds maximum length\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        rc = strcmp_s(g_pWarehouseDiag->WiFi_5glPassword, sizeof(g_pWarehouseDiag->WiFi_5glPassword), WiFi_5glPassword, &ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            CcspTraceInfo(("%s : 5gl Password is same as existing\n", __FUNCTION__));
            return RBUS_ERROR_SUCCESS;
        }
        rc = strcpy_s(g_pWarehouseDiag->WiFi_5glPassword, sizeof(g_pWarehouseDiag->WiFi_5glPassword), WiFi_5glPassword);
        ERR_CHK(rc);
        if (g_pWarehouseDiag->WiFi_5glEnable)
        {
            applyWiFiParameters(WIFI_5G_LOW, g_pWarehouseDiag->WiFi_5glSSID, g_pWarehouseDiag->WiFi_5glPassword, g_pWarehouseDiag->WiFi_5glChannel, g_pWarehouseDiag->WiFi_5glBandwidth, ' ');
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Password") == 0)
    {
        const char* WiFi_5ghPassword = rbusValue_GetString(value, NULL);
        if (strlen(WiFi_5ghPassword) < MIN_PASSPHRASE_LEN)
        {
            CcspTraceError(("%s: 5gh Password length less than minimum length\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (strlen(WiFi_5ghPassword) > MAX_PASSPHRASE_LEN)
        {
            CcspTraceError(("%s: 5gh Password length exceeds maximum length\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        rc = strcmp_s(g_pWarehouseDiag->WiFi_5ghPassword, sizeof(g_pWarehouseDiag->WiFi_5ghPassword), WiFi_5ghPassword, &ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            CcspTraceInfo(("%s : 5gh Password is same as existing\n", __FUNCTION__));
            return RBUS_ERROR_SUCCESS;
        }
        rc = strcpy_s(g_pWarehouseDiag->WiFi_5ghPassword, sizeof(g_pWarehouseDiag->WiFi_5ghPassword), WiFi_5ghPassword);
        ERR_CHK(rc);
        if (g_pWarehouseDiag->WiFi_5ghEnable)
        {
            applyWiFiParameters(WIFI_5G_HIGH, g_pWarehouseDiag->WiFi_5ghSSID, g_pWarehouseDiag->WiFi_5ghPassword, g_pWarehouseDiag->WiFi_5ghChannel, g_pWarehouseDiag->WiFi_5ghBandwidth, ' ');
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Bandwidth") == 0)
    {
        int WiFi_2_4gBandwidth = rbusValue_GetUInt32(value);
        if (WiFi_2_4gBandwidth != 20 && WiFi_2_4gBandwidth != 40)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (WiFi_2_4gBandwidth == g_pWarehouseDiag->WiFi_2_4gBandwidth)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->WiFi_2_4gBandwidth = WiFi_2_4gBandwidth;
        if (g_pWarehouseDiag->WiFi_2_4gEnable)
        {
            if (g_pWarehouseDiag->WiFi_2_4gBandwidth == 40)
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, g_pWarehouseDiag->WiFi_2_4gSideband[0]);
            }
            else
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, ' ');
            }
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Bandwidth") == 0)
    {
        int WiFi_5glBandwidth = rbusValue_GetUInt32(value);
        if (WiFi_5glBandwidth != 20 && WiFi_5glBandwidth != 40 && WiFi_5glBandwidth != 80 && WiFi_5glBandwidth != 160)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (WiFi_5glBandwidth == g_pWarehouseDiag->WiFi_5glBandwidth)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->WiFi_5glBandwidth = WiFi_5glBandwidth;
        if (g_pWarehouseDiag->WiFi_5glEnable)
        {
            applyWiFiParameters(WIFI_5G_LOW, g_pWarehouseDiag->WiFi_5glSSID, g_pWarehouseDiag->WiFi_5glPassword, g_pWarehouseDiag->WiFi_5glChannel, g_pWarehouseDiag->WiFi_5glBandwidth, ' ');
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Bandwidth") == 0)
    {
        int WiFi_5ghBandwidth = rbusValue_GetUInt32(value);
        if (WiFi_5ghBandwidth != 20 && WiFi_5ghBandwidth != 40 && WiFi_5ghBandwidth != 80 && WiFi_5ghBandwidth != 160)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (WiFi_5ghBandwidth == g_pWarehouseDiag->WiFi_5ghBandwidth)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->WiFi_5ghBandwidth = WiFi_5ghBandwidth;
        if (g_pWarehouseDiag->WiFi_5ghEnable)
        {
            applyWiFiParameters(WIFI_5G_HIGH, g_pWarehouseDiag->WiFi_5ghSSID, g_pWarehouseDiag->WiFi_5ghPassword, g_pWarehouseDiag->WiFi_5ghChannel, g_pWarehouseDiag->WiFi_5ghBandwidth, ' ');
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Channel") == 0)
    {
        int WiFi_2_4gChannel = rbusValue_GetUInt32(value);
        if (WiFi_2_4gChannel < 1 || WiFi_2_4gChannel > 11)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (WiFi_2_4gChannel == g_pWarehouseDiag->WiFi_2_4gChannel)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->WiFi_2_4gChannel = WiFi_2_4gChannel;
        if (g_pWarehouseDiag->WiFi_2_4gEnable)
        {
            if (g_pWarehouseDiag->WiFi_2_4gBandwidth == 40)
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, g_pWarehouseDiag->WiFi_2_4gSideband[0]);
            }
            else
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, ' ');
            }
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gl.Channel") == 0)
    {
        int WiFi_5glChannel = rbusValue_GetUInt32(value);
        if (WiFi_5glChannel != 36 && WiFi_5glChannel != 40 && WiFi_5glChannel != 44 && WiFi_5glChannel != 48)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (WiFi_5glChannel == g_pWarehouseDiag->WiFi_5glChannel)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->WiFi_5glChannel = WiFi_5glChannel;
        if (g_pWarehouseDiag->WiFi_5glEnable)
        {
            applyWiFiParameters(WIFI_5G_LOW, g_pWarehouseDiag->WiFi_5glSSID, g_pWarehouseDiag->WiFi_5glPassword, g_pWarehouseDiag->WiFi_5glChannel, g_pWarehouseDiag->WiFi_5glBandwidth, ' ');
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.5gh.Channel") == 0)
    {
        int WiFi_5ghChannel = rbusValue_GetUInt32(value);
        if (WiFi_5ghChannel != 149 && WiFi_5ghChannel != 153 && WiFi_5ghChannel != 157 && WiFi_5ghChannel != 161)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (WiFi_5ghChannel == g_pWarehouseDiag->WiFi_5ghChannel)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->WiFi_5ghChannel = WiFi_5ghChannel;
        if (g_pWarehouseDiag->WiFi_5ghEnable)
        {
            applyWiFiParameters(WIFI_5G_HIGH, g_pWarehouseDiag->WiFi_5ghSSID, g_pWarehouseDiag->WiFi_5ghPassword, g_pWarehouseDiag->WiFi_5ghChannel, g_pWarehouseDiag->WiFi_5ghBandwidth, ' ');
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.WiFi.2_4g.Sideband") == 0)
    {
        const char* WiFi_2_4gSideband = rbusValue_GetString(value, NULL);
        if (WiFi_2_4gSideband[0] != 'u' && WiFi_2_4gSideband[0] != 'l')
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (WiFi_2_4gSideband[0] == g_pWarehouseDiag->WiFi_2_4gSideband[0])
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->WiFi_2_4gSideband[0] = WiFi_2_4gSideband[0];
        if (g_pWarehouseDiag->WiFi_2_4gEnable)
        {
            if (g_pWarehouseDiag->WiFi_2_4gBandwidth == 40)
            {
                applyWiFiParameters(WIFI_2_4G, g_pWarehouseDiag->WiFi_2_4gSSID, g_pWarehouseDiag->WiFi_2_4gPassword, g_pWarehouseDiag->WiFi_2_4gChannel, g_pWarehouseDiag->WiFi_2_4gBandwidth, g_pWarehouseDiag->WiFi_2_4gSideband[0]);
            }
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.Mode") == 0)
    {
        const char* BluetoothMode = rbusValue_GetString(value, NULL);
        if ((strcmp(BluetoothMode, "BEACON") != 0) && (strcmp(BluetoothMode, "TRANSMIT") != 0))
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        rc = strcmp_s(g_pWarehouseDiag->BluetoothMode, sizeof(g_pWarehouseDiag->BluetoothMode), BluetoothMode, &ind);
        ERR_CHK(rc);
        if ((!ind) && (rc == EOK))
        {
            return RBUS_ERROR_SUCCESS;
        }
        rc = strcpy_s(g_pWarehouseDiag->BluetoothMode, sizeof(g_pWarehouseDiag->BluetoothMode), BluetoothMode);
        ERR_CHK(rc);
        if (g_pWarehouseDiag->BluetoothEnable)
        {
            if (strcmp(g_pWarehouseDiag->BluetoothMode, "TRANSMIT") == 0)
            {
                bleBeaconEnable(true);
                bleTransmitModeUpdate(g_pWarehouseDiag->BluetoothTransmitChannel, g_pWarehouseDiag->BluetoothTransmitLength, g_pWarehouseDiag->BluetoothTransmitPattern);
            }
            else if (strcmp(g_pWarehouseDiag->BluetoothMode, "BEACON") == 0)
            {
                bleBeaconEnable(false); // reset TRANSMIT mode
                bleBeaconEnable(true);
            }
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.TransmitChannel") == 0)
    {
        int BluetoothTransmitChannel = rbusValue_GetUInt32(value);
        if (BluetoothTransmitChannel < 0 || BluetoothTransmitChannel > 39)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (BluetoothTransmitChannel == g_pWarehouseDiag->BluetoothTransmitChannel)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->BluetoothTransmitChannel = BluetoothTransmitChannel;
        if (g_pWarehouseDiag->BluetoothEnable)
        {
            if (strcmp(g_pWarehouseDiag->BluetoothMode, "TRANSMIT") == 0)
            {
                bleBeaconEnable(true);
                bleTransmitModeUpdate(g_pWarehouseDiag->BluetoothTransmitChannel, g_pWarehouseDiag->BluetoothTransmitLength, g_pWarehouseDiag->BluetoothTransmitPattern);
            }
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.TransmitLength") == 0)
    {
        int BluetoothTransmitLength = rbusValue_GetUInt32(value);
        if (BluetoothTransmitLength < 0 || BluetoothTransmitLength > 255) //need to update the range
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (BluetoothTransmitLength == g_pWarehouseDiag->BluetoothTransmitLength)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->BluetoothTransmitLength = BluetoothTransmitLength;
        if (g_pWarehouseDiag->BluetoothEnable)
        {
            if (strcmp(g_pWarehouseDiag->BluetoothMode, "TRANSMIT") == 0)
            {
                bleBeaconEnable(true);
                bleTransmitModeUpdate(g_pWarehouseDiag->BluetoothTransmitChannel, g_pWarehouseDiag->BluetoothTransmitLength, g_pWarehouseDiag->BluetoothTransmitPattern);
            }
        }
    }
    else if (strcmp(name, "Device.X_RDKCENTRAL-COM_WarehouseDiagnostics.Bluetooth.TransmitPattern") == 0)
    {
        int BluetoothTransmitPattern = rbusValue_GetUInt32(value);
        if (BluetoothTransmitPattern < 0 || BluetoothTransmitPattern > 7)
        {
            return RBUS_ERROR_INVALID_INPUT;
        }
        if (BluetoothTransmitPattern == g_pWarehouseDiag->BluetoothTransmitPattern)
        {
            return RBUS_ERROR_SUCCESS;
        }
        g_pWarehouseDiag->BluetoothTransmitPattern = BluetoothTransmitPattern;
        if (g_pWarehouseDiag->BluetoothEnable)
        {
            if (strcmp(g_pWarehouseDiag->BluetoothMode, "TRANSMIT") == 0)
            {
                bleBeaconEnable(true);
                bleTransmitModeUpdate(g_pWarehouseDiag->BluetoothTransmitChannel, g_pWarehouseDiag->BluetoothTransmitLength, g_pWarehouseDiag->BluetoothTransmitPattern);
            }
        }
    }
    else
    {
        ret = RBUS_ERROR_INVALID_INPUT;
    }
    return ret;
}
