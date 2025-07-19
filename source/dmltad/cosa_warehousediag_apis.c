#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>
#include "secure_wrapper.h"
#include "cosa_warehousediag_apis.h"
#include "cosa_warehousediag_rbus_apis.h"

rbusHandle_t rbus_handle_whd = NULL;
static bool bleInit = true;
static bool configureNvramDone = false;
PWAREHOUSE_DIAG_GLOBAL_CTXT_INFO g_pWarehouseDiag = NULL;

void configureLAN()
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    v_secure_system("killall dnsmasq");
    v_secure_system("rm -f /tmp/dhcp.conf");
    v_secure_system("rm -f /tmp/dnsmasq.pid");
    v_secure_system("echo 'interface=brlan0' > /tmp/dhcp.conf");
    v_secure_system("echo 'port=0' >> /tmp/dhcp.conf");
    v_secure_system("echo 'dhcp-range=192.168.142.50,192.168.142.250,12h' >> /tmp/dhcp.conf");
    v_secure_system("ip a add 192.168.142.1/24 dev brlan0");
    v_secure_system("dnsmasq -q --clear-on-reload --bind-dynamic --add-mac -C /tmp/dhcp.conf --dhcp-authoritative --stop-dns-rebind --interface=brlan0 --pid-file=/tmp/dnsmasq.pid");
}

void initBle()
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    if (bleInit)
    {
        bleInit = false;
        v_secure_system("syscfg set unit_activated 0; syscfg commit");
        v_secure_system("systemctl start btfwupdate");
        v_secure_system("systemctl start bt-hciactivate");
        v_secure_system("systemctl start bluetooth");
        sleep(2);
    }
}

void bleBeaconEnable(bool enable)
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    initBle();
    if (enable)
    {
        // Run btMgrBus if it is not running -- this will start beaconing
        if ( 0 != v_secure_system("pidof btMgrBus") ) {
            CcspTraceInfo(("btMgrBus not running, starting btMgrBus\n"));
            v_secure_system("/usr/bin/btMgrBus&");
        }
    }
    else
    {
        // Reset TRANSMIT mode
        v_secure_system("hcitool cmd 0x08 0x001f");
        // Kill btMgrBus -- this will stop beaconing
        v_secure_system("killall btMgrBus");
    }
}

void bleTransmitModeUpdate(int channel, int length, int pattern)
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    initBle();
    bleBeaconEnable(true);
    v_secure_system("hcitool cmd 0x08 0x001e 0x%02X 0x%02X 0x%02X", channel, length, pattern);
}

bool isTelit(){
    int telit = 0;
    FILE *fp = v_secure_popen("r", "lsusb | grep Telit | grep LN920 | wc -l");
    if (fp == NULL)
    {
        return false;
    }
    fscanf(fp, "%d", &telit);
    v_secure_pclose(fp);
    if (telit == 0)
    {
        return false;
    }
    return true;
}

void getLTEStatus(char *status)
{
    FILE *fp = v_secure_popen("r", "echo -e 'AT\r' | microcom -s 115200 -t 20 /dev/ttyUSB3");
    if (fp == NULL)
    {
        status[0] = '\0';
        return;
    }
    fscanf(fp, "%*s %127s", status);
    v_secure_pclose(fp);
    CcspTraceInfo(("LTE status: %s\n", status));
}

void getLTEImei(char *imei)
{
    FILE *fp = v_secure_popen("r", "echo -e 'AT+CGSN\r' | microcom -s 115200 -t 20 /dev/ttyUSB3");
    if (fp == NULL)
    {
        return;
    }
    fscanf(fp, "%*s %15s", imei);
    v_secure_pclose(fp);
    CcspTraceInfo(("LTE IMEI: %s\n", imei));
}

void getLTEIccid(char *iccid)
{
    FILE *fp = NULL;
    if (isTelit())
    {
        fp = v_secure_popen("r", "echo -e 'AT+ICCID\r' | microcom -s 115200 -t 20 /dev/ttyUSB3");
    }
    else
    {
        fp = v_secure_popen("r", "echo -e 'AT+CCID\r' | microcom -s 115200 -t 20 /dev/ttyUSB3");
    }
    if (fp == NULL)
    {
        iccid[0] = '\0';
        return;
    }
    fscanf(fp, "%*s %*s %21s", iccid);
    v_secure_pclose(fp);
    CcspTraceInfo(("LTE ICCID: %s\n", iccid));
}

void getLTEFirmwareVersion(char *version)
{
    FILE *fp = NULL;
    if (isTelit())
    {
        fp = v_secure_popen("r", "echo -e 'AT#SWPKGV\r' | microcom -s 115200 -t 20 /dev/ttyUSB3");
    }
    else
    {
        fp = v_secure_popen("r", "echo -e 'AT+QGMR\r' | microcom -s 115200 -t 20 /dev/ttyUSB3");
    }
    if (fp == NULL)
    {
        version[0] = '\0';
        return;
    }
    fscanf(fp, "%*s %127s", version);
    v_secure_pclose(fp);
    CcspTraceInfo(("LTE firmware version: %s\n", version));
}

void setFanSpeed(int speed)
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    int trickle = 0;
    if (speed == 0)
    {
        trickle = 0;
    }
    else
    {
        trickle = 1;
    }
    v_secure_system("echo %d > /sys/class/gpio/gpio9/value", trickle);
    if (speed >= 0 && speed <= MAX_BRIGHTNESS)
    {
        v_secure_system("echo %d > /sys/class/leds/fanDrive/brightness", (MAX_BRIGHTNESS - speed));
    }
}

int getFanSpeed()
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    int trickle = 0;
    int speed = 0;
    FILE *fp = v_secure_popen("r","cat /sys/class/leds/fanDrive/brightness");
    if (fp == NULL)
    {
        return -1;
    }
    fscanf(fp, "%d", &speed);
    v_secure_pclose(fp);
    CcspTraceInfo(("Fan speed: %d\n", MAX_BRIGHTNESS - speed));
    fp = v_secure_popen("r","cat /sys/class/gpio/gpio9/value");
    if (fp == NULL)
    {
        return -1;
    }
    fscanf(fp, "%d", &trickle);
    v_secure_pclose(fp);
    CcspTraceInfo(("Fan trickle: %d\n", trickle));
    if (trickle == 0)
    {
        speed = 0;
    }
    else
    {
        speed = MAX_BRIGHTNESS - speed;
    }
    return speed;
}

const char* getFanState()
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    int count = 0;
    int i = 0;
    FILE *fp;
    int fanval = 0;

    for (i = 0; i < FAN_STATE_CHECK_COUNT; i++) {
        fp = v_secure_popen("r", "cat /sys/class/gpio/gpio33/value");
        if (fp == NULL)
        {
            return "NOT_RUNNING";
        }
        fscanf(fp, "%d", &fanval);
        v_secure_pclose(fp);
        if (fanval == 1) {
            count++;
        }
    }
    CcspTraceInfo(("Fan GPIO count: %d\n", count));
    if (count == FAN_STATE_CHECK_COUNT) {
        if (getFanSpeed() == 0)
        {
            return "STOPPED";
        }
        return "NOT_RUNNING";
    }
    return "RUNNING";
}

void setLedOff()
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    v_secure_system("echo none > /sys/class/leds/RED/trigger");
    v_secure_system("echo %d > /sys/class/leds/RED/brightness", MAX_BRIGHTNESS);
    v_secure_system("echo none > /sys/class/leds/WHITE/trigger");
    v_secure_system("echo %d > /sys/class/leds/WHITE/brightness", MAX_BRIGHTNESS);
}

const char* getLEDColorName(LEDColor color) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    switch (color) {
        case RED:
            return "RED";
        case WHITE:
            return "WHITE";
        default:
            return "UNKNOWN";
    }
}

LEDColor getLEDColor(const char* color) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    if (strcmp(color, "RED") == 0)
    {
        return RED;
    }
    else if (strcmp(color, "WHITE") == 0)
    {
        return WHITE;
    }
    return WHITE;
}

LEDState getLEDState(const char* state) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    if (strcmp(state, "SOLID") == 0)
    {
        return SOLID;
    }
    else if (strcmp(state, "BLINK") == 0)
    {
        return BLINK;
    }
    return SOLID;
}

const char* getLEDStateName(LEDState state) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    switch (state) {
        case SOLID:
            return "SOLID";
        case BLINK:
            return "BLINK";
        default:
            return "UNKNOWN";
    }
}

void setLed(LEDColor color, int bright, LEDState state, int interval)
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    setLedOff();
    if (state == BLINK)
    {
        if (color == WHITE)
        {
            v_secure_system("echo timer > /sys/class/leds/WHITE/trigger");
            v_secure_system("echo %d > /sys/class/leds/WHITE/delay_on", interval);
            v_secure_system("echo %d > /sys/class/leds/WHITE/delay_off", interval);
            v_secure_system("echo %d > /sys/class/leds/WHITE/brightness", bright);
        }
        else if (color == RED)
        {
            v_secure_system("echo timer > /sys/class/leds/RED/trigger");
            v_secure_system("echo %d > /sys/class/leds/RED/delay_on", interval);
            v_secure_system("echo %d > /sys/class/leds/RED/delay_off", interval);
            v_secure_system("echo %d > /sys/class/leds/RED/brightness", bright);
        }
    }
    else if (state == SOLID)
    {
        if (color == WHITE)
        {
            v_secure_system("echo none > /sys/class/leds/WHITE/trigger");
            v_secure_system("echo %d > /sys/class/leds/WHITE/brightness", (MAX_BRIGHTNESS - bright));
        }
        else if (color == RED)
        {
            v_secure_system("echo none > /sys/class/leds/RED/trigger");
            v_secure_system("echo %d > /sys/class/leds/RED/brightness", (MAX_BRIGHTNESS - bright));
        }
    }
}

int getLed(LEDColor* color, int* bright, LEDState* state, int* interval)
{
    int white_brightness = 0;
    int red_brightness = 0;
    LEDState white_state = SOLID;
    LEDState red_state = SOLID;
    char timer_str[BUFLEN_8] = {0};
    int white_timer = 0;
    int red_timer = 0;
    int white_interval = 0;
    int red_interval = 0;
    FILE *fp = NULL;
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    fp = v_secure_popen("r", "cat /sys/class/leds/WHITE/brightness");
    if (fp == NULL)
    {
        return -1;
    }
    fscanf(fp, "%d", &white_brightness);
    v_secure_pclose(fp);
    fp = v_secure_popen("r", "cat /sys/class/leds/RED/brightness");
    if (fp == NULL)
    {
        return -1;
    }
    fscanf(fp, "%d", &red_brightness);
    v_secure_pclose(fp);
    fp = v_secure_popen("r", "cat /sys/class/leds/WHITE/trigger");
    if (fp == NULL)
    {
        return -1;
    }
    // none rfkill-any rfkill-none usbport mmc0 [timer]
    fscanf(fp, "%*s %*s %*s %*s %*s %7s", timer_str);
    if (strchr(timer_str, ']'))
    {
        white_timer = 1;
    }
    v_secure_pclose(fp);
    memset(timer_str, '\0', sizeof(timer_str));
    fp = v_secure_popen("r", "cat /sys/class/leds/RED/trigger");
    if (fp == NULL)
    {
        return -1;
    }
    fscanf(fp, "%*s %*s %*s %*s %*s %7s", timer_str);
    if (strchr(timer_str, ']'))
    {
        red_timer = 1;
    }
    v_secure_pclose(fp);
    if (white_timer == 1)
    {
        white_state = BLINK;
        fp = v_secure_popen("r", "cat /sys/class/leds/WHITE/delay_on");
        if (fp == NULL)
        {
            return -1;
        }
        fscanf(fp, "%d", &white_interval);
        v_secure_pclose(fp);
        *color = WHITE;
        *bright = MAX_BRIGHTNESS - white_brightness;
        *state = white_state;
        *interval = white_interval;
    }
    else if (red_timer == 1)
    {
        red_state = BLINK;
        fp = v_secure_popen("r", "cat /sys/class/leds/RED/delay_on");
        if (fp == NULL)
        {
            return -1;
        }
        fscanf(fp, "%d", &red_interval);
        v_secure_pclose(fp);
        *color = RED;
        *bright = MAX_BRIGHTNESS - red_brightness;
        *state = red_state;
        *interval = red_interval;
    }
    else if (white_brightness == MAX_BRIGHTNESS)
    {
        *color = RED;
        *bright = MAX_BRIGHTNESS - red_brightness;
        *state = red_state;
        *interval = red_interval;
    }
    else if (red_brightness == MAX_BRIGHTNESS)
    {
        *color = WHITE;
        *bright = MAX_BRIGHTNESS - white_brightness;
        *state = white_state;
        *interval = white_interval;
    }
    return 0;
}

void configureNvram()
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    if (configureNvramDone)
    {
        CcspTraceInfo(("configureNvram already done\n"));
        return;
    }
    v_secure_system("nvram set wl1_he_features=1; nvram set wl2_he_features=1");
    v_secure_system("nvram set wl0_wfi_enable=1; nvram set wl1_wfi_enable=1; nvram set wl2_wfi_enable=1");
    v_secure_system("nvram set hapd_enable=1; nvram commit; nvram restart");
    v_secure_system("hapd_conf 0 start; hapd_conf 1 start; hapd_conf 2 start");
    sleep(20);
    v_secure_system("wl -i wl0 down; wl -i wl1 down; wl -i wl2 down");
    configureNvramDone = true;
    CcspTraceInfo(("configureNvram done\n"));
}

const char* wifi_band_to_string(wifi_band_t band) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    switch (band) {
        case WIFI_2_4G: return "wl0";
        case WIFI_5G_LOW: return "wl1";
        case WIFI_5G_HIGH: return "wl2";
        default: return "unknown";
    }
}

const char* get_bandwidth_cap(wifi_band_t band) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    switch (band) {
        case WIFI_2_4G:
            return "2g 3";
        case WIFI_5G_LOW:
            return "5g 7";
        case WIFI_5G_HIGH:
            return  "5g 15";
        default:
            return "unknown";
    }
}

void get_wifi_bssid(wifi_band_t band, char *bssid) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    const char* bandStr = wifi_band_to_string(band);
    FILE *fp = v_secure_popen("r", "wl -i %s bssid", bandStr);
    if (fp == NULL)
    {
        bssid[0] = '\0';
        return;
    }
    fscanf(fp, "%17s", bssid);
    v_secure_pclose(fp);
}

void get_wifi_bss(wifi_band_t band, char *bss) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    const char* bandStr = wifi_band_to_string(band);
    FILE *fp = v_secure_popen("r", "wl -i %s bss", bandStr);
    if (fp == NULL)
    {
        bss[0] = '\0';
        return;
    }
    fscanf(fp, "%7s", bss);
    v_secure_pclose(fp);
}

void get_wifi_channel(wifi_band_t band, int *channel) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    const char* bandStr = wifi_band_to_string(band);
    FILE *fp = v_secure_popen("r", "wl -i %s chanspec", bandStr);
    if (fp == NULL)
    {
        *channel = -1;
        return;
    }
    fscanf(fp, "%d", channel);
    v_secure_pclose(fp);
}

void get_wifi_ssid(wifi_band_t band, char *ssid) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    const char* bandStr = wifi_band_to_string(band);
    FILE *fp = v_secure_popen("r", "wl -i %s ssid", bandStr);
    if (fp == NULL)
    {
        ssid[0] = '\0';
        return;
    }
    fscanf(fp, "%*s %*s \"%32[^\"]\"", ssid);
    v_secure_pclose(fp);
}

bool preservedNameSSID(const char *SSID) {
    if (strcasestr(SSID, "cablewifi") || strcasestr(SSID, "twcwifi") || strcasestr(SSID, "optimumwifi") ||
        strcasestr(SSID, "xfinity") || strcasestr(SSID, "xfinitywifi") || strcasestr(SSID, "home") ||
        strcasestr(SSID, "xfsetup") || strcasestr(SSID, "xhs-") || strcasestr(SSID, "xh-"))
    {
        return true;
    }
    return false;
}

bool isValidSSID(const char *SSID) {
    // "alphabet, digit, underscore, hyphen and dot"
    char* validChars = "_-.";
    int i = 0;
    bool result = true;
    if (strlen(SSID) == 0) {
        result = false;
    }
    else {
        for (i = 0; i < strlen(SSID); i++) {
            if ((isalnum(SSID[i]) == 0) &&
                (strchr(validChars, SSID[i]) == NULL)) {
                result = false;
                break;
            }
        }
    }
    return result;
}

void get_wifi_psk(wifi_band_t band, char *psk) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    const char* bandStr = wifi_band_to_string(band);
    FILE *fp = v_secure_popen("r", "nvram get %s_wpa_psk", bandStr);
    if (fp == NULL)
    {
        psk[0] = '\0';
        return;
    }
    fscanf(fp, "%63s", psk);
    v_secure_pclose(fp);
}

void restartHostapd(wifi_band_t band) {
    int i = 0;
    char bss[8] = {0};
    const char* bandStr = wifi_band_to_string(band);
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    for (i = 0; i < 3; i++) {
        v_secure_system("hapd_conf %d stop", band);
        CcspTraceInfo(("hapd_conf %d stop\n", band));
        v_secure_system("hapd_conf %d start", band);
        CcspTraceInfo(("hapd_conf %d start\n", band));
        get_wifi_bss(band, bss);
        if (strcmp(bss, "down") == 0) {
            CcspTraceError(("Start hostapd for %s interface failed\n", bandStr));
            CcspTraceInfo(("Restart hostapd for %s interface\n", bandStr));
        }
        else {
            CcspTraceInfo(("Start hostapd for %s interface success\n", bandStr));
            break;
        }
    }
    if (i == 3) {
        CcspTraceError(("Reached maximum retries, hostapd restart for %s interface failed\n", bandStr));
    }
}

void
applyWiFiParameters
(wifi_band_t band, const char* ssid, const char* password, int channel, int bandwidth, char sideband)
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    configureNvram();
    const char* bandStr = wifi_band_to_string(band);
    v_secure_system("nvram set %s_ssid=%s; nvram set %s_wpa_psk=%s; nvram commit",
                    bandStr, ssid, bandStr, password);
    restartHostapd(band);
    v_secure_system("wl -i %s down", bandStr);
    if (band != WIFI_2_4G)
    {
        v_secure_system("wl -i %s vhtmode 1", bandStr);
    }
    v_secure_system("wl -i %s he 1; wl -i %s bw_cap %s; wl -i %s chanspec %d/%d%c; wl -i %s up",
                    bandStr, bandStr, get_bandwidth_cap(band), bandStr, channel, bandwidth, sideband, bandStr);
}

void disableWiFi(wifi_band_t band)
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    const char* bandStr = wifi_band_to_string(band);
    v_secure_system("wl -i %s down", bandStr);
}

void warehousediag_init_ctxt()
{
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    errno_t rc = -1;
    char emac[BUFLEN_12+1] = {0};
    FILE *fp = NULL;
    int result = 0;
    if (g_pWarehouseDiag == NULL)
    {
        g_pWarehouseDiag = (PWAREHOUSE_DIAG_GLOBAL_CTXT_INFO)malloc(sizeof(WAREHOUSE_DIAG_GLOBAL_CTXT_INFO));
        if (g_pWarehouseDiag == NULL)
        {
            CcspTraceError(("Failed to allocate memory for Warehouse Diagnostics global context\n"));
            return;
        }
        memset(g_pWarehouseDiag, 0, sizeof(WAREHOUSE_DIAG_GLOBAL_CTXT_INFO));
    }
    g_pWarehouseDiag->WiFi_2_4gEnable = false;
    g_pWarehouseDiag->WiFi_5glEnable = false;
    g_pWarehouseDiag->WiFi_5ghEnable = false;
    g_pWarehouseDiag->BluetoothEnable = false;
    g_pWarehouseDiag->LEDEnable = true;
    g_pWarehouseDiag->LEDInterval = 1000;
    //Read the Ethernet MAC
    fp = v_secure_popen("r", "deviceinfo.sh -emac | tr -d :");
    if(fp)
    {
        result = fscanf(fp, "%12s", emac);
        if(result == 1)
        {
            CcspTraceInfo(("Device Ethernet MAC - %s", emac));
        }
        v_secure_pclose(fp);
    }
    rc = strcpy_s(g_pWarehouseDiag->WiFi_2_4gSSID, sizeof(g_pWarehouseDiag->WiFi_2_4gSSID), "TEST-2.4g-");
    ERR_CHK(rc);
    rc = strcpy_s(g_pWarehouseDiag->WiFi_5glSSID, sizeof(g_pWarehouseDiag->WiFi_5glSSID), "TEST-5gl-");
    ERR_CHK(rc);
    rc = strcpy_s(g_pWarehouseDiag->WiFi_5ghSSID, sizeof(g_pWarehouseDiag->WiFi_5ghSSID), "TEST-5gh-");
    ERR_CHK(rc);
    rc = strcat_s(g_pWarehouseDiag->WiFi_2_4gSSID, sizeof(g_pWarehouseDiag->WiFi_2_4gSSID), emac);
    ERR_CHK(rc);
    rc = strcat_s(g_pWarehouseDiag->WiFi_5glSSID, sizeof(g_pWarehouseDiag->WiFi_5glSSID), emac);
    ERR_CHK(rc);
    rc = strcat_s(g_pWarehouseDiag->WiFi_5ghSSID, sizeof(g_pWarehouseDiag->WiFi_5ghSSID), emac);
    ERR_CHK(rc);
    rc = strcpy_s(g_pWarehouseDiag->WiFi_2_4gPassword, sizeof(g_pWarehouseDiag->WiFi_2_4gPassword), "1231231123");
    ERR_CHK(rc);
    rc = strcpy_s(g_pWarehouseDiag->WiFi_5glPassword, sizeof(g_pWarehouseDiag->WiFi_5glPassword), "1231231123");
    ERR_CHK(rc);
    rc = strcpy_s(g_pWarehouseDiag->WiFi_5ghPassword, sizeof(g_pWarehouseDiag->WiFi_5ghPassword), "1231231123");
    ERR_CHK(rc);
    g_pWarehouseDiag->WiFi_2_4gBandwidth = 20;
    g_pWarehouseDiag->WiFi_5glBandwidth = 40;
    g_pWarehouseDiag->WiFi_5ghBandwidth = 40;
    g_pWarehouseDiag->WiFi_2_4gChannel = 5;
    g_pWarehouseDiag->WiFi_5glChannel = 40;
    g_pWarehouseDiag->WiFi_5ghChannel = 153;
    rc = strcpy_s(g_pWarehouseDiag->WiFi_2_4gSideband, sizeof(g_pWarehouseDiag->WiFi_2_4gSideband), "u");
    ERR_CHK(rc);
    rc = strcpy_s(g_pWarehouseDiag->BluetoothMode, sizeof(g_pWarehouseDiag->BluetoothMode), "BEACON");
    ERR_CHK(rc);
    g_pWarehouseDiag->BluetoothTransmitChannel = 37;
    g_pWarehouseDiag->BluetoothTransmitLength = 66;
    g_pWarehouseDiag->BluetoothTransmitPattern = 3;
}

// Callback function to be called when the file status changes
void file_stat_cb(EV_P_ ev_stat *w, int revents) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    if (w->attr.st_nlink) {
        configureLAN();
        configureNvram();
        WAREHOUSEDIAG_Reg_Elements();
    } else {
        WAREHOUSEDIAG_UnReg_Elements();
    }
}

void* warehousediag_thread(void* arg) {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    pthread_detach(pthread_self());
    struct ev_loop *loop = EV_DEFAULT;
    ev_stat stat_watcher;

    // Initialize the stat watcher
    ev_stat_init(&stat_watcher, file_stat_cb, "/tmp/warehouse_mode", 0.);
    ev_stat_start(loop, &stat_watcher);

    // Start the event loop
    ev_run(loop, 0);
    return NULL;
}

int warehousediag_start() {
    CcspTraceInfo(("Inside %s\n", __FUNCTION__));
    pthread_t thread;
    warehousediag_init_ctxt();
    FILE* fp = fopen("/tmp/warehouse_mode", "r");
    if (fp) {
        fclose(fp);
        configureLAN();
        configureNvram();
        WAREHOUSEDIAG_Reg_Elements();
    }
    pthread_create(&thread, NULL, warehousediag_thread, NULL);
    return 0;
}
