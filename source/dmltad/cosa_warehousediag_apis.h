#ifndef  _WHDIAG_APIS_H
#define  _WHDIAG_APIS_H

#include <rbus/rbus.h>
#include <stdbool.h>
#include <ev.h>
#include "safec_lib_common.h"
#include "ccsp_trace.h"

#define BUFLEN_2 2
#define BUFLEN_8 8
#define BUFLEN_12 12
#define BUFLEN_128 128
#define ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_BRIGHTNESS 255
#define FAN_STATE_CHECK_COUNT 10
#define MAX_SSID_LEN 32
#define BSSID_LEN 17
#define MIN_PASSPHRASE_LEN 8
#define MAX_PASSPHRASE_LEN 63
#define IMEI_LEN 15
#define ICCID_LEN 21

typedef enum {
    WIFI_2_4G,
    WIFI_5G_LOW,
    WIFI_5G_HIGH
} wifi_band_t;

typedef enum {
    RED,
    WHITE
} LEDColor;

typedef enum {
    SOLID,
    BLINK
} LEDState;

typedef struct
_WAREHOUSE_DIAG_GLOBAL_CTXT
{
    bool WiFi_2_4gEnable;
    bool WiFi_5glEnable;
    bool WiFi_5ghEnable;
    char LTEStatus[BUFLEN_128];
    char LTEImei[IMEI_LEN+1];
    char LTEIccid[ICCID_LEN+1];
    char LTEFirmwareVersion[BUFLEN_128];
    bool BluetoothEnable;
    unsigned int FanSpeed;
    char FanState[BUFLEN_12];
    bool LEDEnable;
    char LEDColor[BUFLEN_8];
    char LEDState[BUFLEN_8];
    unsigned int LEDInterval;
    char WiFi_2_4gSSID[MAX_SSID_LEN+1];
    char WiFi_5glSSID[MAX_SSID_LEN+1];
    char WiFi_5ghSSID[MAX_SSID_LEN+1];
    char WiFi_2_4gStatus[BUFLEN_8];
    char WiFi_5glStatus[BUFLEN_8];
    char WiFi_5ghStatus[BUFLEN_8];
    char WiFi_2_4gBSSID[BSSID_LEN+1];
    char WiFi_5glBSSID[BSSID_LEN+1];
    char WiFi_5ghBSSID[BSSID_LEN+1];
    char WiFi_2_4gPassword[MAX_PASSPHRASE_LEN+1];
    char WiFi_5glPassword[MAX_PASSPHRASE_LEN+1];
    char WiFi_5ghPassword[MAX_PASSPHRASE_LEN+1];
    unsigned int WiFi_2_4gBandwidth;
    unsigned int WiFi_5glBandwidth;
    unsigned int WiFi_5ghBandwidth;
    unsigned int WiFi_2_4gChannel;
    unsigned int WiFi_5glChannel;
    unsigned int WiFi_5ghChannel;
    char WiFi_2_4gSideband[BUFLEN_2];
    char BluetoothMode[BUFLEN_12];
    unsigned int BluetoothTransmitChannel;
    unsigned int BluetoothTransmitLength;
    unsigned int BluetoothTransmitPattern;
}
WAREHOUSE_DIAG_GLOBAL_CTXT_INFO, *PWAREHOUSE_DIAG_GLOBAL_CTXT_INFO;

void configureLAN();
void initBle();
void bleBeaconEnable(bool enable);
void bleTransmitModeUpdate(int channel, int length, int pattern);
bool isTelit();
void getLTEStatus(char *status);
void getLTEImei(char *imei);
void getLTEIccid(char *iccid);
void getLTEFirmwareVersion(char *version);
void setFanSpeed(int speed);
int getFanSpeed();
const char* getFanState();
void setLedOff();
const char* getLEDColorName(LEDColor color);
LEDColor getLEDColor(const char* color);
LEDState getLEDState(const char* state);
const char* getLEDStateName(LEDState state);
void setLed(LEDColor color, int bright, LEDState state, int interval);
int getLed(LEDColor* color, int* bright, LEDState* state, int* interval);
void configureNvram();
const char* wifi_band_to_string(wifi_band_t band);
const char* get_bandwidth_cap(wifi_band_t band);
void get_wifi_bssid(wifi_band_t band, char *bssid);
void get_wifi_bss(wifi_band_t band, char *bss);
void get_wifi_channel(wifi_band_t band, int *channel);
void get_wifi_ssid(wifi_band_t band, char *ssid);
bool preservedNameSSID(const char *SSID);
bool isValidSSID(const char *SSID);
void get_wifi_psk(wifi_band_t band, char *psk);
void restartHostapd(wifi_band_t band);
void applyWiFiParameters(wifi_band_t band, const char* ssid, const char* password, int channel, int bandwidth, char sideband);
void disableWiFi(wifi_band_t band);
void warehousediag_init_ctxt();
void run_commands(void);
void file_stat_cb(EV_P_ ev_stat *w, int revents);
void* warehousediag_thread(void* arg);
int warehousediag_start();

#endif