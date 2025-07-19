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

/*
 * diag.h - Implement common backend functoin of TR-181 Device.IP.Diagnostics.xxx.
 * leichen2@cisco.com, Mar 2013, Initialize
 */
#ifndef __DIAG_COMM_H__
#define __DIAG_COMM_H__
#include <net/if.h>
#include "plugin_main_apis.h"

typedef enum diag_mode_e {
    DIAG_MD_PING,
    DIAG_MD_TRACERT,
} diag_mode_t;

typedef enum diag_state_e {
    DIAG_ST_NONE,
    DIAG_ST_ACTING,
    DIAG_ST_COMPLETE,
    DIAG_ST_ERROR,
} diag_state_t;

typedef enum diag_err_e {
    /* module defined ERROR */
    DIAG_ERR_OK = 0,
    DIAG_ERR_PARAM,
    DIAG_ERR_NOMEM,

    /* TR-181 defined ERROR */
    DIAG_ERR_RESOLVE,       /* cannot resolve hostname */
    DIAG_ERR_MAXHOPS,       /* max hop exceeded - traceroute only */
    DIAG_ERR_INTERNAL,
    DIAG_ERR_OTHER,
} diag_err_t;

#define  DIAG_CFG_REF_STRING_LENGTH                 256

typedef struct diag_cfg_s {
    /* common configs */
    char        host[257];
    char        ifname[IFNAMSIZ];
    /* DH  Diag We have to be comptible with TR-181 -- it is not wise to do the opposite.*/
    char        Interface[DIAG_CFG_REF_STRING_LENGTH+1];
    unsigned    cnt;
    unsigned    timo;
    unsigned    size;
    unsigned    tos;
    unsigned    maxhop; /* trace route only */
} diag_cfg_t;

typedef struct ping_stat_s {
    unsigned    success;
    unsigned    failure;
    float       rtt_min;
    float       rtt_avg;
    float       rtt_max;
} ping_stat_t;

typedef struct tracert_hop_s {
    char        host[257];
    char        addr[65];   /* IPv4/IPv6 address */
    unsigned    icmperr;    /* ICMP error code */
    char        rtts[256];  /* string: RTTs for every probe of each hop */
} tracert_hop_t;

typedef struct tracert_stat_s {
    unsigned    resptime;
    unsigned    nhop;
    tracert_hop_t *hops;
} tracert_stat_t;

typedef struct diag_stat_s {
    union {
        ping_stat_t ping;
        tracert_stat_t tracert;
    } u;
} diag_stat_t;

typedef struct diag_pingtest_device_details_s {
    char        PartnerID[64]; 		 /* Partner ID */
    char        ecmMAC[32];   		 /* The MAC address for the eCM interface */
    char        DeviceID[256];    	 /* Serialnumber */
    char        DeviceModel[256];    /* Device Model */
} diag_pingtest_device_details_t;

typedef struct diag_pingtest_stat_s {
	diag_pingtest_device_details_t device_details;
} diag_pingtest_stat_t;

diag_err_t diag_init(void);
diag_err_t diag_term(void);

diag_err_t diag_start(diag_mode_t mode);
diag_err_t diag_stop(diag_mode_t mode);

diag_err_t diag_setcfg(diag_mode_t mode, const diag_cfg_t *cfg);
diag_err_t diag_getcfg(diag_mode_t mode, diag_cfg_t *cfg);

diag_err_t diag_getstatis(diag_mode_t mode, diag_stat_t *stat);
diag_err_t diag_getstate(diag_mode_t mode, diag_state_t *state);
diag_err_t diag_geterr(diag_mode_t mode, diag_err_t *state);
diag_err_t diag_pingtest_init(void);
diag_pingtest_device_details_t* diag_pingtest_getdevicedetails(void);

BOOL isDSLiteEnabled (void);
int getIPbyInterfaceName (char *interface, char *ip, size_t len);
BOOL isIPv4Host (const char *host);

#endif /* __DIAG_COMM_H__ */
