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
 * diag.c - diagnostics API implementation.
 * leichen2@cisco.com, Mar 2013, Initialize
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>

#include "diag_inter.h"
#include "ccsp_base_api.h"
#include "safec_lib_common.h"

#include "ccsp_trace.h"

#ifdef UNIT_TEST_DOCKER_SUPPORT
#define STATIC
#else
#define STATIC static
#endif

extern ANSC_HANDLE bus_handle;
extern COSAGetParamValueByPathNameProc g_GetParamValueByPathNameProc;

int commonSyseventFd = -1;
token_t commonSyseventToken;

static int openCommonSyseventConnection() {
    if (commonSyseventFd == -1) {
        CcspTraceInfo(("%s: sysevent_open for TandD common usage\n", __FUNCTION__));

        commonSyseventFd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "common_Sysevent", &commonSyseventToken);
    }
    return 0;
}

int commonSyseventSet(char* key, char* value){
    if(commonSyseventFd == -1) {
        openCommonSyseventConnection();
    }
    return sysevent_set(commonSyseventFd, commonSyseventToken, key, value, 0);
}

int commonSyseventGet(char* key, char* value, int valLen){
    if(commonSyseventFd == -1) {
        openCommonSyseventConnection();
    }
    return sysevent_get(commonSyseventFd, commonSyseventToken, key, value, valLen);
}

/* XXX: if there are more instances, we may use a dynamic list to 
 * handle these instances, or with dynamic load. */

extern diag_obj_t *diag_ping_load(void);
extern diag_obj_t *diag_tracert_load(void);

STATIC diag_obj_t *diag_ping;
STATIC diag_obj_t *diag_tracert;
diag_pingtest_stat_t diag_pingtest_stat;

static diag_err_t diag_init_blocksize (void);

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#if defined (NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)

#define SE_IP_ADDR      "127.0.0.1"
#define SE_PROG_NAME    "tad"
#define MAPT_INTERFACE  "map0"
static bool is_MAPT();
static bool is_IPv6(const char *);

#endif //NAT46_KERNEL_SUPPORT
#endif //_HUB4_PRODUCT_REQ_

static void trim(char *line)
{
    char *cp;

    if (!line || !strlen(line))
        return;

    for (cp = line + strlen(line) - 1; cp >= line && isspace(*cp); cp--)
        *cp = '\0';

    for (cp = line; *cp && isspace(*cp); cp++)
        ;

    if (cp > line)
        memmove(line, cp, strlen(cp) + 1);

    return;
}

static int is_empty(const char *line)
{
    while (*line++)
        if (!isspace(*line))
            return 0;
    return 1;
}

/* addr is in network order */
static int inet_is_same_net(uint32_t addr1, uint32_t addr2, uint32_t mask)
{
    return (addr1 & mask) == (addr2 & mask);
}

static int inet_is_onlink(const struct in_addr *addr)
{
    char cmd[1024+50];
    char table[1024];
    char entry[1024];
    FILE *rule_fp;
    FILE *tbl_fp;
    char *pref;
    struct in_addr net;
    uint32_t mask;
    errno_t rc = -1;

    if (!addr)
        return 0;

    /*  
     * let's just lookup the duplicated table,
     * btw, if we "sort | uniq" it the priory is changed
     */
    rc = strcpy_s(cmd, sizeof(cmd), "ip rule show | sed -n 's/.*\\<lookup\\> \\(.*\\)/\\1/p'");
    ERR_CHK(rc);
    if ((rule_fp = popen(cmd, "r")) == NULL)
        return 0;

    while (fgets(table, sizeof(table), rule_fp)) {
        trim(table);
        if (is_empty(table) || strcmp(table, "local") == 0)
            continue;

        rc = sprintf_s(cmd, sizeof(cmd), "ip route show table %s | awk '/\\<link\\>/ {print $1}'", table);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        if ((tbl_fp = popen(cmd, "r")) == NULL) {
            pclose(rule_fp);
            return 0;
        }

        while (fgets(entry, sizeof(entry), tbl_fp)) {
            trim(entry);
            if (is_empty(entry))
                continue;

            if ((pref = strchr(entry, '/')) == NULL)
                continue;
            *pref++ = '\0';

            if (inet_pton(AF_INET, entry, &net) <= 0)
                continue;
            int prefix_len = atoi(pref);
            if (prefix_len > 0 && prefix_len <= 32) {
                mask = htonl(0xFFFFFFFF << (32 - prefix_len));

                if (inet_is_same_net(*(uint32_t *)(addr), *(uint32_t *)&net, mask)) {
                    pclose(tbl_fp);
                    pclose(rule_fp);
                    return 1; /* on-link */
                }
            }
        }

        pclose(tbl_fp);
    }

    pclose(rule_fp);
    return 0;
}

static int inet_is_local(const struct in_addr *addr)
{
    char entry[1024];
    FILE *fp;
    char *tok, *delim = " \t\r\n", *sp;
    char *dest, *preflen;
    struct in_addr inaddr;

    if (!addr)
        return 0;

    /* 
     * lookup local table to check:
     * 1. broadcast to local network 'broadcast xxx.xxx.xxx.xxx'
     * 2. unicast to address of local device, 'local xxx.xxx.xxx.xxx'
     * 3. unicast to address in same network e.g,. "xxx.xxx.xxx.xxx/xx" 
     */

    if ((fp = popen("ip route show table local", "r")) == NULL)
        return 0;

    while (fgets(entry, sizeof(entry), fp) != NULL) {
        trim(entry);

        if ((tok = strtok_r(entry, delim, &sp)) == NULL)
            continue;
        if ((dest = strtok_r(NULL, delim, &sp)) == NULL)
            continue;

        if ((preflen = strchr(dest, '/')) != NULL)
            *preflen++ = '\0';
        if (inet_pton(AF_INET, dest, &inaddr) <= 0)
            continue;

        /* check 'broadcast' and 'local' for save */
        if (strcmp(tok, "broadcast") == 0 
                || (strcmp(tok, "local") == 0 && !preflen)) {
            if (*(uint32_t *)&inaddr == *(uint32_t *)addr) {
                pclose(fp);
                return 1;
            }
        } else if (strcmp(tok, "local") == 0 && preflen) {
            int prefix = atoi(preflen);
            if (prefix > 0 && prefix <= 32) {
                uint32_t mask = (prefix == 32) ? 0xFFFFFFFF : htonl(0xFFFFFFFF << (32 - prefix));
                if (inet_is_same_net(*(uint32_t *)addr, *(uint32_t *)&inaddr, mask)) {
                    pclose(fp);
                    return 1;
                }
            }

        } else {
            continue; // never got here actually
        }
    }

    pclose(fp);
    return 0;
}
static bool is_ipv6_same(const struct in6_addr *addr1,
        const struct in6_addr *addr2)
{
	int i;
	
	for(i=0;i<4;i++)
	{	
		if(!(addr1->s6_addr32[i]==addr2->s6_addr32[i]))
		{
			return 0;
		}
		
	}
	return 1;
}
static bool is_prefix_equal(const struct in6_addr *addrs1,
        const struct in6_addr *addrs2,
        unsigned int prefixlen)
{
    unsigned int pdw, pbi, pdw2,i;
	unsigned int mask=0x1f;
	bool bFlag = true;
	
    /* check complete u32 in prefix */
    pdw = prefixlen >> 5;
	pdw2 = pdw<<2;
	for(i=0;i<pdw2;i++)
	{
		if(!(addrs1->s6_addr32[i]==addrs2->s6_addr32[i]))
		{
			bFlag = false;
			break;
		}
	}
    if (pdw && bFlag)
        return false;

    /* check incomplete u32 in prefix */
    pbi = prefixlen & mask;
	mask = htonl((0xffffffff) << (32 - pbi));
    if (pbi && ((addrs1->s6_addr32[pdw] ^ addrs2->s6_addr32[pdw]) & mask))
        return false;

    return true;
}

/* 
 * to check if next hop of the addrs is default route ?
 * entry output
 *   local <addr> ...
 *   <addr>/<pref> ...
 *   <addr> ...
 * e.g.,
 *   local fe80::2676:7dff:feff:e16d via :: dev lo  proto none  metric 0 
 *   ff00::/8 dev l2sm0  metric 256 
 */
static bool inet6_nexthop_not_def(const struct in6_addr *addr)
{
    /* look up all tables */
    FILE *rule_fp = NULL, *tbl_fp = NULL;
    char cmd[128+407], table[512], entry[512];
    char *dest, *delim = " \t\r\n", *sp, *preflen;
    struct in6_addr daddr;
    errno_t rc = -1;

    rule_fp = popen("ip -6 rule show | sed -n 's/.*\\<lookup\\> \\(.*\\)/\\1/p'", "r");
    if (!rule_fp)
        return false;

    while (fgets(table, sizeof(table), rule_fp)) {
        trim(table);
        if (is_empty(table))
            continue;

        rc = sprintf_s(cmd, sizeof(cmd), "ip -6 route show table %s", table);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        if ((tbl_fp = popen(cmd, "r")) == NULL)
            break;

        while (fgets(entry, sizeof(entry), tbl_fp)) {
            trim(entry);
            if (is_empty(entry))
                continue;

            if (!(dest = strtok_r(entry, delim, &sp)))
                continue;
            if (strcmp(dest, "default") == 0)
                continue;
            if (strcmp(dest, "local") == 0)
                if (!(dest = strtok_r(NULL, delim, &sp)))
                    continue;

            if ((preflen = strchr(dest, '/')) != NULL)
                *preflen++ = '\0';

            if (inet_pton(AF_INET6, dest, &daddr) <= 0)
                continue;

            if (!preflen) {
                if (is_ipv6_same(addr, &daddr)) {
                    pclose(tbl_fp);
                    pclose(rule_fp);
                    return true;
                }
            } else {
                if (is_prefix_equal(addr, &daddr, atoi(preflen))) {
                    pclose(tbl_fp);
                    pclose(rule_fp);
                    return true;
                }
            }
        }

        pclose(tbl_fp);
    }

    pclose(rule_fp);
    return false;
}

static const char *assign_iface(const char *host, char *buf, size_t size)
{
    struct in_addr inaddr;
    struct in6_addr in6addr;
    errno_t rc = -1;

    if (inet_pton(AF_INET, host, &inaddr) > 0) {
        if (inet_is_local(&inaddr))
            return NULL;
        if (inet_is_onlink(&inaddr))
            return NULL;
    } else if (inet_pton(AF_INET6, host, &in6addr) > 0) {
        if (inet6_nexthop_not_def(&in6addr))
            return NULL;
    }

    commonSyseventGet("current_wan_ifname", buf, size);
    CcspTraceInfo(("%s: current_wan_ifname is %s\n", __FUNCTION__, buf));
    if (buf[0] == '\0')
    {
        rc = strcpy_s(buf, size, "erouter0");
        ERR_CHK(rc);
    }

    return buf;
}

static diag_obj_t *get_diag_by_mode(diag_mode_t mode)
{
    switch (mode) {
    case DIAG_MD_PING:
        return diag_ping;
    case DIAG_MD_TRACERT:
        return diag_tracert;
    default:
        return NULL;
    }
}

static diag_err_t __diag_stop(diag_obj_t *diag)
{
#ifdef _GNU_SOURCE
    struct timespec timo;
#endif

    diag->op_stop(diag);
    pthread_mutex_unlock(&diag->mutex);

#ifdef _GNU_SOURCE
    timo.tv_sec = 3;
    timo.tv_nsec = 0;
    if (pthread_timedjoin_np(diag->task, NULL, &timo) != 0) {
        fprintf(stderr, "%s: not return, force stop it\n", __FUNCTION__);
        pthread_mutex_lock(&diag->mutex);
        if (diag->op_forcestop)
            diag->op_forcestop(diag);
        pthread_mutex_unlock(&diag->mutex);

        pthread_cancel(diag->task);
        pthread_join(diag->task, NULL);
    }
#else
    pthread_join(diag->task, NULL);
#endif
    pthread_mutex_lock(&diag->mutex);
    diag->state = DIAG_ST_NONE;

    return DIAG_ERR_OK;
}

static void *diag_task(void *arg)
{
    diag_obj_t  *diag = arg;
    diag_cfg_t  cfg;
    diag_stat_t stat;
    diag_err_t  err;
    char        buf[IFNAMSIZ];
    int retrycount;
    errno_t rc = -1;

    if (!diag)
        return NULL;

    pthread_mutex_lock(&diag->mutex);
    cfg = diag->cfg;
    pthread_mutex_unlock(&diag->mutex);

    /* RDKB-12522:If Diagstate comes first and wait for daig params to set */
    retrycount = 0;
    while (strlen(cfg.host) == 0)
    {
        sleep(1);
        pthread_mutex_lock(&diag->mutex);
        cfg = diag->cfg;
        pthread_mutex_unlock(&diag->mutex);
        if (++retrycount >= 5)
            break;
    }

#if defined(_PLATFORM_RASPBERRYPI_) || (_PLATFORM_TURRIS_) || defined(_PLATFORM_BANANAPI_R4_)
/**
 inet_pton is failing because of extra quotes in ip address (cfg.host)
**/
    int len = strlen(cfg.host);
    if( (cfg.host[0] == '\'') && (cfg.host[len-1] == '\'') )
    {
        memmove(cfg.host,&cfg.host[1],len-2);
        cfg.host[len-2]='\0';
    }
#endif

    /**
     * XXX: work around for dual WAN issue.
     * We have two WAN default route, one for wan0 another for erouter0.
     * if wan0 is not connect to Internel and erouter0 is.
     * ping LAN/WAN must also be OK. 
     *
     * consider if wan0 is connected to Internet and no -I is OK.
     * but LAN user cannot access Internet since.
     *
     * wo have policy route for traffic from LAN (direct to erotuer0)
     * but not for localout traffic (ping).
     */
    if (!strlen(cfg.ifname) && assign_iface(cfg.host, buf, sizeof(buf))) {
        rc = strcpy_s(cfg.ifname, sizeof(cfg.ifname), buf);
        ERR_CHK(rc);
        fprintf(stderr, "%s: Changing ifname to %s !!!!\n", __FUNCTION__, buf);
    }

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#if defined (NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)

    if(is_MAPT() == TRUE && is_IPv6(cfg.host) == FALSE)
    {
        rc = strcpy_s(cfg.ifname, sizeof(cfg.ifname), MAPT_INTERFACE);
        ERR_CHK(rc);
        fprintf(stderr, "%s: Changing ifname to %s !!!!\n", __FUNCTION__, cfg.ifname);
    }

#endif //NAT46_KERNEL_SUPPORT
#endif //_HUB4_PRODUCT_REQ_

    err = diag->op_start(diag, &cfg, &stat);

    fprintf(stderr, "%s: op_start %d\n", __FUNCTION__, err);

    pthread_mutex_lock(&diag->mutex);
    switch (err) {
    case DIAG_ERR_OK:
        diag->state = DIAG_ST_COMPLETE;
        diag->stat = stat;
        diag->err = DIAG_ERR_OK;
        break;
    default:
        diag->state = DIAG_ST_ERROR;
        if (err >= DIAG_ERR_RESOLVE)
            diag->err = err;
        else
            diag->err = DIAG_ERR_OTHER;
        break;
    }
    pthread_mutex_unlock(&diag->mutex);

    return NULL;
}

diag_err_t diag_init(void)
{
	//diagnositic PING test initialization
	diag_pingtest_init( );

	if ((diag_ping = diag_ping_load()) == NULL)
        goto errout;

    if ((diag_tracert = diag_tracert_load()) == NULL) {
        goto errout;
    }

    diag_init_blocksize();

    return DIAG_ERR_OK;

errout:
    // TODO:
    return DIAG_ERR_INTERNAL;
}

diag_err_t diag_term(void)
{
    // TODO:
    diag_ping = NULL;
    diag_tracert = NULL;
    return DIAG_ERR_OK;
}

diag_err_t diag_start(diag_mode_t mode)
{
    diag_obj_t *diag = get_diag_by_mode(mode);
    errno_t rc = -1;

    if (!diag)
        return DIAG_ERR_PARAM;

    pthread_mutex_lock(&diag->mutex);
    /* need recyle even DIAG_ST_COMPLETE/ERROR */
    if (diag->state != DIAG_ST_NONE) {
        if (__diag_stop(diag) != DIAG_ERR_OK) {
            pthread_mutex_unlock(&diag->mutex);
            fprintf(stderr, "%s: fail to stop acting diag\n", __FUNCTION__);
            return DIAG_ERR_INTERNAL;
        }
    }

    if (diag->op_clearstatis)
        diag->op_clearstatis(diag);
    rc = memset_s(&diag->stat, sizeof(diag->stat), 0, sizeof(diag->stat));
    ERR_CHK(rc);

    if (pthread_create(&diag->task, NULL, diag_task, diag) != 0) {
        diag->state = DIAG_ST_ERROR;
        diag->err = DIAG_ERR_INTERNAL;
        pthread_mutex_unlock(&diag->mutex);
        fprintf(stderr, "%s: fail to start diag task\n", __FUNCTION__);
        return DIAG_ERR_INTERNAL;
    }

    diag->state = DIAG_ST_ACTING;
    pthread_mutex_unlock(&diag->mutex);
    return DIAG_ERR_OK;
}

diag_err_t diag_stop(diag_mode_t mode)
{
    diag_obj_t *diag = get_diag_by_mode(mode);
    diag_err_t err = DIAG_ERR_OK;

    if (!diag)
        return DIAG_ERR_PARAM;

    pthread_mutex_lock(&diag->mutex);
    /* need recyle even DIAG_ST_COMPLETE/ERROR */
    if (diag->state != DIAG_ST_NONE)
        err = __diag_stop(diag);
    diag->state = DIAG_ST_NONE;

    if (mode == DIAG_MD_PING)
    {
        FILE *fp;

        if ((fp = popen("cat /var/tmp/pinging.txt | grep from | wc -l", "r")) == NULL)
        {
            err = DIAG_ERR_INTERNAL;
        }
        else
        {
            char result[16];

            if (fgets(result, sizeof(result), fp) == NULL)
            {
                err = DIAG_ERR_OTHER;
            }
            else
            {
                diag->stat.u.ping.success = atoi(result);
                fprintf(stderr, "%s: diag->stat.u.ping.success=%d\n", __FUNCTION__, diag->stat.u.ping.success);
            }

            pclose(fp);
        }
    }

    pthread_mutex_unlock(&diag->mutex);

    if (err != DIAG_ERR_OK)
        fprintf(stderr, "%s: fail to stop diag\n", __FUNCTION__);
    return err;
}

diag_err_t diag_setcfg(diag_mode_t mode, const diag_cfg_t *cfg)
{
    diag_obj_t *diag = get_diag_by_mode(mode);
    errno_t rc = -1;

    if (!diag)
        return DIAG_ERR_PARAM;

    pthread_mutex_lock(&diag->mutex);
/*RDKB-12522:From TR-181, "If the ACS sets the value of this parameter to Requested, the CPE MUST initiate the corresponding diagnostic test. When writing, the only allowed value is Requested. To ensure the use of the proper test parameters (the writable parameters in this object), the test parameters MUST be set either prior to or at the same time as (in the same SetParameterValues) setting the DiagnosticsState to Requested."
Mamidi:If we stop the diag test here that is causing the actual test to stop  and assigning the diag state to none(if setparams comes with Diagstate and params comes in a sigle call). This logic is expecting that always set params like host, numberofRepetions... comes in one setparams call and Requested comes in a separate setparams calls.
*/
#if 0
    /* need recyle even DIAG_ST_COMPLETE/ERROR */
    if (diag->state != DIAG_ST_NONE) {
        if ((err = __diag_stop(diag)) != DIAG_ERR_OK) {
            pthread_mutex_unlock(&diag->mutex);
            fprintf(stderr, "%s: fail to stop actiing diag\n", __FUNCTION__);
            return err;
        }
    }
#endif

    memcpy(&diag->cfg, cfg, sizeof(diag_cfg_t));

    if (diag->op_clearstatis)
        diag->op_clearstatis(diag);
    rc = memset_s(&diag->stat, sizeof(diag->stat), 0, sizeof(diag->stat));
    ERR_CHK(rc);
    diag->state = DIAG_ST_NONE;
    pthread_mutex_unlock(&diag->mutex);

    return DIAG_ERR_OK;
}

diag_err_t diag_getcfg(diag_mode_t mode, diag_cfg_t *cfg)
{
    diag_obj_t *diag = get_diag_by_mode(mode);

    if (!diag)
        return DIAG_ERR_PARAM;

    pthread_mutex_lock(&diag->mutex);
    memcpy(cfg, &diag->cfg, sizeof(diag_cfg_t));
    pthread_mutex_unlock(&diag->mutex);

    return DIAG_ERR_OK;
}

diag_err_t diag_getstatis(diag_mode_t mode, diag_stat_t *stat)
{
    diag_obj_t *diag = get_diag_by_mode(mode);

    if (!diag)
        return DIAG_ERR_PARAM;

    pthread_mutex_lock(&diag->mutex);
    *stat = diag->stat;
    pthread_mutex_unlock(&diag->mutex);

    return DIAG_ERR_OK;
}

diag_err_t diag_getstate(diag_mode_t mode, diag_state_t *state)
{
    diag_obj_t *diag = get_diag_by_mode(mode);

    if (!diag)
        return DIAG_ERR_PARAM;

    pthread_mutex_lock(&diag->mutex);
    *state = diag->state;
    pthread_mutex_unlock(&diag->mutex);

    return DIAG_ERR_OK;
}

diag_err_t diag_geterr(diag_mode_t mode, diag_err_t *error)
{
    diag_obj_t *diag = get_diag_by_mode(mode);

    if (!diag)
        return DIAG_ERR_PARAM;

    pthread_mutex_lock(&diag->mutex);
    *error = diag->err;
    pthread_mutex_unlock(&diag->mutex);

    return DIAG_ERR_OK;
}

static diag_err_t diag_init_blocksize (void)
{
    char buf[12];

    syscfg_get(NULL, "selfheal_ping_DataBlockSize", buf, sizeof(buf));

    if (buf[0] != 0)
    {
        diag_cfg_t cfg;

        if (diag_getcfg(DIAG_MD_PING, &cfg) != DIAG_ERR_OK) {
            return DIAG_ERR_PARAM;
        }

        cfg.size = atoi(buf);

        if (diag_setcfg(DIAG_MD_PING, &cfg) != DIAG_ERR_OK) {
            return DIAG_ERR_PARAM;
        }
    }

    return DIAG_ERR_OK;
}

diag_err_t diag_pingtest_init( void )
{
	diag_pingtest_device_details_t *pingtest_devdet = diag_pingtest_getdevicedetails( );

	/* validation */
	if( NULL == pingtest_devdet )
	{
		return DIAG_ERR_PARAM;
	}

	//PartnerID
	getPartnerId( pingtest_devdet->PartnerID );
	
	//ecmMAC
	pingtest_devdet->ecmMAC[ 0 ] = '\0';

	//Device ID
	pingtest_devdet->DeviceID[ 0 ] = '\0';
	
	//Device Model
	pingtest_devdet->DeviceModel[ 0 ] = '\0';

	return DIAG_ERR_OK;
}

diag_pingtest_device_details_t* diag_pingtest_getdevicedetails(void)
{
    return ( &diag_pingtest_stat.device_details);
}

#if defined (FEATURE_MAPT) || defined (FEATURE_SUPPORT_MAPT_NAT46)
#if defined (NAT46_KERNEL_SUPPORT) || defined (FEATURE_SUPPORT_MAPT_NAT46)

static bool is_MAPT()
{
    int sysevent_fd = -1;
    token_t sysevent_token;
    char buf[128] = {'\0'};
    int ret = FALSE;

    sysevent_fd =  sysevent_open(SE_IP_ADDR, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, SE_PROG_NAME, &sysevent_token);
    if (sysevent_fd >= 0)
    {
        if (0 == sysevent_get(sysevent_fd, sysevent_token, "mapt_config_flag", buf, sizeof(buf)))
	{
	    if (0 == strcmp(buf, "set"))
	    {
                ret = TRUE;
                fprintf(stderr, "%s: MAPT Mode !!!!\n", __FUNCTION__);
	    }
	}
	else
	{
	    fprintf(stderr, "%s:  sysevent_get FAIL !!!!\n", __FUNCTION__);
	}
	sysevent_close(sysevent_fd, sysevent_token);
    }
    else
    {
        fprintf(stderr, "%s:  sysevent_open FAIL !!!!\n", __FUNCTION__);
    }

    return ret;
}

static bool is_IPv6(const char *host)
{
    int ret = FALSE;
    struct in6_addr in6addr;
    char *ipPtr = NULL;

    if( (host[0] == '\'') && (host[strlen(host)-1] == '\'') )
    {
        ipPtr = strdup(host+1);
        if(ipPtr != NULL)
        {
            ipPtr[strlen(ipPtr)-1] = '\0';

            if (inet_pton(AF_INET6, ipPtr, &in6addr) > 0)
            {
                ret = TRUE;
            }
            free((char*)ipPtr);
        }
    }
    return ret;
}

#endif //NAT46_KERNEL_SUPPORT
#endif //_HUB4_PRODUCT_REQ_

BOOL isDSLiteEnabled (void)
{
    ANSC_STATUS retval;
    parameterValStruct_t param;
    char value[16] = { 0 };
    ULONG valSize;

    param.parameterName = "Device.DSLite.InterfaceSetting.1.Status";
    param.parameterValue = value;
    valSize = sizeof(value);

    retval = g_GetParamValueByPathNameProc(bus_handle, &param, &valSize);

    if (retval == ANSC_STATUS_SUCCESS) {
        if (strcmp(value, "Enabled") == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

int getIPbyInterfaceName (char *interface, char *ip, size_t len)
{
    int fd;
    struct ifreq ifr;

    snprintf(ip, len, "0.0.0.0");

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) >= 0) {
        snprintf(ip, len, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    }

    close(fd);

    return 0;
}

BOOL isIPv4Host (const char *host)
{
    struct addrinfo hints, *res, *rp;
    int errcode;
    BOOL isIpv4 = FALSE;

    memset (&hints, 0, sizeof (hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    errcode = getaddrinfo (host, NULL, &hints, &res);
    if (errcode != 0) {
        return FALSE;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            isIpv4 = TRUE;
            break;
        }
    }

    if (res != NULL) {
        freeaddrinfo(res);
    }

    return isIpv4;
}
