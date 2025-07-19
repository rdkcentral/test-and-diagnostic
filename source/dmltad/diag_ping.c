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
 * diag_ping.c - backend for IPPing
 * leichen2@cisco.com, Mar 2013, Initialize
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include "diag_inter.h"
#include "safec_lib_common.h"

#define PING_DEF_CNT        1
#define PING_DEF_TIMO       10000       /* mSec */
#define PING_DEF_SIZE       56

static diag_err_t ping_start(diag_obj_t *diag, const diag_cfg_t *cfg, diag_stat_t *st);
static diag_err_t ping_stop(diag_obj_t *diag);
static diag_err_t ping_forcestop(diag_obj_t *diag);

static diag_obj_t diag_ping = {
    .mode       = DIAG_MD_PING,
    .state      = DIAG_ST_NONE,
    .mutex      = PTHREAD_MUTEX_INITIALIZER,
    .cfg        = {
        .cnt        = PING_DEF_CNT,
        .timo       = PING_DEF_TIMO,
        .size       = PING_DEF_SIZE,
    },
    .ops        = {
        .start      = ping_start,
        .stop       = ping_stop,
        .forcestop  = ping_forcestop,
    },
};

diag_obj_t *diag_ping_load(void)
{
    return &diag_ping;
}

/*
 * Methods to implement "ping":
 *
 * 1. use built-in "ping" utility - esaiest way, but not compatible.
 * 2. porting open-source package and customization - best solution, 
 *    more compatible we can do it in the future (when ? emm.. )
 * 3. write own ICMP echo/response functions - NEVER DO IT.
 *    have to handle too may details incluing IPv4/IPv6 packet, and NDS.
 */
static diag_err_t ping_start(diag_obj_t *diag, const diag_cfg_t *cfg, diag_stat_t *st)
{
    char            cmd[1024];
    char            result[256];
    FILE            *fp;
    size_t          left;
    unsigned int    sent;
    int             copy;
    unsigned        cnt;
    errno_t         rc = -1;
    const char      *awkcmd = 
        " > /var/tmp/pinging.txt; cat /var/tmp/pinging.txt | awk -F'[ /]+' '/transmitted/ {SEND=$1; RECV=$4; }; "
        " /^ping:/ { print; exit } " /* capture ping error message */
        " /^round-trip/ { if ($5 == \"mdev\") { MIN=$7; AVG=$8; MAX=$9 } else { MIN=$6; AVG=$7; MAX=$8 } } "
        " /^rtt/ {MIN=$7; AVG=$8; MAX=$9 } "
        " END {print SEND, RECV, MIN, AVG, MAX}' 2>&1";

    assert(diag == &diag_ping);

    if (!cfg || !strlen(cfg->host) || !st)
        return DIAG_ERR_PARAM;

    cmd[0] = '\0', left = sizeof(cmd);

    if (cfg->cnt <= 0)
        cnt = PING_DEF_CNT; /* or never return */
    else
        cnt = cfg->cnt;

#if defined(_PLATFORM_TURRIS_)
    rc = sprintf_s(cmd + strlen(cmd), left, "ping ");
    if (rc < EOK)
    {
        ERR_CHK(rc);
    }
    else
    {
        left -= rc;
    }
#else
    rc = sprintf_s(cmd + strlen(cmd), left, "ping %s ", cfg->host);
    if (rc < EOK)
    {
        ERR_CHK(rc);
    }
    else
    {
        left -= rc;
    }
#endif
    if (isDSLiteEnabled() && isIPv4Host(cfg->host))
    {
        char ifip[16];

        if (getIPbyInterfaceName("brlan0", ifip, sizeof(ifip)) >= 0)
        {
            rc = snprintf(cmd + strlen(cmd), left, "-I %s ", ifip);
            if (rc < EOK)
            {
                ERR_CHK(rc);
            }
            else
            {
                left -= rc;
            }
        }
    }
    else
    {
        if (strlen(cfg->ifname))
        {
            rc = sprintf_s(cmd + strlen(cmd), left, "-I %s ", cfg->ifname);
            if (rc < EOK)
            {
                ERR_CHK(rc);
            }
            else
            {
                left -= rc;
            }
        }
    }

    if (cnt)
    {
        rc = sprintf_s(cmd + strlen(cmd), left, "-c %u ", cnt);
        if (rc < EOK)
        {
            ERR_CHK(rc);
        }
        else
        {
            left -= rc;
        }
    }
    if (cfg->size)
    {
        rc = sprintf_s(cmd + strlen(cmd), left, "-s %u ", cfg->size);
        if (rc < EOK)
        {
            ERR_CHK(rc);
        }
        else
        {
            left -= rc;
        }
    }
    if (cfg->timo)
    {
        rc = sprintf_s(cmd + strlen(cmd), left, "-W %u ", ((cfg->timo + 999) / 1000));  /* convert millisec to sec, rounding up */
        if (rc < EOK)
        {
            ERR_CHK(rc);
        }
        else
        {
            left -= rc;
        }
    }
#ifdef PING_HAS_QOS
    if (cfg->tos)
    {
        rc = sprintf_s(cmd + strlen(cmd), left, "-Q %u ", cfg->tos);
        if (rc < EOK)
        {
            ERR_CHK(rc);
        }
        else
        {
            left -= rc;
        }
    }
#endif

#if defined(_PLATFORM_TURRIS_)
    rc = sprintf_s(cmd + strlen(cmd), left, "%s ", cfg->host);
    if (rc < EOK)
    {
        ERR_CHK(rc);
    }
    else
    {
        left -= rc;
    }
#endif

    rc = sprintf_s(cmd + strlen(cmd), left, "2>&1 ");
    if (rc < EOK)
    {
        ERR_CHK(rc);
    }
    else
    {
        left -= rc;
    }

    if (left <= strlen(awkcmd) + 1)
        return DIAG_ERR_NOMEM;

    rc = sprintf_s(cmd + strlen(cmd), left, "%s ", awkcmd);
    if (rc < EOK)
    {
        ERR_CHK(rc);
    }

    fprintf(stderr, "%s: %s\n", __FUNCTION__, cmd);

    if ((fp = popen(cmd, "r")) == NULL)
        return DIAG_ERR_INTERNAL;

    if (fgets(result, sizeof(result), fp) == NULL) {
        pclose(fp);
        return DIAG_ERR_OTHER;
    }

    pclose(fp);

    fprintf(stderr, "%s: result: %s\n", __FUNCTION__, result);

    /* iputils ping error message: "ping: unknown host" */
    if (strncmp(result, "ping: unknown host", strlen("ping: unknown host")) == 0) {
        return DIAG_ERR_RESOLVE;
    }

    /* busybox ping error message: "ping: bad address" */
    if (strncmp(result, "ping: bad address", strlen("ping: bad address")) == 0) {
        return DIAG_ERR_RESOLVE;
    }

    /* capture all other ping error messages, e.g. "ping: sendto: Network is unreachable" */
    if (strncmp(result, "ping:", strlen("ping:")) == 0) {
        return DIAG_ERR_OTHER;
    }

    rc = memset_s(st, sizeof(*st), 0, sizeof(*st));
    ERR_CHK(rc);
    copy = sscanf(result, "%u %u %f %f %f", 
            &sent, &st->u.ping.success, &st->u.ping.rtt_min, 
            &st->u.ping.rtt_avg, &st->u.ping.rtt_max);

    if (copy == 5 || copy == 2) { /* RTT may not exist */
        if (sent > st->u.ping.success) {
            st->u.ping.failure = sent - st->u.ping.success;
        }
        return DIAG_ERR_OK;
    }

    return DIAG_ERR_OTHER;
}

static diag_err_t ping_stop(diag_obj_t *diag)
{
    assert(diag == &diag_ping);

    if (system("killall ping >/dev/null 2>&1") != 0)
        return DIAG_ERR_INTERNAL;
    return DIAG_ERR_OK;
}

static diag_err_t ping_forcestop(diag_obj_t *diag)
{
    assert(diag == &diag_ping);

    if (system("killall -9 ping >/dev/null 2>&1") != 0)
        return DIAG_ERR_INTERNAL;
    return DIAG_ERR_OK;
}
