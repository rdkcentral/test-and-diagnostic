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
 * diag_traceroute.c - backend for TraceRoute
 * leichen2@cisco.com, 1 Apr 2014, Initialize
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include "diag_inter.h"
#include "ansc_platform.h"
#include "safec_lib_common.h"

#define TRACERT_DEF_CNT     3
#define TRACERT_DEF_TIMO    5000        /* mSec */
#define TRACERT_DEF_SIZE    64
#define TRACERT_DEF_MAXHOP  30

static diag_err_t tracert_start(diag_obj_t *diag, const diag_cfg_t *cfg, diag_stat_t *stat);
static diag_err_t tracert_stop(diag_obj_t *diag);
static diag_err_t tracert_forcestop(diag_obj_t *diag);
static diag_err_t tracert_clearstatis(diag_obj_t *diag);

static diag_obj_t diag_tracert = {
    .mode       = DIAG_MD_TRACERT,
    .state      = DIAG_ST_NONE,
    .mutex      = PTHREAD_MUTEX_INITIALIZER,
    .cfg        = {
        .cnt    = TRACERT_DEF_CNT,
        .timo   = TRACERT_DEF_TIMO,
        .size   = TRACERT_DEF_SIZE,
        .maxhop = TRACERT_DEF_MAXHOP,
    },
    .ops        = {
        .start      = tracert_start,
        .stop       = tracert_stop,
        .forcestop  = tracert_forcestop,
        .clearstatis= tracert_clearstatis,
    },
};

/*
 * 72.872 ms  72.517 ms  71.808 ms
 * 72.311 ms  71.855 ms  71.536 ms
 * 72.243 ms 209.85.243.156 (209.85.243.156)  72.803 ms 209.85.243.158 (209.85.243.158)  71.727 ms
 *
 * for the third case the response comes from different nodes
 * as TR181 do not support that, let's discard the "address(name)" info.
 */
static void convert_rtts(char *rtts, size_t size
#if !defined (_PLATFORM_RASPBERRYPI_)
, float *sum, int *counter, int timeout
#endif
)
{
    char *tok1, *tok2, *delim = " \t\r\n", *sp;
    char *start, buf[1024];
    float f;
    errno_t rc = -1;

    buf[0] = '\0';
#if defined(_PLATFORM_RASPBERRYPI_)
    for (start = rtts; 
            (tok1 = strtok_r(start, delim, &sp)) && (tok2 = strtok_r(NULL, delim, &sp));
            start = NULL) {
        if (strcmp(tok2, "ms") == 0) {
            sscanf(tok1, "%f", &f);
            if (start)
            {
                rc = sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), "%d", (int)f);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }
            }
            else
            {
                rc = sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), ",%d", (int)f);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }
            }
        } else if (tok2[0] == '(') {
            continue;
        } else {
            return; // bad format
#else
	if(strcmp(rtts, "") == 0)
	{
		*sum = *sum+timeout;
		*counter = *counter+1;
	}
    for (start = rtts; (tok1 = strtok_r(start, delim, &sp)) && (tok2 = strtok_r(NULL, delim, &sp));start = NULL)
    {
        if (strcmp(tok2, "ms") == 0)
        {
            sscanf(tok1, "%f", &f);
			*sum = *sum+f;
			*counter=*counter+1;
            if (start)
            {
                rc = sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), "%d", (int)f);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }
            }
            else
            {
                rc = sprintf_s(buf + strlen(buf), sizeof(buf) - strlen(buf), ",%d", (int)f);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }
            }
        }
        else if (strcmp(tok2, "*") == 0 || strcmp(tok1, "*") == 0)
        {
            *sum = *sum+timeout;
            *counter = *counter+1;
        }
		else
		{
            continue;
#endif
        }   
    }

    rc = sprintf_s(rtts, size, "%s", buf);
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }

    if(rc >= size){
        AnscTraceWarning(("%s: String overflow while copying rtts=%s, buf=%s\n", __FUNCTION__, rtts, buf));
    }
}

diag_obj_t *diag_tracert_load(void)
{
    return &diag_tracert;
}

static diag_err_t tracert_start(diag_obj_t *diag, const diag_cfg_t *cfg, diag_stat_t *stat)
{
    char cmd[512];
    char line[512];
    size_t left;
    FILE *fp;
    errno_t rc = -1;
#if !defined(_PLATFORM_RASPBERRYPI_)
    int timeout;
    float avgresptime=0;
#endif
    diag_err_t err = DIAG_ERR_INTERNAL;
    assert(diag == &diag_tracert);

    if (!cfg || !strlen(cfg->host) || !stat)
        return DIAG_ERR_PARAM;

    cmd[0] = '\0', left = sizeof(cmd);

#if !defined(_PLATFORM_RASPBERRYPI_)
    timeout = cfg->timo;
    rc = sprintf_s(cmd + strlen(cmd), left, "traceroute %s ", cfg->host);
    if (rc < EOK)
    {
        ERR_CHK(rc);
    }
    else
    {
        left -= rc;
    }
#else
    rc = sprintf_s(cmd + strlen(cmd), left, "traceroute '%s' ", cfg->host);
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
            rc = snprintf(cmd + strlen(cmd), left, "-s %s ", ifip);
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
            rc = sprintf_s(cmd + strlen(cmd), left, "-i %s ", cfg->ifname);
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

    if (cfg->cnt)
    {
        rc = sprintf_s(cmd + strlen(cmd), left, "-q %u ", cfg->cnt);
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
        rc = sprintf_s(cmd + strlen(cmd), left, "-w %u ", ((cfg->timo + 999) / 1000));  /* convert millisec to sec, rounding up */
        if (rc < EOK)
        {
            ERR_CHK(rc);
        }
        else
        {
            left -= rc;
        }
    }
    if (cfg->tos)
    {
        rc = sprintf_s(cmd + strlen(cmd), left, "-t %u ", cfg->tos);
        if (rc < EOK)
        {
            ERR_CHK(rc);
        }
        else
        {
            left -= rc;
        }
    }
    if (cfg->maxhop)
    {
        rc = sprintf_s(cmd + strlen(cmd), left, "-m %u ", cfg->maxhop);
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
        rc = sprintf_s(cmd + strlen(cmd), left, "%u ", cfg->size);
        if (rc < EOK)
        {
            ERR_CHK(rc);
        }
        else
        {
            left -= rc;
        }
    }

    rc = sprintf_s(cmd + strlen(cmd), left, "2>&1 ");
    if (rc < EOK)
    {
        ERR_CHK(rc);
    }
    else
    {
        left -= rc;
    }

    fprintf(stderr, "%s: %s\n", __FUNCTION__, cmd);

    if ((fp = popen(cmd, "r")) == NULL) {
        return DIAG_ERR_INTERNAL;
    }

    if (fgets(line, sizeof(line), fp) == NULL) {
        pclose(fp);
        return DIAG_ERR_OTHER;
    }

    rc = memset_s(stat, sizeof(diag_stat_t), 0, sizeof(diag_stat_t));
    ERR_CHK(rc);

    if (strncmp(line, "traceroute to", strlen("traceroute to")) != 0) {
        if (strstr(line, "Name or service not known") != NULL
                || strstr(line, "bad address") != NULL)
            err = DIAG_ERR_RESOLVE;
        else
            err = DIAG_ERR_OTHER;
    } else {
        unsigned nhop = 0;
        tracert_hop_t *hops = NULL;
        void *ptr;
        int idx;
        char msg[300], dest_ip[65];
#if !defined(_PLATFORM_RASPBERRYPI_)
	int dest_reached=0;
        char query_ip[65], line_cpy[512];
        float *sum,val=0;
        int *counter,count=0;
        size_t len;
        sum=&val;
        counter=&count;
#endif
        /* traceroute to xxx.cisco.com (10.112.0.118), 30 hops max, 60 byte packets */
        sscanf(line,"%[^(] (%[^)])",msg,dest_ip);

        while (fgets(line, sizeof(line), fp) != NULL) {
            if (strstr(line, "Invalid argument") != NULL){
                if (hops) free(hops);
                pclose(fp);
                return DIAG_ERR_OTHER;
            }
            ptr = realloc(hops, (nhop + 1) * sizeof(tracert_hop_t));
            if (ptr == NULL) {
                if (hops) free(hops);
                fprintf(stderr, "%s: no memory\n", __FUNCTION__);
                pclose(fp);/*RDKB-7458, CID-33358, free unused resources before exit */
                return DIAG_ERR_NOMEM;
            }
            hops = ptr;

            /* 9  xxx.cisco.com (10.112.0.118)  40.469 ms  40.092 ms  40.528 ms */
            rc = memset_s(&hops[nhop], sizeof(tracert_hop_t), 0, sizeof(tracert_hop_t));
            ERR_CHK(rc);
            sscanf(line, "%d %s (%[^)]) %[^\n]",
                    &idx, hops[nhop].host, hops[nhop].addr, hops[nhop].rtts);
            /* TR-181 doesn't like the format, let's convert it */
#if !defined(_PLATFORM_RASPBERRYPI_)
            convert_rtts(hops[nhop].rtts, sizeof(hops[nhop].rtts), sum, counter, timeout);
#else
            convert_rtts(hops[nhop].rtts, sizeof(hops[nhop].rtts));
#endif
            hops[nhop].icmperr = 0; // TODO: we can use output: '!H, !S, ...'
#if !defined(_PLATFORM_RASPBERRYPI_)
            len = strlen (line);
            if (len >= sizeof(line_cpy))
                len = sizeof(line_cpy) - 1;
            memcpy (line_cpy, line, len);
            line_cpy[len] = 0;
            char* savePtr;
            char* token = strtok_r(line_cpy, "(",&savePtr);
            while ((token = (strtok_r(savePtr, "(",&savePtr)))) {
                sscanf(token, "%[^)]",query_ip);
                if (!strncmp(query_ip,dest_ip,strlen(query_ip))) {
                  dest_reached=1;
                  break;
                }
            }
#endif
            nhop++;
        }
#if !defined(_PLATFORM_RASPBERRYPI_)
        avgresptime=*sum/(*counter);
        stat->u.tracert.resptime = avgresptime;
        *sum = 0;
        *counter = 0;
#endif
        stat->u.tracert.nhop = nhop;
        stat->u.tracert.hops = hops;

        if((nhop > 0) && (nhop >= cfg->maxhop) && (strncmp(dest_ip,hops[nhop-1].addr,65)!=0))
        {
	    stat->u.tracert.resptime = 0;
	    err = DIAG_ERR_MAXHOPS;
        }
        else
        {
	    int rtt_sum = 0, rtt_count = 0, resp =0;
	    char rtts[256];
	    char *rtt, *sp;
#if !defined(_PLATFORM_RASPBERRYPI_)
	    if(nhop > 0 && dest_reached==1)
#else
	    if(nhop > 0 && (strncmp(dest_ip,hops[nhop-1].addr,65)==0))
#endif
	    {
	        strncpy(rtts,hops[nhop-1].rtts,256);
		sp = rtts;
		while((rtt = (strtok_r(sp,",",&sp))))
		{
		   rtt_sum += atoi(rtt);
		   rtt_count++;
		}
		if(rtt_count > 0)
		{
		    resp = rtt_sum/rtt_count;
		}
#if !defined(_PLATFORM_RASPBERRYPI_)
                dest_reached=0;
#endif
	    }
	    stat->u.tracert.resptime = resp;
	    err = DIAG_ERR_OK;
        }
    }

    fprintf(stderr, "> done: %d\n", err);
    {
        unsigned int i;
        tracert_hop_t *hop;

        fprintf(stderr, "nhop: %u resp %u\n", stat->u.tracert.nhop, stat->u.tracert.resptime);
        for (i = 0; i < stat->u.tracert.nhop; i++) {
            hop = &stat->u.tracert.hops[i];
            fprintf(stderr, "hop[%d]: host %s addr %s icmp %u rtts: %s\n",
                    i, hop->host, hop->addr, hop->icmperr, hop->rtts);
        }
    }

    pclose(fp);
    return err;
}

static diag_err_t tracert_stop(diag_obj_t *diag)
{
    assert(diag == &diag_tracert);

    if (system("killall traceroute >/dev/null 2>&1") != 0)
        return DIAG_ERR_INTERNAL;
    return DIAG_ERR_OK;
}

static diag_err_t tracert_forcestop(diag_obj_t *diag)
{
    assert(diag == &diag_tracert);

    if (system("killall -9 traceroute >/dev/null 2>&1") != 0)
        return DIAG_ERR_INTERNAL;
    return DIAG_ERR_OK;
}

static diag_err_t tracert_clearstatis(diag_obj_t *diag)
{
    assert(diag == &diag_tracert);

    if (diag->stat.u.tracert.hops)
        free(diag->stat.u.tracert.hops);
    diag->stat.u.tracert.hops = NULL;
    diag->stat.u.tracert.nhop = 0;
    diag->stat.u.tracert.resptime = 0;

    return DIAG_ERR_OK;
}
