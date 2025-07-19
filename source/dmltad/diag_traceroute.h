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
 * diag_traceroute.h - Implement backend functoin of TR-181 Device.IP.Diagnostics.TraceRoute.
 * leichen2@cisco.com, 31 Mar 2014, Initialize
 */
#ifndef _DIAG_TRACEROUTE_H_
#define _DIAG_TRACEROUTE_H_
#include <net/if.h>

struct tracert_cfg {
    char        host[257];
    char        ifname[IFNAMSIZ];
    unsigned    cnt;        /* number of probe packets per hop. */
    unsigned    timeo;      /* timeout for each probe */
    unsigned    size;       /* packet length */
    unsigned    tos;        /* TOS or DSCP/ENC */
    unsigned    maxhop;     /* maximum number of hops */
};

struct tracert_hop {
    char        host[257];
    char        addr[257];
    char        icmperr[257];
    unsigned    rtts[16];   /* RTT of every probe for each hop, 
                               the number of rtts set equals to "cnt" */
};

struct tracert_stat {
    unsigned    resptime;   /**/
    unsigned    uhops;
    tracert_hop *hops;
};

typedef struct tracert_err_e {
    TRACERT_ERR_OK,
    TRACERT_ERR_PARAM,
    TRACERT_ERR_NOMEM,

    /* TR-181 defined ERROR */
    TRACERT_ERR_RESOLVE,    /* cannot resolve host name */
    TRACERT_ERR_MAXHOPEXC,  /* max hop count exceeded */
} tracert_err_t;

typedef enum tracert_state_e {
    TRACERT_ST_NONE,
    TRACERT_ST_ACTING,
    TRACERT_ST_COMPLETE,
    TRACERT_ST_ERROR,
};

int tracert_start(void);
int tracert_stop(void);

int tracert_setcfg(const struct tracert_cfg *cfg);
int tracert_getcfg(struct tracert_cfg *cfg);
int tracert_getstatistics(struct tracert_stat *stat);
int tracert_freestatistics(struct tracert_stat *stat);
int tracert_getstate(tracert_state_t *state);
int tracert_geterror(tracert_err_t *err);

#endif /* _DIAG_TRACEROUTE_H_ */
