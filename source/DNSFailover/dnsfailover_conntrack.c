/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
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

/*
 * dnsfailover_conntrack.c
 *
 * Passive DNS failure detection via libnetfilter_conntrack, per-server
 * HEALTHY -> SUSPECT -> (ACTIVE VERIFY) -> HEALTHY|FAILED state machine, and
 * the all-servers-failed failover policy.
 *
 * LOCKING DISCIPLINE:
 *   ctx->lock protects ctx->pending[], ctx->servers[], ctx->server_count,
 *   ctx->wan_is_up, ctx->failover_active and ctx->counters. It is taken for
 *   short bounded operations only. Active verification and firewall
 *   programming are never performed while ctx->lock is held:
 *     - evaluate_server_locked() only decides to enqueue a verify job
 *       (dnsfailover_verify.c) and returns; the actual query happens later
 *       on the verify worker thread.
 *     - DnsFailover_OnVerifyResult() (called FROM the verify worker thread,
 *       not holding ctx->lock) takes ctx->lock only to update state, then
 *       releases it before calling DnsFailover_SetUnboundFailover(), which
 *       performs the (potentially slow) firewall rule programming.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "ccsp_trace.h"

#include "dnsfailover_conntrack.h"
#include "dnsfailover_util.h"
#include "dnsfailover_verify.h"
#include "dnsfailover_firewall.h"

/* ------------------------------------------------------------------------- */
/* Pending-flow table (open-addressing hash/probe, fixed size, no malloc)   */
/* ------------------------------------------------------------------------- */

static struct pending_flow *PendingLookup(struct dnsfailover_ctx *ctx,
                                          const struct flow_key *key)
{
    uint32_t start = DnsFailover_FlowHash(key) % MAX_PENDING_FLOWS;

    for (uint32_t i = 0; i < MAX_PENDING_FLOWS; ++i) {
        struct pending_flow *p = &ctx->pending[(start + i) % MAX_PENDING_FLOWS];
        if (p->used && DnsFailover_FlowKeyEqual(&p->key, key))
            return p;
    }
    return NULL;
}

static struct pending_flow *PendingAlloc(struct dnsfailover_ctx *ctx,
                                         const struct flow_key *key)
{
    uint32_t start = DnsFailover_FlowHash(key) % MAX_PENDING_FLOWS;
    struct pending_flow *oldest = NULL;

    for (uint32_t i = 0; i < MAX_PENDING_FLOWS; ++i) {
        struct pending_flow *p = &ctx->pending[(start + i) % MAX_PENDING_FLOWS];
        if (!p->used) {
            memset(p, 0, sizeof(*p));
            p->used = true;
            p->key = *key;
            p->created_ms = DnsFailover_MonotonicMs();
            ctx->pending_in_use++;
            if (ctx->pending_in_use > ctx->counters.pending_table_high_watermark)
                ctx->counters.pending_table_high_watermark = ctx->pending_in_use;
            return p;
        }
        if (!oldest || p->created_ms < oldest->created_ms)
            oldest = p;
    }

    /* Table saturation should be rare in practice (bounded at 2048 flows).
     * Replace the oldest entry rather than fail; this bounds memory use at
     * the cost of possibly losing one stale flow's evidence. */
    if (oldest) {
        CcspTraceWarning(("%s: pending flow table full (%u entries); evicting oldest\n",
                          __FUNCTION__, MAX_PENDING_FLOWS));
        memset(oldest, 0, sizeof(*oldest));
        oldest->used = true;
        oldest->key = *key;
        oldest->created_ms = DnsFailover_MonotonicMs();
    }
    return oldest;
}

static void PendingRemove(struct dnsfailover_ctx *ctx, const struct flow_key *key)
{
    struct pending_flow *p = PendingLookup(ctx, key);
    if (p) {
        memset(p, 0, sizeof(*p));
        if (ctx->pending_in_use > 0)
            ctx->pending_in_use--;
    }
}

/* ------------------------------------------------------------------------- */
/* Per-server health table                                                   */
/* ------------------------------------------------------------------------- */

static struct dns_server_health *ServerFind(struct dnsfailover_ctx *ctx,
                                            const dns_addr_t *addr)
{
    for (uint32_t i = 0; i < ctx->server_count; ++i) {
        struct dns_server_health *s = &ctx->servers[i];
        if (s->used && DnsFailover_AddrEqual(&s->addr, addr))
            return s;
    }
    return NULL;
}

/* Only configured resolvers are monitored (see CONNTRACK_NEEDS_SERVER_DETAILS
 * analysis): conntrack observes every UDP/53 flow on the box, including ones
 * that are none of our concern (LAN client testing a public resolver, other
 * local services, etc). Filtering here prevents false failure evidence. */
void DnsFailover_SetConfiguredServers(struct dnsfailover_ctx *ctx,
                                      const dns_addr_t *addrs,
                                      uint32_t count)
{
    if (count > MAX_DNS_SERVERS) {
        CcspTraceWarning(("%s: %u servers requested, clamping to MAX_DNS_SERVERS=%u\n",
                          __FUNCTION__, count, MAX_DNS_SERVERS));
        count = MAX_DNS_SERVERS;
    }

    pthread_mutex_lock(&ctx->lock);

    /* Mark all existing entries as candidates for removal; anything matched
     * below by address is kept (preserving its health state). */
    bool keep[MAX_DNS_SERVERS] = { false };

    for (uint32_t i = 0; i < count; ++i) {
        struct dns_server_health *existing = ServerFind(ctx, &addrs[i]);
        if (existing) {
            for (uint32_t j = 0; j < MAX_DNS_SERVERS; ++j) {
                if (&ctx->servers[j] == existing) {
                    keep[j] = true;
                    break;
                }
            }
            existing->enabled = true;
            continue;
        }

        /* Find a free slot for a newly-configured server. */
        for (uint32_t j = 0; j < MAX_DNS_SERVERS; ++j) {
            if (!ctx->servers[j].used) {
                memset(&ctx->servers[j], 0, sizeof(ctx->servers[j]));
                ctx->servers[j].used = true;
                ctx->servers[j].enabled = true;
                ctx->servers[j].addr = addrs[i];
                ctx->servers[j].state = SERVER_HEALTHY;
                DnsFailover_AddrToString(&addrs[i], ctx->servers[j].ip_string,
                                         sizeof(ctx->servers[j].ip_string));
                keep[j] = true;
                if (j + 1 > ctx->server_count)
                    ctx->server_count = j + 1;
                CcspTraceInfo(("%s: added configured DNS server %s\n",
                               __FUNCTION__, ctx->servers[j].ip_string));
                break;
            }
        }
    }

    for (uint32_t j = 0; j < ctx->server_count; ++j) {
        if (ctx->servers[j].used && !keep[j]) {
            CcspTraceInfo(("%s: removing stale configured DNS server %s\n",
                           __FUNCTION__, ctx->servers[j].ip_string));
            memset(&ctx->servers[j], 0, sizeof(ctx->servers[j]));
        }
    }

    pthread_mutex_unlock(&ctx->lock);
}

/* ------------------------------------------------------------------------- */
/* State machine helpers (all require ctx->lock held by caller)              */
/* ------------------------------------------------------------------------- */

static bool AllUsableServersFailedLocked(struct dnsfailover_ctx *ctx)
{
    bool any_usable = false;

    for (uint32_t i = 0; i < ctx->server_count; ++i) {
        struct dns_server_health *s = &ctx->servers[i];
        if (!s->used || !s->enabled)
            continue;
        any_usable = true;
        if (s->state != SERVER_FAILED)
            return false;
    }

    return any_usable;
}

/* Applies the global failover decision after any per-server state change.
 * Must be called with ctx->lock held; performs no I/O itself -- it only
 * updates ctx->failover_active. The actual firewall/Unbound programming
 * happens in DoFailoverTransition(), invoked without the lock held. */
static bool EvaluateGlobalFailoverLocked(struct dnsfailover_ctx *ctx, bool *out_enable)
{
    bool want_active = ctx->wan_is_up && AllUsableServersFailedLocked(ctx);

    if (want_active == ctx->failover_active)
        return false; /* no transition */

    *out_enable = want_active;
    return true;
}

static void DoFailoverTransition(struct dnsfailover_ctx *ctx, bool enable)
{
    bool applied = DnsFailover_SetUnboundFailover(&ctx->cfg, enable);

    pthread_mutex_lock(&ctx->lock);
    if (applied) {
        uint64_t now = DnsFailover_MonotonicMs();
        if (enable) {
            ctx->failover_active = true;
            ctx->failover_started_ms = now;
            ctx->counters.failover_enabled_total++;
            CcspTraceWarning(("%s: DNS FAILOVER ENABLED - all configured resolvers FAILED, WAN up\n",
                              __FUNCTION__));
        } else {
            ctx->failover_active = false;
            if (ctx->failover_started_ms != 0)
                ctx->failover_total_duration_ms += now - ctx->failover_started_ms;
            ctx->failover_started_ms = 0;
            ctx->counters.failover_disabled_total++;
            CcspTraceInfo(("%s: DNS FAILOVER DISABLED - at least one resolver recovered\n",
                           __FUNCTION__));
        }
    } else {
        CcspTraceError(("%s: failed to %s Unbound failover datapath; will retry on next transition\n",
                        __FUNCTION__, enable ? "enable" : "disable"));
    }
    pthread_mutex_unlock(&ctx->lock);
}

static void RecordReplyLocked(struct dnsfailover_ctx *ctx, const dns_addr_t *server_addr)
{
    struct dns_server_health *s = ServerFind(ctx, server_addr);
    if (!s)
        return; /* not a configured server; ignore per design */

    s->last_reply_ms = DnsFailover_MonotonicMs();
    s->failure_episodes = 0;

    if (s->state == SERVER_SUSPECT) {
        s->state = SERVER_HEALTHY;
        s->recovery_successes = 0;
        CcspTraceInfo(("%s: %s recovered to HEALTHY via passive reply\n",
                       __FUNCTION__, s->ip_string));
    }
    /* Servers in FAILED state are, by definition, no longer receiving real
     * client traffic once failover is active (clients are redirected to
     * Unbound). Recovery for FAILED servers is handled by the sparse
     * exponential-backoff active-verify probes in DnsFailover_MonitorTick(),
     * not by passive replies. */
}

static void RecordFailureEpisodeLocked(struct dnsfailover_ctx *ctx,
                                       const dns_addr_t *server_addr,
                                       uint64_t now_ms)
{
    struct dns_server_health *s = ServerFind(ctx, server_addr);
    if (!s)
        return;

    if (s->last_failure_episode_ms != 0 &&
        now_ms - s->last_failure_episode_ms < ctx->cfg.failure_episode_gap_ms) {
        return; /* still inside the current episode window */
    }

    s->last_failure_episode_ms = now_ms;
    s->failure_episodes++;
    s->total_failure_episodes++;
    s->recovery_successes = 0;
    ctx->counters.failure_episodes_total++;

    if (s->state == SERVER_HEALTHY) {
        s->state = SERVER_SUSPECT;
        CcspTraceWarning(("%s: %s HEALTHY -> SUSPECT (episode %u/%u)\n",
                          __FUNCTION__, s->ip_string, s->failure_episodes,
                          ctx->cfg.passive_failure_threshold));
    } else {
        CcspTraceInfo(("%s: %s failure episode %u/%u\n",
                       __FUNCTION__, s->ip_string, s->failure_episodes,
                       ctx->cfg.passive_failure_threshold));
    }
}

/* Decides whether a server needs an active-verification probe right now and
 * enqueues it. Never performs I/O itself. Called with ctx->lock held. */
static void EvaluateServerLocked(struct dnsfailover_ctx *ctx,
                                 struct dns_server_health *s, uint64_t now_ms)
{
    if (!s->used || !s->enabled || s->verify_in_flight)
        return;

    if (s->state == SERVER_SUSPECT) {
        if (s->failure_episodes < ctx->cfg.passive_failure_threshold)
            return;
        if (s->last_verify_ms != 0 &&
            now_ms - s->last_verify_ms < ctx->cfg.verify_cooldown_ms)
            return;
    } else if (s->state == SERVER_FAILED) {
        /* Sparse recovery probing with exponential backoff, per design
         * doc section 9. next_verify_due_ms is armed the first time a
         * server transitions to FAILED (see DnsFailover_OnVerifyResult). */
        if (s->next_verify_due_ms == 0 || now_ms < s->next_verify_due_ms)
            return;
    } else {
        return; /* HEALTHY: nothing to verify */
    }

    s->last_verify_ms = now_ms;
    s->verify_in_flight = true;
    DnsFailover_QueueVerify(ctx, &s->addr);
}

/* ------------------------------------------------------------------------- */
/* Called by dnsfailover_verify.c on the worker thread (ctx->lock NOT held)  */
/* ------------------------------------------------------------------------- */

void DnsFailover_OnVerifyResult(struct dnsfailover_ctx *ctx,
                                const dns_addr_t *server, bool success)
{
    bool do_transition = false;
    bool transition_enable = false;
    char ipbuf[INET6_ADDRSTRLEN];

    pthread_mutex_lock(&ctx->lock);

    struct dns_server_health *s = ServerFind(ctx, server);
    if (!s) {
        pthread_mutex_unlock(&ctx->lock);
        return; /* server removed from config while verify was in flight */
    }

    s->verify_in_flight = false;
    DnsFailover_AddrToString(server, ipbuf, sizeof(ipbuf));

    if (success) {
        ctx->counters.active_verify_success_total++;
        s->total_verify_success++;

        if (s->state == SERVER_FAILED) {
            if (++s->recovery_successes >= ctx->cfg.recovery_success_threshold) {
                s->state = SERVER_HEALTHY;
                s->recovery_successes = 0;
                s->failure_episodes = 0;
                s->backoff_index = 0;
                s->next_verify_due_ms = 0;
                CcspTraceWarning(("%s: %s FAILED -> HEALTHY (recovery confirmed)\n",
                                  __FUNCTION__, ipbuf));
            } else {
                /* Not enough consecutive successes yet; probe again soon
                 * using the same backoff step (anti-flap hysteresis). */
                s->next_verify_due_ms = DnsFailover_MonotonicMs() +
                    DnsFailover_JitterMs(RECOVERY_BACKOFF_SECONDS[s->backoff_index] * 1000U, 0.15);
            }
        } else {
            s->state = SERVER_HEALTHY;
            s->failure_episodes = 0;
            s->recovery_successes = 0;
        }
    } else {
        ctx->counters.active_verify_failure_total++;
        s->total_verify_failure++;
        s->recovery_successes = 0;

        if (s->state != SERVER_FAILED) {
            /* Passive+active evidence agree: this resolver is down. WAN
             * qualification happens in EvaluateGlobalFailoverLocked() below
             * (a single FAILED resolver never triggers failover on its
             * own; ALL usable resolvers must be FAILED). */
            s->state = SERVER_FAILED;
            s->backoff_index = 0;
            s->next_verify_due_ms = DnsFailover_MonotonicMs() +
                DnsFailover_JitterMs(RECOVERY_BACKOFF_SECONDS[0] * 1000U, 0.15);
            CcspTraceError(("%s: %s SUSPECT -> FAILED (active verification failed)\n",
                           __FUNCTION__, ipbuf));
        } else {
            /* Still failed: advance the backoff schedule (capped). */
            if (s->backoff_index + 1 < RECOVERY_BACKOFF_STEPS)
                s->backoff_index++;
            s->next_verify_due_ms = DnsFailover_MonotonicMs() +
                DnsFailover_JitterMs(RECOVERY_BACKOFF_SECONDS[s->backoff_index] * 1000U, 0.15);
        }
    }

    if (!ctx->wan_is_up) {
        /* WAN-down suppression: never blame DNS for what is actually a WAN
         * outage. Passive/verify state is preserved so evaluation resumes
         * normally once WAN comes back (see DnsFailover_OnWanStatusChanged). */
        if (s->state == SERVER_FAILED) {
            ctx->counters.wan_down_suppressed_total++;
            CcspTraceWarning(("%s: WAN is down; suppressing failover consideration for %s\n",
                              __FUNCTION__, ipbuf));
        }
    } else if (EvaluateGlobalFailoverLocked(ctx, &transition_enable)) {
        do_transition = true;
    }

    pthread_mutex_unlock(&ctx->lock);

    if (do_transition)
        DoFailoverTransition(ctx, transition_enable);
}

void DnsFailover_OnWanStatusChanged(struct dnsfailover_ctx *ctx, bool wan_is_up)
{
    bool do_transition = false;
    bool transition_enable = false;

    pthread_mutex_lock(&ctx->lock);

    bool changed = (ctx->wan_is_up != wan_is_up);
    ctx->wan_is_up = wan_is_up;

    if (changed) {
        CcspTraceInfo(("%s: WAN status changed -> %s\n", __FUNCTION__,
                       wan_is_up ? "UP" : "DOWN"));

        if (!wan_is_up && ctx->failover_active) {
            /* Disable the redirect immediately: if WAN itself is down there
             * is no point sending clients to Unbound (it cannot recurse
             * either), and we do not want to mask a WAN outage as "DNS is
             * fine now". */
            transition_enable = false;
            do_transition = true;
        } else if (wan_is_up && EvaluateGlobalFailoverLocked(ctx, &transition_enable)) {
            do_transition = true;
        }
    }

    pthread_mutex_unlock(&ctx->lock);

    if (do_transition)
        DoFailoverTransition(ctx, transition_enable);
}

/* ------------------------------------------------------------------------- */
/* Conntrack event parsing (dual-stack IPv4/IPv6, UDP/53 only)               */
/* ------------------------------------------------------------------------- */

static bool ExtractDnsKey(const struct nf_conntrack *ct, struct flow_key *key)
{
    if (!nfct_attr_is_set(ct, ATTR_ORIG_L3PROTO) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST)) {
        return false;
    }

    uint8_t l3proto = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
    uint8_t l4proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    uint16_t dport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));

    /* TCP/53 is a documented follow-up (see design doc section 12): DNS
     * stub resolvers overwhelmingly use UDP, and TCP connection semantics
     * (SYN/ACK timing vs. DNS response timing) require separate handling. */
    if (l4proto != IPPROTO_UDP || dport != DNS_PORT)
        return false;

    memset(key, 0, sizeof(*key));
    key->proto = l4proto;
    key->src_port = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
    key->dst_port = dport;

    if (l3proto == AF_INET) {
        if (!nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC) ||
            !nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST))
            return false;

        key->af = AF_INET;
        key->src.af = AF_INET;
        key->dst.af = AF_INET;
        key->src.a.v4.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
        key->dst.a.v4.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
        return true;
    }

    if (l3proto == AF_INET6) {
        if (!nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC) ||
            !nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST))
            return false;

        const void *src = nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC);
        const void *dst = nfct_get_attr(ct, ATTR_ORIG_IPV6_DST);
        if (!src || !dst)
            return false;

        key->af = AF_INET6;
        key->src.af = AF_INET6;
        key->dst.af = AF_INET6;
        memcpy(&key->src.a.v6, src, sizeof(struct in6_addr));
        memcpy(&key->dst.a.v6, dst, sizeof(struct in6_addr));
        return true;
    }

    return false;
}

static int ConntrackEventCb(enum nf_conntrack_msg_type type,
                            struct nf_conntrack *ct, void *data)
{
    struct dnsfailover_ctx *ctx = data;
    struct flow_key key;
    uint32_t status = 0;

    if (!ExtractDnsKey(ct, &key))
        return NFCT_CB_CONTINUE;

    if (nfct_attr_is_set(ct, ATTR_STATUS))
        status = nfct_get_attr_u32(ct, ATTR_STATUS);

    bool seen_reply = (status & IPS_SEEN_REPLY) != 0;

    pthread_mutex_lock(&ctx->lock);
    ctx->counters.ct_events_total++;

    /* Only track flows to servers we actually monitor; see
     * CONNTRACK_NEEDS_SERVER_DETAILS analysis for the rationale. */
    if (!ServerFind(ctx, &key.dst)) {
        pthread_mutex_unlock(&ctx->lock);
        return NFCT_CB_CONTINUE;
    }

    if (seen_reply) {
        ctx->counters.ct_events_reply++;
        PendingRemove(ctx, &key);
        RecordReplyLocked(ctx, &key.dst);
        pthread_mutex_unlock(&ctx->lock);
        return NFCT_CB_CONTINUE;
    }

    switch (type) {
    case NFCT_T_NEW:
        ctx->counters.ct_events_new++;
        if (!PendingLookup(ctx, &key))
            (void)PendingAlloc(ctx, &key);
        break;

    case NFCT_T_DESTROY:
        ctx->counters.ct_events_destroy++;
        {
            struct pending_flow *p = PendingLookup(ctx, &key);
            if (p && !p->expired_reported)
                RecordFailureEpisodeLocked(ctx, &key.dst, DnsFailover_MonotonicMs());
            PendingRemove(ctx, &key);
        }
        break;

    case NFCT_T_UPDATE:
    default:
        break;
    }

    pthread_mutex_unlock(&ctx->lock);
    return NFCT_CB_CONTINUE;
}

static void *ConntrackThread(void *arg)
{
    struct dnsfailover_ctx *ctx = arg;

    CcspTraceInfo(("%s: conntrack event thread started\n", __FUNCTION__));

    while (ctx->running) {
        int rc = nfct_catch(ctx->nfct);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            CcspTraceError(("%s: nfct_catch failed: %s\n", __FUNCTION__, strerror(errno)));
            break;
        }
    }

    CcspTraceInfo(("%s: conntrack event thread exiting\n", __FUNCTION__));
    return NULL;
}

static pthread_t g_conntrack_tid;
static bool g_conntrack_thread_started = false;

bool DnsFailover_ConntrackStart(struct dnsfailover_ctx *ctx)
{
    ctx->nfct = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
    if (!ctx->nfct) {
        CcspTraceError(("%s: nfct_open failed: %s\n", __FUNCTION__, strerror(errno)));
        return false;
    }

    if (nfct_callback_register(ctx->nfct, NFCT_T_ALL, ConntrackEventCb, ctx) < 0) {
        CcspTraceError(("%s: nfct_callback_register failed: %s\n", __FUNCTION__, strerror(errno)));
        nfct_close(ctx->nfct);
        ctx->nfct = NULL;
        return false;
    }

    if (pthread_create(&g_conntrack_tid, NULL, ConntrackThread, ctx) != 0) {
        CcspTraceError(("%s: pthread_create failed: %s\n", __FUNCTION__, strerror(errno)));
        nfct_callback_unregister(ctx->nfct);
        nfct_close(ctx->nfct);
        ctx->nfct = NULL;
        return false;
    }

    g_conntrack_thread_started = true;
    return true;
}

void DnsFailover_ConntrackStop(struct dnsfailover_ctx *ctx)
{
    if (g_conntrack_thread_started) {
        /* nfct_catch() blocks in a netlink recv(), which is a pthread
         * cancellation point on glibc/Linux. Production alternative: wire
         * nfct_fd() into an epoll-based event loop to avoid cancellation
         * entirely; documented here as a follow-up hardening item. */
        pthread_cancel(g_conntrack_tid);
        pthread_join(g_conntrack_tid, NULL);
        g_conntrack_thread_started = false;
    }

    if (ctx->nfct) {
        nfct_callback_unregister(ctx->nfct);
        nfct_close(ctx->nfct);
        ctx->nfct = NULL;
    }
}

/* ------------------------------------------------------------------------- */
/* Local timer loop                                                           */
/* ------------------------------------------------------------------------- */

void DnsFailover_MonitorTick(struct dnsfailover_ctx *ctx)
{
    const uint64_t now = DnsFailover_MonotonicMs();

    pthread_mutex_lock(&ctx->lock);

    for (uint32_t i = 0; i < MAX_PENDING_FLOWS; ++i) {
        struct pending_flow *p = &ctx->pending[i];
        if (!p->used || p->expired_reported)
            continue;

        if (now - p->created_ms >= ctx->cfg.dns_reply_deadline_ms) {
            p->expired_reported = true;
            ctx->counters.unreplied_expirations_total++;
            RecordFailureEpisodeLocked(ctx, &p->key.dst, now);
        }
    }

    for (uint32_t i = 0; i < ctx->server_count; ++i)
        EvaluateServerLocked(ctx, &ctx->servers[i], now);

    pthread_mutex_unlock(&ctx->lock);
}
