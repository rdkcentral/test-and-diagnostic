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

#ifndef DNSFAILOVER_CONNTRACK_H
#define DNSFAILOVER_CONNTRACK_H

#include "dnsfailover.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opens the conntrack netlink handle, registers the event callback, and
 * spawns the conntrack receive thread. Returns true on success. ctx->nfct
 * and the thread are owned by this module until DnsFailover_ConntrackStop(). */
bool DnsFailover_ConntrackStart(struct dnsfailover_ctx *ctx);

/* Signals the conntrack thread to stop and joins it. Safe to call even if
 * DnsFailover_ConntrackStart() failed partway through. */
void DnsFailover_ConntrackStop(struct dnsfailover_ctx *ctx);

/* Called periodically (every ctx->cfg.monitor_tick_ms) from the main loop.
 * Expires stale pending flows into failure episodes and evaluates each
 * server's state machine, queuing active-verification jobs as needed. */
void DnsFailover_MonitorTick(struct dnsfailover_ctx *ctx);

/* Adds (or updates) a configured DNS server. Called at startup and whenever
 * dnsfailover_servers.c detects a resolver-list change. Preserves existing
 * health state for servers that remain configured; new servers start
 * HEALTHY. Servers no longer present are marked unused (state discarded).
 * Thread-safe (acquires ctx->lock internally). */
void DnsFailover_SetConfiguredServers(struct dnsfailover_ctx *ctx,
                                      const dns_addr_t *addrs,
                                      uint32_t count);

/* Invoked by dnsfailover_verify.c (from the verify worker thread, NOT while
 * holding ctx->lock) with the outcome of an active verification. Updates
 * server state, applies recovery/failover policy, and (re)programs the
 * firewall/Unbound redirect as needed. */
void DnsFailover_OnVerifyResult(struct dnsfailover_ctx *ctx,
                                const dns_addr_t *server, bool success);

/* Invoked by dnsfailover_wan.c when the cached WAN status changes. */
void DnsFailover_OnWanStatusChanged(struct dnsfailover_ctx *ctx, bool wan_is_up);

#ifdef __cplusplus
}
#endif

#endif /* DNSFAILOVER_CONNTRACK_H */
