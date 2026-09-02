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
 * dnsfailover_servers.h
 *
 * Discovers the currently configured upstream DNS servers so the conntrack
 * module knows which destinations to monitor (see
 * CONNTRACK_NEEDS_SERVER_DETAILS.md: conntrack itself has no notion of
 * "configured" vs. "incidental" DNS traffic).
 *
 * Primary source: TR-181 Device.DNS.Client.Server.{i}.DNSServer via RBUS.
 * Fallback source: /etc/resolv.conf "nameserver" lines, used only if RBUS
 * is unavailable or returns zero usable entries.
 *
 * Re-read periodically (ctx->cfg.server_refresh_sec) and immediately after
 * a WAN-up transition, since WAN reconnection commonly renews DHCP-learned
 * resolver addresses.
 */

#ifndef DNSFAILOVER_SERVERS_H
#define DNSFAILOVER_SERVERS_H

#include "dnsfailover.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_SERVER_PROBE_MAX_INDEX 16U

/* Performs one immediate discovery pass and applies it via
 * DnsFailover_SetConfiguredServers(), then starts the periodic refresh
 * thread. Returns true if at least one server was discovered. */
bool DnsFailover_ServersStart(struct dnsfailover_ctx *ctx);

void DnsFailover_ServersStop(struct dnsfailover_ctx *ctx);

/* Forces an immediate re-discovery (e.g. on WAN-up transition). Safe to call
 * from any thread; performs RBUS/file I/O so must not be called with
 * ctx->lock held. */
void DnsFailover_ServersRefreshNow(struct dnsfailover_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* DNSFAILOVER_SERVERS_H */
