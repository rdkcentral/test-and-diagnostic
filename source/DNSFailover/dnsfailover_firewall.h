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
 * dnsfailover_firewall.h
 *
 * Transparent DNS interception datapath. When all configured upstream
 * resolvers are FAILED and WAN is up, LAN client traffic destined to port 53
 * on the LAN-facing interface is redirected (DNAT) to the local Unbound
 * listener (see DNS_Failover_Conntrack_Unbound_Design.docx, section 8).
 *
 * Implementation uses a dedicated, idempotently-managed iptables/ip6tables
 * chain ("DNSFAILOVER") jumped from PREROUTING on the LAN bridge interface
 * only, so toggling failover never disturbs unrelated firewall rules and
 * cannot create a redirect loop for Unbound's own upstream (WAN-side)
 * recursive traffic.
 *
 * Rule changes are applied via v_secure_system() (the RDK-B sanctioned safe
 * wrapper used throughout utopia/source/firewall/firewall.c), never via
 * system()/popen() with unsanitized input. Only fixed command templates and
 * values already validated as syntactically-correct hostnames/ports are
 * ever interpolated.
 */

#ifndef DNSFAILOVER_FIREWALL_H
#define DNSFAILOVER_FIREWALL_H

#include "dnsfailover.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Creates the DNSFAILOVER chains (ipv4 + ipv6, if not already present) and
 * the (empty) PREROUTING jump rules. Must be called once at daemon startup,
 * before any DnsFailover_SetUnboundFailover() call. Idempotent: safe to call
 * again after a daemon restart. Returns true on success. */
bool DnsFailover_FirewallInit(const struct dnsfailover_config *cfg);

/* Enables or disables the DNAT redirect to Unbound. Idempotent: calling with
 * the same value as the current state is a safe no-op check performed by
 * the caller (dnsfailover_conntrack.c tracks ctx->failover_active). Must be
 * called OUTSIDE ctx->lock. Returns true on success. */
bool DnsFailover_SetUnboundFailover(const struct dnsfailover_config *cfg, bool enable);

/* Removes the DNSFAILOVER chains and jump rules entirely. Called on daemon
 * shutdown so a crash/restart never leaves the redirect permanently active. */
void DnsFailover_FirewallCleanup(const struct dnsfailover_config *cfg);

#ifdef __cplusplus
}
#endif

#endif /* DNSFAILOVER_FIREWALL_H */
