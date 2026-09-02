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
 * dnsfailover_firewall.c
 *
 * Programs a dedicated "DNSFAILOVER" NAT chain, jumped from PREROUTING on
 * the LAN bridge interface only, to transparently DNAT client UDP/TCP port
 * 53 traffic to the local Unbound listener while failover is active.
 *
 * Scoping the jump rule to `-i <lan_ifname>` (default brlan0) is what
 * prevents a redirect loop: Unbound's own upstream recursive queries
 * originate from 127.0.0.1 on the loopback interface and from the WAN-facing
 * interface for any directly-forwarded traffic, neither of which matches
 * the LAN bridge ingress rule.
 *
 * DNAT rewrites the destination within the same address family, so IPv4
 * client queries can only be redirected to an IPv4 Unbound listener and
 * IPv6 client queries only to an IPv6 listener. The platform's shipped
 * unbound.conf (see caba5ad) binds Unbound to 127.0.0.1 only; until an
 * IPv6 loopback listener is added there, IPv6 client DNS queries cannot be
 * transparently redirected. This module logs that limitation clearly
 * rather than silently doing nothing.
 */

#include <string.h>
#include <stdio.h>

#include "ccsp_trace.h"
#include "secure_wrapper.h"

#include "dnsfailover_firewall.h"
#include "dnsfailover_util.h"

#define DNSFAILOVER_CHAIN "DNSFAILOVER"

static bool RunOk(int rc)
{
    /* v_secure_system() returns the child's exit status (0 == success),
     * matching the convention used throughout utopia/source/firewall. */
    return rc == 0;
}

/* iptables -t nat -C PREROUTING -i <if> -j DNSFAILOVER ; returns true if the
 * jump rule is already present. Used to keep chain/jump setup idempotent
 * across daemon restarts. */
static bool JumpRuleExists(const char *bin, const char *ifname)
{
    return RunOk(v_secure_system(
        "%s -t nat -C PREROUTING -i %s -j %s 2>/dev/null",
        bin, ifname, DNSFAILOVER_CHAIN));
}

static bool EnsureChainAndJump(const char *bin, const char *ifname)
{
    /* Creating an already-existing chain fails harmlessly; ignore result. */
    v_secure_system("%s -t nat -N %s 2>/dev/null", bin, DNSFAILOVER_CHAIN);

    if (!JumpRuleExists(bin, ifname)) {
        if (!RunOk(v_secure_system("%s -t nat -I PREROUTING -i %s -j %s",
                                   bin, ifname, DNSFAILOVER_CHAIN))) {
            CcspTraceError(("%s: failed to install PREROUTING jump to %s via %s\n",
                            __FUNCTION__, DNSFAILOVER_CHAIN, bin));
            return false;
        }
    }

    return true;
}

static bool ProgramRedirect(const char *bin, const char *listen_ip, uint32_t listen_port)
{
    if (!RunOk(v_secure_system("%s -t nat -F %s", bin, DNSFAILOVER_CHAIN))) {
        CcspTraceError(("%s: failed to flush %s via %s\n", __FUNCTION__, DNSFAILOVER_CHAIN, bin));
        return false;
    }

    bool ok = true;
    ok &= RunOk(v_secure_system(
        "%s -t nat -A %s -p udp --dport %u -j DNAT --to-destination %s:%u",
        bin, DNSFAILOVER_CHAIN, DNS_PORT, listen_ip, listen_port));
    ok &= RunOk(v_secure_system(
        "%s -t nat -A %s -p tcp --dport %u -j DNAT --to-destination %s:%u",
        bin, DNSFAILOVER_CHAIN, DNS_PORT, listen_ip, listen_port));

    if (!ok)
        CcspTraceError(("%s: failed to program DNAT rules via %s\n", __FUNCTION__, bin));

    return ok;
}

static bool ClearRedirect(const char *bin)
{
    return RunOk(v_secure_system("%s -t nat -F %s", bin, DNSFAILOVER_CHAIN));
}

bool DnsFailover_FirewallInit(const struct dnsfailover_config *cfg)
{
    dns_addr_t listener;
    bool have_v4 = false, have_v6 = false;

    if (DnsFailover_AddrFromString(cfg->unbound_listen_ip, &listener)) {
        have_v4 = (listener.af == AF_INET);
        have_v6 = (listener.af == AF_INET6);
    } else {
        CcspTraceError(("%s: invalid UnboundListenAddress '%s'\n",
                        __FUNCTION__, cfg->unbound_listen_ip));
        return false;
    }

    bool ok = true;

    if (have_v4)
        ok &= EnsureChainAndJump("iptables", cfg->lan_ifname);

    if (have_v6)
        ok &= EnsureChainAndJump("ip6tables", cfg->lan_ifname);

    if (!have_v6) {
        CcspTraceWarning(("%s: Unbound listener '%s' is IPv4-only; IPv6 client DNS "
                          "queries cannot be redirected until an IPv6 Unbound "
                          "listener is configured (known platform limitation)\n",
                          __FUNCTION__, cfg->unbound_listen_ip));
    }

    return ok;
}

bool DnsFailover_SetUnboundFailover(const struct dnsfailover_config *cfg, bool enable)
{
    dns_addr_t listener;
    if (!DnsFailover_AddrFromString(cfg->unbound_listen_ip, &listener))
        return false;

    bool ok = true;

    if (listener.af == AF_INET) {
        ok &= enable
            ? ProgramRedirect("iptables", cfg->unbound_listen_ip, cfg->unbound_listen_port)
            : ClearRedirect("iptables");
    }

    if (listener.af == AF_INET6) {
        ok &= enable
            ? ProgramRedirect("ip6tables", cfg->unbound_listen_ip, cfg->unbound_listen_port)
            : ClearRedirect("ip6tables");
    }

    return ok;
}

void DnsFailover_FirewallCleanup(const struct dnsfailover_config *cfg)
{
    v_secure_system("iptables -t nat -F %s 2>/dev/null", DNSFAILOVER_CHAIN);
    v_secure_system("iptables -t nat -D PREROUTING -i %s -j %s 2>/dev/null",
                    cfg->lan_ifname, DNSFAILOVER_CHAIN);
    v_secure_system("iptables -t nat -X %s 2>/dev/null", DNSFAILOVER_CHAIN);

    v_secure_system("ip6tables -t nat -F %s 2>/dev/null", DNSFAILOVER_CHAIN);
    v_secure_system("ip6tables -t nat -D PREROUTING -i %s -j %s 2>/dev/null",
                    cfg->lan_ifname, DNSFAILOVER_CHAIN);
    v_secure_system("ip6tables -t nat -X %s 2>/dev/null", DNSFAILOVER_CHAIN);
}
