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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "dnsfailover_util.h"

uint64_t DnsFailover_MonotonicMs(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

void DnsFailover_SleepMs(unsigned ms, const volatile sig_atomic_t *running)
{
    struct timespec req = {
        .tv_sec = ms / 1000U,
        .tv_nsec = (long)(ms % 1000U) * 1000000L
    };
    while (nanosleep(&req, &req) != 0 && errno == EINTR) {
        if (running && !*running)
            break;
    }
}

bool DnsFailover_AddrEqual(const dns_addr_t *a, const dns_addr_t *b)
{
    if (!a || !b || a->af != b->af)
        return false;

    if (a->af == AF_INET)
        return a->a.v4.s_addr == b->a.v4.s_addr;

    if (a->af == AF_INET6)
        return memcmp(&a->a.v6, &b->a.v6, sizeof(struct in6_addr)) == 0;

    return false;
}

const char *DnsFailover_AddrToString(const dns_addr_t *addr, char *buf, size_t len)
{
    if (!buf || len == 0)
        return "";

    buf[0] = '\0';

    if (!addr) {
        snprintf(buf, len, "?");
        return buf;
    }

    if (addr->af == AF_INET) {
        if (!inet_ntop(AF_INET, &addr->a.v4, buf, (socklen_t)len))
            snprintf(buf, len, "?");
    } else if (addr->af == AF_INET6) {
        if (!inet_ntop(AF_INET6, &addr->a.v6, buf, (socklen_t)len))
            snprintf(buf, len, "?");
    } else {
        snprintf(buf, len, "?");
    }

    return buf;
}

bool DnsFailover_AddrFromString(const char *str, dns_addr_t *out)
{
    if (!str || !out || str[0] == '\0')
        return false;

    memset(out, 0, sizeof(*out));

    if (inet_pton(AF_INET, str, &out->a.v4) == 1) {
        out->af = AF_INET;
        return true;
    }

    if (inet_pton(AF_INET6, str, &out->a.v6) == 1) {
        out->af = AF_INET6;
        return true;
    }

    return false;
}

uint32_t DnsFailover_FlowHash(const struct flow_key *k)
{
    uint32_t h = 2166136261u;
#define MIX(v) do { h ^= (uint32_t)(v); h *= 16777619u; } while (0)

    MIX(k->af);
    MIX(k->src_port);
    MIX(k->dst_port);
    MIX(k->proto);

    if (k->af == AF_INET) {
        MIX(k->src.a.v4.s_addr);
        MIX(k->dst.a.v4.s_addr);
    } else if (k->af == AF_INET6) {
        const uint32_t *sp = (const uint32_t *)&k->src.a.v6;
        const uint32_t *dp = (const uint32_t *)&k->dst.a.v6;
        for (int i = 0; i < 4; i++) {
            MIX(sp[i]);
            MIX(dp[i]);
        }
    }
#undef MIX
    return h;
}

bool DnsFailover_FlowKeyEqual(const struct flow_key *a, const struct flow_key *b)
{
    if (a->af != b->af || a->src_port != b->src_port ||
        a->dst_port != b->dst_port || a->proto != b->proto)
        return false;

    return DnsFailover_AddrEqual(&a->src, &b->src) &&
           DnsFailover_AddrEqual(&a->dst, &b->dst);
}

uint32_t DnsFailover_JitterMs(uint32_t base_ms, double frac)
{
    if (frac < 0.0)
        frac = 0.0;
    if (frac > 1.0)
        frac = 1.0;

    double span = (double)base_ms * frac;
    double lo = (double)base_ms - span;
    double hi = (double)base_ms + span;
    if (lo < 0.0)
        lo = 0.0;

    double range = hi - lo;
    double r = (double)rand() / ((double)RAND_MAX + 1.0);

    return (uint32_t)(lo + r * range);
}
