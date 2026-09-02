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

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include <rbus/rbus.h>
#include "ccsp_trace.h"

#include "dnsfailover_servers.h"
#include "dnsfailover_conntrack.h"
#include "dnsfailover_util.h"

#define DNS_SERVER_PARAM_FMT "Device.DNS.Client.Server.%u.DNSServer"
#define DNS_SERVER_ENABLE_FMT "Device.DNS.Client.Server.%u.Enable"

static pthread_t g_refresh_tid;
static bool g_refresh_started = false;

static uint32_t DiscoverViaRbus(struct dnsfailover_ctx *ctx, dns_addr_t *out, uint32_t cap)
{
    rbusHandle_t handle = (rbusHandle_t)ctx->rbus_handle;
    uint32_t found = 0;
    uint32_t consecutive_misses = 0;

    if (!handle)
        return 0;

    for (uint32_t i = 1; i <= DNS_SERVER_PROBE_MAX_INDEX && found < cap; ++i) {
        char param[128];
        snprintf(param, sizeof(param), DNS_SERVER_PARAM_FMT, i);

        rbusValue_t value = NULL;
        if (rbus_get(handle, param, &value) != RBUS_ERROR_SUCCESS || !value) {
            consecutive_misses++;
            /* Server table indices are not guaranteed contiguous, but three
             * consecutive misses after having probed the low indices is a
             * reasonable, bounded stopping condition. */
            if (consecutive_misses >= 3 && found > 0)
                break;
            continue;
        }
        consecutive_misses = 0;

        const char *ip_str = rbusValue_GetString(value, NULL);
        dns_addr_t addr;
        bool valid = ip_str && DnsFailover_AddrFromString(ip_str, &addr);
        rbusValue_Release(value);

        if (!valid)
            continue;

        bool enabled = true; /* default to enabled if .Enable is absent */
        char enable_param[128];
        snprintf(enable_param, sizeof(enable_param), DNS_SERVER_ENABLE_FMT, i);
        rbusValue_t enable_value = NULL;
        if (rbus_get(handle, enable_param, &enable_value) == RBUS_ERROR_SUCCESS && enable_value) {
            enabled = rbusValue_GetBoolean(enable_value);
            rbusValue_Release(enable_value);
        }

        if (enabled)
            out[found++] = addr;
    }

    return found;
}

static uint32_t DiscoverViaResolvConf(dns_addr_t *out, uint32_t cap)
{
    FILE *fp = fopen("/etc/resolv.conf", "r");
    uint32_t found = 0;

    if (!fp) {
        CcspTraceError(("%s: failed to open /etc/resolv.conf: %s\n",
                        __FUNCTION__, strerror(errno)));
        return 0;
    }

    char line[256];
    while (found < cap && fgets(line, sizeof(line), fp)) {
        char ip[INET6_ADDRSTRLEN];
        if (sscanf(line, "nameserver %63s", ip) == 1) {
            dns_addr_t addr;
            if (DnsFailover_AddrFromString(ip, &addr))
                out[found++] = addr;
        }
    }

    fclose(fp);
    return found;
}

void DnsFailover_ServersRefreshNow(struct dnsfailover_ctx *ctx)
{
    dns_addr_t addrs[MAX_DNS_SERVERS];
    uint32_t count = DiscoverViaRbus(ctx, addrs, MAX_DNS_SERVERS);

    if (count == 0) {
        CcspTraceWarning(("%s: no servers discovered via RBUS/TR-181; "
                          "falling back to /etc/resolv.conf\n", __FUNCTION__));
        count = DiscoverViaResolvConf(addrs, MAX_DNS_SERVERS);
    }

    if (count == 0) {
        CcspTraceError(("%s: no configured DNS servers discovered from any source; "
                        "monitoring paused until next refresh\n", __FUNCTION__));
        return;
    }

    DnsFailover_SetConfiguredServers(ctx, addrs, count);
}

static void *ServersRefreshThread(void *arg)
{
    struct dnsfailover_ctx *ctx = arg;

    while (ctx->running) {
        DnsFailover_SleepMs(ctx->cfg.server_refresh_sec * 1000U, &ctx->running);
        if (!ctx->running)
            break;
        DnsFailover_ServersRefreshNow(ctx);
    }

    return NULL;
}

bool DnsFailover_ServersStart(struct dnsfailover_ctx *ctx)
{
    DnsFailover_ServersRefreshNow(ctx);

    if (pthread_create(&g_refresh_tid, NULL, ServersRefreshThread, ctx) != 0) {
        CcspTraceError(("%s: failed to start server refresh thread\n", __FUNCTION__));
        return false;
    }
    g_refresh_started = true;

    pthread_mutex_lock(&ctx->lock);
    bool have_any = ctx->server_count > 0;
    pthread_mutex_unlock(&ctx->lock);
    return have_any;
}

void DnsFailover_ServersStop(struct dnsfailover_ctx *ctx)
{
    (void)ctx;
    if (g_refresh_started) {
        pthread_join(g_refresh_tid, NULL);
        g_refresh_started = false;
    }
}
