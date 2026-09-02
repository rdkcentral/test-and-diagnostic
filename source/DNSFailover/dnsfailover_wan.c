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

#include "dnsfailover_wan.h"
#include "dnsfailover_conntrack.h"
#include "dnsfailover_util.h"

#define WAN_STATUS_PARAM "Device.X_RDK_WanManager.ConnectionStatus"

static bool StatusStringMeansUp(const char *status)
{
    return status && strcmp(status, "Connected") == 0;
}

/* Fallback WAN check: presence of a default route (destination 0.0.0.0/0)
 * in the kernel routing table (see WAN_STATUS_DETECTION.md, Method 3). */
static bool HasDefaultRoute(void)
{
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) {
        CcspTraceError(("%s: failed to open /proc/net/route: %s\n",
                        __FUNCTION__, strerror(errno)));
        return false;
    }

    char line[256];
    bool found = false;

    /* Skip header line. */
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        char iface[64];
        unsigned int dest = 0, flags = 0;

        /* Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT */
        int matched = sscanf(line, "%63s %x %*x %x", iface, &dest, &flags);
        if (matched == 3 && dest == 0 && (flags & 0x1 /* RTF_UP */)) {
            found = true;
            break;
        }
    }

    fclose(fp);
    return found;
}

static void WanStatusEventHandler(rbusHandle_t handle, rbusEvent_t const *event,
                                  rbusEventSubscription_t *subscription)
{
    (void)handle;
    struct dnsfailover_ctx *ctx = (struct dnsfailover_ctx *)subscription->userData;
    const char *status = NULL;

    rbusValue_t value = rbusObject_GetValue(event->data, WAN_STATUS_PARAM);
    if (!value)
        value = rbusObject_GetValue(event->data, "value");

    if (value)
        status = rbusValue_GetString(value, NULL);

    bool wan_up = StatusStringMeansUp(status);
    CcspTraceInfo(("%s: WAN status event received: %s -> %s\n", __FUNCTION__,
                   status ? status : "(null)", wan_up ? "UP" : "DOWN"));

    DnsFailover_OnWanStatusChanged(ctx, wan_up);
}

static bool ReadInitialWanStatusViaRbus(struct dnsfailover_ctx *ctx)
{
    rbusValue_t value = NULL;
    rbusHandle_t handle = (rbusHandle_t)ctx->rbus_handle;

    if (!handle)
        return false;

    if (rbus_get(handle, WAN_STATUS_PARAM, &value) != RBUS_ERROR_SUCCESS) {
        CcspTraceWarning(("%s: rbus_get(%s) failed\n", __FUNCTION__, WAN_STATUS_PARAM));
        return false;
    }

    const char *status = rbusValue_GetString(value, NULL);
    bool wan_up = StatusStringMeansUp(status);
    rbusValue_Release(value);

    CcspTraceInfo(("%s: initial WAN status: %s -> %s\n", __FUNCTION__,
                   status ? status : "(null)", wan_up ? "UP" : "DOWN"));

    pthread_mutex_lock(&ctx->lock);
    ctx->wan_is_up = wan_up;
    pthread_mutex_unlock(&ctx->lock);
    return true;
}

/* ------------------------------------------------------------------------- */
/* Fallback polling thread (used only if RBUS subscription is unavailable)   */
/* ------------------------------------------------------------------------- */

static pthread_t g_fallback_tid;
static bool g_fallback_started = false;
static bool g_subscribed = false;
static rbusEventSubscription_t g_wan_subscription;

static void *WanFallbackPollThread(void *arg)
{
    struct dnsfailover_ctx *ctx = arg;

    CcspTraceWarning(("%s: RBUS WAN status subscription unavailable; "
                      "using /proc/net/route polling fallback every %us\n",
                      __FUNCTION__, WAN_ROUTE_FALLBACK_POLL_SEC));

    while (ctx->running) {
        bool up = HasDefaultRoute();
        DnsFailover_OnWanStatusChanged(ctx, up);
        DnsFailover_SleepMs(WAN_ROUTE_FALLBACK_POLL_SEC * 1000U, &ctx->running);
    }

    return NULL;
}

bool DnsFailover_WanStart(struct dnsfailover_ctx *ctx)
{
    bool have_initial = ReadInitialWanStatusViaRbus(ctx);

    if (!have_initial) {
        bool up = HasDefaultRoute();
        pthread_mutex_lock(&ctx->lock);
        ctx->wan_is_up = up;
        pthread_mutex_unlock(&ctx->lock);
    }

    if (ctx->rbus_handle) {
        memset(&g_wan_subscription, 0, sizeof(g_wan_subscription));
        g_wan_subscription.eventName = WAN_STATUS_PARAM;
        g_wan_subscription.handler = WanStatusEventHandler;
        g_wan_subscription.userData = ctx;
        g_wan_subscription.filter = NULL;
        g_wan_subscription.publishOnSubscribe = false;

        rbusError_t err = rbusEvent_SubscribeEx((rbusHandle_t)ctx->rbus_handle,
                                                 &g_wan_subscription, 1, 30);
        if (err == RBUS_ERROR_SUCCESS) {
            g_subscribed = true;
            CcspTraceInfo(("%s: subscribed to %s\n", __FUNCTION__, WAN_STATUS_PARAM));
            return true;
        }

        CcspTraceWarning(("%s: rbusEvent_SubscribeEx(%s) failed rc=%d; falling back to polling\n",
                          __FUNCTION__, WAN_STATUS_PARAM, err));
    }

    if (pthread_create(&g_fallback_tid, NULL, WanFallbackPollThread, ctx) != 0) {
        CcspTraceError(("%s: failed to start WAN fallback polling thread\n", __FUNCTION__));
        return false;
    }
    g_fallback_started = true;
    return true;
}

void DnsFailover_WanStop(struct dnsfailover_ctx *ctx)
{
    if (g_subscribed && ctx->rbus_handle) {
        rbusEvent_UnsubscribeEx((rbusHandle_t)ctx->rbus_handle, &g_wan_subscription, 1);
        g_subscribed = false;
    }

    if (g_fallback_started) {
        pthread_join(g_fallback_tid, NULL);
        g_fallback_started = false;
    }
}
