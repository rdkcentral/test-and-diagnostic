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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pthread.h>

#include <rbus/rbus.h>
#include "ccsp_trace.h"

#include "dnsfailover_rbus.h"
#include "dnsfailover_util.h"

/* Data-element get/set handlers do not receive user context, so we keep a
 * single back-pointer to the daemon context (there is exactly one instance
 * per process, matching every other RDK-B daemon in this codebase). */
static struct dnsfailover_ctx *g_ctx;

void DnsFailover_LoadDefaultConfig(struct dnsfailover_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->enable = true;
    cfg->monitor_tick_ms = DEFAULT_MONITOR_TICK_MS;
    cfg->dns_reply_deadline_ms = DEFAULT_DNS_REPLY_DEADLINE_MS;
    cfg->failure_episode_gap_ms = DEFAULT_FAILURE_EPISODE_GAP_MS;
    cfg->passive_failure_threshold = DEFAULT_PASSIVE_FAILURE_THRESHOLD;
    cfg->recovery_success_threshold = DEFAULT_RECOVERY_SUCCESS_THRESHOLD;
    cfg->verify_cooldown_ms = DEFAULT_VERIFY_COOLDOWN_MS;
    cfg->verify_timeout_ms = DEFAULT_VERIFY_TIMEOUT_MS;
    cfg->server_refresh_sec = DEFAULT_SERVER_REFRESH_SEC;
    snprintf(cfg->unbound_listen_ip, sizeof(cfg->unbound_listen_ip), "%s", DEFAULT_UNBOUND_LISTEN_IP);
    cfg->unbound_listen_port = DEFAULT_UNBOUND_LISTEN_PORT;
    snprintf(cfg->test_domain, sizeof(cfg->test_domain), "%s", DEFAULT_TEST_DOMAIN);
    snprintf(cfg->lan_ifname, sizeof(cfg->lan_ifname), "%s", DEFAULT_LAN_IFNAME);
}

/* ------------------------------------------------------------------------- */
/* Generic bounded-range setters (defensive validation on every RBUS SET;   */
/* TR-181 is an external, ACS/WebConfig-reachable input surface).           */
/* ------------------------------------------------------------------------- */

static bool SetU32Bounded(uint32_t *field, uint32_t value, uint32_t lo, uint32_t hi,
                          const char *name)
{
    if (value < lo || value > hi) {
        CcspTraceError(("%s: rejecting out-of-range value %u for %s (valid [%u,%u])\n",
                        __FUNCTION__, value, name, lo, hi));
        return false;
    }
    *field = value;
    return true;
}

/* ------------------------------------------------------------------------- */
/* Config parameter handlers                                                 */
/* ------------------------------------------------------------------------- */

#define DM_ENABLE                     DNSFAILOVER_DM_BASE "Enable"
#define DM_DNS_REPLY_DEADLINE_MS       DNSFAILOVER_DM_BASE "DnsReplyDeadlineMs"
#define DM_FAILURE_EPISODE_GAP_MS      DNSFAILOVER_DM_BASE "FailureEpisodeGapMs"
#define DM_PASSIVE_FAILURE_THRESHOLD   DNSFAILOVER_DM_BASE "PassiveFailureThreshold"
#define DM_RECOVERY_SUCCESS_THRESHOLD  DNSFAILOVER_DM_BASE "RecoverySuccessThreshold"
#define DM_VERIFY_COOLDOWN_MS          DNSFAILOVER_DM_BASE "VerifyCooldownMs"
#define DM_VERIFY_TIMEOUT_MS           DNSFAILOVER_DM_BASE "VerifyTimeoutMs"
#define DM_SERVER_REFRESH_SEC          DNSFAILOVER_DM_BASE "ServerRefreshIntervalSeconds"
#define DM_UNBOUND_LISTEN_IP           DNSFAILOVER_DM_BASE "UnboundListenAddress"
#define DM_UNBOUND_LISTEN_PORT         DNSFAILOVER_DM_BASE "UnboundListenPort"
#define DM_TEST_DOMAIN                 DNSFAILOVER_DM_BASE "TestDomain"
#define DM_LAN_IFNAME                  DNSFAILOVER_DM_BASE "LanInterfaceName"

#define DM_STATUS_FAILOVER_ACTIVE      DNSFAILOVER_DM_BASE "Status.FailoverActive"
#define DM_STATUS_FAILOVER_COUNT       DNSFAILOVER_DM_BASE "Status.FailoverCount"
#define DM_STATUS_FAILOVER_DURATION    DNSFAILOVER_DM_BASE "Status.FailoverDurationSeconds"
#define DM_STATUS_WAN_DOWN_SUPPRESSED  DNSFAILOVER_DM_BASE "Status.WANDownSuppressedCount"
#define DM_STATUS_WAN_IS_UP            DNSFAILOVER_DM_BASE "Status.WanIsUp"
#define DM_STATUS_CT_EVENTS_TOTAL      DNSFAILOVER_DM_BASE "Status.ConntrackEventsTotal"
#define DM_STATUS_PENDING_HWM          DNSFAILOVER_DM_BASE "Status.PendingTableHighWatermark"

static rbusError_t GetBoolHandler(rbusHandle_t handle, rbusProperty_t property,
                                  rbusGetHandlerOptions_t *opts)
{
    (void)handle; (void)opts;
    const char *name = rbusProperty_GetName(property);
    bool val = false;

    pthread_mutex_lock(&g_ctx->lock);
    if (strcmp(name, DM_ENABLE) == 0)
        val = g_ctx->cfg.enable;
    else if (strcmp(name, DM_STATUS_FAILOVER_ACTIVE) == 0)
        val = g_ctx->failover_active;
    else if (strcmp(name, DM_STATUS_WAN_IS_UP) == 0)
        val = g_ctx->wan_is_up;
    pthread_mutex_unlock(&g_ctx->lock);

    rbusValue_t v;
    rbusValue_Init(&v);
    rbusValue_SetBoolean(v, val);
    rbusProperty_SetValue(property, v);
    rbusValue_Release(v);
    return RBUS_ERROR_SUCCESS;
}

static rbusError_t SetBoolHandler(rbusHandle_t handle, rbusProperty_t property,
                                  rbusSetHandlerOptions_t *opts)
{
    (void)handle; (void)opts;
    const char *name = rbusProperty_GetName(property);
    rbusValue_t v = rbusProperty_GetValue(property);
    bool val = rbusValue_GetBoolean(v);

    if (strcmp(name, DM_ENABLE) == 0) {
        pthread_mutex_lock(&g_ctx->lock);
        g_ctx->cfg.enable = val;
        pthread_mutex_unlock(&g_ctx->lock);
        CcspTraceInfo(("%s: DNSFailover.Enable set to %s\n", __FUNCTION__, val ? "true" : "false"));
        return RBUS_ERROR_SUCCESS;
    }

    return RBUS_ERROR_INVALID_INPUT;
}

static rbusError_t GetU32Handler(rbusHandle_t handle, rbusProperty_t property,
                                 rbusGetHandlerOptions_t *opts)
{
    (void)handle; (void)opts;
    const char *name = rbusProperty_GetName(property);
    uint32_t val = 0;

    pthread_mutex_lock(&g_ctx->lock);
    if (strcmp(name, DM_DNS_REPLY_DEADLINE_MS) == 0) val = g_ctx->cfg.dns_reply_deadline_ms;
    else if (strcmp(name, DM_FAILURE_EPISODE_GAP_MS) == 0) val = g_ctx->cfg.failure_episode_gap_ms;
    else if (strcmp(name, DM_PASSIVE_FAILURE_THRESHOLD) == 0) val = g_ctx->cfg.passive_failure_threshold;
    else if (strcmp(name, DM_RECOVERY_SUCCESS_THRESHOLD) == 0) val = g_ctx->cfg.recovery_success_threshold;
    else if (strcmp(name, DM_VERIFY_COOLDOWN_MS) == 0) val = g_ctx->cfg.verify_cooldown_ms;
    else if (strcmp(name, DM_VERIFY_TIMEOUT_MS) == 0) val = g_ctx->cfg.verify_timeout_ms;
    else if (strcmp(name, DM_SERVER_REFRESH_SEC) == 0) val = g_ctx->cfg.server_refresh_sec;
    else if (strcmp(name, DM_UNBOUND_LISTEN_PORT) == 0) val = g_ctx->cfg.unbound_listen_port;
    else if (strcmp(name, DM_STATUS_FAILOVER_COUNT) == 0) val = (uint32_t)g_ctx->counters.failover_enabled_total;
    else if (strcmp(name, DM_STATUS_FAILOVER_DURATION) == 0) {
        uint64_t total = g_ctx->failover_total_duration_ms;
        if (g_ctx->failover_active && g_ctx->failover_started_ms != 0) {
            uint64_t now = DnsFailover_MonotonicMs();
            if (now > g_ctx->failover_started_ms)
                total += (now - g_ctx->failover_started_ms);
        }
        val = (uint32_t)(total / 1000ULL);
    }
    else if (strcmp(name, DM_STATUS_WAN_DOWN_SUPPRESSED) == 0) val = (uint32_t)g_ctx->counters.wan_down_suppressed_total;
    else if (strcmp(name, DM_STATUS_CT_EVENTS_TOTAL) == 0) val = (uint32_t)g_ctx->counters.ct_events_total;
    else if (strcmp(name, DM_STATUS_PENDING_HWM) == 0) val = g_ctx->counters.pending_table_high_watermark;
    pthread_mutex_unlock(&g_ctx->lock);

    rbusValue_t v;
    rbusValue_Init(&v);
    rbusValue_SetUInt32(v, val);
    rbusProperty_SetValue(property, v);
    rbusValue_Release(v);
    return RBUS_ERROR_SUCCESS;
}

static rbusError_t SetU32Handler(rbusHandle_t handle, rbusProperty_t property,
                                 rbusSetHandlerOptions_t *opts)
{
    (void)handle; (void)opts;
    const char *name = rbusProperty_GetName(property);
    rbusValue_t v = rbusProperty_GetValue(property);
    uint32_t val = rbusValue_GetUInt32(v);
    bool ok = false;

    pthread_mutex_lock(&g_ctx->lock);
    if (strcmp(name, DM_DNS_REPLY_DEADLINE_MS) == 0)
        ok = SetU32Bounded(&g_ctx->cfg.dns_reply_deadline_ms, val, 200, 30000, name);
    else if (strcmp(name, DM_FAILURE_EPISODE_GAP_MS) == 0)
        ok = SetU32Bounded(&g_ctx->cfg.failure_episode_gap_ms, val, 500, 60000, name);
    else if (strcmp(name, DM_PASSIVE_FAILURE_THRESHOLD) == 0)
        ok = SetU32Bounded(&g_ctx->cfg.passive_failure_threshold, val, 1, 100, name);
    else if (strcmp(name, DM_RECOVERY_SUCCESS_THRESHOLD) == 0)
        ok = SetU32Bounded(&g_ctx->cfg.recovery_success_threshold, val, 1, 100, name);
    else if (strcmp(name, DM_VERIFY_COOLDOWN_MS) == 0)
        ok = SetU32Bounded(&g_ctx->cfg.verify_cooldown_ms, val, 1000, 300000, name);
    else if (strcmp(name, DM_VERIFY_TIMEOUT_MS) == 0)
        ok = SetU32Bounded(&g_ctx->cfg.verify_timeout_ms, val, 200, 10000, name);
    else if (strcmp(name, DM_SERVER_REFRESH_SEC) == 0)
        ok = SetU32Bounded(&g_ctx->cfg.server_refresh_sec, val, 10, 3600, name);
    else if (strcmp(name, DM_UNBOUND_LISTEN_PORT) == 0)
        ok = SetU32Bounded(&g_ctx->cfg.unbound_listen_port, val, 1, 65535, name);
    pthread_mutex_unlock(&g_ctx->lock);

    return ok ? RBUS_ERROR_SUCCESS : RBUS_ERROR_INVALID_INPUT;
}

static rbusError_t GetStringHandler(rbusHandle_t handle, rbusProperty_t property,
                                    rbusGetHandlerOptions_t *opts)
{
    (void)handle; (void)opts;
    const char *name = rbusProperty_GetName(property);
    char buf[256] = { 0 };

    pthread_mutex_lock(&g_ctx->lock);
    if (strcmp(name, DM_UNBOUND_LISTEN_IP) == 0)
        snprintf(buf, sizeof(buf), "%s", g_ctx->cfg.unbound_listen_ip);
    else if (strcmp(name, DM_TEST_DOMAIN) == 0)
        snprintf(buf, sizeof(buf), "%s", g_ctx->cfg.test_domain);
    else if (strcmp(name, DM_LAN_IFNAME) == 0)
        snprintf(buf, sizeof(buf), "%s", g_ctx->cfg.lan_ifname);
    pthread_mutex_unlock(&g_ctx->lock);

    rbusValue_t v;
    rbusValue_Init(&v);
    rbusValue_SetString(v, buf);
    rbusProperty_SetValue(property, v);
    rbusValue_Release(v);
    return RBUS_ERROR_SUCCESS;
}

static rbusError_t SetStringHandler(rbusHandle_t handle, rbusProperty_t property,
                                    rbusSetHandlerOptions_t *opts)
{
    (void)handle; (void)opts;
    const char *name = rbusProperty_GetName(property);
    rbusValue_t v = rbusProperty_GetValue(property);
    const char *val = rbusValue_GetString(v, NULL);

    if (!val || val[0] == '\0') {
        CcspTraceError(("%s: rejecting empty value for %s\n", __FUNCTION__, name));
        return RBUS_ERROR_INVALID_INPUT;
    }

    if (strcmp(name, DM_UNBOUND_LISTEN_IP) == 0) {
        dns_addr_t tmp;
        if (!DnsFailover_AddrFromString(val, &tmp)) {
            CcspTraceError(("%s: rejecting invalid IP literal '%s' for %s\n",
                            __FUNCTION__, val, name));
            return RBUS_ERROR_INVALID_INPUT;
        }
        pthread_mutex_lock(&g_ctx->lock);
        snprintf(g_ctx->cfg.unbound_listen_ip, sizeof(g_ctx->cfg.unbound_listen_ip), "%s", val);
        pthread_mutex_unlock(&g_ctx->lock);
        return RBUS_ERROR_SUCCESS;
    }

    if (strcmp(name, DM_TEST_DOMAIN) == 0) {
        if (strlen(val) >= sizeof(g_ctx->cfg.test_domain)) {
            CcspTraceError(("%s: test domain too long\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        pthread_mutex_lock(&g_ctx->lock);
        snprintf(g_ctx->cfg.test_domain, sizeof(g_ctx->cfg.test_domain), "%s", val);
        pthread_mutex_unlock(&g_ctx->lock);
        return RBUS_ERROR_SUCCESS;
    }

    if (strcmp(name, DM_LAN_IFNAME) == 0) {
        /* Defense-in-depth: this string ultimately flows into a
         * v_secure_system()-invoked iptables command (see
         * dnsfailover_firewall.c). Restrict to a safe interface-name
         * charset even though v_secure_system does not use a shell. */
        for (const char *p = val; *p; ++p) {
            if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-' || *p == '_')) {
                CcspTraceError(("%s: rejecting invalid interface name '%s'\n", __FUNCTION__, val));
                return RBUS_ERROR_INVALID_INPUT;
            }
        }
        if (strlen(val) >= sizeof(g_ctx->cfg.lan_ifname)) {
            CcspTraceError(("%s: interface name too long\n", __FUNCTION__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        pthread_mutex_lock(&g_ctx->lock);
        snprintf(g_ctx->cfg.lan_ifname, sizeof(g_ctx->cfg.lan_ifname), "%s", val);
        pthread_mutex_unlock(&g_ctx->lock);
        return RBUS_ERROR_SUCCESS;
    }

    return RBUS_ERROR_INVALID_INPUT;
}

/* ------------------------------------------------------------------------- */
/* Per-server (bounded, MAX_DNS_SERVERS) diagnostic parameters               */
/* ------------------------------------------------------------------------- */

static char g_server_param_names[MAX_DNS_SERVERS][4][160];
enum { SP_ADDRESS = 0, SP_STATE, SP_EPISODES, SP_RECOVERY };
static const char *const kServerFieldSuffix[4] = {
    "Address", "State", "PassiveEpisodes", "RecoverySuccesses"
};

static const char *ServerStateToString(enum server_state st)
{
    switch (st) {
    case SERVER_HEALTHY: return "HEALTHY";
    case SERVER_SUSPECT: return "SUSPECT";
    case SERVER_FAILED:  return "FAILED";
    default: return "UNKNOWN";
    }
}

static bool ParseServerIndexAndField(const char *name, uint32_t *index, uint32_t *field)
{
    /* Expected form: Device.X_RDK_Features.DNSFailover.ServerState.<n>.<Field> */
    const char *prefix = DNSFAILOVER_DM_BASE "ServerState.";
    size_t prefix_len = strlen(prefix);
    if (strncmp(name, prefix, prefix_len) != 0)
        return false;

    unsigned n = 0;
    int consumed = 0;
    if (sscanf(name + prefix_len, "%u.%n", &n, &consumed) != 1 || n < 1 || n > MAX_DNS_SERVERS)
        return false;

    const char *suffix = name + prefix_len + consumed;
    for (uint32_t i = 0; i < 4; ++i) {
        if (strcmp(suffix, kServerFieldSuffix[i]) == 0) {
            *index = n - 1;
            *field = i;
            return true;
        }
    }
    return false;
}

static rbusError_t GetServerStateHandler(rbusHandle_t handle, rbusProperty_t property,
                                         rbusGetHandlerOptions_t *opts)
{
    (void)handle; (void)opts;
    const char *name = rbusProperty_GetName(property);
    uint32_t idx = 0, field = 0;
    rbusValue_t v;
    rbusValue_Init(&v);

    if (!ParseServerIndexAndField(name, &idx, &field)) {
        rbusValue_SetString(v, "");
        rbusProperty_SetValue(property, v);
        rbusValue_Release(v);
        return RBUS_ERROR_SUCCESS;
    }

    pthread_mutex_lock(&g_ctx->lock);
    struct dns_server_health *s = (idx < g_ctx->server_count) ? &g_ctx->servers[idx] : NULL;

    switch (field) {
    case SP_ADDRESS:
        rbusValue_SetString(v, (s && s->used) ? s->ip_string : "");
        break;
    case SP_STATE:
        rbusValue_SetString(v, (s && s->used) ? ServerStateToString(s->state) : "UNCONFIGURED");
        break;
    case SP_EPISODES:
        rbusValue_SetUInt32(v, (s && s->used) ? s->total_failure_episodes : 0);
        break;
    case SP_RECOVERY:
        rbusValue_SetUInt32(v, (s && s->used) ? s->recovery_successes : 0);
        break;
    default:
        break;
    }
    pthread_mutex_unlock(&g_ctx->lock);

    rbusProperty_SetValue(property, v);
    rbusValue_Release(v);
    return RBUS_ERROR_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Registration                                                              */
/* ------------------------------------------------------------------------- */

#define MAX_DATA_ELEMENTS (32 + (MAX_DNS_SERVERS * 4))

static rbusDataElement_t g_elements[MAX_DATA_ELEMENTS];
static uint32_t g_element_count;

static void AddElement(const char *name, rbusGetHandler_t get, rbusSetHandler_t set)
{
    if (g_element_count >= MAX_DATA_ELEMENTS)
        return;

    rbusDataElement_t *e = &g_elements[g_element_count++];
    memset(e, 0, sizeof(*e));
    e->name = name;
    e->type = RBUS_ELEMENT_TYPE_PROPERTY;
    e->cbTable.getHandler = get;
    e->cbTable.setHandler = set;
}

bool DnsFailover_RbusInit(struct dnsfailover_ctx *ctx)
{
    g_ctx = ctx;
    g_element_count = 0;

    if (RBUS_ENABLED != rbus_checkStatus()) {
        CcspTraceError(("%s: RBUS not available; DNSFailover TR-181 parameters "
                        "will not be exposed. Daemon continues with defaults.\n",
                        __FUNCTION__));
        ctx->rbus_handle = NULL;
        return false;
    }

    rbusHandle_t handle = NULL;
    if (rbus_open(&handle, DNSFAILOVER_COMPONENT_NAME) != RBUS_ERROR_SUCCESS) {
        CcspTraceError(("%s: rbus_open failed\n", __FUNCTION__));
        ctx->rbus_handle = NULL;
        return false;
    }
    ctx->rbus_handle = (void *)handle;

    AddElement(DM_ENABLE, GetBoolHandler, SetBoolHandler);
    AddElement(DM_DNS_REPLY_DEADLINE_MS, GetU32Handler, SetU32Handler);
    AddElement(DM_FAILURE_EPISODE_GAP_MS, GetU32Handler, SetU32Handler);
    AddElement(DM_PASSIVE_FAILURE_THRESHOLD, GetU32Handler, SetU32Handler);
    AddElement(DM_RECOVERY_SUCCESS_THRESHOLD, GetU32Handler, SetU32Handler);
    AddElement(DM_VERIFY_COOLDOWN_MS, GetU32Handler, SetU32Handler);
    AddElement(DM_VERIFY_TIMEOUT_MS, GetU32Handler, SetU32Handler);
    AddElement(DM_SERVER_REFRESH_SEC, GetU32Handler, SetU32Handler);
    AddElement(DM_UNBOUND_LISTEN_IP, GetStringHandler, SetStringHandler);
    AddElement(DM_UNBOUND_LISTEN_PORT, GetU32Handler, SetU32Handler);
    AddElement(DM_TEST_DOMAIN, GetStringHandler, SetStringHandler);
    AddElement(DM_LAN_IFNAME, GetStringHandler, SetStringHandler);

    AddElement(DM_STATUS_FAILOVER_ACTIVE, GetBoolHandler, NULL);
    AddElement(DM_STATUS_WAN_IS_UP, GetBoolHandler, NULL);
    AddElement(DM_STATUS_FAILOVER_COUNT, GetU32Handler, NULL);
    AddElement(DM_STATUS_FAILOVER_DURATION, GetU32Handler, NULL);
    AddElement(DM_STATUS_WAN_DOWN_SUPPRESSED, GetU32Handler, NULL);
    AddElement(DM_STATUS_CT_EVENTS_TOTAL, GetU32Handler, NULL);
    AddElement(DM_STATUS_PENDING_HWM, GetU32Handler, NULL);

    for (uint32_t i = 0; i < MAX_DNS_SERVERS; ++i) {
        for (uint32_t f = 0; f < 4; ++f) {
            snprintf(g_server_param_names[i][f], sizeof(g_server_param_names[i][f]),
                     DNSFAILOVER_DM_BASE "ServerState.%u.%s", i + 1, kServerFieldSuffix[f]);
            AddElement(g_server_param_names[i][f], GetServerStateHandler, NULL);
        }
    }

    if (rbus_regDataElements(handle, g_element_count, g_elements) != RBUS_ERROR_SUCCESS) {
        CcspTraceError(("%s: rbus_regDataElements failed\n", __FUNCTION__));
        rbus_close(handle);
        ctx->rbus_handle = NULL;
        return false;
    }

    CcspTraceInfo(("%s: registered %u RBUS data elements under %s\n",
                   __FUNCTION__, g_element_count, DNSFAILOVER_DM_BASE));
    return true;
}

void DnsFailover_RbusTerminate(struct dnsfailover_ctx *ctx)
{
    if (ctx->rbus_handle) {
        rbus_close((rbusHandle_t)ctx->rbus_handle);
        ctx->rbus_handle = NULL;
    }
}
