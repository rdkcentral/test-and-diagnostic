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
 * dnsfailover.h
 *
 * Shared data types and tunables for the DNS Failover daemon.
 *
 * Design reference: DNS_Failover_Conntrack_Unbound_Design.docx
 *   - Passive conntrack-based detection of upstream DNS non-response
 *   - Failure episode aggregation to avoid false positives on traffic bursts
 *   - Active verification (single controlled query) once passive threshold
 *     is reached
 *   - Global Unbound failover only when ALL configured resolvers have
 *     failed verification AND WAN connectivity is confirmed up
 *   - Sparse, exponential-backoff recovery probing of FAILED resolvers
 *
 * Locking discipline (see dnsfailover_conntrack.c for full detail):
 *   ctx->lock protects: pending[], servers[], server_count, wan_is_up,
 *   failover_active and all counters. It is held only for short, bounded
 *   in-memory operations. Network I/O (active verification, firewall
 *   programming) NEVER happens while ctx->lock is held; the conntrack
 *   callback and monitor tick enqueue work for the verify worker thread
 *   instead of calling it synchronously.
 */

#ifndef DNSFAILOVER_H
#define DNSFAILOVER_H

#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Tunables (overridable at compile time; runtime overrides come from TR-181 */
/* via dnsfailover_rbus.c and are copied into ctx->cfg at startup/on change). */
/* ------------------------------------------------------------------------- */

#define DNSFAILOVER_COMPONENT_NAME     "DNSFailover"

#define DNS_PORT                        53U
#define MAX_PENDING_FLOWS               2048U
#define MAX_DNS_SERVERS                 8U

#define DEFAULT_MONITOR_TICK_MS         250U
#define DEFAULT_DNS_REPLY_DEADLINE_MS   2000U
#define DEFAULT_FAILURE_EPISODE_GAP_MS  5000U
#define DEFAULT_PASSIVE_FAILURE_THRESHOLD  3U
#define DEFAULT_RECOVERY_SUCCESS_THRESHOLD 2U
#define DEFAULT_VERIFY_COOLDOWN_MS      10000U
#define DEFAULT_VERIFY_TIMEOUT_MS       2000U
#define DEFAULT_UNBOUND_LISTEN_IP       "127.0.0.1"
#define DEFAULT_UNBOUND_LISTEN_PORT     5353U
#define DEFAULT_TEST_DOMAIN             "example.com"
#define DEFAULT_LAN_IFNAME              "brlan0"
#define DEFAULT_SERVER_REFRESH_SEC      60U

/* Recovery probing backoff schedule (seconds) once a server is FAILED.
 * Sparse probing avoids hammering a dead resolver; caps at the last entry. */
#define RECOVERY_BACKOFF_STEPS          6U
static const uint32_t RECOVERY_BACKOFF_SECONDS[RECOVERY_BACKOFF_STEPS] =
    { 30U, 60U, 120U, 240U, 480U, 600U };

/* ------------------------------------------------------------------------- */
/* Address helpers (dual-stack)                                              */
/* ------------------------------------------------------------------------- */

typedef struct dns_addr {
    int af;                       /* AF_INET or AF_INET6 */
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } a;
} dns_addr_t;

/* ------------------------------------------------------------------------- */
/* Conntrack pending-flow tracking                                           */
/* ------------------------------------------------------------------------- */

struct flow_key {
    int      af;           /* AF_INET or AF_INET6 */
    dns_addr_t src;
    dns_addr_t dst;
    uint16_t src_port;     /* host byte order */
    uint16_t dst_port;     /* host byte order */
    uint8_t  proto;        /* IPPROTO_UDP (TCP/53 is a documented follow-up) */
};

struct pending_flow {
    bool used;
    bool expired_reported;
    struct flow_key key;
    uint64_t created_ms;
};

/* ------------------------------------------------------------------------- */
/* Per-server health state machine                                           */
/* ------------------------------------------------------------------------- */

enum server_state {
    SERVER_HEALTHY = 0,
    SERVER_SUSPECT,
    SERVER_FAILED
};

struct dns_server_health {
    bool used;
    bool enabled;
    dns_addr_t addr;
    char ip_string[INET6_ADDRSTRLEN];

    enum server_state state;
    uint32_t failure_episodes;
    uint32_t recovery_successes;
    uint64_t last_failure_episode_ms;
    uint64_t last_reply_ms;
    uint64_t last_verify_ms;
    uint64_t next_verify_due_ms;   /* used for FAILED recovery backoff */
    uint32_t backoff_index;        /* index into RECOVERY_BACKOFF_SECONDS */
    bool     verify_in_flight;      /* prevents duplicate queued verify jobs */

    uint32_t total_failure_episodes;   /* lifetime counters, for telemetry */
    uint32_t total_verify_success;
    uint32_t total_verify_failure;
};

/* ------------------------------------------------------------------------- */
/* Runtime configuration (backed by TR-181, see dnsfailover_rbus.c)          */
/* ------------------------------------------------------------------------- */

struct dnsfailover_config {
    bool     enable;
    uint32_t monitor_tick_ms;
    uint32_t dns_reply_deadline_ms;
    uint32_t failure_episode_gap_ms;
    uint32_t passive_failure_threshold;
    uint32_t recovery_success_threshold;
    uint32_t verify_cooldown_ms;
    uint32_t verify_timeout_ms;
    uint32_t server_refresh_sec;
    char     unbound_listen_ip[INET6_ADDRSTRLEN];
    uint32_t unbound_listen_port;
    char     test_domain[256];
    char     lan_ifname[16];
};

/* ------------------------------------------------------------------------- */
/* Telemetry counters                                                        */
/* ------------------------------------------------------------------------- */

struct dnsfailover_counters {
    uint64_t ct_events_total;
    uint64_t ct_events_new;
    uint64_t ct_events_reply;
    uint64_t ct_events_destroy;
    uint64_t unreplied_expirations_total;
    uint64_t failure_episodes_total;
    uint64_t active_verify_success_total;
    uint64_t active_verify_failure_total;
    uint64_t failover_enabled_total;
    uint64_t failover_disabled_total;
    uint64_t wan_down_suppressed_total;
    uint32_t pending_table_high_watermark;
};

/* ------------------------------------------------------------------------- */
/* Top-level daemon context                                                  */
/* ------------------------------------------------------------------------- */

struct dnsfailover_ctx {
    pthread_mutex_t lock;   /* protects everything below except rbus/nfct handles */

    struct pending_flow pending[MAX_PENDING_FLOWS];
    uint32_t pending_in_use;

    struct dns_server_health servers[MAX_DNS_SERVERS];
    uint32_t server_count;

    bool wan_is_up;
    bool failover_active;
    uint64_t failover_started_ms;
    uint64_t failover_total_duration_ms;

    struct dnsfailover_config cfg;
    struct dnsfailover_counters counters;

    /* Non-mutex-protected handles; each owned by exactly one subsystem. */
    struct nfct_handle *nfct;
    void *rbus_handle;     /* rbusHandle_t, opaque here to avoid pulling rbus.h
                             * into every translation unit that includes this
                             * header. */

    volatile sig_atomic_t running;
};

#ifdef __cplusplus
}
#endif

#endif /* DNSFAILOVER_H */
