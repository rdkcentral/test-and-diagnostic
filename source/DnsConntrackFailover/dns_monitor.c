/*
 * dns_monitor.c -- see dns_monitor.h.
 *
 * Detection pipeline (RDKB-66998):
 *   1. Conntrack delivers UDP/53 and TCP/53 flow events (IPv4 and IPv6).
 *   2. Flows to a configured upstream resolver that get no reply within
 *      ReplyDeadline become passive failure evidence, aggregated into
 *      time-separated episodes per server.
 *   3. After FailureThreshold episodes, that specific server is actively
 *      probed (VerifyTimeout x VerifyAttempts). A reply clears it; no reply,
 *      while the WAN is up, marks it FAILED.
 *   4. Failover is engaged only when EVERY known upstream is FAILED, and
 *      released as soon as one recovers.
 *
 * Active verification runs under the state lock. The evaluation tick is
 * low-frequency (MonitorTick) and verification is rare (only after sustained
 * passive failure), so the brief hold is an acceptable trade for keeping the
 * state machine simple and race-free.
 */

#define _GNU_SOURCE

#include "dns_monitor.h"

#include "dns_log.h"
#include "dns_probe.h"
#include "dns_redirect.h"
#include "failover_config.h"
#include "ip_addr.h"
#include "resolver_list.h"
#include "wan_status.h"

#include <errno.h>
#include <inttypes.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define DNS_PORT            53U
#define MAX_PENDING_FLOWS   2048U
#define MAX_DNS_SERVERS     8U

/* Upper bound of the random delay before the first active verification, so a
 * mass outage doesn't make every device probe upstream at the same instant. */
#define VERIFY_JITTER_MAX_MS 60000U

struct flow_key {
    struct ip_addr src_ip;
    struct ip_addr dst_ip;
    uint16_t src_port; /* host byte order */
    uint16_t dst_port; /* host byte order */
    uint8_t  proto;    /* IPPROTO_UDP or IPPROTO_TCP */
};

struct pending_flow {
    bool used;
    bool expired_reported;
    struct flow_key key;
    uint64_t created_ms;
};

enum server_state {
    SERVER_HEALTHY = 0,
    SERVER_SUSPECT,
    SERVER_FAILED
};

struct dns_server_health {
    bool used;
    struct ip_addr address;
    enum server_state state;
    uint32_t failure_episodes;
    uint32_t recovery_successes;
    uint64_t last_failure_episode_ms;
    uint64_t last_verify_ms;
    uint64_t verify_at_ms;      /* 0 = none pending; else jittered time to verify */
    uint64_t recovery_delay_ms; /* current backoff between recovery re-checks */
};

struct monitor_ctx {
    pthread_mutex_t lock;
    struct pending_flow pending[MAX_PENDING_FLOWS];
    struct dns_server_health servers[MAX_DNS_SERVERS];
    struct nfct_handle *nfct;
};

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_event_failed; /* conntrack thread died on an error */
static bool g_failover_active; /* monitor's view of the current failover state */

/* ------------------------------------------------------------------------- */
/* Time helpers                                                              */
/* ------------------------------------------------------------------------- */

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        LOG_ERR("clock_gettime(CLOCK_MONOTONIC) failed: %s", strerror(errno));
        return 0;
    }
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static void sleep_ms(unsigned ms)
{
    struct timespec req = {
        .tv_sec  = ms / 1000U,
        .tv_nsec = (long)(ms % 1000U) * 1000000L,
    };
    while (nanosleep(&req, &req) != 0 && errno == EINTR) {
        if (!g_running)
            break;
    }
}

/* ------------------------------------------------------------------------- */
/* Pending-flow table (open addressing, replace-oldest on saturation)        */
/* ------------------------------------------------------------------------- */

static bool flow_key_equal(const struct flow_key *a, const struct flow_key *b)
{
    return ip_addr_equal(&a->src_ip, &b->src_ip) &&
           ip_addr_equal(&a->dst_ip, &b->dst_ip) &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

static uint32_t flow_hash(const struct flow_key *k)
{
    uint32_t h = 2166136261u;
#define MIX(v) do { h ^= (uint32_t)(v); h *= 16777619u; } while (0)
    MIX(ip_addr_hash(&k->src_ip));
    MIX(ip_addr_hash(&k->dst_ip));
    MIX(k->src_port);
    MIX(k->dst_port);
    MIX(k->proto);
#undef MIX
    return h;
}

static struct pending_flow *pending_lookup(struct monitor_ctx *ctx,
                                           const struct flow_key *key)
{
    uint32_t start = flow_hash(key) % MAX_PENDING_FLOWS;
    for (uint32_t i = 0; i < MAX_PENDING_FLOWS; ++i) {
        struct pending_flow *p = &ctx->pending[(start + i) % MAX_PENDING_FLOWS];
        if (p->used && flow_key_equal(&p->key, key))
            return p;
    }
    return NULL;
}

static struct pending_flow *pending_alloc(struct monitor_ctx *ctx,
                                          const struct flow_key *key)
{
    uint32_t start = flow_hash(key) % MAX_PENDING_FLOWS;
    struct pending_flow *oldest = NULL;

    for (uint32_t i = 0; i < MAX_PENDING_FLOWS; ++i) {
        struct pending_flow *p = &ctx->pending[(start + i) % MAX_PENDING_FLOWS];
        if (!p->used) {
            memset(p, 0, sizeof(*p));
            p->used = true;
            p->key = *key;
            p->created_ms = monotonic_ms();
            return p;
        }
        if (!oldest || p->created_ms < oldest->created_ms)
            oldest = p;
    }

    /* Saturation should be rare: reuse the oldest slot rather than allocate. */
    if (oldest) {
        LOG_WARN("pending DNS flow table full (%u); evicting the oldest entry",
                 MAX_PENDING_FLOWS);
        memset(oldest, 0, sizeof(*oldest));
        oldest->used = true;
        oldest->key = *key;
        oldest->created_ms = monotonic_ms();
    }
    return oldest;
}

static void pending_remove(struct monitor_ctx *ctx, const struct flow_key *key)
{
    struct pending_flow *p = pending_lookup(ctx, key);
    if (p)
        memset(p, 0, sizeof(*p));
}

/* ------------------------------------------------------------------------- */
/* Per-server health table                                                   */
/* ------------------------------------------------------------------------- */

static struct dns_server_health *server_get(struct monitor_ctx *ctx,
                                            const struct ip_addr *address,
                                            bool create)
{
    struct dns_server_health *free_slot = NULL;

    for (uint32_t i = 0; i < MAX_DNS_SERVERS; ++i) {
        struct dns_server_health *s = &ctx->servers[i];
        if (s->used && ip_addr_equal(&s->address, address))
            return s;
        if (!s->used && !free_slot)
            free_slot = s;
    }

    if (!create)
        return NULL;

    if (!free_slot) {
        char ip[INET6_ADDRSTRLEN];
        LOG_ERR("DNS server table full (%u); not tracking %s",
                MAX_DNS_SERVERS, ip_addr_to_str(address, ip, sizeof(ip)));
        return NULL;
    }

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = true;
    free_slot->address = *address;
    free_slot->state = SERVER_HEALTHY;
    return free_slot;
}

/* ------------------------------------------------------------------------- */
/* Active verification                                                       */
/* ------------------------------------------------------------------------- */

/* Probes one specific server up to VerifyAttempts times; true on any reply. */
static bool verify_server(const struct ip_addr *address,
                          const struct failover_config *cfg)
{
    char ip[INET6_ADDRSTRLEN];
    ip_addr_to_str(address, ip, sizeof(ip));

    unsigned attempts = cfg->verify_attempts ? cfg->verify_attempts : 1;
    for (unsigned a = 1; a <= attempts; ++a) {
        if (dns_probe(ip, cfg->verify_timeout_ms)) {
            LOG_INFO("VERIFY: %s replied (attempt %u/%u)", ip, a, attempts);
            return true;
        }
    }

    LOG_INFO("VERIFY: %s no reply after %u attempt(s)", ip, attempts);
    return false;
}

/* ------------------------------------------------------------------------- */
/* State machine (all callers hold ctx->lock)                                */
/* ------------------------------------------------------------------------- */

static void record_reply_locked(struct monitor_ctx *ctx, const struct ip_addr *server_ip)
{
    struct dns_server_health *s = server_get(ctx, server_ip, true);
    if (!s)
        return;

    /* A verification is scheduled/pending: let it make the authoritative call
     * rather than letting one stray passive reply restart episode counting. */
    if (s->verify_at_ms != 0)
        return;

    /* While FAILED, client DNS is redirected to the local resolver, so these
     * passive "replies" come from it -- conntrack still shows the upstream
     * tuple, so they must NOT be read as upstream recovery. Only the marked
     * active probe in evaluate_server_locked() decides recovery. */
    if (s->state == SERVER_FAILED)
        return;

    if (s->failure_episodes != 0) {
        char ip[INET6_ADDRSTRLEN];
        LOG_INFO("PASSIVE: %s answered; cleared %u failure episode(s)",
                 ip_addr_to_str(server_ip, ip, sizeof(ip)), s->failure_episodes);
    }
    s->failure_episodes = 0;
    if (s->state == SERVER_SUSPECT) {
        s->state = SERVER_HEALTHY;
        s->recovery_successes = 0;
    }
}

static void record_failure_episode_locked(struct monitor_ctx *ctx,
                                          const struct ip_addr *server_ip,
                                          uint64_t now_ms,
                                          const struct failover_config *cfg)
{
    struct dns_server_health *s = server_get(ctx, server_ip, true);
    char ip[INET6_ADDRSTRLEN];

    if (!s)
        return; /* table-full error already reported by server_get() */

    /* Already FAILED: recovery is owned by the active probe, and redirected
     * timeouts carry no upstream signal -- stop counting. */
    if (s->state == SERVER_FAILED)
        return;

    /* Enough evidence already gathered; wait for verification to decide. */
    if (s->failure_episodes >= cfg->failure_threshold)
        return;

    /* Collapse a burst of client lookups into one episode per gap window. */
    if (s->last_failure_episode_ms != 0 &&
        now_ms - s->last_failure_episode_ms < cfg->failure_episode_gap_ms)
        return;

    s->last_failure_episode_ms = now_ms;
    s->failure_episodes++;
    s->recovery_successes = 0;
    if (s->state == SERVER_HEALTHY)
        s->state = SERVER_SUSPECT;

    LOG_INFO("PASSIVE: %s failure episode %u/%u",
             ip_addr_to_str(server_ip, ip, sizeof(ip)),
             s->failure_episodes, cfg->failure_threshold);
}

/* True once last_verify_ms is set and fewer than cooldown_ms have elapsed. */
static bool in_cooldown(const struct dns_server_health *s, uint64_t now_ms,
                        uint64_t cooldown_ms)
{
    return s->last_verify_ms != 0 && now_ms - s->last_verify_ms < cooldown_ms;
}

/* Re-verifies a FAILED server, applying RecoveryInitial->RecoveryMax backoff
 * and requiring RecoverySuccessThreshold consecutive successes to recover. */
static void evaluate_recovery_locked(struct dns_server_health *s, uint64_t now_ms,
                                     const struct failover_config *cfg)
{
    char ip[INET6_ADDRSTRLEN];

    if (in_cooldown(s, now_ms, s->recovery_delay_ms))
        return;

    s->last_verify_ms = now_ms;

    if (!verify_server(&s->address, cfg)) {
        s->recovery_successes = 0;
        s->recovery_delay_ms *= 2;
        if (s->recovery_delay_ms > cfg->recovery_max_ms)
            s->recovery_delay_ms = cfg->recovery_max_ms;
        return;
    }

    if (++s->recovery_successes < cfg->recovery_success_threshold) {
        LOG_INFO("RECOVERY: %s success %u/%u",
                 ip_addr_to_str(&s->address, ip, sizeof(ip)),
                 s->recovery_successes, cfg->recovery_success_threshold);
        return;
    }

    LOG_INFO("DECISION: %s recovered", ip_addr_to_str(&s->address, ip, sizeof(ip)));
    s->state = SERVER_HEALTHY;
    s->failure_episodes = 0;
    s->recovery_successes = 0;
}

/* Confirms passive evidence for a non-FAILED server and, on confirmed failure
 * with a reachable WAN, transitions it to FAILED. */
static void evaluate_failure_locked(struct dns_server_health *s, uint64_t now_ms,
                                    const struct failover_config *cfg)
{
    char ip[INET6_ADDRSTRLEN];

    if (s->failure_episodes < cfg->failure_threshold)
        return;

    if (in_cooldown(s, now_ms, cfg->verify_cooldown_ms))
        return;

    /* Stagger the first probe across the jitter window. */
    if (s->verify_at_ms == 0) {
        s->verify_at_ms = now_ms + ((uint64_t)rand() % VERIFY_JITTER_MAX_MS);
        LOG_INFO("VERIFY: %s scheduled in %" PRIu64 " ms",
                 ip_addr_to_str(&s->address, ip, sizeof(ip)), s->verify_at_ms - now_ms);
        return;
    }
    if (now_ms < s->verify_at_ms)
        return;

    s->verify_at_ms = 0;
    s->last_verify_ms = now_ms;

    if (verify_server(&s->address, cfg)) {
        LOG_INFO("DECISION: %s verified healthy; passive failure evidence discarded",
                 ip_addr_to_str(&s->address, ip, sizeof(ip)));
        s->state = SERVER_HEALTHY;
        s->failure_episodes = 0;
        return;
    }

    if (!wan_status_is_reachable()) {
        LOG_INFO("DECISION: WAN down; suppressing failure for %s",
                 ip_addr_to_str(&s->address, ip, sizeof(ip)));
        s->state = SERVER_HEALTHY;
        s->failure_episodes = 0;
        return;
    }

    s->state = SERVER_FAILED;
    s->failure_episodes = 0;
    s->recovery_successes = 0;
    s->recovery_delay_ms = cfg->recovery_initial_ms;
    LOG_WARN("DECISION: %s failed while WAN reachable",
             ip_addr_to_str(&s->address, ip, sizeof(ip)));
}

static void evaluate_server_locked(struct dns_server_health *s, uint64_t now_ms,
                                   const struct failover_config *cfg)
{
    if (!s->used)
        return;

    if (s->state == SERVER_FAILED)
        evaluate_recovery_locked(s, now_ms, cfg);
    else
        evaluate_failure_locked(s, now_ms, cfg);
}

/* ------------------------------------------------------------------------- */
/* Conntrack event ingestion                                                 */
/* ------------------------------------------------------------------------- */

static bool extract_dns_key(const struct nf_conntrack *ct, struct flow_key *key)
{
    if (!nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST))
        return false;

    uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    uint16_t dport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));

    if ((proto != IPPROTO_UDP && proto != IPPROTO_TCP) || dport != DNS_PORT)
        return false;

    memset(key, 0, sizeof(*key));

    /* ATTR_ORIG_L3PROTO isn't reliably marked "set" on every conntrack build;
     * infer the family from whichever address attribute is actually present. */
    if (nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC) && nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST)) {
        key->src_ip.family = AF_INET;
        key->src_ip.a.v4.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
        key->dst_ip.family = AF_INET;
        key->dst_ip.a.v4.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
    } else if (nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC) && nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST)) {
        const void *src6 = nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC);
        const void *dst6 = nfct_get_attr(ct, ATTR_ORIG_IPV6_DST);
        if (!src6 || !dst6)
            return false;
        key->src_ip.family = AF_INET6;
        memcpy(&key->src_ip.a.v6, src6, sizeof(key->src_ip.a.v6));
        key->dst_ip.family = AF_INET6;
        memcpy(&key->dst_ip.a.v6, dst6, sizeof(key->dst_ip.a.v6));
    } else {
        LOG_WARN("conntrack DNS event has no IPv4/IPv6 address attributes");
        return false;
    }

    key->src_port = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
    key->dst_port = dport;
    key->proto = proto;
    return true;
}

static int conntrack_event_cb(enum nf_conntrack_msg_type type,
                              struct nf_conntrack *ct, void *data)
{
    struct monitor_ctx *ctx = data;
    struct flow_key key;
    char dst[INET6_ADDRSTRLEN];
    struct failover_config cfg = failover_config_get();

    if (!cfg.enable)
        return NFCT_CB_CONTINUE; /* master switch off: ignore all DNS */

    if (!extract_dns_key(ct, &key))
        return NFCT_CB_CONTINUE;

    /* Only the gateway's configured upstreams are evidence about its DNS. */
    ip_addr_to_str(&key.dst_ip, dst, sizeof(dst));
    if (!resolver_list_is_upstream(dst))
        return NFCT_CB_CONTINUE;

    uint32_t status = nfct_attr_is_set(ct, ATTR_STATUS)
                          ? nfct_get_attr_u32(ct, ATTR_STATUS) : 0;
    bool seen_reply = (status & IPS_SEEN_REPLY) != 0;

    pthread_mutex_lock(&ctx->lock);

    if (seen_reply) {
        pending_remove(ctx, &key);
        record_reply_locked(ctx, &key.dst_ip);
    } else if (type == NFCT_T_NEW) {
        if (!pending_lookup(ctx, &key))
            (void)pending_alloc(ctx, &key);
    } else if (type == NFCT_T_DESTROY) {
        /* Destroyed before our timer classified it: count it as evidence. */
        struct pending_flow *p = pending_lookup(ctx, &key);
        if (p && !p->expired_reported)
            record_failure_episode_locked(ctx, &key.dst_ip, monotonic_ms(), &cfg);
        pending_remove(ctx, &key);
    }

    pthread_mutex_unlock(&ctx->lock);
    return NFCT_CB_CONTINUE;
}

static void *conntrack_thread(void *arg)
{
    struct monitor_ctx *ctx = arg;

    while (g_running) {
        int rc = nfct_catch(ctx->nfct);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ENOBUFS) {
                /* Netlink receive buffer overrun: some events were lost, but
                 * the stream is still usable. */
                LOG_ERR("conntrack event buffer overrun; events dropped");
                continue;
            }
            LOG_ERR("nfct_catch failed: %s; conntrack monitoring stopped", strerror(errno));
            g_event_failed = 1;
            break;
        }
    }

    g_running = 0;
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Evaluation tick                                                           */
/* ------------------------------------------------------------------------- */

/* Clears all state and returns whether failover was active (so the caller can
 * release it). Used when the master Enable switch is off. */
static bool reset_all_locked(struct monitor_ctx *ctx)
{
    for (uint32_t i = 0; i < MAX_DNS_SERVERS; ++i) {
        struct dns_server_health *s = &ctx->servers[i];
        if (!s->used)
            continue;
        s->state = SERVER_HEALTHY;
        s->failure_episodes = 0;
        s->recovery_successes = 0;
        s->verify_at_ms = 0;
    }
    return g_failover_active;
}

/* Expires overdue pending flows into passive failure evidence. */
static void expire_pending_locked(struct monitor_ctx *ctx, uint64_t now,
                                  const struct failover_config *cfg)
{
    for (uint32_t i = 0; i < MAX_PENDING_FLOWS; ++i) {
        struct pending_flow *p = &ctx->pending[i];
        if (!p->used || p->expired_reported)
            continue;

        if (now - p->created_ms >= cfg->reply_deadline_ms) {
            p->expired_reported = true;
            /* Record evidence unconditionally; WAN check gates the decision in
             * evaluate_failure_locked(), not evidence collection. */
            record_failure_episode_locked(ctx, &p->key.dst_ip, now, cfg);
        }
    }
}

/* Returns true when at least one server is known and every one is FAILED. */
static bool all_servers_failed_locked(struct monitor_ctx *ctx)
{
    uint32_t total = 0, failed = 0;

    for (uint32_t i = 0; i < MAX_DNS_SERVERS; ++i) {
        struct dns_server_health *s = &ctx->servers[i];
        if (!s->used)
            continue;
        total++;
        if (s->state == SERVER_FAILED)
            failed++;
    }

    return total > 0 && failed == total;
}

static void monitor_tick(struct monitor_ctx *ctx)
{
    static uint64_t last_resolver_reload_ms;

    failover_config_refresh();
    struct failover_config cfg = failover_config_get();
    const uint64_t now = monotonic_ms();

    /* Re-read the upstream resolver list on its own cadence (ResolverReload),
     * independent of verification, so ISP DNS changes are picked up promptly. */
    if (last_resolver_reload_ms == 0 || now - last_resolver_reload_ms >= cfg.resolver_reload_ms) {
        resolver_list_refresh();
        last_resolver_reload_ms = now;
    }

    /* Polled every tick so WAN state changes are logged promptly; the verdict
     * itself is re-checked where a decision needs it. */
    (void)wan_status_is_reachable();
    bool want_failover;

    pthread_mutex_lock(&ctx->lock);

    if (!cfg.enable) {
        bool release = reset_all_locked(ctx);
        pthread_mutex_unlock(&ctx->lock);
        if (release && dns_redirect_set_failover(false)) {
            g_failover_active = false;
            LOG_INFO("FAILOVER: disabled by configuration; released");
        }
        return;
    }

    expire_pending_locked(ctx, now, &cfg);

    for (uint32_t i = 0; i < MAX_DNS_SERVERS; ++i)
        evaluate_server_locked(&ctx->servers[i], now, &cfg);

    want_failover = all_servers_failed_locked(ctx);

    pthread_mutex_unlock(&ctx->lock);

    /* Apply the aggregate decision outside the lock (it may run systemctl).
     * Our view only flips once the action succeeded, so a failed attempt is
     * retried (with backoff inside dns_redirect) rather than forgotten. */
    if (want_failover && !g_failover_active) {
        if (dns_redirect_set_failover(true)) {
            g_failover_active = true;
            LOG_WARN("FAILOVER: all upstream resolvers unreachable; engaged");
        }
    } else if (!want_failover && g_failover_active) {
        if (dns_redirect_set_failover(false)) {
            g_failover_active = false;
            LOG_INFO("FAILOVER: an upstream resolver recovered; released");
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------- */

void dns_monitor_stop(void)
{
    g_running = 0;
}

int dns_monitor_run(void)
{
    struct monitor_ctx ctx;
    pthread_t tid;

    memset(&ctx, 0, sizeof(ctx));
    if (pthread_mutex_init(&ctx.lock, NULL) != 0) {
        LOG_ERR("pthread_mutex_init failed");
        return -1;
    }

    /* Seeds per-process verification jitter (see VERIFY_JITTER_MAX_MS). */
    srand((unsigned)(monotonic_ms() ^ (uint64_t)getpid()));

    /* Load configuration and the upstream list before monitoring starts, and
     * before anything can redirect resolv.conf to a local resolver. */
    failover_config_refresh();
    resolver_list_refresh();

    /* Non-fatal: until the WAN source is up, WAN is treated as down, so no
     * false failures are recorded. */
    if (!wan_status_init())
        LOG_WARN("WAN: status unknown, treating WAN as down until available");

    ctx.nfct = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
    if (!ctx.nfct) {
        LOG_ERR("nfct_open failed: %s", strerror(errno));
        pthread_mutex_destroy(&ctx.lock);
        return -1;
    }

    if (nfct_callback_register(ctx.nfct, NFCT_T_ALL, conntrack_event_cb, &ctx) < 0) {
        LOG_ERR("nfct_callback_register failed: %s", strerror(errno));
        nfct_close(ctx.nfct);
        pthread_mutex_destroy(&ctx.lock);
        return -1;
    }

    if (pthread_create(&tid, NULL, conntrack_thread, &ctx) != 0) {
        LOG_ERR("pthread_create failed");
        nfct_callback_unregister(ctx.nfct);
        nfct_close(ctx.nfct);
        pthread_mutex_destroy(&ctx.lock);
        return -1;
    }

    struct failover_config cfg = failover_config_get();
    LOG_INFO("DNS conntrack monitor started: deadline=%ums, threshold=%u episodes",
             cfg.reply_deadline_ms, cfg.failure_threshold);

    while (g_running) {
        monitor_tick(&ctx);
        sleep_ms(failover_config_get().monitor_tick_ms);
    }

    /* nfct_catch() may be blocked in netlink receive (a cancellation point on
     * glibc). Stop the event thread first, then release the handle. */
    (void)pthread_cancel(tid);
    (void)pthread_join(tid, NULL);
    nfct_close(ctx.nfct);
    ctx.nfct = NULL;
    pthread_mutex_destroy(&ctx.lock);
    wan_status_exit();

    LOG_INFO("DNS conntrack monitor stopped");
    return g_event_failed ? -1 : 0;
}
