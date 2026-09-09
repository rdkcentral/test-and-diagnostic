/*
 * dns_conntrack_failover.c
 *
 * Passive DNS failure detector for a routed-gateway deployment where LAN
 * clients send DNS directly to upstream DNS servers.
 *
 * Design:
 *   - Subscribe to Linux conntrack NEW/UPDATE/DESTROY events via
 *     libnetfilter_conntrack.
 *   - Track only UDP/53 flows in a fixed-size in-memory table.
 *   - A reply-direction packet is detected by IPS_SEEN_REPLY.
 *   - If a DNS flow remains unreplied longer than DNS_REPLY_DEADLINE_MS,
 *     convert it to passive failure evidence.
 *   - Aggregate failures into time-separated episodes per DNS server so a
 *     burst of client lookups cannot immediately trigger failover.
 *   - After PASSIVE_FAILURE_THRESHOLD episodes, invoke one active verification
 *     hook. Only if verification fails AND WAN is known reachable should the
 *     platform redirect DNS to Unbound.
 *
 * This sample intentionally leaves one platform-specific hook as a stub:
 *   set_unbound_failover().
 * Replace it with RDK-B/RBUS/Firewall Manager/DNS Manager integration.
 *
 * wan_is_reachable() is implemented via RBUS: it subscribes to the WAN
 * Manager global status event, Device.X_RDK_WanManager.CurrentStatus
 * ("Up"/"Down", published by rdk-wanmanager's Update_Interface_Status()),
 * and caches the last known value. Passive DNS-timeout evidence is only
 * recorded while WAN is known to be up; while WAN is down or unknown, all
 * upstream DNS traffic is expected to fail, so conntrack timeouts on the
 * WAN itself would be meaningless as a DNS-server-health signal.
 *
 * active_verify_dns() confirms passive failure evidence by reading the
 * configured resolver list from Device.DNS.Client.Server.*.DNSServer (RBUS)
 * and sending each one a direct UDP/53 DNS query. Failover is only declared
 * if every configured server fails to reply; a single working server means
 * clients still have DNS, so no failover is triggered.
 *
 * Build (typical Linux host):
 *   gcc -O2 -Wall -Wextra -pthread dns_conntrack_failover.c \
 *       -lnetfilter_conntrack -lrbus -o dns_conntrack_failover
 *
 * Run:
 *   sudo ./dns_conntrack_failover
 *
 * Notes:
 *   - IPv4 UDP/53 is implemented for clarity. Add IPv6 tuple handling and
 *     TCP/53 as separate extensions.
 *   - Conntrack proves reply-direction traffic was seen; it does NOT parse
 *     DNS RCODEs. SERVFAIL/NXDOMAIN semantics require DNS-layer inspection.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <rbus/rbus.h>

#define WAN_STATUS_COMPONENT_NAME      "DnsConntrackFailover"
#define WAN_STATUS_PARAM_NAME          "Device.X_RDK_WanManager.CurrentStatus"
#define WAN_STATUS_VALUE_UP            "Up"

#define DNS_SERVER_LIST_WILDCARD       "Device.DNS.Client.Server.*.DNSServer"
#define MAX_VERIFY_SERVERS             16U
#define DNS_VERIFY_TIMEOUT_MS          2000U

#define DNS_PORT                       53U
#define MAX_PENDING_FLOWS              2048U
#define MAX_DNS_SERVERS                8U
#define MONITOR_TICK_MS                250U
#define DNS_REPLY_DEADLINE_MS          2000U
#define FAILURE_EPISODE_GAP_MS         5000U
#define PASSIVE_FAILURE_THRESHOLD      3U
#define RECOVERY_SUCCESS_THRESHOLD     2U
#define VERIFY_COOLDOWN_MS             10000U

struct flow_key {
    uint32_t src_ip;       /* network byte order */
    uint32_t dst_ip;       /* network byte order */
    uint16_t src_port;     /* host byte order */
    uint16_t dst_port;     /* host byte order */
    uint8_t  proto;
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
    uint32_t address;      /* network byte order */
    enum server_state state;
    uint32_t failure_episodes;
    uint32_t recovery_successes;
    uint64_t last_failure_episode_ms;
    uint64_t last_reply_ms;
    uint64_t last_verify_ms;
};

struct monitor_ctx {
    pthread_mutex_t lock;
    struct pending_flow pending[MAX_PENDING_FLOWS];
    struct dns_server_health servers[MAX_DNS_SERVERS];
    struct nfct_handle *nfct;
};

static volatile sig_atomic_t g_running = 1;

/* Cached WAN status, updated only by the RBUS event handler / initial get. */
static rbusHandle_t g_wanRbusHandle;
static atomic_bool g_wan_up = false;

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static void sleep_ms(unsigned ms)
{
    struct timespec req = {
        .tv_sec = ms / 1000U,
        .tv_nsec = (long)(ms % 1000U) * 1000000L
    };
    while (nanosleep(&req, &req) != 0 && errno == EINTR) {
        if (!g_running)
            break;
    }
}

static const char *ip4_to_str(uint32_t addr, char *buf, size_t len)
{
    struct in_addr a = { .s_addr = addr };
    return inet_ntop(AF_INET, &a, buf, (socklen_t)len) ? buf : "?";
}

static bool flow_key_equal(const struct flow_key *a, const struct flow_key *b)
{
    return a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

static uint32_t flow_hash(const struct flow_key *k)
{
    uint32_t h = 2166136261u;
#define MIX(v) do { h ^= (uint32_t)(v); h *= 16777619u; } while (0)
    MIX(k->src_ip);
    MIX(k->dst_ip);
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

    /* Table saturation should be rare. Replace oldest entry rather than malloc. */
    if (oldest) {
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

static struct dns_server_health *server_get(struct monitor_ctx *ctx,
                                            uint32_t address,
                                            bool create)
{
    struct dns_server_health *free_slot = NULL;

    for (uint32_t i = 0; i < MAX_DNS_SERVERS; ++i) {
        struct dns_server_health *s = &ctx->servers[i];
        if (s->used && s->address == address)
            return s;
        if (!s->used && !free_slot)
            free_slot = s;
    }

    if (!create || !free_slot)
        return NULL;

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = true;
    free_slot->address = address;
    free_slot->state = SERVER_HEALTHY;
    return free_slot;
}

/* ------------------------------------------------------------------------- */
/* Active DNS verification: query every configured resolver directly         */
/* ------------------------------------------------------------------------- */

/* Reads Device.DNS.Client.Server.*.DNSServer via the existing RBUS handle.
 * Returns the number of non-empty server strings copied into out[]. */
static int fetch_dns_server_list(char out[][INET6_ADDRSTRLEN], int max)
{
    const char *names[1] = { DNS_SERVER_LIST_WILDCARD };
    int numProps = 0;
    rbusProperty_t properties = NULL;
    int count = 0;

    if (!g_wanRbusHandle)
        return 0;

    if (rbus_getExt(g_wanRbusHandle, 1, names, &numProps, &properties) != RBUS_ERROR_SUCCESS)
        return 0;

    for (rbusProperty_t p = properties; p && count < max; p = rbusProperty_GetNext(p)) {
        rbusValue_t val = rbusProperty_GetValue(p);
        const char *addr = val ? rbusValue_GetString(val, NULL) : NULL;
        if (addr && addr[0] != '\0')
            snprintf(out[count++], INET6_ADDRSTRLEN, "%s", addr);
    }

    if (properties)
        rbusProperty_Release(properties);

    return count;
}

/* Sends one minimal "A ." query to server_ip over UDP/53 and waits up to
 * timeout_ms for any well-formed response. Any reply (including SERVFAIL/
 * NXDOMAIN) proves the server process is up and answering, which is all this
 * check needs -- RCODE-level interpretation is out of scope. */
static bool dns_probe(const char *server_ip, unsigned timeout_ms)
{
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int family;
    struct in_addr a4;
    struct in6_addr a6;
    static uint16_t query_id;

    memset(&addr, 0, sizeof(addr));
    if (inet_pton(AF_INET, server_ip, &a4) == 1) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(DNS_PORT);
        sin->sin_addr = a4;
        addr_len = sizeof(*sin);
        family = AF_INET;
    } else if (inet_pton(AF_INET6, server_ip, &a6) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(DNS_PORT);
        sin6->sin6_addr = a6;
        addr_len = sizeof(*sin6);
        family = AF_INET6;
    } else {
        fprintf(stderr, "VERIFY: invalid DNS server address '%s'\n", server_ip);
        return false;
    }

    int fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        fprintf(stderr, "VERIFY: socket() failed: %s\n", strerror(errno));
        return false;
    }

    /* DNS header (id, flags, qdcount, ancount, nscount, arcount) + one
     * question for the root name, type A, class IN. */
    uint8_t query[16];
    uint16_t id = ++query_id;
    memset(query, 0, sizeof(query));
    query[0] = (uint8_t)(id >> 8);
    query[1] = (uint8_t)(id & 0xFF);
    query[2] = 0x01; /* flags: recursion desired */
    query[5] = 0x01; /* qdcount = 1 */
    size_t off = 12;
    query[off++] = 0x00;             /* root name terminator */
    query[off++] = 0x00; query[off++] = 0x01; /* qtype = A */
    query[off++] = 0x00; query[off++] = 0x01; /* qclass = IN */

    if (sendto(fd, query, off, 0, (struct sockaddr *)&addr, addr_len) < 0) {
        fprintf(stderr, "VERIFY: sendto(%s) failed: %s\n", server_ip, strerror(errno));
        close(fd);
        return false;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    int rc = poll(&pfd, 1, (int)timeout_ms);
    if (rc <= 0) {
        close(fd);
        return false; /* timeout or poll error: treat as no reply */
    }

    uint8_t resp[512];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    if (n < 12)
        return false;

    bool id_matches = resp[0] == query[0] && resp[1] == query[1];
    bool is_response = (resp[2] & 0x80) != 0; /* QR bit */
    return id_matches && is_response;
}

/*
 * Confirms passive failure evidence by directly querying every configured
 * DNS server (Device.DNS.Client.Server.*.DNSServer). Only if every server
 * fails to reply do we treat DNS as truly down -- a single working
 * server means clients still have working resolution, so no failover.
 */
static bool active_verify_dns(uint32_t dns_server)
{
    (void)dns_server; /* verification covers all configured resolvers, not just this one */

    char servers[MAX_VERIFY_SERVERS][INET6_ADDRSTRLEN];
    int count = fetch_dns_server_list(servers, MAX_VERIFY_SERVERS);

    if (count <= 0) {
        fprintf(stderr, "VERIFY: could not read %s; treating as unverified\n",
                DNS_SERVER_LIST_WILDCARD);
        return false;
    }

    for (int i = 0; i < count; ++i) {
        bool ok = dns_probe(servers[i], DNS_VERIFY_TIMEOUT_MS);
        fprintf(stderr, "VERIFY: %s %s\n", servers[i], ok ? "replied" : "no reply");
        if (ok)
            return true; /* at least one server alive: do not fail over */
    }

    fprintf(stderr, "VERIFY: all %d configured DNS server(s) failed to reply\n", count);
    return false;
}

static bool wan_is_reachable(void)
{
    return atomic_load(&g_wan_up);
}

/* ------------------------------------------------------------------------- */
/* WAN status via RBUS                                                       */
/* ------------------------------------------------------------------------- */

static void wan_status_event_handler(rbusHandle_t handle,
                                     rbusEvent_t const *event,
                                     rbusEventSubscription_t *subscription)
{
    (void)handle;
    (void)subscription;

    rbusValue_t value = rbusObject_GetValue(event->data, NULL);
    if (!value)
        return;

    const char *status = rbusValue_GetString(value, NULL);
    bool up = status != NULL && strcmp(status, WAN_STATUS_VALUE_UP) == 0;

    atomic_store(&g_wan_up, up);
    fprintf(stderr, "WAN: %s -> %s\n", WAN_STATUS_PARAM_NAME, up ? "UP" : "DOWN");
}

/* Opens RBUS, seeds the cached state with a one-time get, then subscribes
 * for change events. Returns false if RBUS/WanManager is unavailable; the
 * daemon still runs, but treats WAN as down until a subscription succeeds. */
static bool wan_status_rbus_init(void)
{
    int rc = rbus_open(&g_wanRbusHandle, WAN_STATUS_COMPONENT_NAME);
    if (rc != RBUS_ERROR_SUCCESS) {
        fprintf(stderr, "WAN: rbus_open failed: %d\n", rc);
        return false;
    }

    rbusValue_t value = NULL;
    if (rbus_get(g_wanRbusHandle, WAN_STATUS_PARAM_NAME, &value) == RBUS_ERROR_SUCCESS && value) {
        const char *status = rbusValue_GetString(value, NULL);
        atomic_store(&g_wan_up, status != NULL && strcmp(status, WAN_STATUS_VALUE_UP) == 0);
        rbusValue_Release(value);
    }

    rc = rbusEvent_Subscribe(g_wanRbusHandle, WAN_STATUS_PARAM_NAME,
                             wan_status_event_handler, NULL, 0);
    if (rc != RBUS_ERROR_SUCCESS) {
        fprintf(stderr, "WAN: rbusEvent_Subscribe failed for %s: %d\n",
                WAN_STATUS_PARAM_NAME, rc);
        rbus_close(g_wanRbusHandle);
        g_wanRbusHandle = NULL;
        return false;
    }

    fprintf(stderr, "WAN: subscribed to %s, initial state=%s\n",
            WAN_STATUS_PARAM_NAME, atomic_load(&g_wan_up) ? "UP" : "DOWN");
    return true;
}

static void wan_status_rbus_exit(void)
{
    if (g_wanRbusHandle) {
        rbusEvent_Unsubscribe(g_wanRbusHandle, WAN_STATUS_PARAM_NAME);
        rbus_close(g_wanRbusHandle);
        g_wanRbusHandle = NULL;
    }
}

static void set_unbound_failover(bool enable)
{
    fprintf(stderr, "ACTION: Unbound failover %s\n", enable ? "ENABLE" : "DISABLE");

    /*
     * Replace with platform control, e.g. Firewall Manager/DNS Manager/RBUS.
     * Typical behavior when enabled:
     *   - transparently redirect client UDP/53 and TCP/53 to local Unbound
     *   - preserve normal routing when disabled
     * Avoid system()/shelling out in production.
     */
}

/* ------------------------------------------------------------------------- */

static void record_reply_locked(struct monitor_ctx *ctx, uint32_t server_ip)
{
    struct dns_server_health *s = server_get(ctx, server_ip, true);
    if (!s)
        return;

    s->last_reply_ms = monotonic_ms();
    s->failure_episodes = 0;

    if (s->state == SERVER_SUSPECT) {
        s->state = SERVER_HEALTHY;
        s->recovery_successes = 0;
    } else if (s->state == SERVER_FAILED) {
        /* Client traffic generally will not reach ISP DNS while redirected.
         * Recovery normally comes from sparse explicit recovery probes. */
        if (++s->recovery_successes >= RECOVERY_SUCCESS_THRESHOLD) {
            s->state = SERVER_HEALTHY;
            s->recovery_successes = 0;
            set_unbound_failover(false);
        }
    }
}

static void record_failure_episode_locked(struct monitor_ctx *ctx,
                                          uint32_t server_ip,
                                          uint64_t now_ms)
{
    struct dns_server_health *s = server_get(ctx, server_ip, true);
    char ip[INET_ADDRSTRLEN];

    if (!s)
        return;

    if (s->last_failure_episode_ms != 0 &&
        now_ms - s->last_failure_episode_ms < FAILURE_EPISODE_GAP_MS) {
        return;
    }

    s->last_failure_episode_ms = now_ms;
    s->failure_episodes++;
    s->recovery_successes = 0;

    if (s->state == SERVER_HEALTHY)
        s->state = SERVER_SUSPECT;

    fprintf(stderr, "PASSIVE: %s failure episode %u/%u\n",
            ip4_to_str(server_ip, ip, sizeof(ip)),
            s->failure_episodes, PASSIVE_FAILURE_THRESHOLD);
}

static void evaluate_server_locked(struct monitor_ctx *ctx,
                                   struct dns_server_health *s,
                                   uint64_t now_ms)
{
    if (!s->used)
        return;

    /* Recovery check: re-verify failed servers and disable failover if alive */
    if (s->state == SERVER_FAILED) {
        if (s->last_verify_ms != 0 && now_ms - s->last_verify_ms < VERIFY_COOLDOWN_MS)
            return;

        s->last_verify_ms = now_ms;

        if (active_verify_dns(s->address)) {
            fprintf(stderr, "DECISION: upstream DNS recovered\n");
            s->state = SERVER_HEALTHY;
            s->failure_episodes = 0;
            s->recovery_successes = 0;
            set_unbound_failover(false);
        }
        return;
    }

    /* Failure detection: verify passive evidence at threshold */
    if (s->failure_episodes < PASSIVE_FAILURE_THRESHOLD)
        return;

    if (s->last_verify_ms != 0 && now_ms - s->last_verify_ms < VERIFY_COOLDOWN_MS)
        return;

    s->last_verify_ms = now_ms;

    if (active_verify_dns(s->address)) {
        s->state = SERVER_HEALTHY;
        s->failure_episodes = 0;
        return;
    }

    if (!wan_is_reachable()) {
        fprintf(stderr, "DECISION: WAN not reachable; suppress DNS failover\n");
        s->failure_episodes = 0;
        s->state = SERVER_HEALTHY;
        return;
    }

    s->state = SERVER_FAILED;
    s->failure_episodes = 0;
    fprintf(stderr, "DECISION: upstream DNS failed while WAN is reachable\n");
    set_unbound_failover(true);
}

static bool extract_dns_key(const struct nf_conntrack *ct, struct flow_key *key)
{
    if (!nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST)) {
        return false;
    }

    uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    uint16_t dport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));

    if (proto != IPPROTO_UDP || dport != DNS_PORT)
        return false;

    key->src_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
    key->dst_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
    key->src_port = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
    key->dst_port = dport;
    key->proto = proto;
    return true;
}

static int conntrack_event_cb(enum nf_conntrack_msg_type type,
                              struct nf_conntrack *ct,
                              void *data)
{
    struct monitor_ctx *ctx = data;
    struct flow_key key;
    uint32_t status = 0;

    if (!extract_dns_key(ct, &key))
        return NFCT_CB_CONTINUE;

    if (nfct_attr_is_set(ct, ATTR_STATUS))
        status = nfct_get_attr_u32(ct, ATTR_STATUS);

    bool seen_reply = (status & IPS_SEEN_REPLY) != 0;

    pthread_mutex_lock(&ctx->lock);

    if (seen_reply) {
        pending_remove(ctx, &key);
        record_reply_locked(ctx, key.dst_ip);
        pthread_mutex_unlock(&ctx->lock);
        return NFCT_CB_CONTINUE;
    }

    switch (type) {
    case NFCT_T_NEW:
        if (!pending_lookup(ctx, &key))
            (void)pending_alloc(ctx, &key);
        break;

    case NFCT_T_DESTROY:
        /* If destroyed before our timer classified it, count it as evidence,
         * unless WAN is down/unknown (all DNS would time out regardless). */
        {
            struct pending_flow *p = pending_lookup(ctx, &key);
            if (p && !p->expired_reported && wan_is_reachable())
                record_failure_episode_locked(ctx, key.dst_ip, monotonic_ms());
            pending_remove(ctx, &key);
        }
        break;

    case NFCT_T_UPDATE:
    default:
        break;
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
            fprintf(stderr, "nfct_catch failed: %s\n", strerror(errno));
            break;
        }
    }

    g_running = 0;
    return NULL;
}

static void monitor_tick(struct monitor_ctx *ctx)
{
    const uint64_t now = monotonic_ms();
    const bool wan_up = wan_is_reachable();

    pthread_mutex_lock(&ctx->lock);

    for (uint32_t i = 0; i < MAX_PENDING_FLOWS; ++i) {
        struct pending_flow *p = &ctx->pending[i];
        if (!p->used || p->expired_reported)
            continue;

        if (now - p->created_ms >= DNS_REPLY_DEADLINE_MS) {
            p->expired_reported = true;
            /* A WAN outage makes every DNS flow time out; that is not
             * evidence of DNS server failure, so skip recording it. */
            if (wan_up)
                record_failure_episode_locked(ctx, p->key.dst_ip, now);
        }
    }

    for (uint32_t i = 0; i < MAX_DNS_SERVERS; ++i)
        evaluate_server_locked(ctx, &ctx->servers[i], now);

    pthread_mutex_unlock(&ctx->lock);
}

static void signal_handler(int signo)
{
    (void)signo;
    g_running = 0;
}

int main(void)
{
    struct monitor_ctx ctx;
    pthread_t tid;

    memset(&ctx, 0, sizeof(ctx));
    if (pthread_mutex_init(&ctx.lock, NULL) != 0) {
        fprintf(stderr, "pthread_mutex_init failed\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Non-fatal: if WanManager/RBUS is not up yet, WAN is treated as down
     * until a subscription later succeeds, so no false failures are recorded. */
    if (!wan_status_rbus_init())
        fprintf(stderr, "WAN: status unknown, treating WAN as down until subscribed\n");

    ctx.nfct = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
    if (!ctx.nfct) {
        fprintf(stderr, "nfct_open failed: %s\n", strerror(errno));
        pthread_mutex_destroy(&ctx.lock);
        return EXIT_FAILURE;
    }

    if (nfct_callback_register(ctx.nfct, NFCT_T_ALL,
                               conntrack_event_cb, &ctx) < 0) {
        fprintf(stderr, "nfct_callback_register failed: %s\n", strerror(errno));
        nfct_close(ctx.nfct);
        pthread_mutex_destroy(&ctx.lock);
        return EXIT_FAILURE;
    }

    if (pthread_create(&tid, NULL, conntrack_thread, &ctx) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        nfct_callback_unregister(ctx.nfct);
        nfct_close(ctx.nfct);
        pthread_mutex_destroy(&ctx.lock);
        return EXIT_FAILURE;
    }

    fprintf(stderr,
            "DNS conntrack monitor started: deadline=%ums, threshold=%u episodes\n",
            DNS_REPLY_DEADLINE_MS, PASSIVE_FAILURE_THRESHOLD);

    while (g_running) {
        monitor_tick(&ctx);
        sleep_ms(MONITOR_TICK_MS);
    }

    /* nfct_catch() may be blocked in netlink receive. recv is a pthread
     * cancellation point on normal Linux/glibc systems, so stop the event
     * thread first, then release the handle after join. Production RDK-B may
     * instead integrate nfct_fd() into its native event loop. */
    (void)pthread_cancel(tid);
    (void)pthread_join(tid, NULL);
    nfct_close(ctx.nfct);
    ctx.nfct = NULL;
    pthread_mutex_destroy(&ctx.lock);
    wan_status_rbus_exit();

    fprintf(stderr, "DNS conntrack monitor stopped\n");
    return EXIT_SUCCESS;
}
