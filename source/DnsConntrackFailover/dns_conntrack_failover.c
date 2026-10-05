/*
 * dns_conntrack_failover.c
 *
 * Passive DNS failure detector for a routed-gateway deployment where LAN
 * clients send DNS directly to upstream DNS servers.
 *
 * Design:
 *   - Subscribe to Linux conntrack NEW/UPDATE/DESTROY events via
 *     libnetfilter_conntrack.
 *   - Track UDP/53 and TCP/53 flows, IPv4 and IPv6, in a fixed-size
 *     in-memory table.
 *   - A reply-direction packet is detected by IPS_SEEN_REPLY.
 *   - If a DNS flow remains unreplied longer than DNS_REPLY_DEADLINE_MS,
 *     convert it to passive failure evidence.
 *   - Aggregate failures into time-separated episodes per DNS server so a
 *     burst of client lookups cannot immediately trigger failover.
 *   - After PASSIVE_FAILURE_THRESHOLD episodes, invoke one active verification
 *     hook. Only if verification fails AND WAN is known reachable should the
 *     platform redirect DNS to Unbound.
 *
 * WAN status source and the failover trigger action are behind platform.h,
 * implemented once in platform_generic.c using only /proc and /sys (no
 * platform-specific dependency); see platform.h for the seam. Passive
 * DNS-timeout evidence is only recorded while WAN is known to be up; while
 * WAN is down or unknown, all upstream DNS traffic is expected to fail, so
 * conntrack timeouts on the WAN itself would be meaningless as a
 * DNS-server-health signal.
 *
 * active_verify_dns() confirms passive failure evidence against a fixed list
 * of upstream DNS servers cached once at startup from /etc/resolv.conf (see
 * load_dns_servers_from_resolv_conf()), and sends each one a direct DNS
 * query, UDP/53 first with a TCP/53 fallback if UDP gets no reply. The
 * cache is read before any DNS redirection can rewrite resolv.conf to point
 * at the local resolver, so it always reflects the real upstream servers.
 * Failover is only declared if every cached server fails to reply; a single
 * working server means clients still have DNS, so no failover is
 * triggered. Recovery uses the same cached list: as soon as one cached
 * server replies again, the failed state is cleared.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -pthread dns_conntrack_failover.c \
 *       platform_generic.c -lnetfilter_conntrack -o dns_conntrack_failover
 *
 * Run:
 *   sudo ./dns_conntrack_failover
 *
 * Notes:
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
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "platform.h"

#define RESOLV_CONF_PATH               "/etc/resolv.conf"
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
/* Upper bound of random delay before the first active verification after a
 * passive failure, so that a mass DNS outage doesn't send every device's
 * verification probe to the same server in the same instant. */
#define VERIFY_JITTER_MAX_MS           60000U

/* Firewall mark stamped on verification probe sockets (SO_MARK). While failover
 * is active, the platform redirects all DNS to the local resolver; the redirect
 * rules exempt this mark so recovery probes still reach the real upstream
 * servers and can detect when they come back. Must match the value the platform
 * failover rules exempt (see redirect scripts). */
#define DNS_PROBE_FWMARK               0x4453U

/* Holds either an IPv4 or IPv6 address; family is AF_INET or AF_INET6. */
struct ip_addr {
    uint8_t family;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } a;
};

struct flow_key {
    struct ip_addr src_ip;
    struct ip_addr dst_ip;
    uint16_t src_port;     /* host byte order */
    uint16_t dst_port;     /* host byte order */
    uint8_t  proto;        /* IPPROTO_UDP or IPPROTO_TCP */
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
    uint64_t last_reply_ms;
    uint64_t last_verify_ms;
    uint64_t verify_at_ms;  /* 0 = no verification pending; jittered time to run one */
};

struct monitor_ctx {
    pthread_mutex_t lock;
    struct pending_flow pending[MAX_PENDING_FLOWS];
    struct dns_server_health servers[MAX_DNS_SERVERS];
    struct nfct_handle *nfct;
};

static volatile sig_atomic_t g_running = 1;

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

static const char *ip_addr_to_str(const struct ip_addr *addr, char *buf, size_t len)
{
    const void *src = (addr->family == AF_INET6) ? (const void *)&addr->a.v6 : (const void *)&addr->a.v4;
    return inet_ntop(addr->family, src, buf, (socklen_t)len) ? buf : "?";
}

static bool ip_addr_equal(const struct ip_addr *a, const struct ip_addr *b)
{
    if (a->family != b->family)
        return false;
    return (a->family == AF_INET6) ?
           memcmp(&a->a.v6, &b->a.v6, sizeof(a->a.v6)) == 0 :
           a->a.v4.s_addr == b->a.v4.s_addr;
}

static bool flow_key_equal(const struct flow_key *a, const struct flow_key *b)
{
    return ip_addr_equal(&a->src_ip, &b->src_ip) &&
           ip_addr_equal(&a->dst_ip, &b->dst_ip) &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

static uint32_t addr_hash(const struct ip_addr *addr)
{
    uint32_t h = 2166136261u;
#define MIX(v) do { h ^= (uint32_t)(v); h *= 16777619u; } while (0)
    if (addr->family == AF_INET6) {
        const uint32_t *w = (const uint32_t *)&addr->a.v6;
        MIX(w[0]); MIX(w[1]); MIX(w[2]); MIX(w[3]);
    } else {
        MIX(addr->a.v4.s_addr);
    }
#undef MIX
    return h;
}

static uint32_t flow_hash(const struct flow_key *k)
{
    uint32_t h = 2166136261u;
#define MIX(v) do { h ^= (uint32_t)(v); h *= 16777619u; } while (0)
    MIX(addr_hash(&k->src_ip));
    MIX(addr_hash(&k->dst_ip));
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

    if (!create || !free_slot)
        return NULL;

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = true;
    free_slot->address = *address;
    free_slot->state = SERVER_HEALTHY;
    return free_slot;
}

/* ------------------------------------------------------------------------- */
/* Active DNS verification: query every configured resolver directly         */
/* ------------------------------------------------------------------------- */

/* Upstream DNS servers cached from /etc/resolv.conf; reloaded whenever its
 * mtime changes so an ISP-side DNS server change doesn't leave this stale. */
static char g_cached_dns_servers[MAX_VERIFY_SERVERS][INET6_ADDRSTRLEN];
static int g_cached_dns_server_count;
static time_t g_resolv_mtime;

/* Parses "nameserver <ip>" lines out of /etc/resolv.conf and caches every
 * valid IPv4/IPv6 address. Called once at startup and again whenever
 * refresh_dns_server_cache() detects the file has changed. */
static void load_dns_servers_from_resolv_conf(void)
{
    FILE *fp = fopen(RESOLV_CONF_PATH, "r");
    if (!fp) {
        fprintf(stderr, "VERIFY: failed to open %s: %s\n", RESOLV_CONF_PATH, strerror(errno));
        return;
    }

    g_cached_dns_server_count = 0;

    char line[256];
    while (g_cached_dns_server_count < MAX_VERIFY_SERVERS && fgets(line, sizeof(line), fp)) {
        char addr[INET6_ADDRSTRLEN];
        struct in_addr a4;
        struct in6_addr a6;

        if (sscanf(line, "nameserver %45s", addr) != 1)
            continue;

        if (inet_pton(AF_INET, addr, &a4) != 1 && inet_pton(AF_INET6, addr, &a6) != 1) {
            fprintf(stderr, "VERIFY: skipping invalid nameserver '%s'\n", addr);
            continue;
        }

        snprintf(g_cached_dns_servers[g_cached_dns_server_count++], INET6_ADDRSTRLEN, "%s", addr);
    }

    fclose(fp);

    fprintf(stderr, "VERIFY: cached %d nameserver(s) from %s\n",
            g_cached_dns_server_count, RESOLV_CONF_PATH);
}

/* Reloads the cache only if /etc/resolv.conf's mtime changed since the last
 * load, so a verification probe stays cheap (one stat()) when nothing
 * changed, but always sees a current server list otherwise. */
static void refresh_dns_server_cache(void)
{
    struct stat st;

    if (stat(RESOLV_CONF_PATH, &st) != 0) {
        fprintf(stderr, "VERIFY: stat(%s) failed: %s\n", RESOLV_CONF_PATH, strerror(errno));
        return;
    }

    if (st.st_mtime == g_resolv_mtime)
        return;

    g_resolv_mtime = st.st_mtime;
    load_dns_servers_from_resolv_conf();
}

/* Copies the cached nameserver list into out[]. Returns the number of
 * entries copied. */
static int fetch_dns_server_list(char out[][INET6_ADDRSTRLEN], int max)
{
    int count = 0;

    for (int i = 0; i < g_cached_dns_server_count && count < max; ++i)
        snprintf(out[count++], INET6_ADDRSTRLEN, "%s", g_cached_dns_servers[i]);

    return count;
}

/* Fills in a minimal DNS query (header + one question for the root name,
 * type A, class IN) at msg[0..16] and returns its length (17 bytes). */
static size_t build_dns_query_msg(uint8_t *msg, uint16_t id)
{
    memset(msg, 0, 17);
    msg[0] = (uint8_t)(id >> 8);
    msg[1] = (uint8_t)(id & 0xFF);
    msg[2] = 0x01; /* flags: recursion desired */
    msg[5] = 0x01; /* qdcount = 1 */
    size_t off = 12;
    msg[off++] = 0x00;             /* root name terminator */
    msg[off++] = 0x00; msg[off++] = 0x01; /* qtype = A */
    msg[off++] = 0x00; msg[off++] = 0x01; /* qclass = IN */
    return off;
}

static bool resolve_dns_server_addr(const char *server_ip, struct sockaddr_storage *addr,
                                    socklen_t *addr_len, int *family)
{
    struct in_addr a4;
    struct in6_addr a6;

    memset(addr, 0, sizeof(*addr));
    if (inet_pton(AF_INET, server_ip, &a4) == 1) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(DNS_PORT);
        sin->sin_addr = a4;
        *addr_len = sizeof(*sin);
        *family = AF_INET;
        return true;
    }
    if (inet_pton(AF_INET6, server_ip, &a6) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(DNS_PORT);
        sin6->sin6_addr = a6;
        *addr_len = sizeof(*sin6);
        *family = AF_INET6;
        return true;
    }
    fprintf(stderr, "VERIFY: invalid DNS server address '%s'\n", server_ip);
    return false;
}

/* Sends one minimal "A ." query to server_ip over UDP/53 and waits up to
 * timeout_ms for any well-formed response. Any reply (including SERVFAIL/
 * NXDOMAIN) proves the server process is up and answering, which is all this
 * check needs -- RCODE-level interpretation is out of scope. */
static bool dns_probe_udp(const char *server_ip, unsigned timeout_ms)
{
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int family;
    static uint16_t query_id;

    if (!resolve_dns_server_addr(server_ip, &addr, &addr_len, &family))
        return false;

    int fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        fprintf(stderr, "VERIFY: socket() failed: %s\n", strerror(errno));
        return false;
    }

    /* Tag the probe so the failover redirect rules let it reach the real
     * upstream server instead of bouncing it back to the local resolver. */
    unsigned mark = DNS_PROBE_FWMARK;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
        fprintf(stderr, "VERIFY: SO_MARK failed: %s\n", strerror(errno));

    uint8_t query[17];
    size_t off = build_dns_query_msg(query, ++query_id);

    if (sendto(fd, query, off, 0, (struct sockaddr *)&addr, addr_len) < 0) {
        fprintf(stderr, "VERIFY: UDP sendto(%s) failed: %s\n", server_ip, strerror(errno));
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

/* TCP/53 fallback probe, used only when UDP got no reply: some resolvers
 * rate-limit or block UDP (or the path drops it) while still answering
 * TCP, so this catches servers that passive UDP-only monitoring would
 * otherwise misreport as down. Message is length-prefixed per RFC 1035. */
static bool dns_probe_tcp(const char *server_ip, unsigned timeout_ms)
{
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int family;
    static uint16_t query_id;

    if (!resolve_dns_server_addr(server_ip, &addr, &addr_len, &family))
        return false;

    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (fd < 0) {
        fprintf(stderr, "VERIFY: TCP socket() failed: %s\n", strerror(errno));
        return false;
    }

    unsigned mark = DNS_PROBE_FWMARK;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
        fprintf(stderr, "VERIFY: SO_MARK failed: %s\n", strerror(errno));

    if (connect(fd, (struct sockaddr *)&addr, addr_len) < 0 && errno != EINPROGRESS) {
        fprintf(stderr, "VERIFY: TCP connect(%s) failed: %s\n", server_ip, strerror(errno));
        close(fd);
        return false;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
    int rc = poll(&pfd, 1, (int)timeout_ms);
    int so_err = 0;
    socklen_t so_err_len = sizeof(so_err);
    if (rc <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_err_len) != 0 || so_err != 0) {
        close(fd);
        return false;
    }

    uint8_t query[17];
    size_t msg_len = build_dns_query_msg(query, ++query_id);
    uint8_t pkt[2 + sizeof(query)];
    pkt[0] = (uint8_t)(msg_len >> 8);
    pkt[1] = (uint8_t)(msg_len & 0xFF);
    memcpy(pkt + 2, query, msg_len);

    if (send(fd, pkt, 2 + msg_len, 0) < 0) {
        fprintf(stderr, "VERIFY: TCP send(%s) failed: %s\n", server_ip, strerror(errno));
        close(fd);
        return false;
    }

    pfd.events = POLLIN;
    rc = poll(&pfd, 1, (int)timeout_ms);
    if (rc <= 0) {
        close(fd);
        return false;
    }

    uint8_t resp[514];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    if (n < 14) /* 2-byte length prefix + 12-byte DNS header */
        return false;

    bool id_matches = resp[2] == query[0] && resp[3] == query[1];
    bool is_response = (resp[4] & 0x80) != 0; /* QR bit */
    return id_matches && is_response;
}

/* UDP first (cheap, how real client traffic mostly works), TCP only as a
 * fallback when UDP gets no reply at all. */
static bool dns_probe(const char *server_ip, unsigned timeout_ms)
{
    if (dns_probe_udp(server_ip, timeout_ms))
        return true;
    return dns_probe_tcp(server_ip, timeout_ms);
}

/*
 * Confirms passive failure evidence by directly querying every configured
 * DNS server (Device.DNS.Client.Server.*.DNSServer). Only if every server
 * fails to reply do we treat DNS as truly down -- a single working
 * server means clients still have working resolution, so no failover.
 */
static bool active_verify_dns(const struct ip_addr *dns_server)
{
    (void)dns_server; /* verification covers all configured resolvers, not just this one */

    refresh_dns_server_cache();

    char servers[MAX_VERIFY_SERVERS][INET6_ADDRSTRLEN];
    int count = fetch_dns_server_list(servers, MAX_VERIFY_SERVERS);

    if (count <= 0) {
        fprintf(stderr, "VERIFY: no cached nameservers from %s; treating as unverified\n",
                RESOLV_CONF_PATH);
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

/* ------------------------------------------------------------------------- */

static void record_reply_locked(struct monitor_ctx *ctx, const struct ip_addr *server_ip)
{
    struct dns_server_health *s = server_get(ctx, server_ip, true);
    if (!s)
        return;

    s->last_reply_ms = monotonic_ms();

    /* An active verification is already scheduled/pending: let it run and
     * make the authoritative call instead of letting a single stray passive
     * reply cancel the in-flight decision and restart episode counting. */
    if (s->verify_at_ms != 0)
        return;

    /* While failed, all client DNS is redirected to the local resolver, so
     * these passive "replies" actually come from it -- conntrack still shows
     * the original upstream tuple, so they must NOT be read as upstream
     * recovery. Recovery is decided only by the active marked probe in
     * evaluate_server_locked(), which reaches the real upstream. */
    if (s->state == SERVER_FAILED)
        return;

    s->failure_episodes = 0;

    if (s->state == SERVER_SUSPECT) {
        s->state = SERVER_HEALTHY;
        s->recovery_successes = 0;
    }
}

static void record_failure_episode_locked(struct monitor_ctx *ctx,
                                          const struct ip_addr *server_ip,
                                          uint64_t now_ms)
{
    struct dns_server_health *s = server_get(ctx, server_ip, true);
    char ip[INET6_ADDRSTRLEN];

    if (!s)
        return;

    /* Already failed: the decision is made and recovery is owned by the active
     * probe. Passive timeouts now mostly hit the local resolver, so they carry
     * no upstream-health signal -- stop counting. */
    if (s->state == SERVER_FAILED)
        return;

    /* Stop recording passive episodes once threshold is reached.
     * Failover decision is made at 3/3; further episodes don't matter.
     * Only active verification can bring us out of failure state. */
    if (s->failure_episodes >= PASSIVE_FAILURE_THRESHOLD)
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
            ip_addr_to_str(server_ip, ip, sizeof(ip)),
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

        if (active_verify_dns(&s->address)) {
            fprintf(stderr, "DECISION: upstream DNS recovered\n");
            s->state = SERVER_HEALTHY;
            s->failure_episodes = 0;
            s->recovery_successes = 0;
            platform_set_unbound_failover(false);
        }
        return;
    }

    /* Failure detection: verify passive evidence at threshold */
    if (s->failure_episodes < PASSIVE_FAILURE_THRESHOLD)
        return;

    if (s->last_verify_ms != 0 && now_ms - s->last_verify_ms < VERIFY_COOLDOWN_MS)
        return;

    /* Stagger the first verification across VERIFY_JITTER_MAX_MS instead of
     * firing the instant the threshold is reached, so a mass outage doesn't
     * make every device probe the DNS servers at the same moment. */
    if (s->verify_at_ms == 0) {
        s->verify_at_ms = now_ms + ((uint64_t)rand() % VERIFY_JITTER_MAX_MS);
        fprintf(stderr, "VERIFY: scheduling verification in %" PRIu64 " ms\n",
                s->verify_at_ms - now_ms);
        return;
    }

    if (now_ms < s->verify_at_ms)
        return;

    s->verify_at_ms = 0;
    s->last_verify_ms = now_ms;

    if (active_verify_dns(&s->address)) {
        s->state = SERVER_HEALTHY;
        s->failure_episodes = 0;
        return;
    }

    if (!platform_wan_is_reachable()) {
        fprintf(stderr, "DECISION: WAN not reachable; suppress DNS failover\n");
        s->failure_episodes = 0;
        s->state = SERVER_HEALTHY;
        return;
    }

    s->state = SERVER_FAILED;
    s->failure_episodes = 0;
    fprintf(stderr, "DECISION: upstream DNS failed while WAN is reachable\n");
    platform_set_unbound_failover(true);
}

static bool extract_dns_key(const struct nf_conntrack *ct, struct flow_key *key)
{
    if (!nfct_attr_is_set(ct, ATTR_ORIG_L3PROTO) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST)) {
        return false;
    }

    uint8_t l3proto = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
    uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    uint16_t dport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));

    if ((proto != IPPROTO_UDP && proto != IPPROTO_TCP) || dport != DNS_PORT)
        return false;

    memset(key, 0, sizeof(*key));

    if (l3proto == AF_INET) {
        if (!nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC) || !nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST))
            return false;
        key->src_ip.family = AF_INET;
        key->src_ip.a.v4.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
        key->dst_ip.family = AF_INET;
        key->dst_ip.a.v4.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
    } else if (l3proto == AF_INET6) {
        if (!nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC) || !nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST))
            return false;
        const void *src6 = nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC);
        const void *dst6 = nfct_get_attr(ct, ATTR_ORIG_IPV6_DST);
        if (!src6 || !dst6)
            return false;
        key->src_ip.family = AF_INET6;
        memcpy(&key->src_ip.a.v6, src6, sizeof(key->src_ip.a.v6));
        key->dst_ip.family = AF_INET6;
        memcpy(&key->dst_ip.a.v6, dst6, sizeof(key->dst_ip.a.v6));
    } else {
        return false;
    }

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
        record_reply_locked(ctx, &key.dst_ip);
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
            if (p && !p->expired_reported && platform_wan_is_reachable())
                record_failure_episode_locked(ctx, &key.dst_ip, monotonic_ms());
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
    const bool wan_up = platform_wan_is_reachable();

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
                record_failure_episode_locked(ctx, &p->key.dst_ip, now);
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

    /* Seeds per-process verification jitter (see VERIFY_JITTER_MAX_MS). */
    srand((unsigned)(monotonic_ms() ^ (uint64_t)getpid()));

    /* Must happen before anything can redirect resolv.conf to a local resolver. */
    refresh_dns_server_cache();

    /* Non-fatal: if the platform WAN-status source is not up yet, WAN is
     * treated as down until it becomes available, so no false failures are
     * recorded. */
    if (!platform_wan_status_init())
        fprintf(stderr, "WAN: status unknown, treating WAN as down until available\n");

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
    platform_wan_status_exit();

    fprintf(stderr, "DNS conntrack monitor stopped\n");
    return EXIT_SUCCESS;
}
