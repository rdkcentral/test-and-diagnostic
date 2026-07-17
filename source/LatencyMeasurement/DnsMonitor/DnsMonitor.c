/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
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

/**
 * DnsMonitor.c  —  libpcap-based DNS latency and failure telemetry (POC)
 *
 * Captures UDP port-53 traffic on the WAN interface using libpcap.
 * Every DNS event is written as a single structured key=value log line with
 * a tag prefix so that log-analysis tools (grep, awk, splunk, ELK) can slice
 * the data without any custom parser.
 *
 * Log line tags
 * ─────────────
 *   [DNS_QUERY]   – outgoing query captured (one line per query)
 *   [DNS_RESP_OK] – successful response matched to a query
 *   [DNS_FAIL]    – response with non-zero RCODE matched to a query
 *   [DNS_TIMEOUT] – query expired with no response
 *   [DNS_SLOW]    – response was OK but latency > slow_threshold_ms
 *   [DNS_SUMMARY] – per-interval summary (telemetry also emitted here)
 *
 * All lines share: ts=<ISO-8601> iface=<iface>
 *
 * Telemetry markers (Telemetry-2):
 *   NET_DNS_PCAP_QUERY_CNT_split
 *   NET_DNS_PCAP_LATENCY_AVG_ms_split
 *   NET_DNS_PCAP_LATENCY_MAX_ms_split
 *   NET_DNS_PCAP_FAIL_CNT_split
 *   NET_DNS_PCAP_FAIL_TYPE_split   "nxdomain=N,servfail=N,refused=N,other_rcode=N,timeout=N"
 *   NET_DNS_PCAP_SLOW_CNT_split
 *
 * Usage:
 *   DnsMonitor -i <wan_iface> [-r <report_sec>] [-t <query_timeout_sec>]
 *              [-s <slow_threshold_ms>] [-v]
 */

#ifndef UNIT_TEST_DOCKER_SUPPORT
#include <pcap.h>
#include <telemetry_busmessage_sender.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>

/* ------------------------------------------------------------------ */
/* Compile-time constants                                               */
/* ------------------------------------------------------------------ */
#define DNS_PORT             53
#define SNAP_LEN             1518
#define PCAP_TIMEOUT_MS      1000
#define DFLT_REPORT_SEC      300
#define DFLT_QUERY_TIMEOUT   5
#define DFLT_SLOW_THRESH_MS  200
#define DFLT_FLOOD_QPS       50    /* queries/sec per client before [DNS_FLOOD]  */
#define DFLT_DEGRADE_AVG_MS  300   /* avg latency (ms) above which = degraded    */
#define DFLT_DEGRADE_TO_PCT  15    /* % timeouts above which = degraded          */
#define MAX_PENDING          4096
#define DNS_HASH_BUCKETS     4096   /* must be power-of-2 */
#define MAX_QNAME_LEN        256
#define MAX_IP_STR           INET6_ADDRSTRLEN
#define MAX_CLIENT_TRACK     32    /* per-client query rate tracker slots        */

/* ------------------------------------------------------------------ */
/* IP / UDP / DNS header layouts (packed, no system-header dependency) */
/* ------------------------------------------------------------------ */
#define ETH_HDR_LEN          14
#define ETHER_TYPE_IP4       0x0800
#define ETHER_TYPE_IP6       0x86DD
#define IP_PROTO_UDP         17

typedef struct __attribute__((packed)) {
    uint8_t  ihl_ver; uint8_t tos; uint16_t tot_len; uint16_t id;
    uint16_t frag_off; uint8_t ttl; uint8_t protocol; uint16_t check;
    uint32_t saddr; uint32_t daddr;
} ip4hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t ver_tc_fl; uint16_t payload_len;
    uint8_t  next_hdr;  uint8_t  hop_limit;
    uint8_t  src[16];   uint8_t  dst[16];
} ip6hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t sport; uint16_t dport; uint16_t len; uint16_t check;
} udphdr_t;

typedef struct __attribute__((packed)) {
    uint16_t id; uint16_t flags;
    uint16_t qdcount; uint16_t ancount;
    uint16_t nscount; uint16_t arcount;
} dnshdr_t;

#define DNS_FLAG_QR    0x8000
#define DNS_FLAG_RCODE 0x000F

/* ------------------------------------------------------------------ */
/* Helper: RCODE integer -> human-readable name                        */
/* ------------------------------------------------------------------ */
static const char *rcode_name(int rcode)
{
    switch (rcode) {
        case 0:  return "NOERROR";
        case 1:  return "FORMERR";
        case 2:  return "SERVFAIL";
        case 3:  return "NXDOMAIN";
        case 4:  return "NOTIMP";
        case 5:  return "REFUSED";
        case 6:  return "YXDOMAIN";
        case 7:  return "XRRSET";
        case 8:  return "NOTAUTH";
        case 9:  return "NOTZONE";
        default: return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------ */
/* Helper: QTYPE integer -> human-readable name                        */
/* ------------------------------------------------------------------ */
static const char *qtype_name(uint16_t qt)
{
    switch (qt) {
        case 1:   return "A";
        case 2:   return "NS";
        case 5:   return "CNAME";
        case 6:   return "SOA";
        case 12:  return "PTR";
        case 15:  return "MX";
        case 16:  return "TXT";
        case 28:  return "AAAA";
        case 33:  return "SRV";
        case 255: return "ANY";
        default:  return "OTHER";
    }
}

/* ------------------------------------------------------------------ */
/* Helper: parse wire-format DNS QNAME into dotted string              */
/* Returns pointer to static buffer - only used for logging.           */
/* ------------------------------------------------------------------ */
static const char *parse_qname(const uint8_t *dns_payload, int payload_len,
                                int offset)
{
    static char qname[MAX_QNAME_LEN];
    int  out   = 0;
    int  limit = offset + MAX_QNAME_LEN;
    if (limit > payload_len) limit = payload_len;

    while (offset < limit) {
        uint8_t len = dns_payload[offset++];
        if (len == 0) break;
        /* Pointer compression (RFC 1035 4.1.4) - stop, not following */
        if ((len & 0xC0) == 0xC0) {
            if (out > 0 && qname[out - 1] == '.') out--;
            break;
        }
        if (out > 0)
            qname[out++] = '.';
        while (len-- > 0 && offset < limit && out < MAX_QNAME_LEN - 2)
            qname[out++] = (char)dns_payload[offset++];
    }
    qname[out] = '\0';
    return (out > 0) ? qname : "<root>";
}

/* ------------------------------------------------------------------ */
/* Helper: current time as ISO-8601 string  2026-07-10T14:32:01.123Z  */
/* ------------------------------------------------------------------ */
static const char *iso_ts(const struct timeval *tv)
{
    static char buf[32];
    struct tm tm_info;
    gmtime_r(&tv->tv_sec, &tm_info);
    int ms = (int)(tv->tv_usec / 1000);
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
             tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ms);
    return buf;
}

/* ------------------------------------------------------------------ */
/* Composite hash key: mix(client_ip, txid) prevents cross-client      */
/* txid collisions                                                      */
/* ------------------------------------------------------------------ */
static unsigned int make_hash(const char *client_ip, uint16_t txid)
{
    unsigned int h = (unsigned int)txid;
    const char  *p = client_ip;
    while (*p) { h = h * 31 + (unsigned char)*p++; }
    return h & (DNS_HASH_BUCKETS - 1);
}

/* ------------------------------------------------------------------ */
/* Pending-query table                                                  */
/* ------------------------------------------------------------------ */
typedef struct pending_entry {
    uint16_t       txid;
    char           client_ip[MAX_IP_STR];
    char           server_ip[MAX_IP_STR];
    char           qname[MAX_QNAME_LEN];
    uint16_t       qtype;
    struct timeval query_ts;
    struct pending_entry *next;
} pending_entry_t;

static pending_entry_t *g_table[DNS_HASH_BUCKETS];
static int              g_pending_count = 0;

static void pending_insert(uint16_t txid, const char *client_ip,
                           const char *server_ip, const char *qname,
                           uint16_t qtype, const struct timeval *ts)
{
    if (g_pending_count >= MAX_PENDING) return;
    pending_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return;

    e->txid     = txid;
    e->qtype    = qtype;
    e->query_ts = *ts;
    strncpy(e->client_ip, client_ip, MAX_IP_STR - 1);
    strncpy(e->server_ip, server_ip, MAX_IP_STR - 1);
    strncpy(e->qname,     qname,     MAX_QNAME_LEN - 1);

    unsigned int b = make_hash(client_ip, txid);
    e->next    = g_table[b];
    g_table[b] = e;
    g_pending_count++;
}

static pending_entry_t *pending_remove(uint16_t txid, const char *client_ip)
{
    unsigned int b = make_hash(client_ip, txid);
    pending_entry_t **pp = &g_table[b];
    while (*pp) {
        if ((*pp)->txid == txid &&
            strncmp((*pp)->client_ip, client_ip, MAX_IP_STR) == 0)
        {
            pending_entry_t *e = *pp;
            *pp = e->next;
            g_pending_count--;
            return e;
        }
        pp = &(*pp)->next;
    }
    return NULL;
}

typedef void (*expire_cb_t)(const pending_entry_t *e, void *ctx);

static int pending_expire(time_t now_sec, int timeout_sec,
                          expire_cb_t cb, void *ctx)
{
    int expired = 0;
    for (int b = 0; b < DNS_HASH_BUCKETS; b++) {
        pending_entry_t **pp = &g_table[b];
        while (*pp) {
            pending_entry_t *e = *pp;
            if ((now_sec - e->query_ts.tv_sec) >= timeout_sec) {
                if (cb) cb(e, ctx);
                *pp = e->next;
                free(e);
                g_pending_count--;
                expired++;
            } else {
                pp = &(*pp)->next;
            }
        }
    }
    return expired;
}

static void free_all_pending(void)
{
    for (int b = 0; b < DNS_HASH_BUCKETS; b++) {
        pending_entry_t *e = g_table[b];
        while (e) { pending_entry_t *n = e->next; free(e); e = n; }
        g_table[b] = NULL;
    }
    g_pending_count = 0;
}

/* ------------------------------------------------------------------ */
/* Per-interval statistics                                              */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t query_count;
    uint64_t success_count;
    uint64_t slow_count;
    uint64_t total_latency_ms;
    uint64_t max_latency_ms;
    uint64_t nxdomain;
    uint64_t servfail;
    uint64_t refused;
    uint64_t other_rcode;
    uint64_t timeout;
    /* Excessive DNS request detection */
    uint64_t flood_events;       /* times a client exceeded flood_qps threshold */
    /* Slow internet / degraded network detection */
    uint64_t degrade_events;     /* intervals where network was degraded        */
} stats_t;

static stats_t g_stats;

/* Per-server failure tracker */
#define MAX_SERVER_TRACK 8
typedef struct { char ip[MAX_IP_STR]; uint64_t fail_count; } server_stat_t;
static server_stat_t g_servers[MAX_SERVER_TRACK];
static int           g_server_count = 0;

static void server_bump_fail(const char *server_ip)
{
    for (int i = 0; i < g_server_count; i++) {
        if (strncmp(g_servers[i].ip, server_ip, MAX_IP_STR) == 0) {
            g_servers[i].fail_count++;
            return;
        }
    }
    if (g_server_count < MAX_SERVER_TRACK) {
        strncpy(g_servers[g_server_count].ip, server_ip, MAX_IP_STR - 1);
        g_servers[g_server_count].fail_count = 1;
        g_server_count++;
    }
}

/* Per-client query rate tracker — includes 1-second burst window for flood detection */
typedef struct {
    char     ip[MAX_IP_STR];
    uint64_t query_count;          /* total queries since interval start      */
    uint64_t burst_count;          /* queries in current 1-second window      */
    time_t   burst_window_start;   /* start of the 1-second burst window      */
} client_stat_t;
static client_stat_t g_clients[MAX_CLIENT_TRACK];
static int           g_client_count = 0;
static time_t        g_interval_start = 0;

/* Returns the current 1-second burst count for the client.
 * Resets the window when a new second begins. */
static uint64_t client_bump(const char *client_ip)
{
    time_t now_sec = time(NULL);
    for (int i = 0; i < g_client_count; i++) {
        if (strncmp(g_clients[i].ip, client_ip, MAX_IP_STR) == 0) {
            g_clients[i].query_count++;
            /* Slide the window if a new second has started */
            if (now_sec != g_clients[i].burst_window_start) {
                g_clients[i].burst_count = 1;
                g_clients[i].burst_window_start = now_sec;
            } else {
                g_clients[i].burst_count++;
            }
            return g_clients[i].burst_count;
        }
    }
    if (g_client_count < MAX_CLIENT_TRACK) {
        strncpy(g_clients[g_client_count].ip, client_ip, MAX_IP_STR - 1);
        g_clients[g_client_count].query_count       = 1;
        g_clients[g_client_count].burst_count       = 1;
        g_clients[g_client_count].burst_window_start = now_sec;
        g_client_count++;
        return 1;
    }
    return 0; /* table full */
}

/* Return IP of the client with most queries (for telemetry) */\nstatic void top_client(char *out_ip, uint64_t *out_count)\n{\n    uint64_t max = 0;\n    out_ip[0] = '\\0';\n    *out_count = 0;\n    for (int i = 0; i < g_client_count; i++) {\n        if (g_clients[i].query_count > max) {\n            max = g_clients[i].query_count;\n            strncpy(out_ip, g_clients[i].ip, MAX_IP_STR - 1);\n            *out_count = max;\n        }\n    }\n}

/* ------------------------------------------------------------------ */
/* Global config (set once at startup, then read-only)                 */
/* ------------------------------------------------------------------ */
static struct {
    char iface[64];
    int  report_sec;
    int  query_timeout;
    int  slow_thresh_ms;
    int  flood_qps;        /* per-client queries/sec threshold for flood alert */
    int  degrade_avg_ms;   /* avg latency threshold for degraded internet alert */
    int  degrade_to_pct;   /* timeout % threshold for degraded internet alert  */
    int  verbose;
} g_cfg;

static volatile int g_running = 1;
static void sig_handler(int s) { (void)s; g_running = 0; }

/* ------------------------------------------------------------------ */
/* Timeout callback - one [DNS_TIMEOUT] line per expired query         */
/* ------------------------------------------------------------------ */
static void on_timeout(const pending_entry_t *e, void *ctx)
{
    (void)ctx;
    struct timeval now_tv;
    gettimeofday(&now_tv, NULL);
    fprintf(stdout,
            "[DNS_TIMEOUT] ts=%s iface=%s"
            " client=%s server=%s txid=0x%04x"
            " qname=%s qtype=%s\n",
            iso_ts(&now_tv), g_cfg.iface,
            e->client_ip, e->server_ip, e->txid,
            e->qname, qtype_name(e->qtype));
    fflush(stdout);
    g_stats.timeout++;
}

/* ------------------------------------------------------------------ */
/* Telemetry + [DNS_SUMMARY] at end of each interval                   */
/* ------------------------------------------------------------------ */
static void report_and_reset(void)
{
    struct timeval now_tv;
    gettimeofday(&now_tv, NULL);

    /* Force-expire all still-pending queries as timeouts */
    pending_expire(now_tv.tv_sec, 0, on_timeout, NULL);

    uint64_t fail_total = g_stats.nxdomain + g_stats.servfail +
                          g_stats.refused  + g_stats.other_rcode +
                          g_stats.timeout;
    uint64_t avg_ms = g_stats.success_count
                    ? (g_stats.total_latency_ms / g_stats.success_count) : 0;

    /* ── Excessive DNS detection: peak 1-second burst across all clients ── */
    char   top_ip[MAX_IP_STR] = "";
    uint64_t top_cnt = 0;
    top_client(top_ip, &top_cnt);
    uint64_t peak_burst = 0;
    char     flood_client[MAX_IP_STR] = "";
    for (int ci = 0; ci < g_client_count; ci++) {
        if (g_clients[ci].burst_count > peak_burst) {
            peak_burst = g_clients[ci].burst_count;
            strncpy(flood_client, g_clients[ci].ip, MAX_IP_STR - 1);
        }
    }
    if (peak_burst >= (uint64_t)g_cfg.flood_qps) {
        g_stats.flood_events++;
        fprintf(stdout,
                "[DNS_FLOOD] ts=%s iface=%s"
                " client=%s burst_qps=%llu threshold_qps=%d\n",
                iso_ts(&now_tv), g_cfg.iface,
                flood_client,
                (unsigned long long)peak_burst,
                g_cfg.flood_qps);
        fflush(stdout);
    }

    /* ── Slow internet / degraded network detection ── */
    uint64_t timeout_pct = (g_stats.query_count > 0)
                         ? (g_stats.timeout * 100 / g_stats.query_count) : 0;
    int high_latency  = (g_stats.success_count >= 5 &&
                         avg_ms  >= (uint64_t)g_cfg.degrade_avg_ms);
    int high_timeouts = (g_stats.query_count >= 10 &&
                         timeout_pct >= (uint64_t)g_cfg.degrade_to_pct);
    int high_servfail = (g_stats.query_count >= 5 &&
                         g_stats.servfail * 100 / g_stats.query_count >= 20);
    if (high_latency || high_timeouts || high_servfail) {
        g_stats.degrade_events++;
        char reason[128];
        snprintf(reason, sizeof(reason), "%s%s%s",
                 high_latency  ? "high_latency " : "",
                 high_timeouts ? "high_timeouts " : "",
                 high_servfail ? "high_servfail" : "");
        fprintf(stdout,
                "[NET_DEGRADED] ts=%s iface=%s"
                " reason=%s avg_ms=%llu timeout_pct=%llu"
                " servfail=%llu queries=%llu\n",
                iso_ts(&now_tv), g_cfg.iface,
                reason,
                (unsigned long long)avg_ms,
                (unsigned long long)timeout_pct,
                (unsigned long long)g_stats.servfail,
                (unsigned long long)g_stats.query_count);
        fflush(stdout);
    }

    /* Build per-server failure string for the summary line */
    char svr_buf[256] = "";
    for (int i = 0; i < g_server_count; i++) {
        char tmp[80];
        snprintf(tmp, sizeof(tmp), "%s:%llu%s",
                 g_servers[i].ip,
                 (unsigned long long)g_servers[i].fail_count,
                 (i + 1 < g_server_count) ? "," : "");
        strncat(svr_buf, tmp, sizeof(svr_buf) - strlen(svr_buf) - 1);
    }

    /* [DNS_SUMMARY] - one line, all key=value, easy to grep/parse */
    fprintf(stdout,
            "[DNS_SUMMARY] ts=%s iface=%s"
            " queries=%llu success=%llu slow=%llu"
            " fail_total=%llu"
            " nxdomain=%llu servfail=%llu refused=%llu"
            " other_rcode=%llu timeout=%llu timeout_pct=%llu"
            " avg_ms=%llu max_ms=%llu"
            " flood_events=%llu degrade_events=%llu"
            " top_client=%s:%llu"
            " server_fails=[%s]\n",
            iso_ts(&now_tv), g_cfg.iface,
            (unsigned long long)g_stats.query_count,
            (unsigned long long)g_stats.success_count,
            (unsigned long long)g_stats.slow_count,
            (unsigned long long)fail_total,
            (unsigned long long)g_stats.nxdomain,
            (unsigned long long)g_stats.servfail,
            (unsigned long long)g_stats.refused,
            (unsigned long long)g_stats.other_rcode,
            (unsigned long long)g_stats.timeout,
            (unsigned long long)timeout_pct,
            (unsigned long long)avg_ms,
            (unsigned long long)g_stats.max_latency_ms,
            (unsigned long long)g_stats.flood_events,
            (unsigned long long)g_stats.degrade_events,
            top_ip[0] ? top_ip : "none",
            (unsigned long long)top_cnt,
            svr_buf);
    fflush(stdout);

    /* Telemetry-2 markers */
    t2_event_d("NET_DNS_PCAP_QUERY_CNT_split",        (int)g_stats.query_count);
    t2_event_d("NET_DNS_PCAP_SLOW_CNT_split",         (int)g_stats.slow_count);
    t2_event_d("NET_DNS_PCAP_FAIL_CNT_split",         (int)fail_total);
    t2_event_d("NET_DNS_PCAP_TIMEOUT_RATE_pct_split", (int)timeout_pct);
    t2_event_d("NET_DNS_PCAP_FLOOD_CNT_split",        (int)g_stats.flood_events);
    t2_event_d("NET_DNS_PCAP_DEGRADED_split",
               (g_stats.degrade_events > 0) ? 1 : 0);
    if (g_stats.success_count > 0) {
        t2_event_d("NET_DNS_PCAP_LATENCY_AVG_ms_split", (int)avg_ms);
        t2_event_d("NET_DNS_PCAP_LATENCY_MAX_ms_split",
                   (int)g_stats.max_latency_ms);
    }
    if (top_ip[0] != '\0') {
        char top_str[MAX_IP_STR + 32];
        snprintf(top_str, sizeof(top_str), "%s:%llu",
                 top_ip, (unsigned long long)top_cnt);
        t2_event_s("NET_DNS_PCAP_TOP_CLIENT_split", top_str);
    }
    if (fail_total > 0) {
        char fail_str[192];
        snprintf(fail_str, sizeof(fail_str),
                 "nxdomain=%llu,servfail=%llu,refused=%llu,"
                 "other_rcode=%llu,timeout=%llu",
                 (unsigned long long)g_stats.nxdomain,
                 (unsigned long long)g_stats.servfail,
                 (unsigned long long)g_stats.refused,
                 (unsigned long long)g_stats.other_rcode,
                 (unsigned long long)g_stats.timeout);
        t2_event_s("NET_DNS_PCAP_FAIL_TYPE_split", fail_str);
    }

    memset(&g_stats,  0, sizeof(g_stats));
    memset(g_servers, 0, sizeof(g_servers));
    memset(g_clients, 0, sizeof(g_clients));
    g_server_count   = 0;
    g_client_count   = 0;
    g_interval_start = now_tv.tv_sec;
}

/* ------------------------------------------------------------------ */
/* IP-address extraction helpers                                        */
/* ------------------------------------------------------------------ */
static void ip4_to_str(uint32_t addr_net, char *out, size_t len)
{
    struct in_addr a; a.s_addr = addr_net;
    inet_ntop(AF_INET, &a, out, (socklen_t)len);
}
static void ip6_to_str(const uint8_t *addr16, char *out, size_t len)
{
    inet_ntop(AF_INET6, addr16, out, (socklen_t)len);
}

/* ------------------------------------------------------------------ */
/* Packet callback                                                       */
/* ------------------------------------------------------------------ */
typedef struct { int query_timeout_sec; } cb_args_t;

static void packet_cb(u_char *user,
                      const struct pcap_pkthdr *header,
                      const u_char *packet)
{
    cb_args_t   *args = (cb_args_t *)user;
    const u_char *ptr = packet;
    int           rem = (int)header->caplen;
    char src_ip[MAX_IP_STR] = {0};
    char dst_ip[MAX_IP_STR] = {0};

    if (rem < ETH_HDR_LEN) return;

    uint16_t ether_type = ntohs(*(const uint16_t *)(ptr + 12));
    ptr += ETH_HDR_LEN; rem -= ETH_HDR_LEN;

    uint8_t ip_proto = 0;
    if (ether_type == ETHER_TYPE_IP4) {
        if (rem < (int)sizeof(ip4hdr_t)) return;
        const ip4hdr_t *ip4 = (const ip4hdr_t *)ptr;
        int ihl = (ip4->ihl_ver & 0x0F) * 4;
        if (ihl < 20 || rem < ihl) return;
        ip_proto = ip4->protocol;
        ip4_to_str(ip4->saddr, src_ip, sizeof(src_ip));
        ip4_to_str(ip4->daddr, dst_ip, sizeof(dst_ip));
        ptr += ihl; rem -= ihl;
    } else if (ether_type == ETHER_TYPE_IP6) {
        if (rem < (int)sizeof(ip6hdr_t)) return;
        const ip6hdr_t *ip6 = (const ip6hdr_t *)ptr;
        ip_proto = ip6->next_hdr;
        ip6_to_str(ip6->src, src_ip, sizeof(src_ip));
        ip6_to_str(ip6->dst, dst_ip, sizeof(dst_ip));
        ptr += sizeof(ip6hdr_t); rem -= (int)sizeof(ip6hdr_t);
    } else {
        return;
    }

    if (ip_proto != IP_PROTO_UDP) return;
    if (rem < (int)sizeof(udphdr_t)) return;

    const udphdr_t *udp = (const udphdr_t *)ptr;
    uint16_t sport = ntohs(udp->sport);
    uint16_t dport = ntohs(udp->dport);
    ptr += sizeof(udphdr_t); rem -= (int)sizeof(udphdr_t);

    if (sport != DNS_PORT && dport != DNS_PORT) return;
    if (rem < (int)sizeof(dnshdr_t)) return;

    const dnshdr_t *dns = (const dnshdr_t *)ptr;
    uint16_t txid       = ntohs(dns->id);
    uint16_t flags      = ntohs(dns->flags);
    int is_response     = (flags & DNS_FLAG_QR) ? 1 : 0;
    int rcode           = (int)(flags & DNS_FLAG_RCODE);

    /* Parse QNAME and QTYPE from question section */
    const uint8_t *dns_start = ptr;
    int dns_len              = rem;
    int qoff                 = (int)sizeof(dnshdr_t);
    const char *qname_str    = "<unknown>";
    uint16_t    qtype        = 0;

    if (dns_len > qoff) {
        qname_str = parse_qname(dns_start, dns_len, qoff);
        /* Walk the wire-format name to find QTYPE offset */
        int off = qoff;
        while (off < dns_len) {
            uint8_t lbl = dns_start[off];
            if (lbl == 0)           { off++; break; }
            if ((lbl & 0xC0) == 0xC0) { off += 2; break; }
            off += 1 + lbl;
        }
        if (off + 2 <= dns_len)
            qtype = ntohs(*(const uint16_t *)(dns_start + off));
    }

    struct timeval pkt_ts = header->ts;

    /* Expire timed-out pending queries before processing this packet */
    pending_expire(pkt_ts.tv_sec, args->query_timeout_sec, on_timeout, NULL);

    /* client = the side that sent the query (dport==53 means query going out) */
    const char *client_ip = (dport == DNS_PORT) ? src_ip : dst_ip;
    const char *server_ip = (dport == DNS_PORT) ? dst_ip : src_ip;

    if (!is_response)
    {
        /* ── Outgoing DNS query ── */
        g_stats.query_count++;

        /* Track per-client query count for flood detection */
        uint64_t burst_qps = client_bump(client_ip); /* queries in current second */
        if (burst_qps >= (uint64_t)g_cfg.flood_qps) {
            fprintf(stdout,
                    "[DNS_FLOOD] ts=%s iface=%s"
                    " client=%s burst_qps=%llu threshold_qps=%d\n",
                    iso_ts(&pkt_ts), g_cfg.iface,
                    client_ip,
                    (unsigned long long)burst_qps,
                    g_cfg.flood_qps);
            fflush(stdout);
        }

        if (g_cfg.verbose) {
            fprintf(stdout,
                    "[DNS_QUERY] ts=%s iface=%s"
                    " client=%s server=%s txid=0x%04x"
                    " qname=%s qtype=%s\n",
                    iso_ts(&pkt_ts), g_cfg.iface,
                    client_ip, server_ip, txid,
                    qname_str, qtype_name(qtype));
            fflush(stdout);
        }

        pending_insert(txid, client_ip, server_ip, qname_str, qtype, &pkt_ts);
    }
    else
    {
        /* ── DNS response ── */
        pending_entry_t *e = pending_remove(txid, client_ip);
        if (!e) return; /* unsolicited / duplicate */

        int64_t diff_sec   = (int64_t)pkt_ts.tv_sec  - (int64_t)e->query_ts.tv_sec;
        int64_t diff_usec  = (int64_t)pkt_ts.tv_usec - (int64_t)e->query_ts.tv_usec;
        int64_t latency_ms = diff_sec * 1000 + diff_usec / 1000;
        if (latency_ms < 0) latency_ms = 0;

        if (rcode != 0)
        {
            /* ── [DNS_FAIL]: log every failure with RCODE name ── */
            switch (rcode) {
                case 3: g_stats.nxdomain++;    break;
                case 2: g_stats.servfail++;    break;
                case 5: g_stats.refused++;     break;
                default: g_stats.other_rcode++; break;
            }
            server_bump_fail(e->server_ip);

            fprintf(stdout,
                    "[DNS_FAIL] ts=%s iface=%s"
                    " client=%s server=%s txid=0x%04x"
                    " qname=%s qtype=%s"
                    " rcode=%d(%s) latency_ms=%lld\n",
                    iso_ts(&pkt_ts), g_cfg.iface,
                    e->client_ip, e->server_ip, txid,
                    e->qname, qtype_name(e->qtype),
                    rcode, rcode_name(rcode),
                    (long long)latency_ms);
            fflush(stdout);
        }
        else
        {
            /* ── [DNS_RESP_OK] or [DNS_SLOW] ── */
            g_stats.success_count++;
            g_stats.total_latency_ms += (uint64_t)latency_ms;
            if ((uint64_t)latency_ms > g_stats.max_latency_ms)
                g_stats.max_latency_ms = (uint64_t)latency_ms;

            int is_slow = (latency_ms >= g_cfg.slow_thresh_ms);
            if (is_slow) g_stats.slow_count++;

            if (g_cfg.verbose || is_slow) {
                fprintf(stdout,
                        "%s ts=%s iface=%s"
                        " client=%s server=%s txid=0x%04x"
                        " qname=%s qtype=%s latency_ms=%lld\n",
                        is_slow ? "[DNS_SLOW]" : "[DNS_RESP_OK]",
                        iso_ts(&pkt_ts), g_cfg.iface,
                        e->client_ip, e->server_ip, txid,
                        e->qname, qtype_name(e->qtype),
                        (long long)latency_ms);
                fflush(stdout);
            }
        }
        free(e);
    }
}

/* ------------------------------------------------------------------ */
/* main                                                                  */
/* ------------------------------------------------------------------ */
static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -i <iface> [-r <report_sec>] [-t <timeout_sec>]"
        " [-s <slow_ms>] [-v]\n"
        "  -i  WAN interface to sniff (required)\n"
        "  -r  Telemetry report interval in seconds    (default: %d)\n"
        "  -t  DNS query timeout in seconds            (default: %d)\n"
        "  -s  Slow-query threshold in milliseconds    (default: %d)\n"
        "  -v  Verbose: log every query and OK response\n",
        prog, DFLT_REPORT_SEC, DFLT_QUERY_TIMEOUT, DFLT_SLOW_THRESH_MS);
}

/* In UNIT_TEST_DOCKER_SUPPORT mode main() is excluded so the test binary
 * can link this file directly and call the internal functions. */
#ifndef UNIT_TEST_DOCKER_SUPPORT
int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int  opt;

    g_cfg.report_sec     = DFLT_REPORT_SEC;
    g_cfg.query_timeout  = DFLT_QUERY_TIMEOUT;
    g_cfg.slow_thresh_ms = DFLT_SLOW_THRESH_MS;
    g_cfg.flood_qps      = DFLT_FLOOD_QPS;
    g_cfg.degrade_avg_ms = DFLT_DEGRADE_AVG_MS;
    g_cfg.degrade_to_pct = DFLT_DEGRADE_TO_PCT;
    g_cfg.verbose        = 0;

    while ((opt = getopt(argc, argv, "i:r:t:s:f:d:vh")) != -1) {
        switch (opt) {
            case 'i': strncpy(g_cfg.iface, optarg, sizeof(g_cfg.iface) - 1); break;
            case 'r': g_cfg.report_sec     = atoi(optarg); break;
            case 't': g_cfg.query_timeout  = atoi(optarg); break;
            case 's': g_cfg.slow_thresh_ms = atoi(optarg); break;
            case 'f': g_cfg.flood_qps      = atoi(optarg); break;
            case 'd': g_cfg.degrade_avg_ms = atoi(optarg); break;
            case 'v': g_cfg.verbose        = 1;            break;
            default:  print_usage(argv[0]); return 1;
        }
    }

    if (g_cfg.iface[0] == '\0') {
        fprintf(stderr, "Error: -i <interface> is required.\n");
        print_usage(argv[0]);
        return 1;
    }
    if (g_cfg.report_sec     <= 0) g_cfg.report_sec     = DFLT_REPORT_SEC;
    if (g_cfg.query_timeout  <= 0) g_cfg.query_timeout  = DFLT_QUERY_TIMEOUT;
    if (g_cfg.slow_thresh_ms <= 0) g_cfg.slow_thresh_ms = DFLT_SLOW_THRESH_MS;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open live capture */
    pcap_t *handle = pcap_open_live(g_cfg.iface, SNAP_LEN, 1 /*promisc*/,
                                    PCAP_TIMEOUT_MS, errbuf);
    if (!handle) {
        fprintf(stderr, "[DnsMonitor] pcap_open_live(%s): %s\n",
                g_cfg.iface, errbuf);
        return 1;
    }

    /* BPF filter: UDP port 53 */
    struct bpf_program bpf;
    if (pcap_compile(handle, &bpf, "udp port 53", 1,
                     PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &bpf) < 0)
    {
        fprintf(stderr, "[DnsMonitor] BPF filter failed: %s\n",
                pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&bpf);

    /* Non-blocking so pcap_dispatch returns immediately when no packets */
    if (pcap_setnonblock(handle, 1, errbuf) < 0) {
        fprintf(stderr, "[DnsMonitor] pcap_setnonblock: %s\n", errbuf);
        pcap_close(handle);
        return 1;
    }

    memset(g_table,   0, sizeof(g_table));
    memset(&g_stats,  0, sizeof(g_stats));
    memset(g_servers, 0, sizeof(g_servers));
    memset(g_clients, 0, sizeof(g_clients));
    g_interval_start = time(NULL);

    struct timeval now_tv;
    gettimeofday(&now_tv, NULL);
    fprintf(stdout,
            "[DNS_SUMMARY] ts=%s iface=%s event=START"
            " report_sec=%d timeout_sec=%d slow_thresh_ms=%d verbose=%d\n",
            iso_ts(&now_tv), g_cfg.iface,
            g_cfg.report_sec, g_cfg.query_timeout,
            g_cfg.slow_thresh_ms, g_cfg.verbose);
    fflush(stdout);

    cb_args_t cb_args = { .query_timeout_sec = g_cfg.query_timeout };
    time_t next_report = time(NULL) + g_cfg.report_sec;

    while (g_running)
    {
        /* 50 ms idle sleep — avoids busy-spin without select()/FD_ZERO */
        usleep(50000);

        int n = pcap_dispatch(handle, 128, packet_cb, (u_char *)&cb_args);
        if (n < 0 && n != PCAP_ERROR_BREAK) {
            fprintf(stderr, "[DnsMonitor] pcap_dispatch: %s\n",
                    pcap_geterr(handle));
            break;
        }

        if (time(NULL) >= next_report) {
            report_and_reset();
            next_report = time(NULL) + g_cfg.report_sec;
        }
    }

    report_and_reset();  /* final flush */
    free_all_pending();
    pcap_close(handle);

    gettimeofday(&now_tv, NULL);
    fprintf(stdout, "[DNS_SUMMARY] ts=%s iface=%s event=STOP\n",
            iso_ts(&now_tv), g_cfg.iface);
    return 0;
}
#endif /* UNIT_TEST_DOCKER_SUPPORT */
