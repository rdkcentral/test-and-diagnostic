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
#define CLIENT_HASH_BUCKETS  256   /* hash buckets for per-client tracker        */

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
/**
 * @brief  Convert a DNS RCODE integer to its RFC-standard name string.
 *
 * Used in [DNS_FAIL] log lines so analysts see "NXDOMAIN" instead of
 * the raw number 3.
 *
 * @param  rcode  DNS response code (0-9) from the DNS flags field
 *                (flags & 0x000F)
 * @return Pointer to a static string literal. Never NULL.
 *
 * Example:
 *   rcode_name(0)  -> "NOERROR"   (successful response)
 *   rcode_name(2)  -> "SERVFAIL"  (upstream DNS server error)
 *   rcode_name(3)  -> "NXDOMAIN"  (domain does not exist)
 *   rcode_name(5)  -> "REFUSED"   (server refused the query)
 *   rcode_name(99) -> "UNKNOWN"   (not in RFC 1035 / RFC 2136)
 */
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
/**
 * @brief  Convert a DNS QTYPE integer to its record-type name string.
 *
 * Used in every log line so analysts see "A", "AAAA", "PTR" instead
 * of raw numbers.
 *
 * @param  qt  DNS question type (network-byte-order already swapped by caller)
 * @return Pointer to a static string literal. Never NULL.
 *
 * Common values observed on XB8:
 *   qtype_name(1)   -> "A"      IPv4 address lookup  (e.g. nslookup google.com)
 *   qtype_name(12)  -> "PTR"   Reverse lookup       (e.g. 44 of 44 failures on XB8)
 *   qtype_name(28)  -> "AAAA"  IPv6 address lookup  (dual-stack queries)
 *   qtype_name(15)  -> "MX"    Mail exchanger
 */
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
/**
 * @brief  Decode a DNS wire-format QNAME (label-length encoded) into a
 *         human-readable dotted string.
 *
 * DNS encodes hostnames as length-prefixed labels (RFC 1035 §3.1):
 *   \x03www\x06google\x03com\x00  ->  "www.google.com"
 *
 * Pointer compression (\xC0 prefix, RFC 1035 §4.1.4) is detected and
 * stopped — we do not follow the pointer since we only need the name
 * for logging, not full resolution.
 *
 * @param  dns_payload   Pointer to the start of the DNS header (not UDP).
 * @param  payload_len   Total bytes available from dns_payload.
 * @param  offset        Byte offset into dns_payload where the QNAME starts.
 *                       For the question section this is sizeof(dnshdr_t) = 12.
 * @return Pointer to a static char buffer with the dotted name.
 *         Returns "<root>" for a zero-length name (root DNS query).
 *         CAUTION: static buffer — not re-entrant, copy before next call.
 *
 * Example (XB8 observed):
 *   Input:  \x0Bconnectivity-check\x06ubuntu\x03com\x00
 *   Output: "connectivity-check.ubuntu.com"
 *
 *   Input:  \x02 75 \x02 75 \x02 75 \x02 75 \x07in-addr\x04arpa\x00
 *   Output: "75.75.75.75.in-addr.arpa"
 */
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
/**
 * @brief  Format a struct timeval as an ISO-8601 UTC timestamp string
 *         with millisecond precision.
 *
 * Output format: YYYY-MM-DDTHH:MM:SS.mmmZ  (always UTC, always 24 chars)
 *
 * All log line tags use this for the ts= field so timestamps are:
 *   - Sortable (lexicographic == chronological)
 *   - Parseable by ELK/Splunk/grep without configuration
 *   - Unambiguous (Z suffix = UTC, no timezone confusion)
 *
 * @param  tv   Kernel-provided packet timestamp from pcap_pkthdr.ts
 *              (set at NIC DMA interrupt time, more accurate than
 *               calling gettimeofday() from application code).
 * @return Pointer to a static 32-byte buffer. Never NULL.
 *         CAUTION: static buffer — not re-entrant.
 *
 * Example:
 *   tv = { .tv_sec=1752634218, .tv_usec=999000 }
 *   result: "2026-07-16T04:50:18.999Z"
 */
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
/**
 * @brief  Compute a hash bucket index from a (client_ip, txid) composite key.
 *
 * Problem solved: Two different LAN clients (e.g. 10.0.0.58 and phone
 * 10.0.0.72) can independently generate DNS queries with the same 16-bit
 * transaction ID (0xac9a in XB8 dual-stack test). A hash on txid alone
 * would place both in the same bucket and pending_remove() might return
 * the wrong entry.
 *
 * Solution: polynomial hash over the IP string XOR'd with txid so each
 * (client, txid) pair maps to a unique-ish bucket.
 *
 * Algorithm:
 *   h = txid
 *   for each byte c in client_ip string:
 *       h = h * 31 + c
 *   bucket = h & (DNS_HASH_BUCKETS - 1)   // fast modulo (power-of-2)
 *
 * @param  client_ip  Null-terminated IP string ("10.0.0.58" or IPv6)
 * @param  txid       DNS transaction ID (host byte order)
 * @return Bucket index in [0, DNS_HASH_BUCKETS-1]  (always in range)
 *
 * Example:
 *   make_hash("10.0.0.58", 0xac9a) -> 1847   (some bucket)
 *   make_hash("10.0.0.72", 0xac9a) -> 2103   (different bucket)
 */
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

/**
 * @brief  Record an outgoing DNS query in the pending table.
 *
 * Called for every QR=0 (query) packet. Stores all the information
 * needed to:
 *   a) Match the query when the response arrives (via txid + client_ip)
 *   b) Compute latency (response_ts - query_ts)
 *   c) Log the qname/qtype on the response line without re-parsing
 *
 * The entry lives in the hash table until:
 *   - pending_remove() is called when the matching response arrives
 *   - pending_expire() evicts it as a timeout after query_timeout_sec
 *
 * Memory: calloc'd per-entry. Freed by pending_remove() or pending_expire().
 * Silently dropped if g_pending_count >= MAX_PENDING (4096).
 *
 * @param  txid       DNS transaction ID (host byte order, e.g. 0x07ac)
 * @param  client_ip  Source IP of the query  (e.g. "10.0.0.58")
 * @param  server_ip  Destination IP (upstream DNS, e.g. "75.75.75.75")
 * @param  qname      Parsed hostname string  (e.g. "www.google.com")
 * @param  qtype      Record type (1=A, 28=AAAA, 12=PTR, ...)
 * @param  ts         Kernel timestamp of the query packet (from pcap_pkthdr)
 */
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

/**
 * @brief  Look up and unlink a pending query entry by (txid, client_ip).
 *
 * Called for every QR=1 (response) packet. The composite key prevents
 * cross-client false matches (two clients with the same txid).
 *
 * The caller is responsible for free()ing the returned pointer.
 * Returns NULL for unsolicited or duplicate responses — caller skips them.
 *
 * @param  txid       DNS transaction ID from the response header
 * @param  client_ip  Client IP — used as second key component.
 *                    For a response (sport==53), client_ip is dst_ip.
 * @return Pointer to the unlinked pending_entry_t, or NULL if not found.
 *
 * Example:
 *   Query stored:    pending_insert(0x07ac, "10.0.0.58", ...)
 *   Response arrives: e = pending_remove(0x07ac, "10.0.0.58")
 *   e != NULL -> latency = response_ts - e->query_ts
 *   free(e);  // caller must free
 */
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

/**
 * @brief  Sweep the hash table and evict entries older than timeout_sec.
 *
 * Called on every incoming packet (using the packet's kernel timestamp)
 * so timeouts are detected lazily without a dedicated timer thread.
 * Also called at report time with timeout_sec=0 to force-expire everything.
 *
 * For each expired entry:
 *   1. The optional callback cb(entry, ctx) is called (used for [DNS_TIMEOUT])
 *   2. The entry is unlinked from the hash chain and freed
 *
 * @param  now_sec      Current time in seconds (from packet ts or time())
 * @param  timeout_sec  Expiry threshold. Entry expires when:
 *                      now_sec - entry->query_ts.tv_sec >= timeout_sec
 *                      Pass 0 to force-expire ALL entries immediately.
 * @param  cb           Callback invoked for each expired entry (may be NULL)
 * @param  ctx          Opaque pointer passed to cb (may be NULL)
 * @return Number of entries expired in this sweep
 *
 * Example (lazy timeout detection on each packet):
 *   pending_expire(pkt_ts.tv_sec, 5, on_timeout, NULL);
 *   // Sweeps all 4096 buckets — entries older than 5s trigger on_timeout()
 *
 * Example (force-expire at report time):
 *   pending_expire(now_tv.tv_sec, 0, on_timeout, NULL);
 *   // timeout_sec=0 means ALL entries qualify (age >= 0 is always true)
 */
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

/**
 * @brief  Increment the failure counter for an upstream DNS server.
 *
 * Called on every [DNS_FAIL] event to track which upstream server
 * is returning errors. Appears in [DNS_SUMMARY] as:
 *   server_fails=[75.75.75.75:42,75.75.76.76:2]
 *
 * Tracks up to MAX_SERVER_TRACK (8) distinct server IPs.
 * If the table is full, new servers are silently dropped.
 * Reset to zero at each report_and_reset() call.
 *
 * @param  server_ip  IP string of the DNS server that returned an error
 *                    (e.g. "75.75.75.75" or "2001:558:feed::1")
 *
 * Example (from XB8 test run):
 *   After 44 PTR NXDOMAIN failures all on 75.75.75.75:
 *   g_servers[0] = { ip="75.75.75.75", fail_count=44 }
 */
static void server_bump_fail(const char *server_ip)
{
    for (int i = 0; i < g_server_count; i++) {
        if (strncmp(g_servers[i].ip, server_ip, MAX_IP_STR) == 0) {
            g_servers[i].fail_count++;  /* found existing slot — increment */
            return;
        }
    }
    /* New server — allocate next slot */
    if (g_server_count < MAX_SERVER_TRACK) {
        strncpy(g_servers[g_server_count].ip, server_ip, MAX_IP_STR - 1);
        g_servers[g_server_count].fail_count = 1;
        g_server_count++;
    }
    /* else: silently drop — table full, MAX_SERVER_TRACK exceeded */
}

/* Per-client query rate tracker — includes 1-second burst window for flood detection */
typedef struct client_stat {
    char     ip[MAX_IP_STR];   /* IP address string (IPv4 or IPv6)        */
    char     mac[18];          /* Ethernet source MAC "aa:bb:cc:dd:ee:ff" */
    uint64_t query_count;      /* total queries since interval start      */
    uint64_t burst_count;      /* queries in current 1-second window      */
    time_t   burst_window_start; /* start of the 1-second burst window    */
    uint32_t qtype_a;          /* per-client QTYPE counters (from net_telemetry) */
    uint32_t qtype_aaaa;
    uint32_t qtype_ptr;
    uint32_t qtype_txt;
    uint32_t qtype_mx;
    uint32_t qtype_srv;
    uint32_t qtype_other;
    struct client_stat *next;  /* hash chain — replaces fixed array       */
} client_stat_t;
static client_stat_t *g_clients[CLIENT_HASH_BUCKETS]; /* hash table of pointers */
static int            g_client_count = 0;
static time_t         g_interval_start = 0;

/* Per-client QTYPE helpers (ported from net_telemetry) */
static unsigned int client_ip_hash(const char *ip)
{
    unsigned int h = 5381;
    while (*ip) { h = ((h << 5) + h) + (unsigned char)*ip++; }
    return h % CLIENT_HASH_BUCKETS;
}

static void increment_client_qtype(client_stat_t *c, uint16_t qtype)
{
    switch (qtype) {
        case 1:  c->qtype_a++;     break;
        case 28: c->qtype_aaaa++;  break;
        case 12: c->qtype_ptr++;   break;
        case 16: c->qtype_txt++;   break;
        case 15: c->qtype_mx++;    break;
        case 33: c->qtype_srv++;   break;
        default: c->qtype_other++; break;
    }
}

static const char *dominant_qtype(const client_stat_t *c)
{
    uint32_t max = c->qtype_a;  const char *label = "A";
    if (c->qtype_aaaa  > max) { max = c->qtype_aaaa;  label = "AAAA"; }
    if (c->qtype_ptr   > max) { max = c->qtype_ptr;   label = "PTR";  }
    if (c->qtype_txt   > max) { max = c->qtype_txt;   label = "TXT";  }
    if (c->qtype_mx    > max) { max = c->qtype_mx;    label = "MX";   }
    if (c->qtype_srv   > max) { max = c->qtype_srv;   label = "SRV";  }
    if (c->qtype_other > max) {                        label = "OTHER"; (void)max; }
    return label;
}

/**
 * @brief  Increment query counters for a client and return the current
 *         1-second burst count (for flood detection).
 *
 * Also records the client's MAC address on first seen (from Ethernet header).
 *
 * @param  client_ip  Source IP string of the querying client
 * @param  src_mac    Source MAC from Ethernet header (e.g. "28:f1:0e:12:a1:a4")
 * @param  qtype      DNS QTYPE of the query (for per-client QTYPE counters)
 * @return Current burst_count for this client (queries in current second).
 *         Returns 0 on allocation failure.
 */
static uint64_t client_bump(const char *client_ip, const char *src_mac,
                             uint16_t qtype)
{
    time_t now_sec = time(NULL);
    unsigned int b = client_ip_hash(client_ip);
    for (client_stat_t *c = g_clients[b]; c; c = c->next) {
        if (strncmp(c->ip, client_ip, MAX_IP_STR) == 0) {
            c->query_count++;
            if (c->mac[0] == '\0' && src_mac)
                strncpy(c->mac, src_mac, sizeof(c->mac) - 1);
            if (now_sec != c->burst_window_start) {
                c->burst_count = 1;
                c->burst_window_start = now_sec;
            } else {
                c->burst_count++;
            }
            increment_client_qtype(c, qtype);
            return c->burst_count;
        }
    }
    /* New client — calloc and chain into hash bucket */
    client_stat_t *c = calloc(1, sizeof(*c));
    if (!c) return 0;
    strncpy(c->ip, client_ip, MAX_IP_STR - 1);
    if (src_mac)
        strncpy(c->mac, src_mac, sizeof(c->mac) - 1);
    c->query_count        = 1;
    c->burst_count        = 1;
    c->burst_window_start = now_sec;
    increment_client_qtype(c, qtype);
    c->next      = g_clients[b];
    g_clients[b] = c;
    g_client_count++;
    return 1;
}

/* Return IP of the client with most queries (for telemetry) */
static void top_client(char *out_ip, uint64_t *out_count)
{
    uint64_t max = 0;
    out_ip[0] = '\0';
    *out_count = 0;
    for (int b = 0; b < CLIENT_HASH_BUCKETS; b++) {
        for (client_stat_t *c = g_clients[b]; c; c = c->next) {
            if (c->query_count > max) {
                max = c->query_count;
                strncpy(out_ip, c->ip, MAX_IP_STR - 1);
                *out_count = max;
            }
        }
    }
}

/**
 * @brief  Print a formatted per-client query summary table.
 *
 * Emits a [CLIENT_SUMMARY] block showing every client seen in the current
 * interval with their IP, MAC address, and query count. Also prints the
 * total unique client count.
 *
 * Output format (one line per client + header + footer):
 *   [CLIENT_SUMMARY] ts=... iface=... total_clients=3
 *   [CLIENT_SUMMARY] #  IP                                    MAC               queries
 *   [CLIENT_SUMMARY] 1  10.0.0.58                             28:f1:0e:12:a1:a4  72
 *   [CLIENT_SUMMARY] 2  2001:558:6045:12:987:cc98:4d57:5740   (unknown)         18
 *   [CLIENT_SUMMARY] 3  10.0.0.72                             aa:bb:cc:dd:ee:ff   5
 *
 * Called from report_and_reset() before resetting g_clients[].
 *
 * @param  now_ts  ISO-8601 timestamp string (from iso_ts())
 */
static void print_client_summary(const char *now_ts)
{
    if (g_client_count == 0) return;

    /* Collect pointers from hash table into flat array for sorting */
    int n = g_client_count;
    client_stat_t **ptrs = malloc((size_t)n * sizeof(client_stat_t *));
    if (!ptrs) return;
    int idx = 0;
    for (int b = 0; b < CLIENT_HASH_BUCKETS && idx < n; b++) {
        for (client_stat_t *c = g_clients[b]; c && idx < n; c = c->next)
            ptrs[idx++] = c;
    }
    n = idx;

    /* Insertion sort by query_count descending */
    for (int i = 1; i < n; i++) {
        client_stat_t *key = ptrs[i];
        int j = i - 1;
        while (j >= 0 && ptrs[j]->query_count < key->query_count) {
            ptrs[j + 1] = ptrs[j];
            j--;
        }
        ptrs[j + 1] = key;
    }

    /* Header line */
    fprintf(stdout,
            "[CLIENT_SUMMARY] ts=%s iface=%s total_clients=%d\n"
            "[CLIENT_SUMMARY] %-3s %-40s %-18s %-6s %s\n",
            now_ts, g_cfg.iface, n,
            "#", "IP", "MAC", "qtype", "queries");

    /* One row per client */
    for (int i = 0; i < n; i++) {
        fprintf(stdout,
                "[CLIENT_SUMMARY] %-3d %-40s %-18s %-6s %llu\n",
                i + 1,
                ptrs[i]->ip,
                ptrs[i]->mac[0] ? ptrs[i]->mac : "(unknown)",
                dominant_qtype(ptrs[i]),
                (unsigned long long)ptrs[i]->query_count);
    }
    fflush(stdout);
    free(ptrs);
}

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
/**
 * @brief  Callback invoked by pending_expire() for each timed-out query.
 *
 * A query times out when it has been in the pending table for
 * query_timeout_sec seconds with no matching response. This indicates
 * the upstream DNS server did not respond — a network or server issue.
 *
 * Emits a [DNS_TIMEOUT] log line and increments g_stats.timeout.
 * The log line contains all the stored query information so analysts
 * know exactly which client, server, domain and record type timed out.
 *
 * This function is a expire_cb_t callback — it does NOT free the entry;
 * pending_expire() frees it after the callback returns.
 *
 * @param  e    The expired pending entry (client_ip, server_ip, qname, qtype)
 * @param  ctx  Unused (NULL passed from all callers)
 *
 * Example output:
 *   [DNS_TIMEOUT] ts=2026-07-17T06:30:15.000Z iface=brlan0
 *     client=10.0.0.58 server=75.75.75.75 txid=0x4f50
 *     qname=timeout-test.com qtype=A
 */
static void on_timeout(const pending_entry_t *e, void *ctx)
{
    (void)ctx;  /* ctx not used — suppress unused-parameter warning */
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
    for (int b = 0; b < CLIENT_HASH_BUCKETS; b++) {
        for (client_stat_t *c = g_clients[b]; c; c = c->next) {
            if (c->burst_count > peak_burst) {
                peak_burst = c->burst_count;
                strncpy(flood_client, c->ip, MAX_IP_STR - 1);
            }
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
    /* ── Degraded internet detection — three independent triggers ── */
    /* Minimum sample requirements prevent false alarms on sparse traffic */
    uint64_t timeout_pct = (g_stats.query_count > 0)
                         ? (g_stats.timeout * 100 / g_stats.query_count) : 0;

    /* Trigger 1: average latency too high (DNS server or path is congested)
     * Requires >= 5 successes to have a meaningful average */
    int high_latency  = (g_stats.success_count >= 5 &&
                         avg_ms  >= (uint64_t)g_cfg.degrade_avg_ms);

    /* Trigger 2: too many timeouts (DNS server unreachable or packet loss)
     * Requires >= 10 queries to have a meaningful percentage */
    int high_timeouts = (g_stats.query_count >= 10 &&
                         timeout_pct >= (uint64_t)g_cfg.degrade_to_pct);

    /* Trigger 3: DNS server returning SERVFAIL (upstream infrastructure issue)
     * Requires >= 5 queries; threshold is 20% SERVFAIL rate */
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

    /* Per-client query table — printed before main summary line */
    print_client_summary(iso_ts(&now_tv));

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
    /* Free all chained client entries, then zero the bucket pointers */
    for (int b = 0; b < CLIENT_HASH_BUCKETS; b++) {
        client_stat_t *c = g_clients[b];
        while (c) { client_stat_t *nx = c->next; free(c); c = nx; }
        g_clients[b] = NULL;
    }
    g_server_count   = 0;
    g_client_count   = 0;
    g_interval_start = now_tv.tv_sec;
}

/* ------------------------------------------------------------------ */
/* IP-address extraction helpers                                        */
/* ------------------------------------------------------------------ */
/**
 * @brief  Convert a 4-byte network-order IPv4 address to a dotted string.
 *
 * Wraps inet_ntop(AF_INET). Called during IPv4 header parsing in packet_cb.
 *
 * @param  addr_net  IPv4 address in network byte order (from ip4hdr_t.saddr)
 * @param  out       Output buffer, must be at least INET_ADDRSTRLEN (16) bytes
 * @param  len       Size of out buffer
 *
 * Example:
 *   ip4_to_str(0xFD4BAC49, buf, sizeof(buf)) -> "73.252.171.253" (XB8 WAN IP)
 *   ip4_to_str(0xFD4B4B4B, buf, sizeof(buf)) -> "75.75.75.75"    (Comcast DNS)
 */
static void ip4_to_str(uint32_t addr_net, char *out, size_t len)
{
    struct in_addr a;
    a.s_addr = addr_net;   /* no byte-swap needed — inet_ntop handles it */
    inet_ntop(AF_INET, &a, out, (socklen_t)len);
}

/**
 * @brief  Convert a 16-byte IPv6 address to a colon-hex string.
 *
 * Wraps inet_ntop(AF_INET6). Called during IPv6 header parsing in packet_cb.
 *
 * @param  addr16  16-byte IPv6 address array (from ip6hdr_t.src or .dst)
 * @param  out     Output buffer, must be at least INET6_ADDRSTRLEN (46) bytes
 * @param  len     Size of out buffer
 *
 * Example:
 *   ip6_to_str(ip6->src, buf, sizeof(buf))
 *   -> "2001:558:6045:12:987:cc98:4d57:5740"  (XB8 IPv6 client observed)
 *   -> "2001:558:feed::1"                      (Comcast IPv6 DNS)
 */
static void ip6_to_str(const uint8_t *addr16, char *out, size_t len)
{
    inet_ntop(AF_INET6, addr16, out, (socklen_t)len);
}

/* ------------------------------------------------------------------ */
/* Packet callback                                                       */
/* ------------------------------------------------------------------ */
typedef struct { int query_timeout_sec; } cb_args_t;

/**
 * @brief  libpcap packet callback — the heart of DnsMonitor.
 *
 * Registered via pcap_dispatch() and called for every UDP port-53 packet
 * that passes the BPF kernel filter. Performs full packet dissection and
 * routes each packet to either the query path or the response path.
 *
 * Packet dissection layers (each advances ptr and decrements rem):
 *   1. Ethernet header (14 bytes)  -> extract EtherType
 *   2. IPv4 or IPv6 header         -> extract src_ip, dst_ip, ip_proto
 *   3. UDP header (8 bytes)        -> extract sport, dport
 *   4. DNS header (12 bytes)       -> extract txid, QR bit, RCODE
 *   5. DNS question section        -> parse_qname(), extract QTYPE
 *
 * Direction determination:
 *   dport==53 -> query going OUT  (client=src_ip, server=dst_ip)
 *   sport==53 -> response coming IN (client=dst_ip, server=src_ip)
 *
 * Query path  (QR=0):
 *   - Increment g_stats.query_count
 *   - client_bump() -> flood detection
 *   - pending_insert() -> record timestamp for latency calculation
 *   - if verbose: print [DNS_QUERY]
 *
 * Response path (QR=1):
 *   - pending_remove() -> look up matching query
 *   - Compute latency_ms = response_ts - query_ts
 *   - if RCODE != 0: classify failure, server_bump_fail(), print [DNS_FAIL]
 *   - if RCODE == 0: update latency stats, print [DNS_RESP_OK] or [DNS_SLOW]
 *
 * @param  user    Pointer to cb_args_t { query_timeout_sec }.  Cast from u_char*.
 * @param  header  libpcap metadata: kernel timestamp (ts), captured length (caplen)
 * @param  packet  Raw packet bytes starting from Ethernet header. Read-only.
 *                 Valid only during this function call — do not store the pointer.
 */
static void packet_cb(u_char *user,
                      const struct pcap_pkthdr *header,
                      const u_char *packet)
{
    cb_args_t   *args = (cb_args_t *)user;  /* cast back from u_char* */
    const u_char *ptr = packet;              /* walking pointer through layers */
    int           rem = (int)header->caplen; /* remaining bytes — bounds guard */
    char src_ip[MAX_IP_STR] = {0};
    char dst_ip[MAX_IP_STR] = {0};
    char src_mac[18] = {0};   /* Ethernet source MAC: "aa:bb:cc:dd:ee:ff" */

    if (rem < ETH_HDR_LEN) return;

    /* Extract source MAC from Ethernet header (bytes 6-11) BEFORE advancing ptr.
     * For a query (dport==53): src_mac is the CLIENT's MAC address.
     * For a response (sport==53): src_mac is the DNS SERVER's MAC (less useful). */
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             ptr[6], ptr[7], ptr[8], ptr[9], ptr[10], ptr[11]);

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

    /* ── Layer 4: UDP header ──────────────────────────────────────── */
    if (rem < (int)sizeof(udphdr_t)) return;

    const udphdr_t *udp = (const udphdr_t *)ptr;
    uint16_t sport = ntohs(udp->sport);  /* source port (host byte order) */
    uint16_t dport = ntohs(udp->dport);  /* destination port */
    ptr += sizeof(udphdr_t); rem -= (int)sizeof(udphdr_t);

    /* BPF already filters udp port 53, but double-check direction:
     * A query has dport==53, a response has sport==53. */
    if (sport != DNS_PORT && dport != DNS_PORT) return;
    if (rem < (int)sizeof(dnshdr_t)) return;

    /* ── Layer 5: DNS header ─────────────────────────────────────── */
    const dnshdr_t *dns = (const dnshdr_t *)ptr;
    uint16_t txid  = ntohs(dns->id);     /* transaction ID (16-bit, chosen by client) */
    uint16_t flags = ntohs(dns->flags);  /* flags word: QR|opcode|AA|TC|RD|RA|Z|RCODE */

    /* QR bit (bit 15): 0 = query, 1 = response */
    int is_response = (flags & DNS_FLAG_QR) ? 1 : 0;

    /* RCODE (bits 0-3): 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED */
    int rcode = (int)(flags & DNS_FLAG_RCODE);

    /* ── Question section: QNAME + QTYPE ────────────────────────── */
    const uint8_t *dns_start = ptr;      /* start of DNS payload (from header) */
    int dns_len              = rem;
    int qoff                 = (int)sizeof(dnshdr_t); /* QNAME starts after 12-byte header */
    const char *qname_str    = "<unknown>";
    uint16_t    qtype        = 0;

    if (dns_len > qoff) {
        /* Decode wire-format name: \x03www\x06google\x03com\x00 -> "www.google.com" */
        qname_str = parse_qname(dns_start, dns_len, qoff);
        /* Walk the wire-format name to find QTYPE offset (2 bytes after the name) */
        int off = qoff;
        while (off < dns_len) {
            uint8_t lbl = dns_start[off];
            if (lbl == 0)             { off++; break; }       /* null terminator */
            if ((lbl & 0xC0) == 0xC0) { off += 2; break; }   /* pointer compression */
            off += 1 + lbl;           /* skip label: 1 byte length + lbl bytes data */
        }
        if (off + 2 <= dns_len)
            qtype = ntohs(*(const uint16_t *)(dns_start + off));
    }

    /* Use the kernel-captured packet timestamp (more accurate than gettimeofday) */
    struct timeval pkt_ts = header->ts;

    /* ── Pre-processing: expire stale queries ───────────────────── */
    /* Check for queries that have been waiting longer than query_timeout_sec.
     * Using packet timestamp (not wall clock) keeps time monotonic with traffic. */
    pending_expire(pkt_ts.tv_sec, args->query_timeout_sec, on_timeout, NULL);

    /* ── Direction: who is the client and who is the server? ─────── */
    /* For a query  (dport==53): client sent it  -> src=client, dst=server
     * For a response(sport==53): server sent it -> src=server, dst=client */
    const char *client_ip = (dport == DNS_PORT) ? src_ip : dst_ip;
    const char *server_ip = (dport == DNS_PORT) ? dst_ip : src_ip;

    if (!is_response)
    {
        /* ── Outgoing DNS query ── */
        g_stats.query_count++;

        /* Track per-client query count for flood detection.
         * Pass src_mac so the client table records the MAC on first query seen. */
        uint64_t burst_qps = client_bump(client_ip, src_mac, qtype);
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

        /* ── Latency calculation ─────────────────────────────────── */
        /* response_ts and query_ts are both kernel timestamps set at NIC
         * interrupt time, so the difference is true network round-trip time. */
        int64_t diff_sec   = (int64_t)pkt_ts.tv_sec  - (int64_t)e->query_ts.tv_sec;
        int64_t diff_usec  = (int64_t)pkt_ts.tv_usec - (int64_t)e->query_ts.tv_usec;
        /* Convert to milliseconds:
         * diff_sec*1000 handles the seconds part
         * diff_usec/1000 handles the microseconds part (may be negative if
         * usec wrapped across a second boundary, but diff_sec covers that) */
        int64_t latency_ms = diff_sec * 1000 + diff_usec / 1000;
        if (latency_ms < 0) latency_ms = 0;  /* guard: clock anomaly / wraparound */

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
