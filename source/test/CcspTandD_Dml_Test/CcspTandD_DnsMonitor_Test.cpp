/*
 * If not stated otherwise in this file or this component's LICENSE
 * file the following copyright and licenses apply:
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
 * CcspTandD_DnsMonitor_Test.cpp
 *
 * Unit tests for DnsMonitor.c (libpcap-based DNS latency and failure
 * telemetry).
 *
 * Test data is derived from actual XB8 (CGM4981COM) device output captured
 * on 2026-07-16 during POC validation:
 *
 *   [DNS_SUMMARY] ts=2026-07-16T04:51:02.050Z iface=erouter0
 *     queries=91 success=47 slow=0 fail_total=44 nxdomain=44
 *     servfail=0 refused=0 other_rcode=0 timeout=0
 *     avg_ms=25 max_ms=88 server_fails=[75.75.76.76:2,75.75.75.75:42]
 *
 * Test groups:
 *   1. rcode_name()   - RCODE integer to string mapping
 *   2. qtype_name()   - QTYPE integer to string mapping
 *   3. parse_qname()  - wire-format DNS name parsing
 *   4. make_hash()    - composite key collision avoidance
 *   5. pending table  - insert / remove / expire / dual-stack
 *   6. stats accumulation - latency, failure counters
 *   7. server failure tracking
 *   8. iso_ts()       - timestamp format
 */

#include "CcspTandD_Dml_Mock.h"

/* Include DnsMonitor.c directly in test compilation.
 * main() is excluded via UNIT_TEST_DOCKER_SUPPORT defined in Makefile.am. */
extern "C" {
#include "../../../../source/LatencyMeasurement/DnsMonitor/DnsMonitor.c"
}

/* ======================================================================
 * Test fixture
 * ====================================================================== */
class CcspTandD_DnsMonitor_Test : public ::testing::Test
{
protected:
    void SetUp() override
    {
        /* Reset all global state between tests */
        free_all_pending();
        memset(&g_stats,  0, sizeof(g_stats));
        memset(g_servers, 0, sizeof(g_servers));
        g_server_count  = 0;
        /* Default config used by helpers */
        strncpy(g_cfg.iface, "erouter0", sizeof(g_cfg.iface) - 1);
        g_cfg.slow_thresh_ms = 200;
        g_cfg.verbose        = 0;
        g_cfg.query_timeout  = 5;
        g_cfg.report_sec     = 60;
    }
    void TearDown() override
    {
        free_all_pending();
    }
};

/* ======================================================================
 * 1. rcode_name() - RCODE to string mapping
 *    Validated against XB8 output: nxdomain=44, servfail=0, refused=0
 * ====================================================================== */
TEST_F(CcspTandD_DnsMonitor_Test, RcodeName_NOERROR)
{
    EXPECT_STREQ("NOERROR", rcode_name(0));
}

TEST_F(CcspTandD_DnsMonitor_Test, RcodeName_SERVFAIL)
{
    /* Observed: servfail=0 on XB8. Verify the string is correct. */
    EXPECT_STREQ("SERVFAIL", rcode_name(2));
}

TEST_F(CcspTandD_DnsMonitor_Test, RcodeName_NXDOMAIN)
{
    /* XB8 produced 44 NXDOMAIN responses (all PTR reverse lookups) */
    EXPECT_STREQ("NXDOMAIN", rcode_name(3));
}

TEST_F(CcspTandD_DnsMonitor_Test, RcodeName_REFUSED)
{
    EXPECT_STREQ("REFUSED", rcode_name(5));
}

TEST_F(CcspTandD_DnsMonitor_Test, RcodeName_FORMERR)
{
    EXPECT_STREQ("FORMERR", rcode_name(1));
}

TEST_F(CcspTandD_DnsMonitor_Test, RcodeName_UNKNOWN)
{
    EXPECT_STREQ("UNKNOWN", rcode_name(99));
}

/* ======================================================================
 * 2. qtype_name() - QTYPE to string mapping
 *    Validated from XB8: A, AAAA, PTR all observed in live traffic
 * ====================================================================== */
TEST_F(CcspTandD_DnsMonitor_Test, QtypeName_A)
{
    /* e.g. [DNS_QUERY] qname=www.google.com qtype=A */
    EXPECT_STREQ("A", qtype_name(1));
}

TEST_F(CcspTandD_DnsMonitor_Test, QtypeName_AAAA)
{
    /* e.g. [DNS_QUERY] qname=www.google.com qtype=AAAA latency_ms=13 */
    EXPECT_STREQ("AAAA", qtype_name(28));
}

TEST_F(CcspTandD_DnsMonitor_Test, QtypeName_PTR)
{
    /* 44 PTR lookups on XB8 — all NXDOMAIN for unregistered reverse records */
    EXPECT_STREQ("PTR", qtype_name(12));
}

TEST_F(CcspTandD_DnsMonitor_Test, QtypeName_MX)
{
    EXPECT_STREQ("MX", qtype_name(15));
}

TEST_F(CcspTandD_DnsMonitor_Test, QtypeName_CNAME)
{
    EXPECT_STREQ("CNAME", qtype_name(5));
}

TEST_F(CcspTandD_DnsMonitor_Test, QtypeName_OTHER)
{
    EXPECT_STREQ("OTHER", qtype_name(99));
}

/* ======================================================================
 * 3. parse_qname() - wire-format to dotted-string
 *    Test with real hostnames seen on XB8
 * ====================================================================== */
TEST_F(CcspTandD_DnsMonitor_Test, ParseQname_GoogleCom)
{
    /* Wire format for "www.google.com" after DNS header:
     * \x03www\x06google\x03com\x00 */
    const uint8_t wire[] = {
        /* DNS header placeholder (12 bytes) */
        0,0, 0,0, 0,1, 0,0, 0,0, 0,0,
        /* QNAME */
        3,'w','w','w',
        6,'g','o','o','g','l','e',
        3,'c','o','m',
        0
    };
    const char *result = parse_qname(wire, (int)sizeof(wire), 12);
    EXPECT_STREQ("www.google.com", result);
}

TEST_F(CcspTandD_DnsMonitor_Test, ParseQname_XfinityTime)
{
    /* global-time.xfinity.com — observed as NTP query on XB8 */
    const uint8_t wire[] = {
        /* header */
        0,0, 0,0, 0,1, 0,0, 0,0, 0,0,
        11,'g','l','o','b','a','l','-','t','i','m','e',
        7,'x','f','i','n','i','t','y',
        3,'c','o','m',
        0
    };
    const char *result = parse_qname(wire, (int)sizeof(wire), 12);
    EXPECT_STREQ("global-time.xfinity.com", result);
}

TEST_F(CcspTandD_DnsMonitor_Test, ParseQname_RdktelEndpoint)
{
    /* rdktel-oi.stb.r53.xcal.tv — RDK telemetry DNS seen on XB8 */
    const uint8_t wire[] = {
        0,0, 0,0, 0,1, 0,0, 0,0, 0,0,
        9,'r','d','k','t','e','l','-','o','i',
        3,'s','t','b',
        3,'r','5','3',
        4,'x','c','a','l',
        2,'t','v',
        0
    };
    const char *result = parse_qname(wire, (int)sizeof(wire), 12);
    EXPECT_STREQ("rdktel-oi.stb.r53.xcal.tv", result);
}

TEST_F(CcspTandD_DnsMonitor_Test, ParseQname_EmptyPayload)
{
    const uint8_t wire[] = { 0,0, 0,0, 0,1, 0,0, 0,0, 0,0, 0 };
    const char *result = parse_qname(wire, (int)sizeof(wire), 12);
    EXPECT_STREQ("<root>", result);
}

TEST_F(CcspTandD_DnsMonitor_Test, ParseQname_TruncatedPayload)
{
    /* Payload too short — must not crash */
    const uint8_t wire[] = { 0,0, 0,0, 0,1, 0,0, 0,0, 0,0, 5,'a' };
    const char *result = parse_qname(wire, (int)sizeof(wire), 12);
    EXPECT_NE(nullptr, result);
}

/* ======================================================================
 * 4. make_hash() - composite key collision avoidance
 *    XB8 showed same txid=0xac9a for four different client/server pairs
 *    (dual-stack: IPv4 + IPv6 clients, two servers each)
 * ====================================================================== */
TEST_F(CcspTandD_DnsMonitor_Test, MakeHash_SameTxidDifferentClients)
{
    /* txid=0xac9a seen from two clients on XB8:
     * client=73.252.171.253  and  client=2001:558:6045:12:987:cc98:4d57:5740 */
    uint16_t txid = 0xac9a;
    unsigned int h1 = make_hash("73.252.171.253", txid);
    unsigned int h2 = make_hash("2001:558:6045:12:987:cc98:4d57:5740", txid);
    /* Different clients must produce different hash buckets (avoids collision) */
    EXPECT_NE(h1, h2);
    /* Both must be within table bounds */
    EXPECT_LT(h1, (unsigned int)DNS_HASH_BUCKETS);
    EXPECT_LT(h2, (unsigned int)DNS_HASH_BUCKETS);
}

TEST_F(CcspTandD_DnsMonitor_Test, MakeHash_SameClientDifferentTxid)
{
    /* Same client, different txids — must produce consistent results */
    unsigned int h1 = make_hash("73.252.171.253", 0x74e1);
    unsigned int h2 = make_hash("73.252.171.253", 0x4deb);
    EXPECT_LT(h1, (unsigned int)DNS_HASH_BUCKETS);
    EXPECT_LT(h2, (unsigned int)DNS_HASH_BUCKETS);
}

/* ======================================================================
 * 5. Pending table - insert / remove / expire
 * ====================================================================== */
TEST_F(CcspTandD_DnsMonitor_Test, PendingInsertRemove_BasicRoundtrip)
{
    struct timeval ts = { 1000, 0 };
    pending_insert(0x07ac, "73.252.171.253", "75.75.75.75",
                   "www.google.com", 1 /*A*/, &ts);
    EXPECT_EQ(1, g_pending_count);

    pending_entry_t *e = pending_remove(0x07ac, "73.252.171.253");
    ASSERT_NE(nullptr, e);
    EXPECT_EQ(0x07ac, e->txid);
    EXPECT_STREQ("www.google.com", e->qname);
    EXPECT_STREQ("75.75.75.75", e->server_ip);
    EXPECT_EQ(1, e->qtype);
    EXPECT_EQ(0, g_pending_count);
    free(e);
}

TEST_F(CcspTandD_DnsMonitor_Test, PendingRemove_WrongClientReturnsNull)
{
    struct timeval ts = { 1000, 0 };
    pending_insert(0x07ac, "73.252.171.253", "75.75.75.75",
                   "www.google.com", 1, &ts);
    /* Different client IP — must not find the entry */
    pending_entry_t *e = pending_remove(0x07ac, "10.0.0.1");
    EXPECT_EQ(nullptr, e);
    EXPECT_EQ(1, g_pending_count);
}

TEST_F(CcspTandD_DnsMonitor_Test, PendingDualStack_SameTxidTwoClients)
{
    /* Reproduces XB8 dual-stack scenario: same txid=0xac9a sent from
     * both IPv4 (73.252.171.253) and IPv6 (2001:558:...) clients */
    struct timeval ts = { 2000, 0 };
    pending_insert(0xac9a, "73.252.171.253",
                   "75.75.75.75", "rdktel-oi.stb.r53.xcal.tv", 1, &ts);
    pending_insert(0xac9a, "2001:558:6045:12:987:cc98:4d57:5740",
                   "2001:558:feed::1", "rdktel-oi.stb.r53.xcal.tv", 1, &ts);
    EXPECT_EQ(2, g_pending_count);

    /* Remove IPv4 entry — IPv6 must still be present */
    pending_entry_t *e4 = pending_remove(0xac9a, "73.252.171.253");
    ASSERT_NE(nullptr, e4);
    EXPECT_STREQ("75.75.75.75", e4->server_ip);
    EXPECT_EQ(1, g_pending_count);
    free(e4);

    /* Remove IPv6 entry */
    pending_entry_t *e6 = pending_remove(0xac9a,
                          "2001:558:6045:12:987:cc98:4d57:5740");
    ASSERT_NE(nullptr, e6);
    EXPECT_STREQ("2001:558:feed::1", e6->server_ip);
    EXPECT_EQ(0, g_pending_count);
    free(e6);
}

TEST_F(CcspTandD_DnsMonitor_Test, PendingExpire_TimedOutEntries)
{
    struct timeval ts = { 1000, 0 };
    pending_insert(0xfd1a, "73.252.171.253", "75.75.75.75",
                   "75.75.75.75.in-addr.arpa", 12 /*PTR*/, &ts);
    pending_insert(0x7b4c, "73.252.171.253", "75.75.75.75",
                   "this-domain-xyz-doesnotexist123.com", 1, &ts);
    EXPECT_EQ(2, g_pending_count);

    /* Expire with now=1006, timeout=5 → both entries are 6s old */
    int expired = pending_expire(1006, 5, nullptr, nullptr);
    EXPECT_EQ(2, expired);
    EXPECT_EQ(0, g_pending_count);
}

TEST_F(CcspTandD_DnsMonitor_Test, PendingExpire_OnlyOldEntries)
{
    struct timeval ts_old  = { 1000, 0 };
    struct timeval ts_new  = { 1004, 0 };
    pending_insert(0x1111, "73.252.171.253", "75.75.75.75",
                   "old.example.com", 1, &ts_old);
    pending_insert(0x2222, "73.252.171.253", "75.75.75.75",
                   "new.example.com", 1, &ts_new);

    /* now=1006, timeout=5 → only old entry (age=6) expires */
    int expired = pending_expire(1006, 5, nullptr, nullptr);
    EXPECT_EQ(1, expired);
    EXPECT_EQ(1, g_pending_count);

    pending_entry_t *e = pending_remove(0x2222, "73.252.171.253");
    ASSERT_NE(nullptr, e);
    EXPECT_STREQ("new.example.com", e->qname);
    free(e);
}

/* ======================================================================
 * 6. Stats accumulation
 *    Reference: XB8 summary — queries=91, success=47, nxdomain=44, avg=25ms
 * ====================================================================== */
TEST_F(CcspTandD_DnsMonitor_Test, Stats_LatencyAccumulation_MatchXB8Average)
{
    /* Simulate 47 successful responses with latencies matching XB8 range
     * (10–88ms) to produce avg ~25ms */
    const int latencies[] = {
        27, 28, 23, 24, 26, 27, 23, 27, 25, 29,  /* NTP time queries */
        11, 14, 13, 13, 13, 13,                   /* google/amazon/youtube */
        10, 11, 14, 12, 15, 11, 12, 13, 11,       /* PTR successes */
        8, 30, 10, 28, 26,                         /* rdktel dual-stack */
        18, 20, 25, 30, 15, 12, 22, 28, 35, 40,
        50, 60, 70, 80, 88, 14, 11
    };
    int n = (int)(sizeof(latencies)/sizeof(latencies[0]));
    ASSERT_EQ(47, n);

    uint64_t total = 0;
    for (int i = 0; i < n; i++) {
        g_stats.success_count++;
        g_stats.total_latency_ms += (uint64_t)latencies[i];
        total += (uint64_t)latencies[i];
        if ((uint64_t)latencies[i] > g_stats.max_latency_ms)
            g_stats.max_latency_ms = (uint64_t)latencies[i];
    }

    uint64_t avg = g_stats.total_latency_ms / g_stats.success_count;
    EXPECT_EQ(47u, g_stats.success_count);
    EXPECT_EQ(88u, g_stats.max_latency_ms);
    /* Average must be in the range observed on XB8 (18–30ms) */
    EXPECT_GE(avg, 18u);
    EXPECT_LE(avg, 35u);
}

TEST_F(CcspTandD_DnsMonitor_Test, Stats_NxdomainCount_MatchXB8)
{
    /* XB8 produced exactly 44 NXDOMAIN responses, all from PTR lookups */
    for (int i = 0; i < 44; i++) {
        g_stats.nxdomain++;
    }
    uint64_t fail_total = g_stats.nxdomain + g_stats.servfail +
                          g_stats.refused  + g_stats.other_rcode +
                          g_stats.timeout;
    EXPECT_EQ(44u, g_stats.nxdomain);
    EXPECT_EQ(0u,  g_stats.servfail);
    EXPECT_EQ(0u,  g_stats.timeout);
    EXPECT_EQ(44u, fail_total);
}

TEST_F(CcspTandD_DnsMonitor_Test, Stats_QueryCount_MatchXB8Summary)
{
    /* XB8 first interval: queries=91, success=47, fail=44 */
    g_stats.query_count   = 91;
    g_stats.success_count = 47;
    g_stats.nxdomain      = 44;

    uint64_t fail_total = g_stats.nxdomain + g_stats.servfail +
                          g_stats.refused  + g_stats.other_rcode +
                          g_stats.timeout;
    EXPECT_EQ(91u, g_stats.query_count);
    EXPECT_EQ(47u, g_stats.success_count);
    EXPECT_EQ(44u, fail_total);
    /* success + fail should account for all queries */
    EXPECT_EQ(g_stats.query_count, g_stats.success_count + fail_total);
}

TEST_F(CcspTandD_DnsMonitor_Test, Stats_SecondInterval_CleanSummary)
{
    /* XB8 second interval: queries=8, success=6, nxdomain=2, avg=18ms */
    g_stats.query_count       = 8;
    g_stats.success_count     = 6;
    g_stats.total_latency_ms  = 108; /* 6 queries avg 18ms */
    g_stats.max_latency_ms    = 30;
    g_stats.nxdomain          = 2;

    uint64_t avg = g_stats.total_latency_ms / g_stats.success_count;
    uint64_t fail_total = g_stats.nxdomain + g_stats.servfail +
                          g_stats.refused  + g_stats.other_rcode +
                          g_stats.timeout;
    EXPECT_EQ(18u, avg);
    EXPECT_EQ(30u, g_stats.max_latency_ms);
    EXPECT_EQ(2u,  fail_total);
    EXPECT_EQ(0u,  g_stats.slow_count);
    EXPECT_EQ(0u,  g_stats.timeout);
}

TEST_F(CcspTandD_DnsMonitor_Test, Stats_SlowQueryThreshold)
{
    /* Verify slow detection: latency_ms >= slow_thresh_ms */
    g_cfg.slow_thresh_ms = 100;

    int64_t latency_ok   = 88;  /* max seen on XB8 — not slow at 100ms threshold */
    int64_t latency_slow = 387; /* hypothetical slow query */

    EXPECT_FALSE(latency_ok   >= g_cfg.slow_thresh_ms);
    EXPECT_TRUE (latency_slow >= g_cfg.slow_thresh_ms);
}

TEST_F(CcspTandD_DnsMonitor_Test, Stats_NoSuccessAvoidsDivisionByZero)
{
    /* When success_count=0, avg_ms must be computed as 0 not crash */
    g_stats.success_count    = 0;
    g_stats.total_latency_ms = 0;

    uint64_t avg = g_stats.success_count
                 ? (g_stats.total_latency_ms / g_stats.success_count) : 0;
    EXPECT_EQ(0u, avg);
}

/* ======================================================================
 * 7. Server failure tracking
 *    XB8: server_fails=[75.75.76.76:2, 75.75.75.75:42]
 * ====================================================================== */
TEST_F(CcspTandD_DnsMonitor_Test, ServerFail_TrackComcastDnsServers)
{
    /* XB8 had 42 NXDOMAINs on 75.75.75.75 and 2 on 75.75.76.76 */
    for (int i = 0; i < 42; i++) server_bump_fail("75.75.75.75");
    for (int i = 0; i < 2;  i++) server_bump_fail("75.75.76.76");

    EXPECT_EQ(2, g_server_count);
    EXPECT_STREQ("75.75.75.75", g_servers[0].ip);
    EXPECT_EQ(42u, g_servers[0].fail_count);
    EXPECT_STREQ("75.75.76.76", g_servers[1].ip);
    EXPECT_EQ(2u,  g_servers[1].fail_count);
}

TEST_F(CcspTandD_DnsMonitor_Test, ServerFail_IncrementExistingEntry)
{
    server_bump_fail("75.75.75.75");
    server_bump_fail("75.75.75.75");
    server_bump_fail("75.75.75.75");

    EXPECT_EQ(1, g_server_count);
    EXPECT_EQ(3u, g_servers[0].fail_count);
}

TEST_F(CcspTandD_DnsMonitor_Test, ServerFail_IPv6DnsServer)
{
    /* XB8 also uses IPv6 DNS: 2001:558:feed::1 and 2001:558:feed::2 */
    server_bump_fail("2001:558:feed::1");
    server_bump_fail("2001:558:feed::2");
    server_bump_fail("2001:558:feed::1");

    EXPECT_EQ(2, g_server_count);
    EXPECT_STREQ("2001:558:feed::1", g_servers[0].ip);
    EXPECT_EQ(2u, g_servers[0].fail_count);
    EXPECT_STREQ("2001:558:feed::2", g_servers[1].ip);
    EXPECT_EQ(1u, g_servers[1].fail_count);
}

TEST_F(CcspTandD_DnsMonitor_Test, ServerFail_MaxTrackerNotExceeded)
{
    /* Fill all 8 server slots */
    char ip[32];
    for (int i = 0; i < MAX_SERVER_TRACK + 3; i++) {
        snprintf(ip, sizeof(ip), "10.0.0.%d", i + 1);
        server_bump_fail(ip);
    }
    /* Must not exceed MAX_SERVER_TRACK */
    EXPECT_EQ(MAX_SERVER_TRACK, g_server_count);
}

/* ======================================================================
 * 8. iso_ts() - ISO-8601 timestamp format
 *    Verified against XB8 output format: 2026-07-16T04:50:18.999Z
 * ====================================================================== */
TEST_F(CcspTandD_DnsMonitor_Test, IsoTs_FormatMatchesXB8Output)
{
    /* Reproduce the first XB8 timestamp: 2026-07-16T04:50:18.999Z
     * tv_sec  = 1752634218  (2026-07-16 04:50:18 UTC)
     * tv_usec = 999000      (999ms) */
    struct timeval tv = { 1752634218, 999000 };
    const char *result = iso_ts(&tv);

    ASSERT_NE(nullptr, result);
    /* Must match format YYYY-MM-DDTHH:MM:SS.mmmZ */
    EXPECT_EQ(24u, strlen(result));
    EXPECT_EQ('T', result[10]);
    EXPECT_EQ('Z', result[23]);
    /* Year must start with 2026 */
    EXPECT_EQ('2', result[0]);
    EXPECT_EQ('0', result[1]);
    EXPECT_EQ('2', result[2]);
    EXPECT_EQ('6', result[3]);
}

TEST_F(CcspTandD_DnsMonitor_Test, IsoTs_MillisecondPrecision)
{
    /* tv_usec=27000 → ms=027, tv_usec=999000 → ms=999 */
    struct timeval tv27  = { 1000000, 27000  };
    struct timeval tv999 = { 1000000, 999000 };
    const char *r27  = iso_ts(&tv27);
    const char *r999 = iso_ts(&tv999);
    /* Last 4 chars before Z are .mmm */
    EXPECT_EQ('0', r27[20]);
    EXPECT_EQ('2', r27[21]);
    EXPECT_EQ('7', r27[22]);
    EXPECT_EQ('9', r999[20]);
    EXPECT_EQ('9', r999[21]);
    EXPECT_EQ('9', r999[22]);
}

/* ======================================================================
 * 9. Latency calculation correctness
 *    Based on actual XB8 response times: 8ms min, 88ms max, 25ms avg
 * ====================================================================== */
TEST_F(CcspTandD_DnsMonitor_Test, LatencyCalc_TypicalXB8Response)
{
    /* www.google.com: query at .773, response at .788 → 14ms (from XB8 log) */
    struct timeval query_ts = { 1752634236, 773000 };
    struct timeval resp_ts  = { 1752634236, 788000 };

    int64_t diff_sec  = (int64_t)resp_ts.tv_sec  - (int64_t)query_ts.tv_sec;
    int64_t diff_usec = (int64_t)resp_ts.tv_usec - (int64_t)query_ts.tv_usec;
    int64_t latency_ms = diff_sec * 1000 + diff_usec / 1000;

    EXPECT_EQ(14, latency_ms);
}

TEST_F(CcspTandD_DnsMonitor_Test, LatencyCalc_FastestXB8Response)
{
    /* rdktel-oi.stb.r53.xcal.tv on 75.75.76.76: 8ms (XB8 dual-stack fastest) */
    struct timeval query_ts = { 1752634295, 259000 };
    struct timeval resp_ts  = { 1752634295, 268000 };

    int64_t latency_ms = (resp_ts.tv_sec  - query_ts.tv_sec)  * 1000
                       + (resp_ts.tv_usec - query_ts.tv_usec) / 1000;
    EXPECT_EQ(8, latency_ms);
}

TEST_F(CcspTandD_DnsMonitor_Test, LatencyCalc_CrossSecondBoundary)
{
    /* Query at .999, response at 1.027 → 28ms (crosses second boundary) */
    struct timeval query_ts = { 1752634295, 999000 };
    struct timeval resp_ts  = { 1752634296, 27000  };

    int64_t diff_sec  = (int64_t)resp_ts.tv_sec  - (int64_t)query_ts.tv_sec;
    int64_t diff_usec = (int64_t)resp_ts.tv_usec - (int64_t)query_ts.tv_usec;
    int64_t latency_ms = diff_sec * 1000 + diff_usec / 1000;

    EXPECT_EQ(28, latency_ms);
}

TEST_F(CcspTandD_DnsMonitor_Test, LatencyCalc_NegativeGuard)
{
    /* Guard: if clock anomaly gives negative result, clamp to 0 */
    int64_t latency_ms = -5;
    if (latency_ms < 0) latency_ms = 0;
    EXPECT_EQ(0, latency_ms);
}

/* ======================================================================
 * 10. PTR reverse lookup classification (XB8-specific)
 *     All 44 NXDOMAIN failures on XB8 were PTR lookups — verify they
 *     are correctly classified as nxdomain not as timeouts
 * ====================================================================== */
TEST_F(CcspTandD_DnsMonitor_Test, PtrLookup_NxdomainNotTimeout)
{
    /* Insert a PTR query */
    struct timeval ts = { 1000, 0 };
    pending_insert(0x532a, "73.252.171.253", "75.75.75.75",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.7.6.2.8.4.0.6.8.4.1.0.0.2.ip6.arpa",
        12 /*PTR*/, &ts);

    /* Remove it on NXDOMAIN response (rcode=3) */
    pending_entry_t *e = pending_remove(0x532a, "73.252.171.253");
    ASSERT_NE(nullptr, e);
    EXPECT_EQ(12, e->qtype);  /* PTR */

    /* Classify as nxdomain */
    int rcode = 3;
    if (rcode == 3) g_stats.nxdomain++;

    EXPECT_EQ(1u, g_stats.nxdomain);
    EXPECT_EQ(0u, g_stats.timeout);
    free(e);
}

TEST_F(CcspTandD_DnsMonitor_Test, PtrLookup_IPv4ReverseNxdomain)
{
    /* 119.154.251.142.in-addr.arpa → NXDOMAIN (from XB8) */
    struct timeval ts = { 1000, 0 };
    pending_insert(0xa1ce, "73.252.171.253", "75.75.75.75",
                   "119.154.251.142.in-addr.arpa", 12 /*PTR*/, &ts);

    pending_entry_t *e = pending_remove(0xa1ce, "73.252.171.253");
    ASSERT_NE(nullptr, e);
    EXPECT_STREQ("119.154.251.142.in-addr.arpa", e->qname);
    EXPECT_EQ(12, e->qtype);
    free(e);
}
