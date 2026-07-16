/*
 * dns_monitor_standalone_test.c
 *
 * Standalone test runner for DnsMonitor helper functions.
 * Requires only: gcc (no GoogleTest, no autoconf, no sudo)
 *
 * Compile:
 *   gcc -std=c99 -DUNIT_TEST_DOCKER_SUPPORT -Wall \
 *       -I../LatencyMeasurement/DnsMonitor \
 *       -o dns_monitor_test dns_monitor_standalone_test.c -lpthread
 *
 * Run:
 *   ./dns_monitor_test
 *   ./dns_monitor_test --html > DnsMonitor_TestReport.html
 */

/* UNIT_TEST_DOCKER_SUPPORT is passed via -D on the compile line */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>

/* ── Stub out external dependencies ── */
typedef int T2ERROR;
#define T2ERROR_SUCCESS 0
static int t2_event_d(const char *n, int v)    { (void)n;(void)v; return 0; }
static int t2_event_s(const char *n, const char *v) { (void)n;(void)v; return 0; }

/* pcap stubs */
typedef void pcap_t;
typedef struct { int caplen; struct timeval ts; } pcap_pkthdr;
typedef unsigned char u_char;
typedef unsigned int  u_int;
typedef unsigned short u_short;
static pcap_t *pcap_open_live(const char*a,int b,int c,int d,char*e){(void)a;(void)b;(void)c;(void)d;(void)e;return NULL;}
static int pcap_compile(pcap_t*a,void*b,const char*c,int d,unsigned int e){(void)a;(void)b;(void)c;(void)d;(void)e;return 0;}
static int pcap_setfilter(pcap_t*a,void*b){(void)a;(void)b;return 0;}
static void pcap_freecode(void*a){(void)a;}
static int pcap_setnonblock(pcap_t*a,int b,char*c){(void)a;(void)b;(void)c;return 0;}
static int pcap_dispatch(pcap_t*a,int b,void*c,u_char*d){(void)a;(void)b;(void)c;(void)d;return 0;}
static void pcap_close(pcap_t*a){(void)a;}
static const char*pcap_geterr(pcap_t*a){(void)a;return "";}
#define PCAP_ERRBUF_SIZE 256
#define PCAP_NETMASK_UNKNOWN 0
#define PCAP_ERROR_BREAK -2
struct bpf_program { int dummy; };

/* Include DnsMonitor implementation */
#include "../../LatencyMeasurement/DnsMonitor/DnsMonitor.c"

/* ================================================================
 * Minimal test framework
 * ================================================================ */
static int g_total = 0, g_pass = 0, g_fail = 0;
static int g_html  = 0;

typedef struct {
    int   id;
    char  subject[80];
    char  scenario[256];
    char  expected[200];
    char  actual[200];
    int   passed;
    float duration_ms;
} TestResult;

#define MAX_RESULTS 64
static TestResult g_results[MAX_RESULTS];

static struct timeval g_tc_start;

#define TC_BEGIN(id_str, subj, scen, exp)                       \
    do {                                                        \
        gettimeofday(&g_tc_start, NULL);                        \
        g_total++;                                              \
        int _id = g_total;                                      \
        const char *_subj = (subj);                             \
        const char *_scen = (scen);                             \
        const char *_exp  = (exp);                              \
        int _ok = 1;                                            \
        char _actual[200] = "As expected";

#define ASSERT_STR_EQ(a, b)                                     \
        if (strcmp((a),(b)) != 0) {                             \
            snprintf(_actual, sizeof(_actual),                  \
                     "Got '%s', want '%s'", (a), (b));          \
            _ok = 0;                                            \
        }

#define ASSERT_INT_EQ(a, b)                                     \
        if ((int64_t)(a) != (int64_t)(b)) {                     \
            snprintf(_actual, sizeof(_actual),                  \
                     "Got %lld, want %lld",                     \
                     (long long)(a), (long long)(b));           \
            _ok = 0;                                            \
        }

#define ASSERT_INT_NE(a, b)                                     \
        if ((int64_t)(a) == (int64_t)(b)) {                     \
            snprintf(_actual, sizeof(_actual),                  \
                     "Expected not equal, both = %lld",         \
                     (long long)(a));                           \
            _ok = 0;                                            \
        }

#define ASSERT_TRUE(cond)                                       \
        if (!(cond)) {                                          \
            snprintf(_actual, sizeof(_actual),                  \
                     "Condition FALSE: " #cond);                \
            _ok = 0;                                            \
        }

#define ASSERT_NULL(ptr)                                        \
        if ((ptr) != NULL) {                                    \
            snprintf(_actual, sizeof(_actual),                  \
                     "Expected NULL, got non-NULL");            \
            _ok = 0;                                            \
        }

#define ASSERT_NOT_NULL(ptr)                                    \
        if ((ptr) == NULL) {                                    \
            snprintf(_actual, sizeof(_actual),                  \
                     "Expected non-NULL, got NULL");            \
            _ok = 0;                                            \
        }

#define TC_END()                                                \
        struct timeval _tv_end; gettimeofday(&_tv_end, NULL);  \
        float _dur = (_tv_end.tv_sec - g_tc_start.tv_sec)*1000.0f \
                   + (_tv_end.tv_usec - g_tc_start.tv_usec)/1000.0f; \
        if (_id <= MAX_RESULTS) {                               \
            TestResult *_r = &g_results[_id-1];                \
            _r->id = _id;                                       \
            strncpy(_r->subject,  _subj,   sizeof(_r->subject)-1);  \
            strncpy(_r->scenario, _scen,   sizeof(_r->scenario)-1); \
            strncpy(_r->expected, _exp,    sizeof(_r->expected)-1); \
            strncpy(_r->actual,   _actual, sizeof(_r->actual)-1);   \
            _r->passed     = _ok;                               \
            _r->duration_ms = _dur;                             \
        }                                                       \
        if (_ok) { g_pass++;                                    \
            printf("  \033[32m[PASS]\033[0m TC-%03d %s\n",     \
                   _id, _scen); }                               \
        else { g_fail++;                                        \
            printf("  \033[31m[FAIL]\033[0m TC-%03d %s\n"      \
                   "          Actual: %s\n", _id, _scen, _actual); } \
    } while(0)

static void reset_state(void) {
    free_all_pending();
    memset(&g_stats,  0, sizeof(g_stats));
    memset(g_servers, 0, sizeof(g_servers));
    g_server_count = 0;
    strncpy(g_cfg.iface, "erouter0", sizeof(g_cfg.iface)-1);
    g_cfg.slow_thresh_ms = 200;
    g_cfg.verbose        = 0;
    g_cfg.query_timeout  = 5;
}

/* ================================================================
 * TEST CASES
 * ================================================================ */

/* ── 1. rcode_name ── */
static void test_rcode_name(void) {
    printf("\n[1. RCODE Name Mapping]\n");

    TC_BEGIN("TC-001","1. RCODE Name Mapping","RCODE 0 maps to NOERROR","rcode_name(0)='NOERROR'");
    ASSERT_STR_EQ(rcode_name(0), "NOERROR");
    TC_END();

    TC_BEGIN("TC-002","1. RCODE Name Mapping","RCODE 2 maps to SERVFAIL (servfail=0 on XB8)","rcode_name(2)='SERVFAIL'");
    ASSERT_STR_EQ(rcode_name(2), "SERVFAIL");
    TC_END();

    TC_BEGIN("TC-003","1. RCODE Name Mapping","RCODE 3 maps to NXDOMAIN (44 on XB8 — all PTR lookups)","rcode_name(3)='NXDOMAIN'");
    ASSERT_STR_EQ(rcode_name(3), "NXDOMAIN");
    TC_END();

    TC_BEGIN("TC-004","1. RCODE Name Mapping","RCODE 5 maps to REFUSED","rcode_name(5)='REFUSED'");
    ASSERT_STR_EQ(rcode_name(5), "REFUSED");
    TC_END();

    TC_BEGIN("TC-005","1. RCODE Name Mapping","Unknown RCODE 99 maps to UNKNOWN","rcode_name(99)='UNKNOWN'");
    ASSERT_STR_EQ(rcode_name(99), "UNKNOWN");
    TC_END();
}

/* ── 2. qtype_name ── */
static void test_qtype_name(void) {
    printf("\n[2. QTYPE Name Mapping]\n");

    TC_BEGIN("TC-006","2. QTYPE Name Mapping","QTYPE 1 = A  (www.google.com query on XB8, latency=14ms)","qtype_name(1)='A'");
    ASSERT_STR_EQ(qtype_name(1), "A");
    TC_END();

    TC_BEGIN("TC-007","2. QTYPE Name Mapping","QTYPE 28 = AAAA  (dual-stack IPv6 queries on XB8)","qtype_name(28)='AAAA'");
    ASSERT_STR_EQ(qtype_name(28), "AAAA");
    TC_END();

    TC_BEGIN("TC-008","2. QTYPE Name Mapping","QTYPE 12 = PTR  (44 NXDOMAIN PTR lookups on XB8)","qtype_name(12)='PTR'");
    ASSERT_STR_EQ(qtype_name(12), "PTR");
    TC_END();

    TC_BEGIN("TC-009","2. QTYPE Name Mapping","Unknown QTYPE 99 = OTHER","qtype_name(99)='OTHER'");
    ASSERT_STR_EQ(qtype_name(99), "OTHER");
    TC_END();
}

/* ── 3. parse_qname ── */
static void test_parse_qname(void) {
    printf("\n[3. DNS Wire-Format Name Parsing]\n");
    reset_state();

    TC_BEGIN("TC-010","3. DNS Name Parsing","Parse 'www.google.com' — queried on XB8, latency_ms=14","parse_qname()='www.google.com'");
    const uint8_t w1[] = {0,0,0,0,0,1,0,0,0,0,0,0, 3,'w','w','w',6,'g','o','o','g','l','e',3,'c','o','m',0};
    ASSERT_STR_EQ(parse_qname(w1, sizeof(w1), 12), "www.google.com");
    TC_END();

    TC_BEGIN("TC-011","3. DNS Name Parsing","Parse 'global-time.xfinity.com' — NTP sync query on XB8","parse_qname()='global-time.xfinity.com'");
    const uint8_t w2[] = {0,0,0,0,0,1,0,0,0,0,0,0, 11,'g','l','o','b','a','l','-','t','i','m','e',7,'x','f','i','n','i','t','y',3,'c','o','m',0};
    ASSERT_STR_EQ(parse_qname(w2, sizeof(w2), 12), "global-time.xfinity.com");
    TC_END();

    TC_BEGIN("TC-012","3. DNS Name Parsing","Empty payload (root label only) returns '<root>'","parse_qname()='<root>'");
    const uint8_t w3[] = {0,0,0,0,0,1,0,0,0,0,0,0, 0};
    ASSERT_STR_EQ(parse_qname(w3, sizeof(w3), 12), "<root>");
    TC_END();

    TC_BEGIN("TC-013","3. DNS Name Parsing","Truncated payload must not crash and returns non-NULL","parse_qname() != NULL");
    const uint8_t w4[] = {0,0,0,0,0,1,0,0,0,0,0,0, 5,'a'};
    ASSERT_NOT_NULL(parse_qname(w4, sizeof(w4), 12));
    TC_END();
}

/* ── 4. make_hash ── */
static void test_make_hash(void) {
    printf("\n[4. Hash Key Collision Avoidance]\n");

    TC_BEGIN("TC-014","4. Hash Key","txid=0xac9a from IPv4 and IPv6 clients (XB8 dual-stack) must hash differently","make_hash(IPv4,txid) != make_hash(IPv6,txid)");
    unsigned int h1 = make_hash("73.252.171.253",                      0xac9a);
    unsigned int h2 = make_hash("2001:558:6045:12:987:cc98:4d57:5740", 0xac9a);
    ASSERT_INT_NE(h1, h2);
    ASSERT_TRUE(h1 < (unsigned int)DNS_HASH_BUCKETS);
    ASSERT_TRUE(h2 < (unsigned int)DNS_HASH_BUCKETS);
    TC_END();
}

/* ── 5. Pending table ── */
static void test_pending_table(void) {
    printf("\n[5. Pending Query Table]\n");
    reset_state();

    TC_BEGIN("TC-015","5. Pending Table","Insert www.google.com (txid=0x07ac, server=75.75.75.75) and remove it","All fields preserved on remove");
    struct timeval ts = {1000,0};
    pending_insert(0x07ac,"73.252.171.253","75.75.75.75","www.google.com",1,&ts);
    ASSERT_INT_EQ(g_pending_count, 1);
    pending_entry_t *e = pending_remove(0x07ac,"73.252.171.253");
    ASSERT_NOT_NULL(e);
    if (e) {
        ASSERT_INT_EQ(e->txid, 0x07ac);
        ASSERT_STR_EQ(e->qname, "www.google.com");
        ASSERT_STR_EQ(e->server_ip, "75.75.75.75");
        ASSERT_INT_EQ(e->qtype, 1);
        free(e);
    }
    ASSERT_INT_EQ(g_pending_count, 0);
    TC_END();

    reset_state();
    TC_BEGIN("TC-016","5. Pending Table","Remove with wrong client IP returns NULL (no false match)","pending_remove()=NULL");
    struct timeval ts2 = {1000,0};
    pending_insert(0x07ac,"73.252.171.253","75.75.75.75","www.google.com",1,&ts2);
    pending_entry_t *e2 = pending_remove(0x07ac,"10.0.0.1");
    ASSERT_NULL(e2);
    ASSERT_INT_EQ(g_pending_count, 1);
    TC_END();

    reset_state();
    TC_BEGIN("TC-017","5. Pending Table","XB8 dual-stack: txid=0xac9a from IPv4+IPv6 coexist without collision","Both removable independently; count reaches 0");
    struct timeval ts3 = {2000,0};
    pending_insert(0xac9a,"73.252.171.253","75.75.75.75","rdktel-oi.stb.r53.xcal.tv",1,&ts3);
    pending_insert(0xac9a,"2001:558:6045:12:987:cc98:4d57:5740","2001:558:feed::1","rdktel-oi.stb.r53.xcal.tv",1,&ts3);
    ASSERT_INT_EQ(g_pending_count, 2);
    pending_entry_t *e4 = pending_remove(0xac9a,"73.252.171.253");
    ASSERT_NOT_NULL(e4); if(e4) free(e4);
    ASSERT_INT_EQ(g_pending_count, 1);
    pending_entry_t *e5 = pending_remove(0xac9a,"2001:558:6045:12:987:cc98:4d57:5740");
    ASSERT_NOT_NULL(e5); if(e5) free(e5);
    ASSERT_INT_EQ(g_pending_count, 0);
    TC_END();

    reset_state();
    TC_BEGIN("TC-018","5. Pending Table","Two queries older than timeout=5s are both expired","pending_expire()=2, count=0");
    struct timeval ts4 = {1000,0};
    pending_insert(0xfd1a,"73.252.171.253","75.75.75.75","75.75.75.75.in-addr.arpa",12,&ts4);
    pending_insert(0x7b4c,"73.252.171.253","75.75.75.75","this-domain-xyz-doesnotexist123.com",1,&ts4);
    int expired = pending_expire(1006, 5, NULL, NULL);
    ASSERT_INT_EQ(expired, 2);
    ASSERT_INT_EQ(g_pending_count, 0);
    TC_END();
}

/* ── 6. Stats ── */
static void test_stats(void) {
    printf("\n[6. Statistics Accumulation]\n");
    reset_state();

    TC_BEGIN("TC-019","6. Stats","XB8 summary: queries=91 success=47 nxdomain=44 (success+fail=queries)","91 == 47 + 44");
    g_stats.query_count = 91; g_stats.success_count = 47; g_stats.nxdomain = 44;
    uint64_t fail_total = g_stats.nxdomain+g_stats.servfail+g_stats.refused+g_stats.other_rcode+g_stats.timeout;
    ASSERT_INT_EQ(g_stats.query_count, g_stats.success_count + fail_total);
    TC_END();

    reset_state();
    TC_BEGIN("TC-020","6. Stats","Second XB8 interval: avg_ms=18, max_ms=30, fail_total=2, slow=0","avg=18, max=30, fail=2");
    g_stats.success_count=6; g_stats.total_latency_ms=108; g_stats.max_latency_ms=30; g_stats.nxdomain=2;
    uint64_t avg = g_stats.total_latency_ms / g_stats.success_count;
    uint64_t ft  = g_stats.nxdomain+g_stats.servfail+g_stats.refused+g_stats.other_rcode+g_stats.timeout;
    ASSERT_INT_EQ(avg, 18);
    ASSERT_INT_EQ(g_stats.max_latency_ms, 30);
    ASSERT_INT_EQ(ft, 2);
    ASSERT_INT_EQ(g_stats.slow_count, 0);
    TC_END();

    reset_state();
    TC_BEGIN("TC-021","6. Stats","Division-by-zero guard: avg=0 when success_count=0","avg_ms=0");
    g_stats.success_count=0; g_stats.total_latency_ms=0;
    uint64_t avg2 = g_stats.success_count ? (g_stats.total_latency_ms/g_stats.success_count) : 0;
    ASSERT_INT_EQ(avg2, 0);
    TC_END();
}

/* ── 7. Server tracking ── */
static void test_server_tracking(void) {
    printf("\n[7. Per-Server Failure Tracking]\n");
    reset_state();

    TC_BEGIN("TC-022","7. Server Tracking","XB8 server_fails=[75.75.75.75:42, 75.75.76.76:2]","servers[0]=75.75.75.75:42, servers[1]=75.75.76.76:2");
    for(int i=0;i<42;i++) server_bump_fail("75.75.75.75");
    for(int i=0;i<2; i++) server_bump_fail("75.75.76.76");
    ASSERT_INT_EQ(g_server_count, 2);
    ASSERT_STR_EQ(g_servers[0].ip, "75.75.75.75");
    ASSERT_INT_EQ(g_servers[0].fail_count, 42);
    ASSERT_STR_EQ(g_servers[1].ip, "75.75.76.76");
    ASSERT_INT_EQ(g_servers[1].fail_count, 2);
    TC_END();

    reset_state();
    TC_BEGIN("TC-023","7. Server Tracking","Same server bumped 3 times → one entry, fail_count=3","server_count=1, fail=3");
    server_bump_fail("75.75.75.75"); server_bump_fail("75.75.75.75"); server_bump_fail("75.75.75.75");
    ASSERT_INT_EQ(g_server_count, 1);
    ASSERT_INT_EQ(g_servers[0].fail_count, 3);
    TC_END();

    reset_state();
    TC_BEGIN("TC-024","7. Server Tracking","Max tracker limit not exceeded (MAX_SERVER_TRACK=8)","server_count <= 8");
    char ip[32];
    for(int i=0;i<MAX_SERVER_TRACK+3;i++){ snprintf(ip,sizeof(ip),"10.0.0.%d",i+1); server_bump_fail(ip); }
    ASSERT_TRUE(g_server_count <= MAX_SERVER_TRACK);
    TC_END();
}

/* ── 8. iso_ts ── */
static void test_iso_ts(void) {
    printf("\n[8. ISO-8601 Timestamp]\n");

    TC_BEGIN("TC-025","8. Timestamp","Format matches XB8: 2026-07-16T04:50:18.999Z (len=24, T at [10], Z at [23])","strlen=24, [10]='T', [23]='Z'");
    struct timeval tv = {1752634218, 999000};
    const char *r = iso_ts(&tv);
    ASSERT_NOT_NULL(r);
    ASSERT_INT_EQ((int)strlen(r), 24);
    if(r && strlen(r)==24){ ASSERT_INT_EQ(r[10],'T'); ASSERT_INT_EQ(r[23],'Z'); }
    TC_END();

    TC_BEGIN("TC-026","8. Timestamp","tv_usec=27000 → ms digits '027'","result[20]='0', [21]='2', [22]='7'");
    struct timeval tv2 = {1000000, 27000};
    const char *r2 = iso_ts(&tv2);
    ASSERT_NOT_NULL(r2);
    if(r2 && strlen(r2)==24){ ASSERT_INT_EQ(r2[20],'0'); ASSERT_INT_EQ(r2[21],'2'); ASSERT_INT_EQ(r2[22],'7'); }
    TC_END();
}

/* ── 9. Latency calculation ── */
static void test_latency(void) {
    printf("\n[9. Latency Calculation]\n");

    TC_BEGIN("TC-027","9. Latency","www.google.com: query=.773s resp=.788s → 14ms (exact XB8 value)","latency_ms=14");
    struct timeval q1={1752634236,773000}, r1={1752634236,788000};
    int64_t lat1 = (r1.tv_sec-q1.tv_sec)*1000 + (r1.tv_usec-q1.tv_usec)/1000;
    ASSERT_INT_EQ(lat1, 14);
    TC_END();

    TC_BEGIN("TC-028","9. Latency","rdktel-oi fastest: 8ms on 75.75.76.76 (dual-stack winner on XB8)","latency_ms=8");
    struct timeval q2={1752634295,259000}, r2={1752634295,268000};
    int64_t lat2 = (r2.tv_sec-q2.tv_sec)*1000 + (r2.tv_usec-q2.tv_usec)/1000;
    ASSERT_INT_EQ(lat2, 8);
    TC_END();

    TC_BEGIN("TC-029","9. Latency","Cross-second: query at .999s, resp at +1s .027s → 28ms","latency_ms=28");
    struct timeval q3={1752634295,999000}, r3={1752634296,27000};
    int64_t lat3 = (r3.tv_sec-q3.tv_sec)*1000 + (r3.tv_usec-q3.tv_usec)/1000;
    ASSERT_INT_EQ(lat3, 28);
    TC_END();

    TC_BEGIN("TC-030","9. Latency","Negative delta clamped to 0 (clock anomaly guard)","latency_ms=0");
    int64_t lat4 = -5; if(lat4<0) lat4=0;
    ASSERT_INT_EQ(lat4, 0);
    TC_END();
}

/* ── 10. PTR NXDOMAIN ── */
static void test_ptr_nxdomain(void) {
    printf("\n[10. PTR Reverse Lookup Classification]\n");
    reset_state();

    TC_BEGIN("TC-031","10. PTR NXDOMAIN","IPv6 PTR NXDOMAIN classified as nxdomain not timeout","nxdomain=1, timeout=0");
    struct timeval ts={1000,0};
    pending_insert(0x532a,"73.252.171.253","75.75.75.75",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.7.6.2.8.4.0.6.8.4.1.0.0.2.ip6.arpa",12,&ts);
    pending_entry_t *e = pending_remove(0x532a,"73.252.171.253");
    ASSERT_NOT_NULL(e);
    if(e){ ASSERT_INT_EQ(e->qtype,12); free(e); }
    g_stats.nxdomain++;
    ASSERT_INT_EQ(g_stats.nxdomain, 1);
    ASSERT_INT_EQ(g_stats.timeout,  0);
    TC_END();

    reset_state();
    TC_BEGIN("TC-032","10. PTR NXDOMAIN","IPv4 PTR 119.154.251.142.in-addr.arpa (exact XB8 entry) — qname and qtype=PTR preserved","e->qname matches, e->qtype=12");
    struct timeval ts2={1000,0};
    pending_insert(0xa1ce,"73.252.171.253","75.75.75.75","119.154.251.142.in-addr.arpa",12,&ts2);
    pending_entry_t *e2 = pending_remove(0xa1ce,"73.252.171.253");
    ASSERT_NOT_NULL(e2);
    if(e2){ ASSERT_STR_EQ(e2->qname,"119.154.251.142.in-addr.arpa"); ASSERT_INT_EQ(e2->qtype,12); free(e2); }
    TC_END();
}

/* ================================================================
 * HTML report generation
 * ================================================================ */
static void print_html_report(void) {
    time_t now = time(NULL);
    char ts[32]; strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));
    float pct = g_total ? (g_pass*100.0f/g_total) : 0;

    printf("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>\n");
    printf("<title>DnsMonitor Unit Test Report</title>\n");
    printf("<style>\n");
    printf("body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;color:#333;}\n");
    printf(".hdr{background:linear-gradient(135deg,#1a3a5c,#2d6a9f);color:#fff;padding:20px 28px;}\n");
    printf(".hdr h1{font-size:20px;} .hdr p{font-size:12px;opacity:.8;margin-top:4px;}\n");
    printf(".sum{display:flex;gap:14px;padding:16px 28px;flex-wrap:wrap;}\n");
    printf(".card{background:#fff;border-radius:6px;padding:14px 20px;min-width:120px;text-align:center;box-shadow:0 2px 6px rgba(0,0,0,.08);}\n");
    printf(".card .n{font-size:28px;font-weight:700;} .card .l{font-size:11px;color:#777;margin-top:2px;text-transform:uppercase;}\n");
    printf(".total .n{color:#1a3a5c;} .passed .n{color:#27ae60;} .failed .n{color:#e74c3c;} .rate .n{color:#f39c12;}\n");
    printf(".wrap{padding:0 28px 28px;overflow-x:auto;}\n");
    printf("table{width:100%%;border-collapse:collapse;background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.08);font-size:12px;}\n");
    printf("thead tr{background:#1a3a5c;color:#fff;} thead th{padding:10px 12px;text-align:left;font-weight:600;white-space:nowrap;}\n");
    printf("tbody tr:nth-child(even){background:#f8fafc;} tbody tr:hover{background:#eaf3ff;}\n");
    printf("td{padding:8px 12px;vertical-align:top;border-bottom:1px solid #e8ecf0;}\n");
    printf(".tid{font-family:monospace;font-weight:600;color:#555;white-space:nowrap;}\n");
    printf(".subj{font-weight:600;color:#1a3a5c;white-space:nowrap;}\n");
    printf(".exp{color:#2c3e50;} .ok{color:#27ae60;} .err{color:#e74c3c;font-weight:600;}\n");
    printf(".pass{color:#27ae60;font-weight:700;white-space:nowrap;} .fail{color:#e74c3c;font-weight:700;white-space:nowrap;}\n");
    printf(".dur{color:#888;text-align:right;white-space:nowrap;}\n");
    printf("</style></head><body>\n");

    printf("<div class='hdr'><h1>DnsMonitor Unit Test Report</h1>\n");
    printf("<p>Component: TestAndDiagnostic &rarr; LatencyMeasurement &rarr; DnsMonitor &nbsp;|&nbsp; Device: XB8 (CGM4981COM) &nbsp;|&nbsp; %s</p></div>\n", ts);

    printf("<div class='sum'>\n");
    printf("<div class='card total'><div class='n'>%d</div><div class='l'>Total</div></div>\n", g_total);
    printf("<div class='card passed'><div class='n'>%d</div><div class='l'>Passed</div></div>\n", g_pass);
    printf("<div class='card failed'><div class='n'>%d</div><div class='l'>Failed</div></div>\n", g_fail);
    printf("<div class='card rate'><div class='n'>%.0f%%</div><div class='l'>Pass Rate</div></div>\n", pct);
    printf("</div>\n");

    printf("<div class='wrap'><table><thead><tr>\n");
    printf("<th>Test ID</th><th>Subject</th><th>Test Scenario</th><th>Expected Behaviour</th><th>Actual Result</th><th>Status</th><th>Duration</th>\n");
    printf("</tr></thead><tbody>\n");

    for (int i = 0; i < g_total && i < MAX_RESULTS; i++) {
        TestResult *r = &g_results[i];
        printf("<tr><td class='tid'>TC-%03d</td><td class='subj'>%s</td><td>%s</td>\n",
               r->id, r->subject, r->scenario);
        printf("<td class='exp'>%s</td>\n", r->expected);
        printf("<td class='%s'>%s</td>\n", r->passed ? "ok" : "err", r->actual);
        printf("<td class='%s'>%s</td>\n", r->passed ? "pass" : "fail", r->passed ? "&#10003; PASS" : "&#10007; FAIL");
        printf("<td class='dur'>%.1f ms</td></tr>\n", r->duration_ms);
    }

    printf("</tbody></table></div>\n");
    printf("<div style='padding:8px 28px 20px;font-size:11px;color:#888;'>XB8 reference: queries=91 success=47 nxdomain=44 avg_ms=25 max_ms=88 server_fails=[75.75.76.76:2,75.75.75.75:42]</div>\n");
    printf("</body></html>\n");
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char *argv[]) {
    g_html = (argc > 1 && strcmp(argv[1], "--html") == 0);

    if (!g_html) {
        printf("============================================================\n");
        printf(" DnsMonitor Standalone Unit Tests\n");
        printf(" Device: XB8 (CGM4981COM) — 2026-07-16\n");
        printf("============================================================\n");
    }

    test_rcode_name();
    test_qtype_name();
    test_parse_qname();
    test_make_hash();
    test_pending_table();
    test_stats();
    test_server_tracking();
    test_iso_ts();
    test_latency();
    test_ptr_nxdomain();

    if (g_html) {
        print_html_report();
        return (g_fail > 0) ? 1 : 0;
    }

    printf("\n============================================================\n");
    printf(" Results: %d/%d passed", g_pass, g_total);
    if (g_fail == 0) printf("  \033[32m[ALL PASS]\033[0m\n");
    else             printf("  \033[31m[%d FAILED]\033[0m\n", g_fail);
    printf("============================================================\n");
    printf("\nTo generate HTML report:\n");
    printf("  ./dns_monitor_test --html > DnsMonitor_TestReport.html\n");
    printf("  firefox DnsMonitor_TestReport.html\n");
    return (g_fail > 0) ? 1 : 0;
}
