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
 * dnsfailover_verify.c
 *
 * Active DNS verification worker. Builds a minimal, well-formed DNS query
 * for ctx->cfg.test_domain and sends it directly (raw UDP socket) to the
 * suspect upstream server, bypassing the system resolver entirely so the
 * result reflects that specific server's health.
 *
 * A response is treated as "server is reachable/responsive" if it is a
 * syntactically valid DNS message with a matching transaction ID and the
 * QR (response) bit set -- regardless of RCODE. Per the design doc's
 * stated non-goals, this deliberately does not attempt to validate
 * SERVFAIL/NXDOMAIN semantics; the only question being answered here is
 * "did this server answer at all", which is the failure mode conntrack
 * cannot distinguish from a dropped/blackholed query.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/random.h>

#include "ccsp_trace.h"

#include "dnsfailover_verify.h"
#include "dnsfailover_util.h"
#include "dnsfailover_conntrack.h"

struct verify_job {
    bool used;
    dns_addr_t server;
};

struct verify_worker_state {
    struct dnsfailover_ctx *ctx;
    pthread_mutex_t qlock;
    pthread_cond_t qcond;
    struct verify_job queue[MAX_PENDING_VERIFY_JOBS];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    volatile sig_atomic_t running;
    pthread_t tid;
    bool started;
};

static struct verify_worker_state g_worker;

/* ------------------------------------------------------------------------- */
/* Minimal DNS query/response codec (RFC 1035 header + single question)     */
/* ------------------------------------------------------------------------- */

#define DNS_HDR_LEN   12U
#define DNS_MAX_MSG   512U
#define DNS_QTYPE_A   1U
#define DNS_QCLASS_IN 1U

static uint16_t RandomTransactionId(void)
{
    uint16_t id = 0;
    if (getrandom(&id, sizeof(id), 0) != (ssize_t)sizeof(id)) {
        /* getrandom() failing is exceedingly unlikely on Linux; fall back to
         * a time-derived value rather than leaving id uninitialized/zero. */
        id = (uint16_t)(DnsFailover_MonotonicMs() & 0xFFFFU);
    }
    return id ? id : 1U;
}

/* Encodes `domain` (e.g. "example.com") into DNS label format at *out,
 * NUL-terminating with a zero-length root label. Returns bytes written, or
 * 0 on invalid input (defensive validation: rejects overly long labels /
 * names, since test_domain ultimately originates from TR-181 config). */
static size_t EncodeQName(const char *domain, uint8_t *out, size_t out_cap)
{
    size_t out_len = 0;
    const char *p = domain;

    while (*p) {
        const char *label_start = p;
        while (*p && *p != '.')
            p++;
        size_t label_len = (size_t)(p - label_start);

        if (label_len == 0 || label_len > 63)
            return 0;
        if (out_len + 1 + label_len + 1 /* trailing root label */ > out_cap)
            return 0;

        out[out_len++] = (uint8_t)label_len;
        memcpy(&out[out_len], label_start, label_len);
        out_len += label_len;

        if (*p == '.')
            p++;
    }

    if (out_len + 1 > out_cap)
        return 0;

    out[out_len++] = 0; /* root label */
    return out_len;
}

static size_t BuildQuery(uint16_t txid, const char *domain, uint8_t *buf, size_t cap)
{
    if (cap < DNS_HDR_LEN)
        return 0;

    memset(buf, 0, cap);

    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
    buf[2] = 0x01; /* RD=1 (recursion desired), standard query */
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01; /* QDCOUNT = 1 */
    /* ANCOUNT/NSCOUNT/ARCOUNT already zeroed */

    size_t qname_len = EncodeQName(domain, buf + DNS_HDR_LEN, cap - DNS_HDR_LEN - 4);
    if (qname_len == 0)
        return 0;

    size_t off = DNS_HDR_LEN + qname_len;
    if (off + 4 > cap)
        return 0;

    buf[off++] = 0x00; buf[off++] = (uint8_t)DNS_QTYPE_A;
    buf[off++] = 0x00; buf[off++] = (uint8_t)DNS_QCLASS_IN;

    return off;
}

/* Validates that buf/len looks like a DNS response matching txid: correct
 * ID, QR bit set. RCODE is intentionally not inspected (see file header). */
static bool IsValidDnsResponse(const uint8_t *buf, size_t len, uint16_t txid)
{
    if (len < DNS_HDR_LEN)
        return false;

    uint16_t resp_id = (uint16_t)((buf[0] << 8) | buf[1]);
    if (resp_id != txid)
        return false;

    bool qr = (buf[2] & 0x80) != 0;
    return qr;
}

/* Sends one query and waits up to timeout_ms for a matching reply. Runs
 * entirely on the verify worker thread; never touches ctx->lock. */
static bool SendAndWaitOne(const dns_addr_t *server, uint16_t port,
                           const char *test_domain, uint32_t timeout_ms)
{
    uint8_t query[DNS_MAX_MSG];
    uint8_t reply[DNS_MAX_MSG];
    uint16_t txid = RandomTransactionId();

    size_t qlen = BuildQuery(txid, test_domain, query, sizeof(query));
    if (qlen == 0) {
        CcspTraceError(("%s: failed to encode query for domain '%s'\n",
                        __FUNCTION__, test_domain));
        return false;
    }

    int sock = socket(server->af, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        CcspTraceError(("%s: socket() failed: %s\n", __FUNCTION__, strerror(errno)));
        return false;
    }

    struct sockaddr_storage ss;
    socklen_t sslen;
    memset(&ss, 0, sizeof(ss));

    if (server->af == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        sin->sin_addr = server->a.v4;
        sslen = sizeof(*sin);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        sin6->sin6_addr = server->a.v6;
        sslen = sizeof(*sin6);
    }

    bool success = false;
    ssize_t sent = sendto(sock, query, qlen, 0, (struct sockaddr *)&ss, sslen);
    if (sent != (ssize_t)qlen) {
        CcspTraceError(("%s: sendto() failed: %s\n", __FUNCTION__, strerror(errno)));
        close(sock);
        return false;
    }

    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    uint64_t deadline = DnsFailover_MonotonicMs() + timeout_ms;

    for (;;) {
        uint64_t now = DnsFailover_MonotonicMs();
        if (now >= deadline)
            break;

        int prc = poll(&pfd, 1, (int)(deadline - now));
        if (prc < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (prc == 0)
            break; /* timeout */

        ssize_t n = recv(sock, reply, sizeof(reply), 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (IsValidDnsResponse(reply, (size_t)n, txid)) {
            success = true;
            break;
        }
        /* Mismatched/spoofed/stale packet: keep waiting until deadline. */
    }

    close(sock);
    return success;
}

/* ------------------------------------------------------------------------- */
/* Worker thread and bounded FIFO job queue                                  */
/* ------------------------------------------------------------------------- */

void DnsFailover_QueueVerify(struct dnsfailover_ctx *ctx, const dns_addr_t *server)
{
    (void)ctx;
    pthread_mutex_lock(&g_worker.qlock);

    if (g_worker.count >= MAX_PENDING_VERIFY_JOBS) {
        pthread_mutex_unlock(&g_worker.qlock);
        CcspTraceWarning(("%s: verify queue full, dropping request (will retry next tick)\n",
                          __FUNCTION__));
        return;
    }

    g_worker.queue[g_worker.tail].used = true;
    g_worker.queue[g_worker.tail].server = *server;
    g_worker.tail = (g_worker.tail + 1) % MAX_PENDING_VERIFY_JOBS;
    g_worker.count++;

    pthread_cond_signal(&g_worker.qcond);
    pthread_mutex_unlock(&g_worker.qlock);
}

static bool DequeueVerify(struct verify_job *out)
{
    pthread_mutex_lock(&g_worker.qlock);

    while (g_worker.count == 0 && g_worker.running)
        pthread_cond_wait(&g_worker.qcond, &g_worker.qlock);

    if (!g_worker.running && g_worker.count == 0) {
        pthread_mutex_unlock(&g_worker.qlock);
        return false;
    }

    *out = g_worker.queue[g_worker.head];
    g_worker.queue[g_worker.head].used = false;
    g_worker.head = (g_worker.head + 1) % MAX_PENDING_VERIFY_JOBS;
    g_worker.count--;

    pthread_mutex_unlock(&g_worker.qlock);
    return true;
}

static void *VerifyWorkerThread(void *arg)
{
    struct dnsfailover_ctx *ctx = arg;

    CcspTraceInfo(("%s: verify worker thread started\n", __FUNCTION__));

    while (g_worker.running) {
        struct verify_job job;
        if (!DequeueVerify(&job))
            break;
        if (!job.used)
            continue;

        char ipbuf[INET6_ADDRSTRLEN];
        DnsFailover_AddrToString(&job.server, ipbuf, sizeof(ipbuf));

        CcspTraceInfo(("%s: verifying %s (domain=%s timeout=%ums)\n", __FUNCTION__,
                       ipbuf, ctx->cfg.test_domain, ctx->cfg.verify_timeout_ms));

        bool ok = SendAndWaitOne(&job.server, DNS_PORT, ctx->cfg.test_domain,
                                 ctx->cfg.verify_timeout_ms);

        CcspTraceInfo(("%s: verification result for %s: %s\n", __FUNCTION__,
                       ipbuf, ok ? "SUCCESS" : "FAILURE"));

        DnsFailover_OnVerifyResult(ctx, &job.server, ok);
    }

    CcspTraceInfo(("%s: verify worker thread exiting\n", __FUNCTION__));
    return NULL;
}

bool DnsFailover_VerifyStart(struct dnsfailover_ctx *ctx)
{
    memset(&g_worker, 0, sizeof(g_worker));
    g_worker.ctx = ctx;
    g_worker.running = 1;

    if (pthread_mutex_init(&g_worker.qlock, NULL) != 0)
        return false;
    if (pthread_cond_init(&g_worker.qcond, NULL) != 0) {
        pthread_mutex_destroy(&g_worker.qlock);
        return false;
    }

    if (pthread_create(&g_worker.tid, NULL, VerifyWorkerThread, ctx) != 0) {
        CcspTraceError(("%s: pthread_create failed: %s\n", __FUNCTION__, strerror(errno)));
        pthread_cond_destroy(&g_worker.qcond);
        pthread_mutex_destroy(&g_worker.qlock);
        return false;
    }

    g_worker.started = true;
    return true;
}

void DnsFailover_VerifyStop(struct dnsfailover_ctx *ctx)
{
    (void)ctx;
    if (!g_worker.started)
        return;

    pthread_mutex_lock(&g_worker.qlock);
    g_worker.running = 0;
    pthread_cond_broadcast(&g_worker.qcond);
    pthread_mutex_unlock(&g_worker.qlock);

    pthread_join(g_worker.tid, NULL);
    pthread_cond_destroy(&g_worker.qcond);
    pthread_mutex_destroy(&g_worker.qlock);
    g_worker.started = false;
}
