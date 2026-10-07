/*
 * dns_probe.c -- see dns_probe.h.
 */

#define _GNU_SOURCE

#include "dns_probe.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DNS_PORT 53U

/* Firewall mark stamped on probe sockets (SO_MARK). While failover is active
 * the platform redirects all DNS to the local resolver; the redirect rules
 * exempt this mark so recovery probes still reach the real upstream servers
 * and can detect when they come back. Must match the value the failover
 * redirect rules exempt. */
#define DNS_PROBE_FWMARK 0x4453U

/* 12-byte header + root-name question (type A, class IN) = 17 bytes. */
#define DNS_QUERY_LEN 17

/* Fills msg[0..16] with a minimal "A ." query and returns its length. */
static size_t build_query(uint8_t *msg, uint16_t id)
{
    memset(msg, 0, DNS_QUERY_LEN);
    msg[0] = (uint8_t)(id >> 8);
    msg[1] = (uint8_t)(id & 0xFF);
    msg[2] = 0x01; /* flags: recursion desired */
    msg[5] = 0x01; /* qdcount = 1 */
    msg[12] = 0x00;             /* root name terminator */
    msg[13] = 0x00; msg[14] = 0x01; /* qtype = A */
    msg[15] = 0x00; msg[16] = 0x01; /* qclass = IN */
    return DNS_QUERY_LEN;
}

/* Builds a sockaddr for server_ip:53. Returns false if it isn't an IP literal. */
static bool resolve_addr(const char *server_ip, struct sockaddr_storage *addr,
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

static void tag_probe_socket(int fd)
{
    unsigned mark = DNS_PROBE_FWMARK;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
        fprintf(stderr, "VERIFY: SO_MARK failed: %s\n", strerror(errno));
}

/* True if resp is a DNS response whose ID matches query[0..1]. */
static bool reply_matches(const uint8_t *query, const uint8_t *resp, ssize_t n)
{
    if (n < 12)
        return false;
    bool id_matches = resp[0] == query[0] && resp[1] == query[1];
    bool is_response = (resp[2] & 0x80) != 0; /* QR bit */
    return id_matches && is_response;
}

static uint16_t next_query_id(void)
{
    static uint16_t id;
    return ++id;
}

static bool probe_udp(const char *server_ip, unsigned timeout_ms)
{
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int family;

    if (!resolve_addr(server_ip, &addr, &addr_len, &family))
        return false;

    int fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        fprintf(stderr, "VERIFY: UDP socket() failed: %s\n", strerror(errno));
        return false;
    }
    tag_probe_socket(fd);

    uint8_t query[DNS_QUERY_LEN];
    size_t len = build_query(query, next_query_id());

    bool ok = false;
    if (sendto(fd, query, len, 0, (struct sockaddr *)&addr, addr_len) < 0) {
        fprintf(stderr, "VERIFY: UDP sendto(%s) failed: %s\n", server_ip, strerror(errno));
    } else {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, (int)timeout_ms) > 0) {
            uint8_t resp[512];
            ssize_t n = recv(fd, resp, sizeof(resp), 0);
            ok = reply_matches(query, resp, n);
        }
    }

    close(fd);
    return ok;
}

/* TCP/53 fallback: some resolvers (or paths) drop UDP while still answering
 * TCP. Message is length-prefixed per RFC 1035. */
static bool probe_tcp(const char *server_ip, unsigned timeout_ms)
{
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int family;

    if (!resolve_addr(server_ip, &addr, &addr_len, &family))
        return false;

    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (fd < 0) {
        fprintf(stderr, "VERIFY: TCP socket() failed: %s\n", strerror(errno));
        return false;
    }
    tag_probe_socket(fd);

    if (connect(fd, (struct sockaddr *)&addr, addr_len) < 0 && errno != EINPROGRESS) {
        fprintf(stderr, "VERIFY: TCP connect(%s) failed: %s\n", server_ip, strerror(errno));
        close(fd);
        return false;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int so_err = 0;
    socklen_t so_err_len = sizeof(so_err);
    if (poll(&pfd, 1, (int)timeout_ms) <= 0 ||
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_err_len) != 0 || so_err != 0) {
        close(fd);
        return false;
    }

    uint8_t query[DNS_QUERY_LEN];
    size_t len = build_query(query, next_query_id());
    uint8_t pkt[2 + DNS_QUERY_LEN];
    pkt[0] = (uint8_t)(len >> 8);
    pkt[1] = (uint8_t)(len & 0xFF);
    memcpy(pkt + 2, query, len);

    bool ok = false;
    if (send(fd, pkt, 2 + len, 0) < 0) {
        fprintf(stderr, "VERIFY: TCP send(%s) failed: %s\n", server_ip, strerror(errno));
    } else {
        pfd.events = POLLIN;
        if (poll(&pfd, 1, (int)timeout_ms) > 0) {
            uint8_t resp[514];
            ssize_t n = recv(fd, resp, sizeof(resp), 0);
            /* Skip the 2-byte length prefix before matching the DNS header. */
            if (n >= 2)
                ok = reply_matches(query, resp + 2, n - 2);
        }
    }

    close(fd);
    return ok;
}

bool dns_probe(const char *server_ip, unsigned timeout_ms)
{
    if (probe_udp(server_ip, timeout_ms))
        return true;
    return probe_tcp(server_ip, timeout_ms);
}
