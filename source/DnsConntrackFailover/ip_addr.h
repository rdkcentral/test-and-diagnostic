/*
 * ip_addr.h
 *
 * Dual-stack IP address value type. A single struct carries either an IPv4 or
 * IPv6 address so the rest of the code can treat both families uniformly when
 * keying flow tables and per-server health.
 */

#ifndef IP_ADDR_H
#define IP_ADDR_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* family is AF_INET or AF_INET6; the matching union member is valid. */
struct ip_addr {
    uint8_t family;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } a;
};

/* Formats addr into buf (needs INET6_ADDRSTRLEN). Returns buf, or "?" on error. */
const char *ip_addr_to_str(const struct ip_addr *addr, char *buf, size_t len);

/* True when both addresses are the same family and value. */
bool ip_addr_equal(const struct ip_addr *a, const struct ip_addr *b);

/* FNV-1a hash over the address, for open-addressed tables. */
uint32_t ip_addr_hash(const struct ip_addr *addr);

#endif /* IP_ADDR_H */
