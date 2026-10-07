/*
 * ip_addr.c -- see ip_addr.h.
 */

#include "ip_addr.h"

#include <arpa/inet.h>
#include <string.h>

const char *ip_addr_to_str(const struct ip_addr *addr, char *buf, size_t len)
{
    const void *src = (addr->family == AF_INET6)
                          ? (const void *)&addr->a.v6
                          : (const void *)&addr->a.v4;
    return inet_ntop(addr->family, src, buf, (socklen_t)len) ? buf : "?";
}

bool ip_addr_equal(const struct ip_addr *a, const struct ip_addr *b)
{
    if (a->family != b->family)
        return false;
    return (a->family == AF_INET6)
               ? memcmp(&a->a.v6, &b->a.v6, sizeof(a->a.v6)) == 0
               : a->a.v4.s_addr == b->a.v4.s_addr;
}

uint32_t ip_addr_hash(const struct ip_addr *addr)
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
