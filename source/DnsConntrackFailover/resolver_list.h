/*
 * resolver_list.h
 *
 * Set of upstream DNS servers the gateway is configured to use, parsed from
 * the "nameserver" lines of the ResolverSource file (default /etc/resolv.conf)
 * and re-read when that file changes. Used to scope failure detection to the
 * gateway's own resolvers: DNS a LAN client sends to some unrelated server is
 * not evidence about upstream health.
 */

#ifndef RESOLVER_LIST_H
#define RESOLVER_LIST_H

#include <stdbool.h>

#define RESOLVER_LIST_MAX 16

/* Reloads the set if the ResolverSource path or its mtime changed since the
 * last load. Cheap (one stat()) when nothing changed. */
void resolver_list_refresh(void);

/* True if ip (an IPv4/IPv6 literal) is a configured upstream resolver. Also
 * true when the set is empty/unavailable, so detection degrades to monitoring
 * all DNS rather than nothing. */
bool resolver_list_is_upstream(const char *ip);

#endif /* RESOLVER_LIST_H */
