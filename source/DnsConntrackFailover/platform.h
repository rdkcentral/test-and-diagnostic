/*
 * platform.h
 *
 * Platform abstraction seam for dns_conntrack_failover.c.
 *
 * The core file (conntrack monitoring, passive/active DNS verification) is
 * plain POSIX/Linux and has no platform-specific dependency. WAN status and
 * the failover trigger action are declared here and implemented once, in
 * platform_generic.c, using only /proc and /sys (see Makefile.am).
 */

#ifndef DNS_CONNTRACK_FAILOVER_PLATFORM_H
#define DNS_CONNTRACK_FAILOVER_PLATFORM_H

#include <stdbool.h>

/* Initializes platform WAN-status monitoring. Returns false if the
 * platform's status source is unavailable at startup; the caller should
 * keep running and treat WAN as down until it becomes available. */
bool platform_wan_status_init(void);

/* Releases anything acquired by platform_wan_status_init(). Safe to call
 * even if init failed or was never called. */
void platform_wan_status_exit(void);

/* Returns the last known WAN reachability state. Must be safe to call from
 * any thread. */
bool platform_wan_is_reachable(void);

/* Enables/disables redirecting client DNS to the local resolver (Unbound).
 * Replace the implementation with real firewall/DNS-manager control. */
void platform_set_unbound_failover(bool enable);

#endif /* DNS_CONNTRACK_FAILOVER_PLATFORM_H */
