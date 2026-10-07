/*
 * dns_redirect.h
 *
 * Failover action: enable or disable redirecting client DNS to the local
 * resolver (Unbound). This is the one side effect the monitor produces once it
 * decides upstream DNS is up or down.
 */

#ifndef DNS_REDIRECT_H
#define DNS_REDIRECT_H

#include <stdbool.h>

/* enable=true routes client DNS to the local resolver (failover active);
 * enable=false restores normal upstream resolution. */
void dns_redirect_set_failover(bool enable);

#endif /* DNS_REDIRECT_H */
