/*
 * dns_redirect.c -- see dns_redirect.h.
 *
 * Generic Linux implementation: start/stop the local Unbound resolver. The
 * monitor calls this every evaluation tick, so the action is made idempotent
 * here -- the systemctl command runs only when the failover state actually
 * changes.
 */

#define _GNU_SOURCE

#include "dns_redirect.h"

#include <stdio.h>
#include <stdlib.h>

void dns_redirect_set_failover(bool enable)
{
    static int current = -1; /* -1 unknown, 0 disabled, 1 enabled */

    if (current == (int)enable)
        return; /* no transition: nothing to do */

    const char *cmd = enable ? "systemctl start unbound" : "systemctl stop unbound";
    fprintf(stderr, "ACTION: Unbound failover %s\n", enable ? "ENABLE" : "DISABLE");

    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "ACTION: '%s' failed (rc=%d)\n", cmd, rc);
        return; /* leave state unchanged so the next tick retries */
    }

    current = (int)enable;

    /*
     * To fully take over resolution, also add DNS redirection here, e.g.:
     *   iptables -t nat -A/-D PREROUTING -i <lan-if> -p udp --dport 53 \
     *       -j DNAT --to-destination 127.0.0.1:5353
     */
}
