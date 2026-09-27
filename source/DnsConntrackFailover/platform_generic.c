/*
 * platform_generic.c
 *
 * Generic Linux implementation of the platform.h seam, for building and
 * running dns_conntrack_failover outside of RDK-B (no RBUS/WanManager
 * available). WAN reachability is approximated by checking for a default
 * route in an "up" state; the failover action is a logging stub, replace
 * it with iptables/nftables rules on the target system.
 */

#define _GNU_SOURCE

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "platform.h"

/* RTF_UP, see <linux/route.h>; duplicated to avoid pulling in kernel headers. */
#define RT_FLAG_UP 0x0001U

static atomic_bool g_wan_up = false;

/* Scans /proc/net/route for a default route (destination 00000000) whose
 * flags include RTF_UP. No default route means "no WAN" is a reasonable
 * proxy on a generic Linux box; adapt to your topology if needed. */
static bool has_default_route(void)
{
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp)
        return false;

    char line[256];
    bool up = false;

    /* Skip header line. */
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        char iface[64];
        unsigned long dest, flags;

        /* Iface Destination Gateway Flags RefCnt Use Metric Mask ... */
        if (sscanf(line, "%63s %lx %*lx %lx", iface, &dest, &flags) != 3)
            continue;

        if (dest == 0 && (flags & RT_FLAG_UP)) {
            up = true;
            break;
        }
    }

    fclose(fp);
    return up;
}

bool platform_wan_status_init(void)
{
    atomic_store(&g_wan_up, has_default_route());
    fprintf(stderr, "WAN: generic-Linux default-route probe, initial state=%s\n",
            atomic_load(&g_wan_up) ? "UP" : "DOWN");
    return true;
}

void platform_wan_status_exit(void)
{
    /* No resources held. */
}

bool platform_wan_is_reachable(void)
{
    /* No push notifications on generic Linux: re-check on every call. */
    bool up = has_default_route();
    atomic_store(&g_wan_up, up);
    return up;
}

void platform_set_unbound_failover(bool enable)
{
    fprintf(stderr, "ACTION: Unbound failover %s (generic Linux)\n",
            enable ? "ENABLE" : "DISABLE");

    /*
     * Replace with real control for your system, e.g.:
     *   iptables -t nat -A/-D PREROUTING -i <lan-if> -p udp --dport 53 \
     *       -j DNAT --to-destination 127.0.0.1:5353
     * Avoid system()/shelling out in production; use a netlink/nftables
     * library or a small privileged helper instead.
     */
}
