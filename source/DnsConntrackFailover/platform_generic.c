/*
 * platform_generic.c
 *
 * Generic Linux implementation of the platform.h seam, for building and
 * running dns_conntrack_failover on any Linux host (RDK-B or otherwise), with
 * no platform-specific dependency (no RBUS). WAN status is derived purely
 * from /proc and /sys: the interface holding the IPv4 default route is taken
 * as "the WAN interface" (works regardless of its name -- erouter0, eth0,
 * wan0, ...), and its /sys/class/net/<if>/operstate and carrier files give
 * the actual link state. The failover action is a logging stub, replace it
 * with iptables/nftables rules on the target system.
 */

#define _GNU_SOURCE

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

/* RTF_UP, see <linux/route.h>; duplicated to avoid pulling in kernel headers. */
#define RT_FLAG_UP 0x0001U

static atomic_bool g_wan_up = false;

/* Scans /proc/net/route for the IPv4 default route (destination 00000000)
 * and returns its interface name. Returns false if none is found -- there is
 * no WAN interface to check, so the caller should treat WAN as down. */
static bool find_default_route_iface(char *iface, size_t iface_len)
{
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp)
        return false;

    char line[256];
    bool found = false;

    /* Skip header line. */
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        char name[64];
        unsigned long dest;

        /* Iface Destination Gateway Flags RefCnt Use Metric Mask ... */
        if (sscanf(line, "%63s %lx", name, &dest) != 2)
            continue;

        if (dest == 0) {
            snprintf(iface, iface_len, "%s", name);
            found = true;
            break;
        }
    }

    fclose(fp);
    return found;
}

/* Reads a one-line /sys/class/net/<iface>/<attr> file into out. Returns
 * false if the file is missing or unreadable (interface gone, no carrier
 * attribute on this driver, etc.). */
static bool read_sysfs_net_attr(const char *iface, const char *attr,
                                char *out, size_t out_len)
{
    char path[160];
    snprintf(path, sizeof(path), "/sys/class/net/%s/%s", iface, attr);

    FILE *fp = fopen(path, "r");
    if (!fp)
        return false;

    bool ok = fgets(out, (int)out_len, fp) != NULL;
    fclose(fp);
    return ok;
}

/* WAN is "up" when the default-route interface reports operstate "up" and a
 * live carrier (actual link present, not just administratively up). Falls
 * back to the /proc/net/route RTF_UP flag if sysfs attributes are missing
 * (e.g. driver doesn't expose carrier). */
static bool has_default_route(void)
{
    char iface[64];
    if (!find_default_route_iface(iface, sizeof(iface)))
        return false;

    char operstate[16];
    char carrier[16];
    bool have_operstate = read_sysfs_net_attr(iface, "operstate", operstate, sizeof(operstate));
    bool have_carrier = read_sysfs_net_attr(iface, "carrier", carrier, sizeof(carrier));

    if (have_operstate)
        return strncmp(operstate, "up", 2) == 0 && (!have_carrier || carrier[0] == '1');

    /* Sysfs attributes unavailable: fall back to the route table's own flag. */
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp)
        return false;

    char line[256];
    bool up = false;

    if (fgets(line, sizeof(line), fp)) {
        while (fgets(line, sizeof(line), fp)) {
            char name[64];
            unsigned long dest, flags;

            if (sscanf(line, "%63s %lx %*lx %lx", name, &dest, &flags) != 3)
                continue;

            if (dest == 0 && strcmp(name, iface) == 0 && (flags & RT_FLAG_UP)) {
                up = true;
                break;
            }
        }
    }

    fclose(fp);
    return up;
}

bool platform_wan_status_init(void)
{
    atomic_store(&g_wan_up, has_default_route());
    fprintf(stderr, "WAN: default-route-interface probe, initial state=%s\n",
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
    const char *cmd = enable ? "systemctl start unbound" : "systemctl stop unbound";

    fprintf(stderr, "ACTION: Unbound failover %s (generic Linux)\n",
            enable ? "ENABLE" : "DISABLE");

    int rc = system(cmd);
    if (rc != 0)
        fprintf(stderr, "ACTION: '%s' failed (rc=%d)\n", cmd, rc);

    /*
     * Also add DNS redirection to fully take over resolution, e.g.:
     *   iptables -t nat -A/-D PREROUTING -i <lan-if> -p udp --dport 53 \
     *       -j DNAT --to-destination 127.0.0.1:5353
     */
}
