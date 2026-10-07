/*
 * wan_status.c -- see wan_status.h.
 *
 * Generic Linux implementation using only /proc and /sys, with no
 * platform-specific dependency. The interface holding the IPv4 default route
 * is taken as "the WAN interface" (works regardless of its name -- erouter0,
 * eth0, wan0, ...) and its /sys/class/net/<if>/operstate and carrier files
 * give the actual link state.
 */

#define _GNU_SOURCE

#include "wan_status.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* RTF_UP from <linux/route.h>; inlined to avoid pulling in kernel headers. */
#define RT_FLAG_UP 0x0001U

static atomic_bool g_wan_up = false;

/* Finds the interface owning the IPv4 default route (destination 00000000) in
 * /proc/net/route. Returns false if there is none. */
static bool find_default_route_iface(char *iface, size_t iface_len)
{
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp)
        return false;

    char line[256];
    bool found = false;

    if (!fgets(line, sizeof(line), fp)) { /* skip header */
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

/* Reads a one-line /sys/class/net/<iface>/<attr> file. Returns false if the
 * attribute is missing (interface gone, driver doesn't expose it, etc.). */
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

/* Falls back to the /proc/net/route RTF_UP flag when sysfs link state for
 * iface is unavailable. */
static bool route_flag_up(const char *iface)
{
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp)
        return false;

    char line[256];
    bool up = false;

    if (fgets(line, sizeof(line), fp)) { /* skip header */
        while (fgets(line, sizeof(line), fp)) {
            char name[64];
            unsigned long dest, flags;

            if (sscanf(line, "%63s %lx %*x %lx", name, &dest, &flags) != 3)
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

/* WAN is "up" when the default-route interface reports operstate "up" and a
 * live carrier (actual link present, not just administratively up). */
static bool wan_is_up(void)
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

    return route_flag_up(iface);
}

bool wan_status_init(void)
{
    atomic_store(&g_wan_up, wan_is_up());
    fprintf(stderr, "WAN: default-route-interface probe, initial state=%s\n",
            atomic_load(&g_wan_up) ? "UP" : "DOWN");
    return true;
}

void wan_status_exit(void)
{
    /* No resources held. */
}

bool wan_status_is_reachable(void)
{
    /* No push notifications on generic Linux: re-check on every call. */
    bool up = wan_is_up();
    atomic_store(&g_wan_up, up);
    return up;
}
