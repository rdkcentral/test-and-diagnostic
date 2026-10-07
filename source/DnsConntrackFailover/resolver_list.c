/*
 * resolver_list.c -- see resolver_list.h.
 */

#include "resolver_list.h"

#include "failover_config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char   g_servers[RESOLVER_LIST_MAX][INET6_ADDRSTRLEN]; /* guarded by g_lock */
static int    g_count;                                        /* guarded by g_lock */
static time_t g_mtime;
static char   g_loaded_path[256]; /* "" until first load; compared to detect path change */

/* Parses "nameserver <ip>" lines from path, keeping every valid IPv4/IPv6
 * address. Replaces the current cache atomically under g_lock. */
static void load_from_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "RESOLVER: failed to open %s: %s\n", path, strerror(errno));
        return;
    }

    char servers[RESOLVER_LIST_MAX][INET6_ADDRSTRLEN];
    int count = 0;
    char line[256];

    while (count < RESOLVER_LIST_MAX && fgets(line, sizeof(line), fp)) {
        char addr[INET6_ADDRSTRLEN];
        struct in_addr a4;
        struct in6_addr a6;

        if (sscanf(line, "nameserver %45s", addr) != 1)
            continue;

        /* Re-render through inet_ntop so the cached form matches exactly what
         * ip_addr_to_str() produces for the same address later (resolv.conf
         * text isn't guaranteed to already be in canonical form). */
        if (inet_pton(AF_INET, addr, &a4) == 1)
            inet_ntop(AF_INET, &a4, servers[count++], INET6_ADDRSTRLEN);
        else if (inet_pton(AF_INET6, addr, &a6) == 1)
            inet_ntop(AF_INET6, &a6, servers[count++], INET6_ADDRSTRLEN);
        else
            fprintf(stderr, "RESOLVER: skipping invalid nameserver '%s'\n", addr);
    }
    fclose(fp);

    pthread_mutex_lock(&g_lock);
    memcpy(g_servers, servers, sizeof(servers));
    g_count = count;
    pthread_mutex_unlock(&g_lock);

    fprintf(stderr, "RESOLVER: cached %d nameserver(s) from %s\n", count, path);
}

void resolver_list_refresh(void)
{
    struct failover_config cfg = failover_config_get();
    const char *path = cfg.resolver_source;

    bool path_changed = strcmp(path, g_loaded_path) != 0;

    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "RESOLVER: stat(%s) failed: %s\n", path, strerror(errno));
        return;
    }

    if (!path_changed && st.st_mtime == g_mtime)
        return;

    g_mtime = st.st_mtime;
    snprintf(g_loaded_path, sizeof(g_loaded_path), "%s", path);
    load_from_file(path);
}

bool resolver_list_is_upstream(const char *ip)
{
    bool match;

    pthread_mutex_lock(&g_lock);
    match = (g_count == 0); /* empty set: monitor everything */
    for (int i = 0; !match && i < g_count; ++i)
        match = strcmp(ip, g_servers[i]) == 0;
    pthread_mutex_unlock(&g_lock);

    return match;
}
