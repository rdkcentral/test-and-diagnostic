/*
 * resolver_list.c -- see resolver_list.h.
 */

#include "resolver_list.h"

#include "dns_log.h"
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
static bool   g_err_logged;       /* a stat/open failure is already reported; re-arm on success */

/* Logs a stat/open failure once until the source becomes readable again, since
 * refresh retries every ResolverReload period. The previous list stays active. */
static void report_error(const char *what, const char *path)
{
    int err = errno;

    if (g_err_logged)
        return;
    g_err_logged = true;
    LOG_ERR("RESOLVER: %s(%s) failed: %s; keeping previous list (%d server(s))",
            what, path, strerror(err), g_count);
}

static bool list_contains(char list[][INET6_ADDRSTRLEN], int count, const char *ip)
{
    for (int i = 0; i < count; ++i)
        if (strcmp(list[i], ip) == 0)
            return true;
    return false;
}

static void log_list_change(bool first, const char *path,
                            char old_list[][INET6_ADDRSTRLEN], int old_count,
                            char new_list[][INET6_ADDRSTRLEN], int new_count)
{
    bool changed = first;

    for (int i = 0; i < new_count; ++i) {
        if (!list_contains(old_list, old_count, new_list[i])) {
            LOG_INFO("RESOLVER: upstream %s %s", first ? "loaded" : "added", new_list[i]);
            changed = true;
        }
    }
    for (int i = 0; i < old_count; ++i) {
        if (!list_contains(new_list, new_count, old_list[i])) {
            LOG_INFO("RESOLVER: upstream removed %s", old_list[i]);
            changed = true;
        }
    }

    if (!changed)
        return; /* file touched or reordered, same set of servers */

    LOG_INFO("RESOLVER: %d nameserver(s) from %s", new_count, path);
    if (new_count == 0)
        LOG_WARN("RESOLVER: no valid nameserver in %s; monitoring all DNS destinations", path);
}

/* Parses "nameserver <ip>" lines from path, keeping every valid IPv4/IPv6
 * address in canonical text form (the form conntrack addresses are rendered
 * in, so string comparison is reliable). Replaces the cache atomically. */
static bool load_from_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        report_error("open", path);
        return false;
    }

    char servers[RESOLVER_LIST_MAX][INET6_ADDRSTRLEN];
    int count = 0;
    char line[256];

    while (fgets(line, sizeof(line), fp)) {
        char addr[INET6_ADDRSTRLEN];
        char canon[INET6_ADDRSTRLEN];
        unsigned char raw[sizeof(struct in6_addr)];
        int af;

        if (sscanf(line, "nameserver %45s", addr) != 1)
            continue;

        if (inet_pton(AF_INET, addr, raw) == 1)
            af = AF_INET;
        else if (inet_pton(AF_INET6, addr, raw) == 1)
            af = AF_INET6;
        else
            af = 0;

        if (af == 0 || !inet_ntop(af, raw, canon, sizeof(canon))) {
            LOG_WARN("RESOLVER: skipping invalid nameserver '%s' in %s", addr, path);
            continue;
        }

        if (count == RESOLVER_LIST_MAX) {
            LOG_WARN("RESOLVER: more than %d nameservers in %s; ignoring the rest",
                     RESOLVER_LIST_MAX, path);
            break;
        }

        snprintf(servers[count++], INET6_ADDRSTRLEN, "%s", canon);
    }
    fclose(fp);

    char old_list[RESOLVER_LIST_MAX][INET6_ADDRSTRLEN];
    int old_count;
    bool first = g_loaded_path[0] == '\0';

    pthread_mutex_lock(&g_lock);
    old_count = g_count;
    memcpy(old_list, g_servers, sizeof(old_list));
    memcpy(g_servers, servers, sizeof(servers));
    g_count = count;
    pthread_mutex_unlock(&g_lock);

    log_list_change(first, path, old_list, old_count, servers, count);
    return true;
}

void resolver_list_refresh(void)
{
    struct failover_config cfg = failover_config_get();
    const char *path = cfg.resolver_source;

    bool path_changed = strcmp(path, g_loaded_path) != 0;

    struct stat st;
    if (stat(path, &st) != 0) {
        report_error("stat", path);
        return;
    }

    if (!path_changed && st.st_mtime == g_mtime)
        return;

    if (path_changed && g_loaded_path[0] != '\0')
        LOG_INFO("RESOLVER: source changed %s -> %s", g_loaded_path, path);

    if (!load_from_file(path))
        return; /* retried next refresh; error already reported once */

    if (g_err_logged) {
        g_err_logged = false;
        LOG_INFO("RESOLVER: %s readable again", path);
    }

    g_mtime = st.st_mtime;
    snprintf(g_loaded_path, sizeof(g_loaded_path), "%s", path);
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
