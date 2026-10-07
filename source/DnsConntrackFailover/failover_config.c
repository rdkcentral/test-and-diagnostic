/*
 * failover_config.c -- see failover_config.h.
 *
 * Parsing strategy: the numeric parameters share one validation rule ("must be
 * an integer >= a per-key minimum"), so they live in a small table and are
 * handled by one loop. Only Enable (0/1) and ResolverSource (string) need
 * special handling. This keeps adding a parameter to a one-line table edit.
 */

#include "failover_config.h"

#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CONFIG_PATH        "/nvram/dns_failover.conf"
#define DEFAULT_RESOLVER   "/etc/resolv.conf"

static const struct failover_config g_defaults = {
    .enable                     = true,
    .resolver_source            = DEFAULT_RESOLVER,
    .reply_deadline_ms          = 2000U,
    .failure_episode_gap_ms     = 5000U,
    .failure_threshold          = 3U,
    .monitor_tick_ms            = 250U,
    .verify_timeout_ms          = 1500U,
    .verify_attempts            = 1U,
    .verify_cooldown_ms         = 10000U,
    .recovery_initial_ms        = 15000U,
    .recovery_max_ms            = 60000U,
    .recovery_success_threshold = 2U,
    .resolver_reload_ms         = 5000U,
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct failover_config g_config;      /* guarded by g_lock */
static bool   g_initialized;                 /* guarded by g_lock */
static time_t g_mtime;                       /* only touched from refresh path */

/* Table of the unsigned parameters: file key, field, and minimum valid value.
 * "ms" timers require >= 1 (0 would busy-loop); counts also require >= 1. */
struct uint_param {
    const char *key;
    size_t      offset;
    unsigned    min;
};

static const struct uint_param g_uint_params[] = {
    { "ReplyDeadline",            offsetof(struct failover_config, reply_deadline_ms),          1 },
    { "FailureEpisodeGap",        offsetof(struct failover_config, failure_episode_gap_ms),     1 },
    { "FailureThreshold",         offsetof(struct failover_config, failure_threshold),          1 },
    { "MonitorTick",              offsetof(struct failover_config, monitor_tick_ms),            1 },
    { "VerifyTimeout",            offsetof(struct failover_config, verify_timeout_ms),          1 },
    { "VerifyAttempts",           offsetof(struct failover_config, verify_attempts),            1 },
    { "VerifyCooldown",           offsetof(struct failover_config, verify_cooldown_ms),         1 },
    { "RecoveryInitial",          offsetof(struct failover_config, recovery_initial_ms),        1 },
    { "RecoveryMax",              offsetof(struct failover_config, recovery_max_ms),            1 },
    { "RecoverySuccessThreshold", offsetof(struct failover_config, recovery_success_threshold), 1 },
    { "ResolverReload",           offsetof(struct failover_config, resolver_reload_ms),         1 },
};

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        ++s;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t'))
        *--end = '\0';
    return s;
}

/* Parses val as a non-negative integer; returns false if it isn't one. */
static bool parse_uint(const char *val, unsigned *out)
{
    char *endp = NULL;
    unsigned long n = strtoul(val, &endp, 10);
    if (endp == val || *endp != '\0')
        return false;
    *out = (unsigned)n;
    return true;
}

/* Applies one "Key=Value" line to cfg. Unknown keys and invalid values are
 * logged and skipped, leaving the default/previous value in place. */
static void apply_line(struct failover_config *cfg, char *line)
{
    char *eq = strchr(line, '=');
    if (!eq)
        return;

    *eq = '\0';
    char *key = trim(line);
    char *val = trim(eq + 1);
    if (key[0] == '\0' || key[0] == '#')
        return;

    if (strcmp(key, "Enable") == 0) {
        unsigned n;
        if (parse_uint(val, &n) && n <= 1)
            cfg->enable = (n != 0);
        else
            fprintf(stderr, "CONFIG: rejected Enable='%s' (expect 0/1)\n", val);
        return;
    }

    if (strcmp(key, "ResolverSource") == 0) {
        if (val[0] != '\0')
            snprintf(cfg->resolver_source, sizeof(cfg->resolver_source), "%s", val);
        else
            fprintf(stderr, "CONFIG: rejected empty ResolverSource\n");
        return;
    }

    for (size_t i = 0; i < sizeof(g_uint_params) / sizeof(g_uint_params[0]); ++i) {
        const struct uint_param *p = &g_uint_params[i];
        if (strcmp(key, p->key) != 0)
            continue;

        unsigned n;
        if (parse_uint(val, &n) && n >= p->min)
            *(unsigned *)((char *)cfg + p->offset) = n;
        else
            fprintf(stderr, "CONFIG: rejected %s='%s' (min %u)\n", key, val, p->min);
        return;
    }

    fprintf(stderr, "CONFIG: ignoring unknown key '%s'\n", key);
}

/* Builds a fresh config from defaults overlaid with the file (if present). */
static struct failover_config build_config(void)
{
    struct failover_config cfg = g_defaults;

    FILE *fp = fopen(CONFIG_PATH, "r");
    if (!fp) {
        fprintf(stderr, "CONFIG: %s not present, using defaults\n", CONFIG_PATH);
        return cfg;
    }

    char line[320];
    while (fgets(line, sizeof(line), fp))
        apply_line(&cfg, line);
    fclose(fp);

    if (cfg.recovery_initial_ms > cfg.recovery_max_ms) {
        fprintf(stderr, "CONFIG: RecoveryInitial > RecoveryMax, clamping to RecoveryMax\n");
        cfg.recovery_initial_ms = cfg.recovery_max_ms;
    }

    fprintf(stderr, "CONFIG: loaded %s\n", CONFIG_PATH);
    return cfg;
}

void failover_config_refresh(void)
{
    struct stat st;
    bool have_stat = stat(CONFIG_PATH, &st) == 0;

    /* After the first load, only rebuild when the file is present and its
     * mtime changed. A vanished file keeps the last-known config rather than
     * snapping back to defaults or rebuilding every tick. */
    if (g_initialized) {
        if (!have_stat)
            return;
        if (st.st_mtime == g_mtime)
            return;
    }

    struct failover_config fresh = build_config();

    pthread_mutex_lock(&g_lock);
    g_config = fresh;
    g_initialized = true;
    pthread_mutex_unlock(&g_lock);

    if (have_stat)
        g_mtime = st.st_mtime;
}

struct failover_config failover_config_get(void)
{
    struct failover_config copy;

    pthread_mutex_lock(&g_lock);
    copy = g_initialized ? g_config : g_defaults;
    pthread_mutex_unlock(&g_lock);
    return copy;
}
