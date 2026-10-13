/*
 * failover_config.c -- see failover_config.h.
 *
 * Parsing strategy: the numeric parameters share one validation rule ("must be
 * an integer >= a per-key minimum"), so they live in a small table and are
 * handled by one loop. Only Enable (0/1) and ResolverSource (string) need
 * special handling. This keeps adding a parameter to a one-line table edit.
 */

#include "failover_config.h"

#include "dns_log.h"

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Applies one "Key=Value" line to cfg. Unknown keys are skipped; an invalid
 * value is logged and cfg takes that key's value from prev instead. */
static void apply_line(struct failover_config *cfg, const struct failover_config *prev,
                       char *line)
{
    char *eq = strchr(line, '=');
    if (!eq) {
        char *t = trim(line);
        if (t[0] != '\0' && t[0] != '#')
            LOG_WARN("CONFIG: ignoring malformed line '%s' (expect Key=Value)", t);
        return;
    }

    *eq = '\0';
    char *key = trim(line);
    char *val = trim(eq + 1);
    if (key[0] == '\0' || key[0] == '#')
        return;

    if (strcmp(key, "Enable") == 0) {
        unsigned n;
        if (parse_uint(val, &n) && n <= 1) {
            cfg->enable = (n != 0);
        } else {
            cfg->enable = prev->enable;
            LOG_ERR("CONFIG: rejected Enable='%s' (expect 0/1); keeping previous value", val);
        }
        return;
    }

    if (strcmp(key, "ResolverSource") == 0) {
        if (val[0] != '\0' && strlen(val) < sizeof(cfg->resolver_source)) {
            snprintf(cfg->resolver_source, sizeof(cfg->resolver_source), "%s", val);
        } else {
            snprintf(cfg->resolver_source, sizeof(cfg->resolver_source), "%s",
                     prev->resolver_source);
            LOG_ERR("CONFIG: rejected ResolverSource (empty or longer than %zu chars); "
                    "keeping previous value", sizeof(cfg->resolver_source) - 1);
        }
        return;
    }

    for (size_t i = 0; i < sizeof(g_uint_params) / sizeof(g_uint_params[0]); ++i) {
        const struct uint_param *p = &g_uint_params[i];
        if (strcmp(key, p->key) != 0)
            continue;

        unsigned n;
        if (parse_uint(val, &n) && n >= p->min) {
            *(unsigned *)((char *)cfg + p->offset) = n;
        } else {
            *(unsigned *)((char *)cfg + p->offset) =
                *(const unsigned *)((const char *)prev + p->offset);
            LOG_ERR("CONFIG: rejected %s='%s' (integer >= %u expected); keeping previous value",
                    key, val, p->min);
        }
        return;
    }

    LOG_WARN("CONFIG: ignoring unknown key '%s'", key);
}

/* Builds a fresh config: defaults overlaid with the file (if present), where an
 * invalid value falls back to prev. Returns 0 on success (*from_file says
 * whether a file was read), or the errno of a failed open. */
static int build_config(struct failover_config *cfg, const struct failover_config *prev,
                        bool *from_file)
{
    *cfg = g_defaults;
    *from_file = false;

    FILE *fp = fopen(CONFIG_PATH, "r");
    if (!fp)
        return errno == ENOENT ? 0 : errno;

    char line[320];
    while (fgets(line, sizeof(line), fp))
        apply_line(cfg, prev, line);
    fclose(fp);
    *from_file = true;

    if (cfg->recovery_initial_ms > cfg->recovery_max_ms) {
        LOG_WARN("CONFIG: RecoveryInitial (%u) > RecoveryMax (%u), clamping to RecoveryMax",
                 cfg->recovery_initial_ms, cfg->recovery_max_ms);
        cfg->recovery_initial_ms = cfg->recovery_max_ms;
    }

    return 0;
}

static void log_effective_config(const struct failover_config *c, bool from_file)
{
    LOG_INFO("CONFIG: %s; Enable=%d ResolverSource=%s ReplyDeadline=%u FailureEpisodeGap=%u "
             "FailureThreshold=%u MonitorTick=%u VerifyTimeout=%u VerifyAttempts=%u "
             "VerifyCooldown=%u RecoveryInitial=%u RecoveryMax=%u "
             "RecoverySuccessThreshold=%u ResolverReload=%u",
             from_file ? CONFIG_PATH : "no config file, using defaults",
             c->enable, c->resolver_source, c->reply_deadline_ms, c->failure_episode_gap_ms,
             c->failure_threshold, c->monitor_tick_ms, c->verify_timeout_ms,
             c->verify_attempts, c->verify_cooldown_ms, c->recovery_initial_ms,
             c->recovery_max_ms, c->recovery_success_threshold, c->resolver_reload_ms);
}

/* One line per setting whose value differs between old and fresh. */
static void log_config_changes(const struct failover_config *old,
                               const struct failover_config *fresh, bool from_file)
{
    bool changed = false;

    if (old->enable != fresh->enable) {
        LOG_INFO("CONFIG: Enable %d -> %d", old->enable, fresh->enable);
        changed = true;
    }
    if (strcmp(old->resolver_source, fresh->resolver_source) != 0) {
        LOG_INFO("CONFIG: ResolverSource %s -> %s", old->resolver_source, fresh->resolver_source);
        changed = true;
    }
    for (size_t i = 0; i < sizeof(g_uint_params) / sizeof(g_uint_params[0]); ++i) {
        const struct uint_param *p = &g_uint_params[i];
        unsigned o = *(const unsigned *)((const char *)old + p->offset);
        unsigned n = *(const unsigned *)((const char *)fresh + p->offset);
        if (o != n) {
            LOG_INFO("CONFIG: %s %u -> %u", p->key, o, n);
            changed = true;
        }
    }

    if (!changed)
        LOG_INFO("CONFIG: %s reloaded, no setting changed", from_file ? CONFIG_PATH : "defaults");
}

void failover_config_load(void)
{
    struct failover_config prev, fresh;
    bool from_file, first;

    pthread_mutex_lock(&g_lock);
    first = !g_initialized;
    prev = first ? g_defaults : g_config;
    pthread_mutex_unlock(&g_lock);

    int err = build_config(&fresh, &prev, &from_file);
    if (err) {
        LOG_ERR("CONFIG: cannot read %s: %s; %s", CONFIG_PATH, strerror(err),
                first ? "using defaults" : "keeping previous configuration");
        if (!first)
            return;
    } else if (!from_file && !first) {
        LOG_WARN("CONFIG: %s not found; keeping previous configuration", CONFIG_PATH);
        return;
    }

    pthread_mutex_lock(&g_lock);
    g_config = fresh;
    g_initialized = true;
    pthread_mutex_unlock(&g_lock);

    if (first)
        log_effective_config(&fresh, from_file);
    else
        log_config_changes(&prev, &fresh, from_file);
}

struct failover_config failover_config_get(void)
{
    struct failover_config copy;

    pthread_mutex_lock(&g_lock);
    copy = g_initialized ? g_config : g_defaults;
    pthread_mutex_unlock(&g_lock);
    return copy;
}
