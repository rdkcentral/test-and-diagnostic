/*
 * failover_config.h
 *
 * Runtime configuration for the DNS failover monitor, sourced from a flat
 * key=value file (/nvram/dns_failover.conf). Each key mirrors a leaf of
 * Device.X_RDK_DNSFailover.* (RDKB-66999) with the object prefix stripped,
 * e.g. ResolverSource=/etc/resolv.conf. Unset keys fall back to the built-in
 * defaults; the file is re-read automatically when it changes on disk.
 */

#ifndef FAILOVER_CONFIG_H
#define FAILOVER_CONFIG_H

#include <stdbool.h>

struct failover_config {
    bool     enable;                     /* Enable: master on/off switch */
    char     resolver_source[256];       /* ResolverSource: upstream resolver list file */
    unsigned reply_deadline_ms;          /* ReplyDeadline: unreplied DNS flow -> evidence */
    unsigned failure_episode_gap_ms;     /* FailureEpisodeGap: min spacing between episodes */
    unsigned failure_threshold;          /* FailureThreshold: episodes before verifying */
    unsigned monitor_tick_ms;            /* MonitorTick: evaluation loop period */
    unsigned verify_timeout_ms;          /* VerifyTimeout: per-probe reply wait */
    unsigned verify_attempts;            /* VerifyAttempts: probes per server before giving up */
    unsigned verify_cooldown_ms;         /* VerifyCooldown: min spacing between verifications */
    unsigned recovery_initial_ms;        /* RecoveryInitial: first recovery re-check delay */
    unsigned recovery_max_ms;            /* RecoveryMax: recovery re-check backoff ceiling */
    unsigned recovery_success_threshold; /* RecoverySuccessThreshold: successes to clear failure */
    unsigned resolver_reload_ms;         /* ResolverReload: ResolverSource re-read period */
};

/* Re-reads the config file if its mtime changed since the last load; a cheap
 * stat() no-op otherwise. Missing/invalid keys revert to defaults. */
void failover_config_refresh(void);

/* Returns a thread-safe snapshot of the current configuration. */
struct failover_config failover_config_get(void);

#endif /* FAILOVER_CONFIG_H */
