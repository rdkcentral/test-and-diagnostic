/*
 * status_file.h
 *
 * Publishes the monitor's status as key=value lines in
 * /tmp/dns_failover_status.txt for scripts and diagnostics.
 */

#ifndef STATUS_FILE_H
#define STATUS_FILE_H

#include <time.h>

struct status_info {
    const char *state;              /* Disabled, Healthy, Suspect, Failed or FailoverActive */
    int         active_resolver_count;
    time_t      last_failure_time;  /* 0 = never */
    time_t      last_recovery_time; /* 0 = never */
    const char *last_verification;  /* Success, Failed or None */
};

/* Rewrites the file atomically, and only when the content changed. */
void status_file_update(const struct status_info *info);

#endif /* STATUS_FILE_H */
