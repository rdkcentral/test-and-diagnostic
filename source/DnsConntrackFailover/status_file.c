/*
 * status_file.c -- see status_file.h.
 */

#define _GNU_SOURCE

#include "status_file.h"

#include "dns_log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define STATUS_PATH     "/tmp/dns_conntrack_failover_status.txt"
#define STATUS_TMP_PATH STATUS_PATH ".tmp"

static const char *format_time(time_t t, char *buf, size_t len)
{
    struct tm tm;

    if (t == 0 || !gmtime_r(&t, &tm) ||
        strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
        return "None";
    return buf;
}

/* Writes content to a temp file and renames it over the status file. */
static bool write_atomic(const char *content, size_t len)
{
    /* O_NOFOLLOW: /tmp is world-writable, so refuse a pre-planted symlink. */
    int fd = open(STATUS_TMP_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0)
        return false;

    bool ok = fchmod(fd, 0644) == 0 && write(fd, content, len) == (ssize_t)len;
    ok = (close(fd) == 0) && ok;

    if (ok)
        ok = rename(STATUS_TMP_PATH, STATUS_PATH) == 0;
    if (!ok)
        unlink(STATUS_TMP_PATH);
    return ok;
}

void status_file_update(const struct status_info *info)
{
    static char last[512];
    static bool err_logged;
    char failure[32], recovery[32], content[512];

    int n = snprintf(content, sizeof(content),
                     "State=%s\n"
                     "ActiveResolverCount=%d\n"
                     "LastFailureTime=%s\n"
                     "LastRecoveryTime=%s\n"
                     "LastVerificationResult=%s\n",
                     info->state, info->active_resolver_count,
                     format_time(info->last_failure_time, failure, sizeof(failure)),
                     format_time(info->last_recovery_time, recovery, sizeof(recovery)),
                     info->last_verification);
    if (n < 0 || (size_t)n >= sizeof(content))
        return;

    if (strcmp(content, last) == 0)
        return;

    if (!write_atomic(content, (size_t)n)) {
        if (!err_logged)
            LOG_ERR("STATUS: cannot write %s: %s", STATUS_PATH, strerror(errno));
        err_logged = true;
        return;
    }

    err_logged = false;
    memcpy(last, content, (size_t)n + 1);
}
