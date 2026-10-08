/*
 * dns_redirect.c -- see dns_redirect.h.
 *
 * Generic Linux implementation: start/stop the local Unbound resolver. The
 * monitor calls this every evaluation tick, so the action is made idempotent
 * here -- the systemctl command runs only when the failover state actually
 * changes.
 */

#define _GNU_SOURCE

#include "dns_redirect.h"

#include "dns_log.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>

/* Minimum spacing between attempts after a failed command. */
#define RETRY_BACKOFF_MS 15000ULL

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

bool dns_redirect_set_failover(bool enable)
{
    static int current = -1; /* -1 unknown, 0 disabled, 1 enabled */
    static uint64_t last_failure_ms;
    static unsigned failures;

    if (current == (int)enable)
        return true; /* no transition: nothing to do */

    uint64_t now = monotonic_ms();
    if (failures != 0 && now - last_failure_ms < RETRY_BACKOFF_MS)
        return false; /* waiting out the backoff after a failed attempt */

    const char *cmd = enable ? "systemctl start unbound" : "systemctl stop unbound";
    LOG_INFO("ACTION: Unbound failover %s", enable ? "ENABLE" : "DISABLE");

    int rc = system(cmd);
    if (rc != 0) {
        failures++;
        last_failure_ms = now ? now : 1;
        if (rc == -1)
            LOG_ERR("ACTION: '%s' could not be run (attempt %u); retrying in %llus",
                    cmd, failures, RETRY_BACKOFF_MS / 1000ULL);
        else if (WIFEXITED(rc))
            LOG_ERR("ACTION: '%s' exited with status %d (attempt %u); retrying in %llus",
                    cmd, WEXITSTATUS(rc), failures, RETRY_BACKOFF_MS / 1000ULL);
        else
            LOG_ERR("ACTION: '%s' terminated abnormally, wait status 0x%x (attempt %u); "
                    "retrying in %llus", cmd, rc, failures, RETRY_BACKOFF_MS / 1000ULL);
        return false; /* state unchanged; the caller retries after the backoff */
    }

    if (failures != 0)
        LOG_INFO("ACTION: '%s' succeeded after %u failed attempt(s)", cmd, failures);
    failures = 0;
    current = (int)enable;

    /*
     * To fully take over resolution, also add DNS redirection here, e.g.:
     *   iptables -t nat -A/-D PREROUTING -i <lan-if> -p udp --dport 53 \
     *       -j DNAT --to-destination 127.0.0.1:5353
     */
    return true;
}
