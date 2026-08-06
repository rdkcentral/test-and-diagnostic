/*
 * If not stated otherwise in this file or this component's LICENSE file
 * the following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * ntp_sync_monitor.c
 *
 * Chrony-gated two-thread NTP clock observer hosted in CcspTandDSsp. See
 * ntp_sync_monitor.h for the design summary. All state in this translation unit
 * is file-static; this file deliberately does NOT touch current_time.c globals
 * (buf, stored_time, ...) to remain thread-safe alongside updateTimeThread.
 *
 * Both threads are spawned only when syscfg:chrony_enabled == "true".
 * Thread 1 uses adjtimex() for daemon-agnostic convergence detection.
 * Thread 2 uses chronyctl_get_offset() (libchronyctl) for periodic metrics.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/timex.h>
#include <sys/timerfd.h>

#include "ccsp_trace.h"
#include "syscfg/syscfg.h"
#include "sysevent/sysevent.h"
#include "telemetry_busmessage_sender.h"
#include "current_time.h"        /* reuse setClockEventFile() */
#include "libchronyctl.h"        /* chronyctl_get_offset(), chronyctl_init/cleanup */
#include "ntp_sync_monitor.h"

#define T2_COMPONENT            "ntp_sync_monitor"
#define FIRST_SYNC_MARKER       "/tmp/.ntp_first_sync_done"
#define NTP_SYNCED_FILE         "/tmp/.ntp_time_synced"

/* T2 marker for Thread 1: first-sync kernel offset/frequency. */
#define T2_MARKER_NTP_DELTA         "SYS_INFO_NTP_DELTA_split"

/* T2 marker for Thread 2: periodic chrony offset via libchronyctl. */
#define T2_MARKER_CHRONY_TRACKING   "SYS_INFO_CHRONY_TRACKING_split"

/* Thread 1: poll kernel sync state once per second, unbounded, until synced. */
#define FIRSTSYNC_POLL_SEC      1

/* Thread 2: sample every 10 minutes. */
#define METRICS_INTERVAL_SEC    600

/* sysevent connection parameters (mirror other TandDSsp producers). */
#define SE_IP                   "127.0.0.1"
#define SE_PROG                 "ntp_sync_monitor"

/*
 * g_chronyctl_mutex — serializes all chronyctl_*() calls except chronyctl_strerror().
 * Per the libchronyctl API contract, the library is not internally thread-safe.
 */
static pthread_mutex_t g_chronyctl_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * read_clock_state
 *   Query kernel clock-discipline state via ntp_adjtime(). Fills *synced (1 if
 *   the clock is currently disciplined), *offset_ns (offset in nanoseconds,
 *   STA_NANO honoured else microseconds*1000) and *freq_ppm (freq/65536.0).
 *   Returns 0 on success, -1 on adjtimex() failure. Daemon-agnostic: reads the
 *   kernel regardless of whether chrony or ntpd disciplines the clock.
 */
static int read_clock_state(int *synced, long long *offset_ns, double *freq_ppm)
{
    struct timex tx;
    memset(&tx, 0, sizeof(tx));

    int state = ntp_adjtime(&tx);   /* mode 0 (all-zero) = read-only query */
    if (state < 0) {
        return -1;
    }

    if (synced != NULL) {
        *synced = (state != TIME_ERROR && !(tx.status & STA_UNSYNC)) ? 1 : 0;
    }

    if (offset_ns != NULL) {
        if (tx.status & STA_NANO)
            *offset_ns = (long long)tx.offset;           /* already ns */
        else
            *offset_ns = (long long)tx.offset * 1000LL;  /* us -> ns */
    }

    if (freq_ppm != NULL) {
        *freq_ppm = (double)tx.freq / 65536.0;
    }

    return 0;
}

/*
 * emit_ntp_delta
 *   Emit the current offset and frequency under the single unified marker.
 *   Used by BOTH the first-sync thread and the periodic thread (no distinction
 *   between first and subsequent samples).
 */
static void emit_ntp_delta(long long offset_ns, double freq_ppm)
{
    char buf[96];
    snprintf(buf, sizeof(buf), "offset_ns=%lld,freq_ppm=%.6f", offset_ns, freq_ppm);
    t2_event_s(T2_MARKER_NTP_DELTA, buf);
    CcspTraceInfo(("NTP_SYNC_MONITOR : delta %s\n", buf));
}

/*
 * notify_first_sync
 *   Write the sync-notification side effects that service_chronyd.sh's
 *   set_chrony_sync_status() produced historically. Returns 0 only when the
 *   required writes succeed, so the caller sets the marker only on success.
 *   Order: syscfg ntp_status=3, sysevent ntp_time_sync=1, /tmp/clock-event,
 *   /tmp/.ntp_time_synced, device_first_use_date (set-if-unset).
 */
static int notify_first_sync(void)
{
    int rc = 0;

    if (syscfg_set_commit(NULL, "ntp_status", "3") != 0) {
        CcspTraceError(("NTP_SYNC_MONITOR : syscfg set ntp_status failed\n"));
        rc = -1;
    }

    token_t token;
    int se_fd = sysevent_open(SE_IP, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION,
                              SE_PROG, &token);
    if (se_fd >= 0) {
        if (sysevent_set(se_fd, token, "ntp_time_sync", "1", 0) != 0) {
            CcspTraceError(("NTP_SYNC_MONITOR : sysevent set ntp_time_sync failed\n"));
            rc = -1;
        }
        sysevent_close(se_fd, token);
    } else {
        CcspTraceError(("NTP_SYNC_MONITOR : sysevent_open failed\n"));
        rc = -1;
    }

    /* Reuse the existing helper (idempotent) to create /tmp/clock-event. */
    setClockEventFile();

    int fd = open(NTP_SYNCED_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0)
        close(fd);
    else
        rc = -1;

    /* device_first_use_date: stamp only if unset or "0". */
    char dfud[64] = {0};
    if (syscfg_get(NULL, "device_first_use_date", dfud, sizeof(dfud)) != 0 ||
        dfud[0] == '\0' || strcmp(dfud, "0") == 0) {
        time_t now = time(NULL);
        struct tm tmv;
        char ts[32];
        localtime_r(&now, &tmv);
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmv);
        if (syscfg_set_commit(NULL, "device_first_use_date", ts) != 0) {
            CcspTraceError(("NTP_SYNC_MONITOR : syscfg set device_first_use_date failed\n"));
            rc = -1;
        }
    }

    return rc;
}

/*
 * first_sync_thread (Thread 1)
 *   No-op if the marker already exists. Otherwise polls the kernel every 1s in
 *   an unbounded loop until the first sync; on sync it emits the initial
 *   offset/frequency, writes the side effects, and (only if they succeed) sets
 *   the marker and exits. If the side effects fail (e.g. sysevent not ready),
 *   it retries on the next poll rather than losing the signals.
 */
static void *first_sync_thread(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());

    if (access(FIRST_SYNC_MARKER, F_OK) == 0) {
        return NULL;    /* already recorded this boot */
    }

    CcspTraceInfo(("NTP_SYNC_MONITOR : firstsync - waiting for first NTP sync\n"));

    for (;;) {
        int synced = 0;
        long long offset_ns = 0;
        double freq_ppm = 0.0;

        if (read_clock_state(&synced, &offset_ns, &freq_ppm) == 0 && synced) {
            emit_ntp_delta(offset_ns, freq_ppm);

            if (notify_first_sync() == 0) {
                int fd = open(FIRST_SYNC_MARKER, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd >= 0)
                    close(fd);
                CcspTraceInfo(("NTP_SYNC_MONITOR : firstsync - first NTP sync recorded\n"));
                return NULL;
            }
            /* side effects not fully applied yet — retry on next poll */
            CcspTraceWarning(("NTP_SYNC_MONITOR : firstsync - side effects incomplete, retrying\n"));
        }

        sleep(FIRSTSYNC_POLL_SEC);
    }

    return NULL;
}

/*
 * metrics_thread (Thread 2)
 *   Every 10 minutes queries the current NTP clock offset from chronyd via
 *   chronyctl_get_offset() (libchronyctl Unix-socket API) and emits it under
 *   T2_MARKER_CHRONY_TRACKING. Uses timerfd rather than sleep(600) for
 *   drift-free, signal-safe intervals.
 *   All chronyctl_*() calls are serialized by g_chronyctl_mutex per the
 *   libchronyctl thread-safety contract.
 */
static void *metrics_thread(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());

    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tfd < 0) {
        CcspTraceError(("NTP_SYNC_MONITOR : metrics - timerfd_create failed: %s\n",
                        strerror(errno)));
        return NULL;
    }

    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec    = METRICS_INTERVAL_SEC;   /* first fire */
    its.it_interval.tv_sec = METRICS_INTERVAL_SEC;   /* then every 10 min */

    if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
        CcspTraceError(("NTP_SYNC_MONITOR : metrics - timerfd_settime failed: %s\n",
                        strerror(errno)));
        close(tfd);
        return NULL;
    }

    for (;;) {
        uint64_t expirations = 0;
        ssize_t n = read(tfd, &expirations, sizeof(expirations));
        if (n != (ssize_t)sizeof(expirations)) {
            if (errno == EINTR)
                continue;   /* interrupted by a signal; interval still runs */
            CcspTraceError(("NTP_SYNC_MONITOR : metrics - timerfd read failed: %s\n",
                            strerror(errno)));
            break;
        }

        double offset_s = 0.0;
        int ret;

        pthread_mutex_lock(&g_chronyctl_mutex);
        ret = chronyctl_get_offset(&offset_s);
        pthread_mutex_unlock(&g_chronyctl_mutex);

        if (ret == CHRONYCTL_SUCCESS) {
            char buf[64];
            snprintf(buf, sizeof(buf), "offset_s=%.9f", offset_s);
            t2_event_s(T2_MARKER_CHRONY_TRACKING, buf);
            CcspTraceInfo(("NTP_SYNC_MONITOR : metrics - %s\n", buf));
        } else {
            CcspTraceError(("NTP_SYNC_MONITOR : metrics - chronyctl_get_offset failed: %s\n",
                            chronyctl_strerror(ret)));
        }
    }

    close(tfd);
    return NULL;
}

/*
 * ntp_sync_monitor_start
 *   Entry point called from ssp_main.c. Guards on syscfg:chrony_enabled;
 *   returns immediately (no threads spawned) when chrony is not the active
 *   NTP client. When chrony_enabled=="true", initialises libchronyctl and
 *   Telemetry 2.0, then spawns both detached threads.
 */
void ntp_sync_monitor_start(void)
{
    char chrony_enabled[8] = {0};
    int rc = syscfg_get(NULL, "chrony_enabled", chrony_enabled, sizeof(chrony_enabled));
    if (rc != 0) {
        CcspTraceError(("NTP_SYNC_MONITOR : syscfg_get chrony_enabled failed (rc=%d), not starting\n", rc));
        return;
    }
    if (strcmp(chrony_enabled, "true") != 0) {
        CcspTraceInfo(("NTP_SYNC_MONITOR : chrony_enabled='%s', skipping NTP monitor threads\n",
                       chrony_enabled));
        return;
    }

    /* Initialise libchronyctl before spawning threads. */
    pthread_mutex_lock(&g_chronyctl_mutex);
    rc = chronyctl_init();
    pthread_mutex_unlock(&g_chronyctl_mutex);
    if (rc != CHRONYCTL_SUCCESS) {
        CcspTraceError(("NTP_SYNC_MONITOR : chronyctl_init failed: %s, not starting\n",
                        chronyctl_strerror(rc)));
        return;
    }

    pthread_t tid;

    t2_init(T2_COMPONENT);

    if (pthread_create(&tid, NULL, first_sync_thread, NULL) != 0)
        CcspTraceError(("NTP_SYNC_MONITOR : failed to start first-sync thread\n"));

    if (pthread_create(&tid, NULL, metrics_thread, NULL) != 0)
        CcspTraceError(("NTP_SYNC_MONITOR : failed to start metrics thread\n"));

    CcspTraceInfo(("NTP_SYNC_MONITOR : chrony_enabled=true, threads started\n"));
}
