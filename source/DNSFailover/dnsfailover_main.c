/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
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
 * dnsfailover_main.c
 *
 * Entry point for the standalone DNSFailover daemon. Wires together:
 *   - RBUS/TR-181 registration (dnsfailover_rbus.c)
 *   - firewall/Unbound DNAT chain setup (dnsfailover_firewall.c)
 *   - DNS server discovery (dnsfailover_servers.c)
 *   - WAN status detection (dnsfailover_wan.c)
 *   - conntrack passive-detection state machine (dnsfailover_conntrack.c)
 *   - active-verification worker (dnsfailover_verify.c)
 *
 * Process lifecycle mirrors test-and-diagnostic/source/TandDSsp/ssp_main.c
 * (fork/setsid daemonize, signal handlers), adapted to request a graceful
 * shutdown (ctx.running = 0) rather than an immediate exit(), so in-flight
 * conntrack/verify work is drained and the firewall chain is cleaned up
 * before the process exits.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include "ccsp_trace.h"

#include "dnsfailover.h"
#include "dnsfailover_util.h"
#include "dnsfailover_rbus.h"
#include "dnsfailover_firewall.h"
#include "dnsfailover_servers.h"
#include "dnsfailover_wan.h"
#include "dnsfailover_conntrack.h"
#include "dnsfailover_verify.h"

static struct dnsfailover_ctx g_ctx;

static void Daemonize(void)
{
    switch (fork()) {
    case 0:
        break;
    case -1:
        CcspTraceError(("%s: fork() failed: %s\n", __FUNCTION__, strerror(errno)));
        exit(1);
    default:
        _exit(0);
    }

    if (setsid() < 0) {
        CcspTraceError(("%s: setsid() failed: %s\n", __FUNCTION__, strerror(errno)));
        exit(1);
    }

    int fd = open("/dev/null", O_RDONLY);
    if (fd >= 0) {
        if (fd != 0) dup2(fd, 0);
        if (fd > 2) close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) {
        if (fd != 1) dup2(fd, 1);
        if (fd != 2) dup2(fd, 2);
        if (fd > 2) close(fd);
    }
}

static void SigHandler(int sig)
{
    /* Async-signal-safe: only sets a sig_atomic_t flag. All real shutdown
     * work happens in main()'s loop after DnsFailover_SleepMs() wakes up. */
    if (sig == SIGTERM || sig == SIGINT) {
        g_ctx.running = 0;
    }
}

static void InstallSignalHandlers(void)
{
    signal(SIGTERM, SigHandler);
    signal(SIGINT, SigHandler);
    signal(SIGPIPE, SIG_IGN);
}

int main(int argc, char *argv[])
{
    bool run_as_daemon = true;

    setlinebuf(stdout);
    setlinebuf(stderr);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0)
            run_as_daemon = false;
    }

    if (run_as_daemon)
        Daemonize();

    InstallSignalHandlers();

    memset(&g_ctx, 0, sizeof(g_ctx));
    if (pthread_mutex_init(&g_ctx.lock, NULL) != 0) {
        CcspTraceError(("%s: pthread_mutex_init failed\n", __FUNCTION__));
        return 1;
    }
    g_ctx.running = 1;

    DnsFailover_LoadDefaultConfig(&g_ctx.cfg);

    /* RBUS is best-effort: if unavailable, TR-181 parameters are not
     * exposed but the daemon still runs on compiled-in defaults. WAN
     * status and server discovery each have their own non-RBUS fallback. */
    DnsFailover_RbusInit(&g_ctx);

    if (!DnsFailover_FirewallInit(&g_ctx.cfg)) {
        CcspTraceError(("%s: firewall init failed; failover redirect will not be "
                        "available. Continuing in detection-only mode.\n", __FUNCTION__));
    }

    if (!DnsFailover_WanStart(&g_ctx)) {
        CcspTraceError(("%s: WAN status detection failed to start\n", __FUNCTION__));
    }

    if (!DnsFailover_ServersStart(&g_ctx)) {
        CcspTraceWarning(("%s: no DNS servers discovered at startup; will keep "
                          "retrying on the periodic refresh timer\n", __FUNCTION__));
    }

    if (!DnsFailover_VerifyStart(&g_ctx)) {
        CcspTraceError(("%s: failed to start verify worker; active verification "
                        "disabled for this run\n", __FUNCTION__));
    }

    if (!DnsFailover_ConntrackStart(&g_ctx)) {
        CcspTraceError(("%s: failed to start conntrack monitor; daemon cannot "
                        "detect DNS failures and will exit\n", __FUNCTION__));
        DnsFailover_VerifyStop(&g_ctx);
        DnsFailover_WanStop(&g_ctx);
        DnsFailover_ServersStop(&g_ctx);
        DnsFailover_FirewallCleanup(&g_ctx.cfg);
        DnsFailover_RbusTerminate(&g_ctx);
        return 1;
    }

    CcspTraceInfo(("%s: DNSFailover daemon started (monitor_tick_ms=%u)\n",
                   __FUNCTION__, g_ctx.cfg.monitor_tick_ms));

    while (g_ctx.running) {
        DnsFailover_MonitorTick(&g_ctx);
        DnsFailover_SleepMs(g_ctx.cfg.monitor_tick_ms, &g_ctx.running);
    }

    CcspTraceInfo(("%s: shutdown requested, stopping subsystems\n", __FUNCTION__));

    DnsFailover_ConntrackStop(&g_ctx);
    DnsFailover_VerifyStop(&g_ctx);
    DnsFailover_WanStop(&g_ctx);
    DnsFailover_ServersStop(&g_ctx);
    DnsFailover_FirewallCleanup(&g_ctx.cfg);
    DnsFailover_RbusTerminate(&g_ctx);

    pthread_mutex_destroy(&g_ctx.lock);

    CcspTraceInfo(("%s: DNSFailover daemon exiting cleanly\n", __FUNCTION__));
    return 0;
}
