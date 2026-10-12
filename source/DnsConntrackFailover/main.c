/*
 * main.c
 *
 * Entry point for the DNS conntrack failover monitor. Wires signal handling to
 * a clean shutdown and hands control to the monitor; all behaviour lives in the
 * dns_monitor and its collaborating modules.
 */

#include "dns_monitor.h"

#include <signal.h>
#include <stdlib.h>

#include <telemetry_busmessage_sender.h>

static void on_signal(int signo)
{
    (void)signo;
    dns_monitor_stop();
}

int main(void)
{
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    t2_init("dns_conntrack_failover");
    int rc = dns_monitor_run();
    t2_uninit();

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
