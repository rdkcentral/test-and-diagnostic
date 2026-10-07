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

static void on_signal(int signo)
{
    (void)signo;
    dns_monitor_stop();
}

int main(void)
{
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    return dns_monitor_run() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
