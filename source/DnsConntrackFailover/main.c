/*
 * main.c
 *
 * Entry point for the DNS conntrack failover monitor. Wires signal handling to
 * a clean shutdown and hands control to the monitor; all behaviour lives in the
 * dns_monitor and its collaborating modules.
 */

#include "dns_monitor.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dns_log.h"
#include "rdk_debug.h"
#include <telemetry_busmessage_sender.h>

#define PID_FILE "/tmp/dns_failover_manager.pid"

static void write_pid_file(void)
{
    FILE *fp = fopen(PID_FILE, "w");
    if (!fp) {
        LOG_ERR("cannot create %s", PID_FILE);
        return;
    }
    fprintf(fp, "%d\n", (int)getpid());
    fclose(fp);
}

static void on_signal(int signo)
{
    if (signo == SIGUSR1)
        dns_monitor_reload_config();
    else
        dns_monitor_stop();
}

int main(void)
{
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGUSR1, on_signal);

    setenv("LOG4C_RCPATH", "/rdklogger", 1);
    rdk_logger_init("/etc/debug.ini");

    write_pid_file(); /* after handlers are installed so SIGUSR1 is never fatal */

    t2_init("dns_failover_manager");
    int rc = dns_monitor_run();
    t2_uninit();

    unlink(PID_FILE);

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
