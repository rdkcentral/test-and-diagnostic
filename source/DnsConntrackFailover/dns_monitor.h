/*
 * dns_monitor.h
 *
 * The DNS failure detector. Subscribes to conntrack events, tracks per-server
 * health from passive timeout evidence plus active verification, and toggles
 * failover when every configured upstream resolver is confirmed down.
 */

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

/* Runs the monitor: opens conntrack, starts the event thread, and drives the
 * evaluation loop until dns_monitor_stop() is called. Blocks for the lifetime
 * of the service. Returns 0 on clean shutdown, non-zero on fatal setup error. */
int dns_monitor_run(void);

/* Requests shutdown of the run loop. Async-signal-safe (for signal handlers). */
void dns_monitor_stop(void);

#endif /* DNS_MONITOR_H */
