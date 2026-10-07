/*
 * wan_status.h
 *
 * WAN reachability check. The monitor only treats DNS timeouts as evidence of
 * server failure while the WAN is up; if the WAN itself is down, all upstream
 * DNS would time out regardless, so that signal is meaningless.
 */

#ifndef WAN_STATUS_H
#define WAN_STATUS_H

#include <stdbool.h>

/* Samples the initial WAN state. Returns false if the status source is not
 * available yet; the caller should keep running and treat WAN as down until
 * it becomes available. */
bool wan_status_init(void);

/* Releases anything acquired by wan_status_init(). Safe to call unconditionally. */
void wan_status_exit(void);

/* Returns current WAN reachability. Safe to call from any thread. */
bool wan_status_is_reachable(void);

#endif /* WAN_STATUS_H */
