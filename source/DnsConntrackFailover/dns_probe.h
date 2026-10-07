/*
 * dns_probe.h
 *
 * Active DNS verification: send a minimal query directly to one server and
 * report whether it answered. Any well-formed reply -- including SERVFAIL or
 * NXDOMAIN -- proves the server process is up and serving, which is all the
 * failover decision needs; RCODE-level interpretation is out of scope.
 */

#ifndef DNS_PROBE_H
#define DNS_PROBE_H

#include <stdbool.h>

/* Probes server_ip (IPv4 or IPv6 literal) on port 53, UDP first with a TCP
 * fallback if UDP gets no reply, waiting up to timeout_ms per transport.
 * Returns true if the server answered. */
bool dns_probe(const char *server_ip, unsigned timeout_ms);

#endif /* DNS_PROBE_H */
