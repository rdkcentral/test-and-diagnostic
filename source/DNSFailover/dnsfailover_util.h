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

#ifndef DNSFAILOVER_UTIL_H
#define DNSFAILOVER_UTIL_H

#include "dnsfailover.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Monotonic clock, milliseconds. Returns 0 on failure (should not happen). */
uint64_t DnsFailover_MonotonicMs(void);

/* Sleep for the given number of milliseconds, restarting on EINTR unless
 * *running becomes false (checked once per interruption, not polled). */
void DnsFailover_SleepMs(unsigned ms, const volatile sig_atomic_t *running);

/* Compare two dns_addr_t for equality (address family and bytes). */
bool DnsFailover_AddrEqual(const dns_addr_t *a, const dns_addr_t *b);

/* Render an address to a human-readable string. buf must be at least
 * INET6_ADDRSTRLEN bytes. Always returns buf. */
const char *DnsFailover_AddrToString(const dns_addr_t *addr, char *buf, size_t len);

/* Parse a numeric IPv4 or IPv6 literal into a dns_addr_t. Returns false on
 * invalid input (defensive validation for all externally supplied strings:
 * TR-181 values, /etc/resolv.conf lines, rbus results). */
bool DnsFailover_AddrFromString(const char *str, dns_addr_t *out);

/* FNV-1a style hash over a flow_key, used for the pending-flow hash table. */
uint32_t DnsFailover_FlowHash(const struct flow_key *k);

bool DnsFailover_FlowKeyEqual(const struct flow_key *a, const struct flow_key *b);

/* Returns a jittered delay in milliseconds within [base*(1-frac), base*(1+frac)].
 * Used to avoid synchronized recovery-probe storms across a fleet of devices. */
uint32_t DnsFailover_JitterMs(uint32_t base_ms, double frac);

#ifdef __cplusplus
}
#endif

#endif /* DNSFAILOVER_UTIL_H */
