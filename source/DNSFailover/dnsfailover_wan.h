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
 * dnsfailover_wan.h
 *
 * WAN connectivity qualification. Primary source of truth is an RBUS
 * subscription to Device.X_RDK_WanManager.ConnectionStatus (event-driven,
 * no polling). If RBUS is unavailable or the subscription fails, falls
 * back to periodically checking for a default route in /proc/net/route
 * (see WAN_STATUS_DETECTION.md, Method 3).
 */

#ifndef DNSFAILOVER_WAN_H
#define DNSFAILOVER_WAN_H

#include "dnsfailover.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WAN_ROUTE_FALLBACK_POLL_SEC 10U

/* Reads the current WAN status once (rbus_get, or /proc/net/route fallback)
 * and primes ctx->wan_is_up before the daemon makes any failover decisions.
 * Then subscribes to the RBUS change event (or starts the fallback polling
 * thread if RBUS subscription is unavailable). Returns true on success. */
bool DnsFailover_WanStart(struct dnsfailover_ctx *ctx);

/* Unsubscribes / stops the fallback polling thread. */
void DnsFailover_WanStop(struct dnsfailover_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* DNSFAILOVER_WAN_H */
