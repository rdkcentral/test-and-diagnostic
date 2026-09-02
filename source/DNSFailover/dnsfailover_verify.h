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
 * dnsfailover_verify.h
 *
 * Asynchronous active DNS verification. A single controlled DNS query is
 * sent directly to a suspect upstream server (bypassing the normal resolver
 * stack) to confirm whether it is actually unreachable before the daemon
 * commits to a failover decision.
 *
 * All network I/O happens on a dedicated worker thread so the state mutex
 * (ctx->lock) is never held during a blocking socket operation.
 */

#ifndef DNSFAILOVER_VERIFY_H
#define DNSFAILOVER_VERIFY_H

#include "dnsfailover.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PENDING_VERIFY_JOBS 16U

/* Starts the verify worker thread and its job queue. Returns true on success. */
bool DnsFailover_VerifyStart(struct dnsfailover_ctx *ctx);

/* Signals the worker thread to stop and joins it. */
void DnsFailover_VerifyStop(struct dnsfailover_ctx *ctx);

/* Enqueues an asynchronous verification request for the given server.
 * Non-blocking; silently drops the request (and logs) if the queue is full,
 * since a subsequent monitor tick will re-queue if still needed.
 * Safe to call while ctx->lock is held. */
void DnsFailover_QueueVerify(struct dnsfailover_ctx *ctx, const dns_addr_t *server);

#ifdef __cplusplus
}
#endif

#endif /* DNSFAILOVER_VERIFY_H */
