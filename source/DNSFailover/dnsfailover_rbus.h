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
 * dnsfailover_rbus.h
 *
 * TR-181 exposure for the DNSFailover daemon, implemented as native RBUS
 * data elements (rbus_regDataElements), matching the pattern already used
 * by wan-manager (wanmgr_rbus_handler_apis.c) and DevicePrioritization
 * (device_prio_rbus_handler_apis.c) in this repository.
 *
 * Namespace: Device.X_RDK_Features.DNSFailover.*
 *
 * Full WebConfig blob decoding and a dynamic per-server RBUS table are
 * deferred to future work (per project scope decision); v1 exposes the
 * core Enable/tunable parameters plus a bounded (MAX_DNS_SERVERS) set of
 * per-index diagnostic parameters, which is sufficient for dmcli-based
 * inspection and TR-069/WebConfig ACS integration via the existing
 * component's data model translation layer.
 */

#ifndef DNSFAILOVER_RBUS_H
#define DNSFAILOVER_RBUS_H

#include "dnsfailover.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNSFAILOVER_DM_BASE "Device.X_RDK_Features.DNSFailover."

/* Opens the RBUS connection (ctx->rbus_handle) and registers all config and
 * diagnostic data elements. Loads cfg defaults into ctx->cfg first, so get
 * handlers always have a valid value to return even before any TR-181 set.
 * Returns true on success. If RBUS is unavailable, ctx->rbus_handle is left
 * NULL and the daemon continues in a degraded, config-via-defaults-only
 * mode (WAN status and server discovery fall back accordingly). */
bool DnsFailover_RbusInit(struct dnsfailover_ctx *ctx);

void DnsFailover_RbusTerminate(struct dnsfailover_ctx *ctx);

/* Populates ctx->cfg with compiled-in defaults. Called before RBUS init so
 * every field is well-defined regardless of RBUS availability. */
void DnsFailover_LoadDefaultConfig(struct dnsfailover_config *cfg);

#ifdef __cplusplus
}
#endif

#endif /* DNSFAILOVER_RBUS_H */
