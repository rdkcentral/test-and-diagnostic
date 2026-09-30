/*
 * platform_rdkb.c
 *
 * RDK-B implementation of the platform.h seam: WAN status comes from RBUS
 * (WanManager's Device.X_RDK_WanManager.CurrentStatus), and the failover
 * action is a stub to be wired to Firewall Manager/DNS Manager/RBUS.
 */

#define _GNU_SOURCE

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rbus/rbus.h>

#include "platform.h"

#define WAN_STATUS_COMPONENT_NAME      "DnsConntrackFailover"
#define WAN_STATUS_PARAM_NAME          "Device.X_RDK_WanManager.CurrentStatus"
#define WAN_STATUS_VALUE_UP            "Up"

static rbusHandle_t g_wanRbusHandle;
static atomic_bool g_wan_up = false;

static void wan_status_event_handler(rbusHandle_t handle,
                                     rbusEvent_t const *event,
                                     rbusEventSubscription_t *subscription)
{
    (void)handle;
    (void)subscription;

    rbusValue_t value = rbusObject_GetValue(event->data, NULL);
    if (!value)
        return;

    const char *status = rbusValue_GetString(value, NULL);
    bool up = status != NULL && strcmp(status, WAN_STATUS_VALUE_UP) == 0;

    atomic_store(&g_wan_up, up);
    fprintf(stderr, "WAN: %s -> %s\n", WAN_STATUS_PARAM_NAME, up ? "UP" : "DOWN");
}

/* Opens RBUS, seeds the cached state with a one-time get, then subscribes
 * for change events. Returns false if RBUS/WanManager is unavailable; the
 * daemon still runs, but treats WAN as down until a subscription later
 * succeeds. */
bool platform_wan_status_init(void)
{
    int rc = rbus_open(&g_wanRbusHandle, WAN_STATUS_COMPONENT_NAME);
    if (rc != RBUS_ERROR_SUCCESS) {
        fprintf(stderr, "WAN: rbus_open failed: %d\n", rc);
        return false;
    }

    rbusValue_t value = NULL;
    if (rbus_get(g_wanRbusHandle, WAN_STATUS_PARAM_NAME, &value) == RBUS_ERROR_SUCCESS && value) {
        const char *status = rbusValue_GetString(value, NULL);
        atomic_store(&g_wan_up, status != NULL && strcmp(status, WAN_STATUS_VALUE_UP) == 0);
        rbusValue_Release(value);
    }

    rc = rbusEvent_Subscribe(g_wanRbusHandle, WAN_STATUS_PARAM_NAME,
                             wan_status_event_handler, NULL, 0);
    if (rc != RBUS_ERROR_SUCCESS) {
        fprintf(stderr, "WAN: rbusEvent_Subscribe failed for %s: %d\n",
                WAN_STATUS_PARAM_NAME, rc);
        rbus_close(g_wanRbusHandle);
        g_wanRbusHandle = NULL;
        return false;
    }

    fprintf(stderr, "WAN: subscribed to %s, initial state=%s\n",
            WAN_STATUS_PARAM_NAME, atomic_load(&g_wan_up) ? "UP" : "DOWN");
    return true;
}

void platform_wan_status_exit(void)
{
    if (g_wanRbusHandle) {
        rbusEvent_Unsubscribe(g_wanRbusHandle, WAN_STATUS_PARAM_NAME);
        rbus_close(g_wanRbusHandle);
        g_wanRbusHandle = NULL;
    }
}

bool platform_wan_is_reachable(void)
{
    return atomic_load(&g_wan_up);
}

/* unbound.service's own ExecStartPost/ExecStop hooks (redirect-to-unbound.sh /
 * restore-system-dns.sh) apply and undo the DNS redirect; systemctl blocks
 * until those hooks complete, so no iptables rules are needed here. */
void platform_set_unbound_failover(bool enable)
{
    const char *svc_cmd = enable ? "systemctl start unbound" : "systemctl stop unbound";

    fprintf(stderr, "ACTION: Unbound failover %s (RDK-B)\n", enable ? "ENABLE" : "DISABLE");

    if (system(svc_cmd) != 0)
        fprintf(stderr, "ACTION: '%s' failed\n", svc_cmd);
}
