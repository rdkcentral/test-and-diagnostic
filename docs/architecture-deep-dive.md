# Architecture Deep Dive

## 1. CCSP Framework Integration

### TR-181 Data Model Registration

TAD registers its namespace with the CCSP Component Registrar (CR) during `ssp_engage_tad()`. The data model is auto-generated from `config/TestAndDiagnostic_arm.XML` by `dm_pack_code_gen.py`, producing `dm_pack_datamodel.c` at build time.

**Registration call chain:**
```
ssp_engage_tad()
  → pDslhCpeController->RegisterCcspDataModel2(
        CrName    = "eRT.com.cisco.spvtg.ccsp.CR",
        XML       = DMPackCreateDataModelXML,
        CompName  = "com.cisco.spvtg.ccsp.tdm",
        CompVer   = 1,
        CompPath  = "/com/cisco/spvtg/ccsp/tdm",
        Subsystem = "eRT."
    )
```

This registers ownership of these TR-181 namespaces:
- `Device.IP.Diagnostics.*`
- `Device.DNS.Diagnostics.*`
- `Device.SelfHeal.*`
- `Device.LogBackup.*`
- `Device.PowerManagement.*`
- `Device.Thermal.*`
- `Device.X_RDK_hwHealthTest.*`
- `Device.X_RDK_AutomationTest.*`

### DML Callback Pattern

Every TR-181 parameter is implemented as a set of C callback functions registered in `plugin_main.c`. The CCSP framework dispatches D-Bus parameter requests to these callbacks.

```c
// Standard DML callback signature pattern:
BOOL <Object>_GetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL* pBool);
BOOL <Object>_SetParamBoolValue(ANSC_HANDLE hInsContext, char* ParamName, BOOL bValue);
ULONG <Object>_GetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName,
                                    char* pValue, ULONG* pUlSize);
// Return: 0=success, 1=buffer too small (caller retries), -1=not supported

// Table entry lifecycle:
ULONG <Table>_GetEntryCount(ANSC_HANDLE hInsContext);
ANSC_HANDLE <Table>_GetEntry(ANSC_HANDLE hInsContext, ULONG nIndex, ULONG* pInsNumber);
ANSC_HANDLE <Table>_AddEntry(ANSC_HANDLE hInsContext, ULONG* pInsNumber);
ANSC_STATUS <Table>_DelEntry(ANSC_HANDLE hInsContext, ANSC_HANDLE hInstance);
BOOL <Table>_Validate(ANSC_HANDLE hInsContext, ANSC_HANDLE hInstance, char* pErr, ULONG ulSize);
ULONG <Table>_Commit(ANSC_HANDLE hInsContext, ANSC_HANDLE hInstance);
ULONG <Table>_Rollback(ANSC_HANDLE hInsContext, ANSC_HANDLE hInstance);
```

## 2. BBHM Object Model Deep Dive

### ANSC COM-Style Pattern

The BBHM diagnostic subsystem uses a C-based object-oriented pattern that simulates C++ inheritance via macro-embedded "class content". Each object type defines a `*_CLASS_CONTENT` macro that includes its parent's class content, creating a flat struct with all inherited and new fields.

```c
// Hierarchy:
#define BBHM_DIAG_EXEC_CLASS_CONTENT    \
    ANSCCO_CLASS_CONTENT                \   // Base ANSC component object
    ANSC_LOCK         AccessLock;       \
    BOOL              bActive;          \
    ANSC_HANDLE       hDslhDiagInfo;    \
    // ... methods as function pointers
    PFN_BBHM_STARTDIAG   StartDiag;    \   // Virtual (overridable)
    PFN_BBHM_STOPDIAG    StopDiag;     \   // Virtual

#define BBHM_DIAG_IP_PING_CLASS_CONTENT \
    BBHM_DIAG_EXEC_CLASS_CONTENT       \   // Inherit executor
    BBHM_IP_PING_PROPERTY Property;    \   // IPPing-specific data
    ANSC_HANDLE    hSinkObject;        \   // Raw socket sink
    ANSC_HANDLE    hXsocketObject;     \   // Socket wrapper
    ANSC_HANDLE    hDiagTdo;           \   // Timer descriptor
    // ... additional methods
```

### Virtual Method Dispatch

"Virtual" methods are overridden by setting function pointers during object creation:

```c
// In bbhm_diagip_base.c → BbhmDiagipCreate():
pMyObject = BbhmDiageoCreate(container, owner, reserved);  // Base creation
pMyObject->StartDiag     = BbhmDiagipStartDiag;    // Override
pMyObject->StopDiag      = BbhmDiagipStopDiag;     // Override
pMyObject->CopyDiagParams = BbhmDiagipCopyDiagParams; // Override
pMyObject->RetrieveResult = BbhmDiagipRetrieveResult; // Override
```

### Diagnostic Completion Notification

When a diagnostic completes, the BBHM engine sends a D-Bus signal:

```c
CosaSendDiagCompleteSignal()
  → CcspBaseIf_SenddiagCompleteSignal(g_MessageBusHandle, ...)
```

This allows the DML layer to detect completion and update `DiagnosticsState` for the next GetParameterValues query.

## 3. Self-Heal Architecture Details

### Cron vs. Process Mode

The execution mode is determined by `SelfHealCronEnable` syscfg key:

| Mode | Behavior | Advantages | Disadvantages |
|------|----------|------------|---------------|
| CRON | Scripts invoked by crontab periodically | Low memory footprint, clean exit | No state between runs, cron dependency |
| PROCESS | Scripts run as long-lived background processes | Persistent state, faster response | Higher memory, crash risk |

### Script Dependency Graph

```
boot_mode.sh (sourced by all)
├── Provides: MODE variable, acquire_lock(), LOCKFILE paths
│
corrective_action.sh (sourced by all heal scripts)
├── Provides: resetNeeded(), rebootNeeded(), resetRouter()
├── Provides: checkConditionsbeforeAction(), storeInformation()
├── Provides: checkMaintenanceWindow(), setRebootreason()
│
self_heal_connectivity_test.sh → corrective_action.sh + boot_mode.sh
resource_monitor.sh → corrective_action.sh + boot_mode.sh
│   └── task_health_monitor.sh → corrective_action.sh
│       └── xle_selfheal (binary, XLE only)
selfheal_aggressive.sh → corrective_action.sh + boot_mode.sh
```

### Self-Heal Timing

```
Time
  │
0 ├── Boot
  │
5m├── selfheal_aggressive.sh starts (5-min cycle)
  │   └── DHCP, interface, WAN quick checks
  │
10m├── selfheal_bootup.sh (one-shot process checks)
   │
15m├── resource_monitor.sh starts (15-min cycle)
   │   └── CPU/memory monitoring
   │   └── [maintenance window] → task_health_monitor.sh (20+ process checks)
   │
60m├── self_heal_connectivity_test.sh (60-min cycle)
   │   └── GW ping, server ping, DNS test
   │
   ├── log_hourly.sh → uptime + mem/cpu info
   │
   ├── dhcp_rouge_server_detection.sh (hourly, >1h uptime)
   │
   ├── check_memory_health.sh (on threshold breach)
   │
   └── ... repeat ...
```

## 4. Syscfg Key Reference

### Self-Heal Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `selfheal_enable` | bool | true | Master self-heal enable |
| `SelfHealCronEnable` | bool | varies | CRON vs PROCESS mode |
| `ConnTest_PingInterval` | int | 60 | Minutes between connectivity tests |
| `ConnTest_NumPingsPerServer` | int | 3 | Pings per server per test |
| `ConnTest_MinNumPingServer` | int | 1 | Min servers that must reply |
| `ConnTest_PingRespWaitTime` | int | 1000 | Ping timeout (ms) |
| `ConnTest_CorrectiveAction` | bool | true | Allow corrective actions |
| `resource_monitor_interval` | int | 15 | Minutes between resource checks |
| `avg_cpu_threshold` | int | 100 | CPU % threshold |
| `avg_memory_threshold` | int | 100 | Memory % threshold |
| `max_reboot_count` | int | 3 | Max reboots per 24h |
| `max_reset_count` | int | 3 | Max process resets per 24h |
| `AggressiveInterval` | int | 5 | Minutes for aggressive heal cycle |
| `Selfheal_DiagnosticMode` | bool | false | Suppresses corrective actions |
| `selfheal_dns_pingtest_enable` | bool | false | DNS lookup test enable |
| `selfheal_dns_pingtest_url` | string | — | DNS test URL |
| `Free_Mem_Threshold` | int | — | Min free memory (MB) |
| `Mem_Frag_Threshold` | int | 50 | Memory fragmentation % threshold |
| `router_reboot_Interval` | int | — | Min seconds between reboots |

### Ping Server Tables

| Key Pattern | Description |
|-------------|-------------|
| `Ipv4PingServer_Count` | Number of IPv4 servers |
| `Ipv4_PingServer_<N>` | IPv4 server N address |
| `Ipv6PingServer_Count` | Number of IPv6 servers |
| `Ipv6_PingServer_<N>` | IPv6 server N address |

### Diagnostic State

| Key | Description |
|-----|-------------|
| `todays_reboot_count` | Current reboot count for today |
| `todays_reset_count` | Current reset count for today |
| `lastActiontakentime` | Timestamp of last corrective action |
| `last_router_reboot_time` | Timestamp of last router reboot |
| `last_reboot_reason` | Reason for last reboot |

### Latency & QoS

| Key | Description |
|-----|-------------|
| `LatencyMeasure_IPv4Enable` | IPv4 latency capture enable |
| `LatencyMeasure_IPv6Enable` | IPv6 latency capture enable |
| `LatencyMeasure_TCP_ReportInterval` | Report interval (minutes) |
| `LatencyMeasure_PercentileCalc_Enable` | Enable percentile calculation |

## 5. Telemetry Integration

TAD reports operational events via Telemetry 2.0 (`t2_init`, `t2_event_s`, `t2_event_d`) and marker-based logging.

### Key Telemetry Markers

| Marker | Source | Meaning |
|--------|--------|---------|
| `SYS_SH_Reboot_split` | corrective_action.sh | Self-heal initiated reboot |
| `SYS_SH_Ping_split` | connectivity_test.sh | Connectivity failure reboot |
| `SYS_SH_MEM_split` | resource_monitor.sh | Memory threshold reboot |
| `SYS_SH_CPU_split` | resource_monitor.sh | CPU threshold reboot |
| `RDKB_REBOOT` | corrective_action.sh | Any self-heal reboot |
| `THERMAL:Fan_Rotor_Lock` | check_fan.sh | Fan hardware failure |
| `SYS_INFO_CrashPortalEnable` | task_health_monitor.sh | Captive portal re-enabled |
| `IHC_*` | ImageHealthChecker | Image health check findings |

## 6. Platform Abstraction

ARM-specific code overrides are in `source-arm/`:

| Override | Generic | ARM-Specific |
|----------|---------|-------------|
| ARP table reading | `/proc/net/arp` or utapi | `ip neigh show` output parsing |
| IP Ping address resolution | Multi-step DNS | Single `getaddrinfo()` call (performance) |
| DML API registration | Base set | Adds NSLookup, ARP, Download/Upload table callbacks |

Platform-specific code is compiled into separate libraries (`libdmlarm.la`, `libdiagprivarm.la`) and linked alongside the generic implementation.

## 7. Platform-Specific Edge Cases

### Multi-Core Devices (ARM + Atom)

On devices with separate ARM and Atom processors (e.g., XB3):
- `task_health_monitor.sh` pings the Atom processor via `arping_peer`/`ping_peer`
- 3 consecutive ping failures → full device reboot (peer presumed hung)
- `rpcclient` is used to query Atom load average and process status
- `downstream_manager` CPU monitoring is Atom-specific

### EthWAN Mode

When `IsEthWanEnabled()` returns true:
- Time synchronization thread starts in `CcspTandDSsp` (uses syscfg `timeoffset_ethwan_enable`)
- `selfheal_aggressive.sh` includes EthWAN failover logic (bring down/up Ethernet port)
- WAN interface is Ethernet-based instead of DOCSIS, affecting health checks

### XLE Extender Mode

For WNXL11BWL and similar extender devices:
- `self_heal_connectivity_test.sh` only runs in Extender mode (skips Gateway mode)
- `xle_selfheal` binary performs cellular/LTE connectivity checks
- Cellular Manager restart limited to 3 per day; beyond → sets `LTE_DOWN` sysevent
- Mesh backhaul bridge (`br403`) existence is validated
- NTP time sync self-heal via `ntpd-restart` sysevent

### Resource-Optimized Builds

When `--enable-resourceoptimization` is used:
- ARP table, Download/Upload diagnostics, and UDP Echo Server are excluded
- Reduces memory footprint for constrained devices
- Corresponding DML callbacks and BBHM objects are omitted at compile time
- ARM-specific registration in `plugin_main_priv.c` skips these objects

### Hub4/SR300 Variants

- Use `WAN_MAC` instead of `CM_MAC` for device identification
- Include IPoE health check in connectivity test
- Product-specific `EWAN_INTERFACE` for WAN operations

### Dual-Fan Devices (CBR2)

- `COSA_DML_THERMAL_FAN_MaxNum` is 2 instead of default 1
- `check_fan.sh` checks both `Fan.1` and `Fan.2` for rotor lock

