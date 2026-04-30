# High-Level Design (HLD)

## 1. System View

The TAD component operates as a CCSP service within the RDK-B software stack. It registers with the Component Registrar (CR) over D-Bus and exposes TR-181 data model parameters for management by TR-069 ACS, WebPA, and local CLI (dmcli).

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Management Plane                              │
│   TR-069 ACS  │  WebPA/Parodus  │  dmcli (local CLI)  │  rbus       │
└───────┬────────────────┬─────────────────┬──────────────────┬────────┘
        │                │                 │                  │
┌───────▼────────────────▼─────────────────▼──────────────────▼────────┐
│                    CCSP Message Bus (D-Bus)                           │
│                                                                      │
│  ┌────────────┐ ┌────────────┐ ┌──────────────┐ ┌───────────────┐   │
│  │     CR     │ │    PSM     │ │   PAM/WiFi   │ │  Other CCSP   │   │
│  │(Registrar) │ │(Persistent │ │  Components  │ │  Components   │   │
│  │            │ │  Storage)  │ │              │ │               │   │
│  └────────────┘ └────────────┘ └──────────────┘ └───────────────┘   │
└──────────────────────────┬───────────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────────┐
│                    CcspTandDSsp (TAD Process)                        │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  TandDSsp (SSP Layer)                                          │ │
│  │  - daemonization, signal handling, bus connect, CR registration │ │
│  │  - telemetry 2.0, rbus init, latency init, time sync           │ │
│  └──────────────────────────┬──────────────────────────────────────┘ │
│                              │                                       │
│  ┌──────────────────────────▼──────────────────────────────────────┐ │
│  │  dmltad (DML Plugin Layer)                                      │ │
│  │  ┌─────────┐┌──────────┐┌──────────┐┌─────────┐┌────────────┐ │ │
│  │  │ IP Diag ││ DNS Diag ││ SelfHeal ││  HWST   ││  WAN Chk   │ │ │
│  │  │ (ping,  ││(nslookup)││(conn,res,││(hw test)││(DNS monit) │ │ │
│  │  │ trace,  ││          ││ process) ││         ││            │ │ │
│  │  │ dl/ul)  ││          ││          ││         ││            │ │ │
│  │  └────┬────┘└──────────┘└─────┬────┘└─────────┘└────────────┘ │ │
│  └───────│───────────────────────│────────────────────────────────┘ │
│          │                       │                                   │
│  ┌───────▼───────────┐   ┌──────▼────────────────────────────────┐ │
│  │ libdiagnostic.so  │   │  Shell Scripts (/usr/ccsp/tad/)       │ │
│  │ (BBHM Engine)     │   │  - connectivity test                  │ │
│  │ - IPPing           │   │  - resource monitor                   │ │
│  │ - Traceroute       │   │  - task health monitor                │ │
│  │ - NSLookup         │   │  - aggressive self-heal               │ │
│  │ - Download/Upload  │   │  - corrective actions                 │ │
│  │ - UDP Echo Server  │   │  - log collection                     │ │
│  └───────────────────┘   └───────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  Auxiliary Modules                                              │ │
│  │  ┌─────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │ │
│  │  │ Latency     │ │ Device       │ │ Image Health Checker     │ │ │
│  │  │ Measurement │ │ Prioritize   │ │ (post-upgrade verify)    │ │ │
│  │  │ xNetSniffer │ │ (QoS DSCP)  │ │                          │ │ │
│  │  │ xNetDP      │ │              │ │                          │ │ │
│  │  └─────────────┘ └──────────────┘ └──────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
            │               │              │              │
    ┌───────▼───┐   ┌──────▼────┐  ┌──────▼────┐  ┌─────▼──────┐
    │  syscfg   │   │ sysevent  │  │ platform  │  │ crontab    │
    │  (nvram)  │   │           │  │ HAL       │  │            │
    └───────────┘   └───────────┘  └───────────┘  └────────────┘
```

## 2. Major Components

### 2.1 TandDSsp — Service Setup Program

The main daemon process. Handles:
- Process daemonization and signal handling
- D-Bus message bus connection
- CR (Component Registrar) registration of TR-181 namespace
- Plugin loading (`libdiagnostic.so`)
- Rbus handle initialization
- Latency measurement and device prioritization init
- Time synchronization thread (EthWAN/extender mode)

### 2.2 dmltad — Data Model Library

The TR-181 DML plugin implementing CCSP-standard callback interfaces:
- `GetParamBoolValue` / `SetParamBoolValue`
- `GetParamStringValue` / `SetParamStringValue`
- `GetParamUlongValue` / `SetParamUlongValue`
- Table entry CRUD (Add/Del/Get/Set/Validate/Commit/Rollback)

Manages all TR-181 objects under `Device.IP.Diagnostics.*`, `Device.DNS.Diagnostics.*`, `Device.SelfHeal.*`, etc.

### 2.3 BBHM Diagnostic Engine (libdiagnostic.so)

Dynamically loaded plugin implementing network diagnostics with a COM-style object model:
- **IPPing** — ICMP echo request/reply via raw sockets
- **Traceroute** — TTL-incrementing ICMP probes
- **NSLookup** — Direct UDP DNS queries
- **Download/Upload** — HTTP GET/PUT throughput tests (TR-143)
- **UDP Echo Server** — Loopback echo service

### 2.4 Self-Heal Subsystem

Multi-layered shell script system providing:
- **Connectivity monitoring** — Gateway/server ping tests (hourly)
- **Resource monitoring** — CPU/memory threshold checks (every 15 min)
- **Process health monitoring** — 30+ critical process checks (maintenance window)
- **Aggressive self-heal** — DHCP/interface/WAN quick-cycle checks (every 5 min)
- **Corrective actions** — Process restart, router reset, device reboot (with safety limits)

### 2.5 Latency Measurement

Per-client TCP handshake latency monitoring:
- **xNetSniffer** — Captures TCP SYN/SYN-ACK/ACK packets via libpcap
- **xNetDP** — Correlates handshake timing, computes WAN/LAN latency
- **ServiceMonitor** — Manages sniffer/DP process lifecycle

### 2.6 Device Prioritization

Cloud-driven per-client QoS:
- WebConfig blob ingestion (msgpack)
- rdkscheduler for time-based rule application
- iptables DSCP marking via sysevent firewall-restart

### 2.7 WAN Connectivity Check

DNS-based internet reachability monitoring:
- Passive DNS monitoring via packet capture
- Active DNS query probing
- Per-WAN-interface monitoring threads
- Rbus event publishing for status changes

## 3. Interactions

### 3.1 Inter-Component Communication

| Source | Target | Mechanism | Purpose |
|--------|--------|-----------|---------|
| TAD | CR | D-Bus | Data model namespace registration |
| TAD | PSM | D-Bus | Persistent parameter storage (SpeedTest servers) |
| TAD | PAM/WiFi/CM | D-Bus `dmcli` | Cross-component parameter queries |
| TAD | rbus subscribers | rbus events | Latency reports, WAN connectivity status, ActiveRules |
| TAD | WebConfig | rbus + libwebconfig | Device prioritization blob ingestion |
| Self-heal scripts | CCSP processes | `dmcli` | Health probing and configuration |
| Self-heal scripts | sysevent | `sysevent` CLI | Firewall restart, WAN restart, interface events |
| xNetSniffer → xNetDP | SysV msg queue | `msgsnd`/`msgrcv` | Captured packet metadata |

### 3.2 Data Flow — Diagnostic Request

```
ACS/WebPA → D-Bus → CR → TAD DML callback
    → dmltad sets DiagnosticsState=Requested
    → CosaDmlDiagScheduleDiagnostic() (async task)
    → BBHM object SetDiagParams + StartDiag
    → Raw socket operations (ICMP/TCP/UDP/HTTP)
    → ResultQueryTask polls for completion
    → CosaSendDiagCompleteSignal() → D-Bus signal
    → DML GetResult returns data to caller
```

### 3.3 Data Flow — Self-Heal

```
crontab triggers → self-heal script runs
    → sources corrective_action.sh + boot_mode.sh
    → checks process/interface/connectivity health
    → on failure: resetNeeded() or rebootNeeded()
        → safety checks (daily limit, voice call, diagnostic mode)
        → restart process or reboot device
    → telemetry events logged
```

## 4. External Dependencies

| Dependency | Type | Purpose | Impact if Missing |
|------------|------|---------|-------------------|
| CCSP Common (libccsp_common) | Library | Framework APIs, D-Bus, DSLH | Fatal — component cannot start |
| D-Bus | IPC | Message bus for TR-181 | Fatal — no parameter access |
| Rbus (librbus) | IPC | Event-based communication | Latency/WAN/DevicePrio features disabled |
| syscfg (libsyscfg) | Library | Persistent key-value store | Self-heal config lost on reboot |
| sysevent (libsysevent) | Library | System event messaging | WAN connectivity and firewall triggers fail |
| PSM | Service | Persistent storage manager | SpeedTest server config unavailable |
| CR | Service | Component Registrar | Data model not accessible |
| libpcap | Library | Packet capture | Latency measurement and passive DNS monitoring fail |
| platform_hal | HAL | Fan/thermal, Ethernet stats | Hardware diagnostics fail |
| libtelemetry_msgsender | Library | Telemetry 2.0 | Telemetry events not reported |
| Safe-C (safec_lib) | Library | Safe string operations | Build failure |
| libsecure_wrapper | Library | Secure system/popen calls | Script execution fails |
| crontab | System | Periodic script scheduling | Self-heal scripts don't run |
| ping/ping6/traceroute | System | Network diagnostic commands | Generic ping/traceroute diagnostics fail |
