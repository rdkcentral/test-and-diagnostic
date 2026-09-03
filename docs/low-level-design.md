# Low-Level Design (LLD)

## 1. Module Architecture

### 1.1 TandDSsp Module

**Files:** `ssp_main.c`, `ssp_action.c`, `ssp_messagebus_interface.c`, `tad_rbus_apis.c`, `current_time.c`

#### Initialization Sequence

```
main()
├── t2_init("CcspTandDSsp")                          // Telemetry 2.0
├── Parse CLI: -subsys <prefix>, -c (console mode)
├── daemonize() [if not console mode]
│   └── fork → setsid → redirect stdin/stdout/stderr to /dev/null
├── Install signal handlers (SIGINT, SIGUSR1/2, SIGCHLD, SIGPIPE=IGN, etc.)
│
├── cmd_dispatch('e')  // 'e' = engage
│   ├── ssp_TadMbi_MessageBusEngage()
│   │   ├── CCSP_Message_Bus_Init("eRT.com.cisco.spvtg.ccsp.tdm", "msg_daemon.cfg")
│   │   ├── Wait for PSM availability
│   │   ├── Set CcspBaseIf callbacks (get/setParameterValues, etc.)
│   │   └── Register "currentSessionIDSignal" event
│   │
│   ├── ssp_create_tad()
│   │   ├── Allocate COMPONENT_COMMON_DM (Health = Red)
│   │   ├── Create CCSP_CCD_INTERFACE vtable
│   │   ├── Allocate CCSP_FC_CONTEXT
│   │   └── DslhCreateCpeController()
│   │
│   └── ssp_engage_tad()
│       ├── Health = Yellow (initializing)
│       ├── Wire FC context → CCD interface + bus handle
│       ├── pDslhCpeController->AddInterface(MBI, CCD)
│       ├── pDslhCpeController->Engage()
│       ├── dlopen("libdiagnostic.so") → resolve 11 symbols
│       │   └── Call InitProc(bus_handle) → registers COSAGetDiagPluginInfo
│       ├── RegisterCcspDataModel2(CR, DMPackCreateDataModelXML)
│       └── Health = Green (operational)
│
├── tadRbusInit()                                     // Open rbus handle
├── LatencyMeasurementInit()                          // Latency subsystem
├── DevicePrioInit() [conditional]                    // QoS prioritization
├── updateTimeThread_create() [EthWAN/Extender]       // Time sync thread
│
└── Event loop: sleep(30) forever [daemon] / char dispatch [console]
```

#### Health State Machine

```
┌──────┐     ssp_create_tad()     ┌────────┐    ssp_engage_tad()     ┌───────┐
│  RED ├─────────────────────────►│ YELLOW ├────────────────────────►│ GREEN │
│(init)│                          │(engage)│   CR registration OK    │(ready)│
└──────┘                          └────────┘                          └───────┘
```

#### Signal Handling

| Signal | Behavior |
|--------|----------|
| SIGINT | Log + exit(0) |
| SIGUSR1/2 | Log warning, no action |
| SIGCHLD | Log, re-install handler |
| SIGPIPE | Ignored (SIG_IGN) |
| SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGQUIT/SIGHUP | Backtrace to `/nvram/tadssp_backtrace` + exit(0) |
| SIGTERM | Default → backtrace + exit |
| INCLUDE_BREAKPAD | All signals → breakpad crash dump |

### 1.2 dmltad Module

**Entry Point:** `COSA_Init()` in `plugin_main.c`

#### Plugin Lifecycle

```
COSA_Init(bus_handle)
├── Acquire bus handle + subsystem prefix
├── CosaBackEndManagerCreate()
│   ├── CosaDiagCreate() → COSA_DATAMODEL_DIAG
│   │   ├── Allocate ping/traceroute/nslookup/download/upload info objects
│   │   └── CosaDmlDiagGetConfigs() from BBHM plugin
│   ├── CosaSelfHealCreate()
│   │   ├── CosaDmlGetSelfHealCfg() → loads 25+ syscfg keys
│   │   ├── CosaDmlGetSelfHealMonitorCfg()
│   │   ├── Load ping server lists from syscfg
│   │   └── start_self_heal_scripts() [if enabled]
│   └── CosaWanCnctvtyChk_Init() → rbus + sysevent init
├── Register all DML callback functions with CCSP framework:
│   ├── IP.Diagnostics.* (IPPing, TraceRoute, SpeedTest, ARP, RxTx, etc.)
│   ├── DNS.Diagnostics.* (NSLookupDiagnostics)
│   ├── SelfHeal.* (ConnectivityTest, ResourceMonitor, CpuMemFrag)
│   ├── X_RDK_hwHealthTest.*
│   ├── LogBackup.*
│   ├── PowerManagement.*
│   ├── Thermal.Fan.*
│   └── X_RDK_AutomationTest.*
└── Return ANSC_STATUS_SUCCESS

COSA_Unload()
├── diag_term()
└── CosaBackEndManagerRemove()
```

#### Key Data Structures

```c
COSA_BACKEND_MANAGER_OBJECT (singleton: g_pCosaBEManager)
├── hDiag          → COSA_DATAMODEL_DIAG
│   ├── hDiagPingInfo        (DSLH_PING_INFO)
│   ├── hDiagTracerouteInfo  (DSLH_TRACEROUTE_INFO)
│   ├── hDiagNSLookInfo      (DSLH_NSLOOKUP_INFO)
│   ├── hDiagDownloadInfo    (DSLH_TR143_DOWNLOAD_DIAG_INFO)
│   ├── hDiagUploadInfo      (DSLH_TR143_UPLOAD_DIAG_INFO)
│   ├── hDiagUdpechoSrvInfo  (DSLH_TR143_UDPECHO_CONFIG)
│   ├── pArpTable[]          (COSA_DML_DIAG_ARP_TABLE)
│   ├── pSpeedTestServer     (COSA_DML_DIAG_SPEEDTEST_SERVER)
│   └── pRxTxStats           (COSA_DML_DIAG_RXTX_STATS)
├── hSelfHeal      → COSA_DATAMODEL_SELFHEAL
│   ├── Enable, DNSPingTest_Enable, DiagnosticMode, NoWaitLogSync
│   ├── MaxRebootCnt, MaxResetCnt, FreeMemThreshold, MemFragThreshold
│   ├── pConnTest → COSA_DML_CONNECTIVITY_TEST
│   │   ├── CorrectiveAction, PingInterval, PingCount, WaitTime
│   │   ├── IPv4PingServerList (linked list)
│   │   └── IPv6PingServerList (linked list)
│   ├── pResMonitor → COSA_DML_RESOURCE_MONITOR
│   └── pCpuMemFrag[] → COSA_DML_CPU_MEM_FRAG
└── hWanCnctvty_Chk → WAN connectivity check context
```

### 1.3 BBHM Diagnostic Engine

#### Object Model (ANSC COM-style inheritance)

```
ANSC_COMPONENT_OBJECT
└── BBHM_DIAG_EXEC_OBJECT (base executor)
    ├── Fields: AccessLock, bActive, hDslhDiagInfo, ResultQueryEvent
    ├── Concrete: Reset, Engage, Cancel, SetDiagParams, GetResult
    ├── Virtual: CopyDiagParams, CheckCanStart, StartDiag, StopDiag, RetrieveResult
    │
    ├── BBHM_DIAG_IP_PING_OBJECT
    │   ├── Sink: BBHM_IP_PING_SINK_OBJECT (async socket I/O)
    │   ├── Timer: BBHM_IP_PING_TDO_OBJECT (packet send timing)
    │   └── Properties: SrcIp, DstIp, NumPkts, PktSize, Timeout, Stats
    │
    ├── BBHM_DIAG_IP_TRACEROUTE_OBJECT
    │   ├── Sink: BBHM_TRACERT_SINK_OBJECT
    │   ├── Timer: BBHM_TRACERT_TDO_OBJECT
    │   └── Properties: as Ping + TTL, MaxHopCount, RouteHops[]
    │
    ├── BBHM_DIAG_NS_LOOKUP_OBJECT
    │   ├── XSink: BBHM_NS_LOOKUP_XSINK_OBJECT (UDP DNS socket)
    │   ├── Timer: BBHM_NS_LOOKUP_TDO_OBJECT
    │   └── Properties: DNSServer, HostName, QueryResults[]
    │
    ├── BBHM_DOWNLOAD_DIAG_OBJECT
    │   └── HTTP GET: ParseHttpURL → TCP connect → download → timing
    │
    ├── BBHM_UPLOAD_DIAG_OBJECT
    │   └── HTTP PUT/POST: TCP connect → upload → timing
    │
    └── BBHM_UDP_ECHOSRV_OBJECT
        └── UDP bind → poll loop → echo packets → stats
```

#### IPPing State Machine

```
                     SetDiagParams + StartDiag
     ┌─────────┐ ──────────────────────────────► ┌─────────┐
     │ NOTRUN  │                                  │ RUNNING │
     │  (1)    │ ◄────────────────────────────── │  (2)    │
     └─────────┘       StopDiag/Cancel            └────┬────┘
                                                       │
                    ┌──── all replies ─────────────┐   │
                    ▼                              │   │
              ┌──────────┐                         │   │
              │ COMPLETE │                         │   │
              │   (3)    │                         │   │
              └──────────┘                         │   │
                                                   │   │
              ┌──────────┐     TDO Expire2 ────────┘   │
              │ TIMEOUT  │ ◄───────────────────────────┘
              │   (5)    │                             │
              └──────────┘                             │
                                                       │
              ┌──────────┐   Socket/DNS error ─────────┘
              │  ABORT   │ ◄───────────────────────────
              │   (4)    │
              └──────────┘
              ┌──────────┐   User SetControl(STOP) ────
              │   STOP   │ ◄───────────────────────────
              │   (6)    │
              └──────────┘
              ┌──────────┐   DNS resolve fail ─────────
              │ERROR_HOST│ ◄───────────────────────────
              │   (7)    │
              └──────────┘
```

#### Timer Descriptor Object (TDO) Logic

```
Counter = NumPkts (e.g., 10)

TDO fires:
  if Counter > 2:
      Expire1() → send packet, Counter--, restart timer (interval=TimeBetween)
  if Counter == 2:
      Expire1() → send last packet, Counter--, restart timer (interval=Timeout)
  if Counter <= 1:
      Expire2() → timeout reached, set TIMEOUT status, stop diagnostic
```

#### Download/Upload Sequence

```
SetDiagParams(URL, DSCP, EthernetPriority, ProtocolVersion)
    │
    ▼
StartDiag()
    ├── StopDiag() [reset prior state]
    ├── ParseHttpURL(url) → host, port, path
    ├── TCP connect, record TCPOpenRequest/Response times
    ├── Send HTTP GET/PUT request, record ROM/BOM times
    ├── Transfer data, accumulate bytes
    ├── Record EOM time
    ├── Calculate throughput
    └── Set DiagnosticsState = Completed | Error_*
```

### 1.4 Self-Heal State Flows

#### Execution Mode Selection

```
boot_mode.sh:
  SelfHealCronEnable = syscfg get SelfHealCronEnable

  if SelfHealCronEnable == "true":
      MODE = CRON
      → scripts added to crontab with configured intervals
  else:
      MODE = PROCESS
      → scripts run as background processes with internal sleep loops
      → resource_monitor_recover.sh watches for crashes
```

#### Connectivity Test Flow

```
self_heal_connectivity_test.sh (every PingInterval minutes)
│
├── Guard: uptime < 900s → exit
├── Guard: selfheal_enable != true → exit
├── Guard: DiagnosticMode == true → exit
│
├── Ping IPv4 gateway ($WAN_INTERFACE)
│   ├── Success → log, continue
│   └── Failure → ping IPv4 server list
│       ├── Any success → partial connectivity, continue
│       └── All fail → IPv4 connectivity lost
│
├── Ping IPv6 gateway
│   └── [same pattern as IPv4]
│
├── DNS ping test (if dns_pingtest_enable)
│   └── nslookup $dns_url
│
└── If connectivity lost:
    ├── Check CorrectiveAction flag
    ├── Check daily reboot limit
    ├── checkConditionsbeforeAction()
    │   ├── No active voice calls?
    │   └── eCM registered?
    └── resetNeeded("", "PING") → router reset
```

#### Resource Monitor Flow

```
resource_monitor.sh (every resource_monitor_interval minutes)
│
├── Guard: uptime < 900s → exit
│
├── Memory check:
│   ├── free → total/used/available
│   ├── Compare with avg_memory_threshold
│   └── Exceeded → rebootNeeded("RM", "MEM")
│
├── CPU check:
│   ├── Sample /proc/stat → sleep 30s → sample again → compute %
│   ├── If > threshold → 5-min average (10 × 30s samples)
│   └── Sustained → rebootNeeded("RM", "CPU")
│
├── Fan check (WNXL11BWL/SE501):
│   └── check_fan.sh → rotor lock → telemetry
│
├── Image Health Check (first boot after upgrade):
│   └── ImageHealthChecker bootup-check
│
└── Maintenance window:
    ├── task_health_monitor.sh (30+ process checks)
    ├── syscfg_cleanup.sh (stale DB entries)
    └── check_memory_health.sh (drop caches, compact)
```

#### Corrective Action Safety Chain

```
rebootNeeded(source, reason)
│
├── Check Selfheal_DiagnosticMode → skip if true
├── Check todays_reboot_count < max_reboot_count
├── Check last_router_reboot_time (24h window)
├── checkConditionsbeforeAction()
│   ├── XconfHttpDl http_reboot_status (voice call check)
│   │   └── Active call → wait, retry
│   └── Cable modem eCM registered?
│       └── Not registered → skip
├── storeInformation() (log CPU/mem/WiFi/MoCA stats)
├── setRebootreason(reason)
├── Increment todays_reboot_count
├── Telemetry event: SYS_SH_<reason>_split
└── /rdklogger/backupLogs.sh → reboot -f
```

### 1.5 WAN Connectivity Check Module

#### Architecture

```
CosaWanCnctvtyChk_Init()
├── sysevent_open("127.0.0.1")
├── CosaWanCnctvtyChk_RbusInit()
│   └── rbus_open("WanCnctvtyChk")
├── Register rbus elements:
│   ├── Device.Diagnostics.X_RDK_DNSInternet.Enable
│   ├── Device.Diagnostics.X_RDK_DNSInternet.Active
│   └── Device.Diagnostics.X_RDK_DNSInternet.TestURL.{i}.*
├── Subscribe to ActiveGateway events
└── wancnctvty_chk_start_threads()
    ├── Per-interface passive monitor (DNS packet sniffing)
    └── Per-interface active monitor (DNS query probing)
```

#### DNS Monitoring Threads

```
Passive Monitor Thread:
    ├── Open pcap on WAN interface, filter: "udp port 53"
    ├── Capture DNS responses
    ├── If valid response → internet reachable
    └── If no responses for X seconds → set inactive

Active Monitor Thread:
    ├── Construct DNS query for configured test URLs
    ├── Send via raw UDP socket to configured DNS servers
    ├── Wait for response with timeout
    ├── Success → set active, publish rbus event
    └── Failure → set inactive, publish rbus event
```

### 1.6 Latency Measurement Module

#### Data Flow

```
┌───────────────┐    SysV msgqueue    ┌────────────────┐
│  xNetSniffer  ├───────────────────►│    xNetDP      │
│  (pcap on     │                     │  (correlate    │
│   br0/brlan0) │                     │   handshakes)  │
└───────────────┘                     └───────┬────────┘
                                              │
                                    rbus publish event
                                              │
                                    ┌─────────▼────────┐
                                    │   TR-181 report  │
                                    │   (JSON stats)   │
                                    └──────────────────┘

ServiceMonitor (in CcspTandDSsp)
├── Monitors syscfg: LatencyMeasure_IPv4Enable/IPv6Enable
├── spawn/kill xNetSniffer process
├── spawn/kill xNetDP process
└── Reacts to bridge_mode, lan_prefix sysevent changes
```

#### Latency Calculation

```
TCP 3-way handshake:
  Client → SYN → Server          (T1: SYN timestamp)
  Server → SYN-ACK → Client      (T2: SYN-ACK timestamp)
  Client → ACK → Server          (T3: ACK timestamp)

  WAN Latency = T2 - T1  (server response time)
  LAN Latency = T3 - T2  (client response time)
```

## 2. Error/Retry Logic Summary

| Component | Error Condition | Retry Behavior |
|-----------|----------------|----------------|
| SSP bus connect | `CCSP_Message_Bus_Init` fails | No retry — process logs error, non-functional |
| SSP plugin load | Any of 11 `AnscGetProcAddress` fails | No retry — diagnostics unavailable, process continues |
| SSP CPE controller | `DslhCreateCpeController` returns NULL | One retry attempt in `ssp_engage_tad()` |
| BBHM IPPing | Socket error | Diagnostic set to ABORT, no automatic retry |
| BBHM IPPing | DNS resolution failure | Set ERROR_HostName, no retry |
| BBHM Download | HTTP connect failure | Diagnostic set to Error_InitConnectionFailed |
| Self-heal scripts | Process crash detected | Restart process via `resetNeeded()`, max N/day |
| Self-heal scripts | Connectivity failure | Router reset via `resetNeeded()`, max N/day |
| Self-heal scripts | Resource exhaustion | Full device reboot via `rebootNeeded()`, max N/day |
| WAN connectivity | DNS query timeout | Active monitor retries on next interval |
| Latency measurement | xNetSniffer crash | ServiceMonitor respawns |
| Time sync thread | Clock drift detected | Continuous correction loop (3600s interval) |
| syscfg | Database corruption | `syscfg_recover.sh` recreates shared memory |
