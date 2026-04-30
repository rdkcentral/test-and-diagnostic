# External Dependencies

## 1. Dependency Map

```
┌─────────────────────────────────────────────────────────────────┐
│                      CcspTandDSsp                               │
└──────┬───────┬───────┬───────┬──────┬───────┬──────┬───────────┘
       │       │       │       │      │       │      │
  ┌────▼──┐ ┌─▼────┐ ┌▼─────┐ ┌▼────┐┌▼────┐┌▼────┐┌▼──────────┐
  │CCSP   │ │D-Bus │ │rbus  │ │sys  ││sys  ││plat ││telemetry  │
  │Common │ │      │ │      │ │cfg  ││event││HAL  ││2.0        │
  └───────┘ └──────┘ └──────┘ └─────┘└─────┘└─────┘└───────────┘
```

## 2. Library Dependencies

### Build-Time Libraries

| Library | Headers | Purpose | Used By |
|---------|---------|---------|---------|
| libccsp_common | ccsp_base_api.h, dslh_cpeco_interface.h, ansc_platform.h | CCSP framework, D-Bus abstraction, DSLH, ANSC memory/trace | All modules |
| librbus | rbus.h | RDK Bus IPC, event pub/sub | TandDSsp, dmltad (WAN check), LatencyMeasurement, DevicePrioritization |
| libsyscfg | syscfg/syscfg.h | Persistent key-value store in NVRAM | dmltad (self-heal config), scripts, LatencyMeasurement |
| libsysevent | sysevent/sysevent.h | System event pub/sub | WAN connectivity check, DevicePrioritization, scripts |
| libpcap | pcap.h | Packet capture | xNetSniffer, xNetDP, WAN connectivity passive monitor |
| libsecure_wrapper | secure_wrapper.h | Secure system()/popen() | All modules executing shell commands |
| libtelemetry_msgsender | telemetry_busmessage_sender.h | Telemetry 2.0 events | TandDSsp, ImageHealthChecker, RxTx100 |
| libsafec | safec_lib_common.h | Safe C string operations | All C modules |
| libnet | | Network packet construction | dmltad (conditional: CORE_NET_LIB_FEATURE_SUPPORT) |
| libresolv | resolv.h | DNS resolution | dmltad diagnostics |
| libev | ev.h | Event loop | Warehouse diagnostics (file watchers) |
| libm | math.h | Math functions | xNetDP (percentile calculation) |
| libmsgpackc | msgpack.h | MessagePack serialization | DevicePrioritization (WebConfig blobs) |
| libtrower-base64 | base64.h | Base64 encoding/decoding | DevicePrioritization |
| libwebconfig_framework | webconfig_framework.h | WebConfig subdoc registration | DevicePrioritization |
| librdk_scheduler | rdk_scheduler.h | Time-based scheduling | DevicePrioritization |
| libcurl | curl/curl.h | HTTP client | WebConfig (transitive) |
| libhal_ethsw | ccsp_hal_ethsw.h | Ethernet switch HAL | ImageHealthChecker |
| platform_hal | platform_hal.h | Platform hardware abstraction | Fan/thermal, RxTx100 |
| ccsp_hal_emmc | ccsp_hal_emmc.h | eMMC flash diagnostics | dmltad (conditional: EMMC_DIAG_SUPPORT) |

### Runtime Service Dependencies

| Service | Port/Path | Purpose | Impact if Unavailable |
|---------|-----------|---------|----------------------|
| CCSP Component Registrar (CR) | D-Bus: eRT.com.cisco.spvtg.ccsp.CR | Data model registration | **Fatal**: TAD data model inaccessible |
| CCSP PSM | D-Bus: eRT.com.cisco.spvtg.ccsp.psm | Persistent parameter storage | SpeedTest server config missing; startup delayed |
| D-Bus daemon | /var/run/dbus/system_bus_socket | IPC bus | **Fatal**: No inter-component communication |
| crontab service | cron daemon | Periodic script execution | Self-heal scripts don't run (CRON mode) |

### CCSP Component Dependencies (Cross-Component Queries)

| Component | D-Bus Name | Parameters Queried | Query Source |
|-----------|------------|-------------------|--------------|
| PAM (PandM) | com.cisco.spvtg.ccsp.pam | Device.DeviceInfo.*, Device.X_CISCO_COM_CableModem.CMStatus | task_health_monitor, check_gw_health |
| WiFi | com.cisco.spvtg.ccsp.wifi | Device.WiFi.SSID.*, Device.WiFi.Radio.* | task_health_monitor, ImageHealthChecker |
| CM Agent | com.cisco.spvtg.ccsp.cm | Device.X_CISCO_COM_CableModem.* | check_gw_health, connectivity test |
| WAN Manager | | Device.X_RDK_WanManager.* | xle_selfheal, selfheal_aggressive |
| Cellular Manager | | Device.Cellular.* | xle_selfheal (XLE devices) |
| Ethernet Agent | | Device.Ethernet.Interface.* | ImageHealthChecker |

## 3. Interaction Patterns

### D-Bus via CCSP Message Bus

```
TAD ←→ D-Bus ←→ Other CCSP Components

- CosaGetParamValueString(bus_handle, component, param, &value)
- CosaGetParamValueUlong(bus_handle, component, param, &value)
- CcspBaseIf_getParameterValues(bus_handle, component, path[], ...)
- CcspBaseIf_setParameterValues(bus_handle, component, values[], ...)
- CcspBaseIf_SenddiagCompleteSignal(bus_handle, ...) — diagnostic completion
```

### Rbus Event-Based

```
TAD publishes:
- Device.QOS.X_RDK_LatencyMeasure_TCP_Stats_Report (latency JSON)
- Device.QOS.X_RDK_DscpControlPerClient.ActiveRules (QoS rules)
- Device.Diagnostics.X_RDK_DNSInternet.* (WAN connectivity events)

TAD subscribes:
- ActiveGateway status change events
- Device.X_RDK_Connection.Interface changes (xle_selfheal)
```

### sysevent

```
TAD fires:
- firewall-restart (after QoS rule changes)
- wan-restart (selfheal_aggressive WAN recovery)
- ntpd-restart (xle_selfheal time sync)

TAD reads/subscribes:
- bridge_mode (latency measurement adjust)
- lan-status, current_wan_ifname (WAN connectivity check)
```

### SysV Message Queue

```
xNetSniffer --[msgsnd]--> queue --[msgrcv]--> xNetDP
  (captured TCP packets)          (latency calculation)
```

### Direct File I/O

| File | Access | Purpose |
|------|--------|---------|
| /proc/net/arp | Read | Generic ARP table (non-ARM) |
| /proc/stat | Read | CPU utilization |
| /proc/loadavg | Read | Load average |
| /proc/meminfo | Read | Memory info |
| /proc/buddyinfo | Read | Memory fragmentation |
| /proc/sys/vm/drop_caches | Write | Memory cache flush |
| /proc/sys/vm/compact_memory | Write | Memory compaction |
| /tmp/hwselftest.results | Read | HW self-test results |
| /nvram/tadssp_backtrace | Write | Crash backtrace dump |
| /nvram/procanalyzerconfig.ini | Read/Write | CPU Proc Analyzer config |
| /sys/module/pcie_aspm/parameters/policy | Read | PCIe power state |
| /rdklogs/logs/SelfHeal*.txt | Write | Self-heal logging |
| /rdklogs/logs/CPUInfo.txt.0 | Write | CPU/memory telemetry |

## 4. Failure Impact Matrix

| Dependency | Failure Mode | Impact | Detection | Recovery |
|------------|-------------|--------|-----------|----------|
| D-Bus | Daemon crash | All parameter access fails; TAD non-functional | `CCSP_Message_Bus_Init` returns error | TAD process restart required |
| CR | Not running | Data model not registered; no external access | Registration call fails | CR must start first; TAD re-registers on restart |
| PSM | Not available | SpeedTest server config missing; delayed startup | `ssp_TadMbi_WaitConditionReady` blocks | TAD waits; PSM recovery resumes |
| syscfg | Database corrupted | All config lost; self-heal uses defaults | `syscfg_get` returns empty/error | `syscfg_recover.sh` restores |
| crontab | Cron daemon stopped | Self-heal scripts stop running (CRON mode) | Missing expected log entries | Restart cron; or switch to PROCESS mode |
| libpcap | Missing/broken | Latency measurement and passive WAN monitor fail | pcap_open returns error | Latency features disabled; active WAN monitor continues |
| platform_hal | HAL library missing | Fan/thermal reads fail; RxTx stats fail | Function calls return error | Feature disabled; logged as warning |
| rbus | rbus_open fails | Latency, WAN check, DevicePrio disabled | rbus_open returns error | Features disabled; D-Bus-based functions continue |
| PAM component | PAM crash | Self-heal cannot query device info for health checks | dmcli timeout | task_health_monitor restarts PAM |
| WiFi component | WiFi hang | Self-heal cannot probe WiFi health | dmcli timeout (30s) | task_health_monitor kills/restarts WifiSsp |

## 5. Debugging Dependency Issues

### Verify D-Bus Connectivity
```bash
# Check if TAD is registered with CR
dmcli eRT getv Device.IP.Diagnostics.IPPing.Host

# Check message bus
busctl --system list | grep ccsp
```

### Verify Rbus
```bash
# Check rbus connections
rbuscli getvalues Device.QOS.X_RDK_LatencyMeasure_IPv4Enable
```

### Verify Syscfg
```bash
# Check syscfg database health
syscfg show | grep selfheal
syscfg get selfheal_enable
```

### Verify Sysevent
```bash
# Check sysevent daemon
sysevent get bridge_mode
sysevent get current_wan_ifname
```

### Verify Process Dependencies
```bash
# Check all TAD processes
pidof CcspTandDSsp
pidof xNetSniffer
pidof xNetDP
pidof ImageHealthChecker

# Check CCSP ecosystem
pidof CcspCrSsp CcspPandMSsp CcspWifiSsp PsmSsp
```
