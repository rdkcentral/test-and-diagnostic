# Knowledge Base: Test and Diagnostic (TAD)

## Signals and Indicators

### Health Signals

| Signal | Source | Meaning | Action |
|--------|--------|---------|--------|
| Health = Red | `ssp_action.c` | Component not initialized | Wait or restart |
| Health = Yellow | `ssp_action.c` | Component initializing | Wait for Green |
| Health = Green | `ssp_action.c` | Component fully operational | Normal |
| DiagnosticsState = Error_* | BBHM engine | Diagnostic failed | Check error subtype |
| `RDKB_PROCESS_CRASHED` | task_health_monitor.sh | Critical process died | Auto-restart via resetNeeded |
| `RDKB_REBOOT` | corrective_action.sh | Self-heal reboot triggered | Check reboot reason |
| `SYS_SH_*_split` | Self-heal scripts | Specific self-heal action taken | Telemetry tracking |
| `THERMAL:Fan_Rotor_Lock` | check_fan.sh | Fan hardware failure | Hardware inspection needed |
| `IHC_*` | ImageHealthChecker | Post-upgrade anomaly detected | Check WiFi/Ethernet state |

### Diagnostic State Values

| State | Code | Meaning |
|-------|------|---------|
| None | 0 | Idle, no diagnostic requested |
| Requested | 1 | Diagnostic requested, pending start |
| Complete | 2 | Diagnostic completed successfully |
| Error_InitConnectionFailed | 3 | TCP/HTTP connection failed |
| Error_CannotResolveHostName | 4 | DNS resolution failed |
| Error_NoRouteToHost | 5 | Routing failure |
| Error_Internal | 6 | Internal error |
| Error_Other | 7 | Unclassified error |
| Inprogress | 8 | Diagnostic currently executing |

### Self-Heal Reboot Reasons

| Reason | Trigger |
|--------|---------|
| `Selfheal_PING` | WAN connectivity failure |
| `Selfheal_MEM` | Memory threshold exceeded |
| `Selfheal_CPU` | CPU threshold exceeded (sustained) |
| `Selfheal_ATOM_HANG` | Atom/Peer processor unresponsive |
| `Selfheal_DS_MANAGER_HIGH_CPU` | downstream_manager runaway |
| `Selfheal_SNMP_AGENT_CM_HIGH_CPU` | SNMP agent runaway |
| `wan_link_heal` | WAN link health check failure |
| `Software_upgrade` | Firmware upgrade reboot |

---

## Error Patterns

### Pattern: Diagnostic Stuck at Requested
**Logs:** DiagnosticsState remains "Requested" indefinitely
**Cause:** Prior diagnostic still running (ANSC_STATUS_PENDING), or BBHM plugin not loaded
**Fix:** Reset state to None; if persistent, restart CcspTandDSsp

### Pattern: Self-Heal Reboot Loop
**Logs:** Repeated `RDKB_REBOOT` + `SYS_SH_*` at fixed intervals
**Cause:** Persistent failure not fixed by reboot (e.g., hardware fault, upstream network)
**Fix:** Enable diagnostic mode to halt reboots; investigate root cause

### Pattern: Process Crash-Restart Cycle
**Logs:** Alternating `RDKB_PROCESS_CRASHED` and `Process restarted` for same process
**Cause:** Code bug in the restarted process causing immediate re-crash
**Fix:** Analyze crash logs of the affected process; daily reset limit prevents infinite loops

### Pattern: Self-Heal Not Acting
**Logs:** No `RDKB_SELFHEAL` entries despite detected failures
**Cause:** Daily limit reached (`todays_reboot_count >= max_reboot_count`), or diagnostic mode enabled, or self-heal disabled
**Fix:** Check `selfheal_enable`, `Selfheal_DiagnosticMode`, `todays_reboot_count`

### Pattern: WAN Connectivity False Alarm
**Logs:** `WANCNCTVTYCHK` reports inactive but internet works
**Cause:** Configured DNS test URLs unreachable, DNS server overloaded, pcap interface mismatch
**Fix:** Verify test URL validity; check DNS server configuration

### Pattern: Latency Reports Missing
**Logs:** No `LatencyMeasure` rbus events
**Cause:** Feature disabled, xNetSniffer/xNetDP not running, pcap interface down
**Fix:** Enable feature; check processes; verify LAN bridge interface

### Pattern: CcspTandDSsp Crash (SIGSEGV)
**Logs:** `/nvram/tadssp_backtrace` contains stack trace
**Cause:** Null pointer dereference, buffer overflow, use-after-free in DML or diagnostic code
**Fix:** Analyze backtrace; check for NULL handle before access; verify input validation

---

## Failure Patterns by Subsystem

### BBHM Diagnostic Engine Failures

| Failure | State Set | Log Indicator | Root Cause |
|---------|-----------|---------------|------------|
| DNS resolution timeout | Error_CannotResolveHostName | `getaddrinfo failed` | DNS server unreachable |
| Raw socket permission | Error_Internal | `EACCES` | Process not running as root |
| Socket bind failure | Error_Internal | `bind() failed` | Interface not available |
| HTTP server unreachable | Error_InitConnectionFailed | `connect() failed` | Download/Upload server down |
| Packet loss 100% | Timeout | TDO Expire2 triggered | Network unreachable or filtered |

### Self-Heal Script Failures

| Failure | Log Indicator | Root Cause |
|---------|---------------|------------|
| Script not running | No cron entries | CcspTandDSsp didn't initialize cron |
| Action suppressed | "DiagnosticMode is true" | Diagnostic mode enabled |
| Limit reached | "dailyLimit" or "already rebooted" | max_reboot_count exceeded |
| Lock contention | Script exits immediately | Stale `/tmp/*.lock` file |
| Can't reach dmcli | "dmcli timeout" or empty result | CR or target component down |

### WAN Connectivity Check Failures

| Failure | Log Indicator | Root Cause |
|---------|---------------|------------|
| Passive monitor no data | "No DNS traffic seen" | No outgoing DNS queries |
| Active monitor timeout | "DNS query timeout" | DNS server unreachable |
| rbus registration fail | "rbus_open failed" | rbus daemon not running |
| Interface not found | "pcap_open failed" | WAN interface name changed |

---

## Dependency Failure Quick Reference

| Dependency Down | TAD Impact | Detection | Recovery |
|----------------|------------|-----------|----------|
| D-Bus | All TR-181 access fails | Bus init error | Restart D-Bus + TAD |
| CR | Data model not accessible | Registration fails | Restart CR + TAD |
| PSM | SpeedTest server config lost | PSM wait timeout | Restart PSM |
| syscfg | All config defaults | empty syscfg_get | Run syscfg_recover.sh |
| crontab | Self-heal scripts stop | No cron entries | Restart cron + TAD |
| rbus | Latency/WAN/DevicePrio off | rbus_open error | Features degrade gracefully |
| PAM | Health queries fail | dmcli timeout | task_health_monitor restarts PAM |
| WiFi | WiFi probes fail | dmcli timeout | task_health_monitor restarts WiFi |
| pcap/interface | Latency capture stops | pcap_open error | Fix interface; restart sniffer |
| platform_hal | Fan/RxTx reads fail | HAL returns error | Features disabled, logged |

---

## Diagnostic Type Selection Guide

| Need to Test | Use This Diagnostic | TR-181 Path |
|-------------|---------------------|-------------|
| Basic reachability to a host | IP Ping | `Device.IP.Diagnostics.IPPing` |
| Network path / hop-by-hop | Traceroute | `Device.IP.Diagnostics.TraceRoute` |
| DNS resolution | NSLookup | `Device.DNS.Diagnostics.NSLookupDiagnostics` |
| Download throughput | Download Diagnostics | `Device.IP.Diagnostics.DownloadDiagnostics` |
| Upload throughput | Upload Diagnostics | `Device.IP.Diagnostics.UploadDiagnostics` |
| UDP echo loopback | UDP Echo Config | `Device.IP.Diagnostics.UDPEchoConfig` |
| ISP speed | SpeedTest | `Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest` |
| Per-client latency | Latency Measurement | `Device.QOS.X_RDK_LatencyMeasure_*` |
| WAN internet status | WAN Connectivity Check | `Device.Diagnostics.X_RDK_DNSInternet` |
| Hardware health | HW Self-Test | `Device.X_RDK_hwHealthTest` |
| Memory fragmentation | CpuMemFrag | `Device.SelfHeal.X_RDKCENTRAL-COM_CpuMemFrag` |

---

## Self-Heal Timing Quick Reference

| Script | Default Interval | Config Key | What It Checks |
|--------|-----------------|------------|----------------|
| selfheal_aggressive.sh | 5 min | `AggressiveInterval` | DHCP, interfaces, WAN, peer, dibbler, dropbear |
| resource_monitor.sh | 15 min | `resource_monitor_interval` | CPU, memory, fan; launches task_health_monitor |
| self_heal_connectivity_test.sh | 60 min | `ConnTest_PingInterval` | Gateway ping, server ping, DNS test |
| task_health_monitor.sh | During maintenance window | N/A (called by resource_monitor) | 30+ critical CCSP processes |
| check_memory_health.sh | On threshold breach | N/A | Free memory, fragmentation |
| selfheal_bootup.sh | Once (10 min after boot) | N/A | Key processes started |
| start_gw_heath.sh | Once (15 min after boot) | N/A | CM status, WAN IP, DNS connectivity |
