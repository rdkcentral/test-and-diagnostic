# Troubleshooting Guide

## Quick Reference: Symptom → Root Cause Map

| Symptom | Most Likely Root Cause | First Check |
|---------|----------------------|-------------|
| CcspTandDSsp not running | D-Bus/CR not ready, crash | `cat /nvram/tadssp_backtrace` |
| TR-181 params inaccessible | TAD not registered with CR | `pidof CcspTandDSsp`, Health=Green? |
| Diagnostic stuck at "Requested" | Prior diagnostic running or plugin not loaded | Reset state to None |
| Diagnostic returns Error_CannotResolveHostName | DNS misconfiguration | `nslookup <host>` |
| Self-heal not running | Disabled, diagnostic mode, or cron missing | `syscfg get selfheal_enable` |
| Excessive reboots | Self-heal reboot loop | `syscfg get last_reboot_reason`, enable diagnostic mode |
| Daily reboot limit reached | Self-heal already acted max times | `syscfg get todays_reboot_count` |
| Latency reports empty | Feature disabled or processes dead | `pidof xNetSniffer xNetDP` |
| WAN check false positive | DNS test URL unreachable | Verify test URLs and DNS servers |
| Fan rotor lock alert | Hardware failure or HAL bug | `dmcli eRT getv Device.Thermal.Fan.1.RotorLock` |
| SpeedTest fails | Credentials missing or server unreachable | Check server config in PSM |
| Syscfg config lost | Database corruption | `syscfg show \| wc -l`, run recovery |
| Self-heal actions suppressed | Diagnostic mode ON | `syscfg get Selfheal_DiagnosticMode` |
| Process crash-restart loop | Bug in restarted process | Check that process's own logs |
| Connectivity test not pinging | Ping server list empty | `syscfg get Ipv4PingServer_Count` |

## Decision Tree: Diagnostic Troubleshooting

```
Issue reported with TAD
│
├── Is CcspTandDSsp running? (pidof CcspTandDSsp)
│   ├── NO → Is /nvram/tadssp_backtrace present?
│   │   ├── YES → Analyze crash (SIGSEGV? NULL deref? Stack overflow?)
│   │   └── NO → Are dependencies running? (CR, PSM, D-Bus)
│   │       ├── NO → Start dependencies first, then TAD
│   │       └── YES → Start TAD in console mode for debug output
│   │
│   └── YES → Is Health = Green?
│       ├── NO (Red/Yellow) → Initialization stuck
│       │   ├── Check D-Bus connection (bus_handle valid?)
│       │   ├── Check CR registration (dmcli test query)
│       │   └── Check plugin load (libdiagnostic.so exists?)
│       │
│       └── YES → Which feature is broken?
│           ├── Diagnostics → See Section 2 (IPPing/Trace/NSLookup)
│           ├── Self-Heal → See Section 3
│           ├── Latency → See Section 5
│           ├── WAN Check → See Section 6
│           ├── SpeedTest → See Section 8
│           └── Hardware → See Section 7 (HWST) / Section 10 (Fan)
```

## Dependency Failure Impact Matrix

| Dependency | Self-Heal | Diagnostics | Latency | WAN Check | DevicePrio | HW Test |
|------------|-----------|-------------|---------|-----------|------------|---------|
| D-Bus down | DEGRADED¹ | BROKEN | OK² | OK² | OK² | BROKEN |
| CR down | DEGRADED¹ | BROKEN | OK² | OK² | OK² | BROKEN |
| PSM down | OK | DEGRADED³ | OK | OK | OK | OK |
| syscfg corrupt | DEFAULTS | OK | DEFAULTS | OK | DEFAULTS | OK |
| crontab stopped | BROKEN⁴ | OK | OK | OK | OK | OK |
| rbus down | OK | OK | BROKEN | BROKEN | BROKEN | OK |
| libpcap missing | OK | OK | BROKEN | DEGRADED⁵ | OK | OK |
| platform_hal missing | OK | OK | OK | OK | OK | BROKEN |

¹ Scripts work but can't query dmcli for health checks
² Uses rbus (independent of D-Bus for rbus-based features)
³ SpeedTest server config unavailable
⁴ Only in CRON mode; PROCESS mode unaffected
⁵ Passive monitor broken; active monitor still works

---

## 1. CcspTandDSsp Fails to Start

### Symptom
CcspTandDSsp process not running; TR-181 diagnostics parameters inaccessible.

### Logs
```
# Check system log
grep "CcspTandDSsp" /rdklogs/logs/ArmConsolelog.txt.0
grep "CCSP_Message_Bus_Init" /rdklogs/logs/ArmConsolelog.txt.0
```

### Root Cause
| Cause | Log Signature |
|-------|---------------|
| D-Bus bus not available | `CCSP_Message_Bus_Init failed` |
| CR not running | `RegisterCcspDataModel2 failed` |
| libdiagnostic.so missing | `AnscLoadLibrary... failed` or `COSA_STATUS_ERROR_LOAD_LIBRARY` |
| PSM not available | Process hangs at `ssp_TadMbi_WaitConditionReady` |
| Crash on startup | Backtrace in `/nvram/tadssp_backtrace` |

### Debug Steps
```bash
# 1. Check if process is running
pidof CcspTandDSsp

# 2. Check if D-Bus daemon is up
pidof dbus-daemon

# 3. Check if CR and PSM are running
pidof CcspCrSsp PsmSsp

# 4. Check library availability
ls -la /usr/lib/libdiagnostic.so

# 5. Check for crash backtrace
cat /nvram/tadssp_backtrace

# 6. Try starting manually for debug
/usr/bin/CcspTandDSsp -subsys eRT. -c   # Console mode
```

### Resolution
1. Ensure D-Bus daemon, CR, and PSM are running before TAD
2. If library missing, verify firmware image integrity
3. If crash backtrace present, analyze stack trace for root cause
4. If PSM timeout, restart PSM: `systemctl restart PsmSsp`

---

## 2. IP Ping Diagnostic Not Working

### Symptom
`Device.IP.Diagnostics.IPPing.DiagnosticsState` stays at `Requested` or returns `Error_Other`.

### Logs
```
grep -i "ping\|diagip\|diag_ping" /rdklogs/logs/ArmConsolelog.txt.0
grep "CosaDmlDiagScheduleDiagnostic" /rdklogs/logs/ArmConsolelog.txt.0
```

### Root Cause
| Cause | Log/Indicator |
|-------|---------------|
| libdiagnostic.so not loaded | `uLoadStatus = COSA_STATUS_ERROR_LOAD_LIBRARY` |
| Host DNS resolution failure | State = `Error_CannotResolveHostName` |
| Interface binding failure | Socket open/bind errors |
| Raw socket permission denied | `EACCES` in trace |
| Prior diagnostic still running | State stays `Requested` (ANSC_STATUS_PENDING) |

### Debug Steps
```bash
# 1. Check diagnostic state
dmcli eRT getv Device.IP.Diagnostics.IPPing.DiagnosticsState

# 2. Verify TAD process is running and healthy
dmcli eRT getv com.cisco.spvtg.ccsp.tdm.Health
# Should return "Green"

# 3. Test ping manually to rule out network issues
ping -c 3 <target_host>

# 4. Verify DNS resolution
nslookup <target_host>

# 5. Check if a prior diagnostic is stuck
# Set to None first, then retry
dmcli eRT setv Device.IP.Diagnostics.IPPing.DiagnosticsState string None
```

### Resolution
1. If plugin not loaded, restart CcspTandDSsp
2. If DNS failure, check DNS configuration or use IP address
3. If raw socket issue, verify process runs as root
4. If stuck, reset state to `None` and retry

---

## 3. Self-Heal Not Running

### Symptom
No self-heal actions observed; processes not being restarted; connectivity failures not corrected.

### Logs
```
grep "RDKB_SELFHEAL" /rdklogs/logs/SelfHeal*.txt
grep "selfheal" /rdklogs/logs/ArmConsolelog.txt.0
crontab -l | grep -i "selfheal\|resource_monitor\|connectivity"
```

### Root Cause
| Cause | Indicator |
|-------|-----------|
| Self-heal disabled | `syscfg get selfheal_enable` returns `false` |
| Diagnostic mode enabled | `syscfg get Selfheal_DiagnosticMode` returns `true` |
| Cron not running | `crontab -l` shows no self-heal entries |
| Scripts not deployed | `/usr/ccsp/tad/*.sh` missing |
| Lock file stuck | `/tmp/selfheal_*.lock` stale files |
| Daily limit reached | `todays_reboot_count >= max_reboot_count` |

### Debug Steps
```bash
# 1. Check master enable
syscfg get selfheal_enable
dmcli eRT getv Device.SelfHeal.X_RDKCENTRAL-COM_Enable

# 2. Check diagnostic mode
syscfg get Selfheal_DiagnosticMode

# 3. Check execution mode and cron
syscfg get SelfHealCronEnable
crontab -l

# 4. Check for running self-heal processes
ps aux | grep -E "selfheal|resource_monitor|connectivity_test"

# 5. Check lock files
ls -la /tmp/*selfheal*.lock /tmp/*resource*.lock 2>/dev/null

# 6. Check daily counters
syscfg get todays_reboot_count
syscfg get todays_reset_count
syscfg get max_reboot_count
```

### Resolution
1. Enable self-heal: `dmcli eRT setv Device.SelfHeal.X_RDKCENTRAL-COM_Enable bool true`
2. Disable diagnostic mode: `dmcli eRT setv Device.SelfHeal.X_RDKCENTRAL-COM_DiagnosticMode bool false`
3. Fix cron: `manage_self_heal_cron_state TRUE` or restart CcspTandDSsp
4. Remove stale lock files: `rm /tmp/*selfheal*.lock`
5. Reset daily counters: `syscfg set todays_reboot_count 0; syscfg commit`

---

## 4. Excessive Self-Heal Reboots

### Symptom
Device rebooting repeatedly; reboot reason shows `Selfheal_<reason>`.

### Logs
```
grep "RDKB_REBOOT\|rebootNeeded\|SYS_SH" /rdklogs/logs/SelfHeal*.txt
syscfg get last_reboot_reason
grep "reboot" /rdklogs/logs/ArmConsolelog.txt.0
```

### Root Cause
| Cause | Indicator |
|-------|-----------|
| Persistent WAN connectivity failure | `SYS_SH_Ping_split` markers |
| Sustained CPU overload | `SYS_SH_CPU_split` markers |
| Memory leak (threshold breach) | `SYS_SH_MEM_split` markers |
| Critical process crash loop | `RDKB_PROCESS_CRASHED` + immediate re-crash |
| Atom/Peer unresponsive | `RDKB_SYS_ATOM_HANG` markers |

### Debug Steps
```bash
# 1. Check reboot reason
syscfg get last_reboot_reason

# 2. Check pre-reboot information (logged by storeInformation)
grep "storeInformation\|SELFHEAL\|REBOOT" /rdklogs/logs/SelfHeal*.txt | tail -50

# 3. Check reboot frequency
syscfg get todays_reboot_count
syscfg get max_reboot_count

# 4. If CPU-related, check processes
top -b -n 1 | head -20

# 5. If memory-related, check usage
free -m
cat /proc/meminfo

# 6. If connectivity-related, check WAN
ping -I erouter0 8.8.8.8 -c 3
ip route show default
```

### Resolution
1. **Temporary**: Increase `max_reboot_count` or enable diagnostic mode to stop reboots
2. **Investigate root cause**: Memory leak → identify leaking process; WAN issue → fix upstream connectivity; CPU → identify runaway process
3. **Reduce frequency**: Increase `ConnTest_PingInterval` or `resource_monitor_interval`
4. **Gather data**: Enable diagnostic mode to allow collection without reboots:
   ```bash
   dmcli eRT setv Device.SelfHeal.X_RDKCENTRAL-COM_DiagnosticMode bool true
   ```

---

## 5. Latency Measurement Not Reporting

### Symptom
`Device.QOS.X_RDK_LatencyMeasure_TCP_Stats_Report` returns empty or no events received.

### Logs
```
grep -i "latency\|xNetSniffer\|xNetDP" /rdklogs/logs/ArmConsolelog.txt.0
```

### Root Cause
| Cause | Indicator |
|-------|-----------|
| Feature disabled | `LatencyMeasure_IPv4Enable` = false |
| xNetSniffer/xNetDP not running | `pidof xNetSniffer xNetDP` empty |
| pcap interface down | Interface specified in config is down |
| SysV msg queue full | xNetDP not consuming messages |
| rbus not connected | rbus_open failure in logs |

### Debug Steps
```bash
# 1. Check enable status
syscfg get LatencyMeasure_IPv4Enable
syscfg get LatencyMeasure_IPv6Enable

# 2. Check processes
pidof xNetSniffer
pidof xNetDP

# 3. Check interface
ip link show brlan0

# 4. Check rbus
rbuscli getvalues Device.QOS.X_RDK_LatencyMeasure_IPv4Enable

# 5. Check message queues
ipcs -q
```

### Resolution
1. Enable: `rbuscli setvalues Device.QOS.X_RDK_LatencyMeasure_IPv4Enable bool true`
2. If processes missing, restart CcspTandDSsp (ServiceMonitor will respawn them)
3. If interface issue, verify LAN bridge is up
4. If msg queue full, kill and restart xNetDP

---

## 6. WAN Connectivity Check False Positives

### Symptom
WAN connectivity reported as down when internet is actually reachable.

### Logs
```
grep "WANCNCTVTYCHK\|DNSInternet" /rdklogs/logs/ArmConsolelog.txt.0
```

### Root Cause
| Cause | Indicator |
|-------|-----------|
| DNS server unreachable | Active monitor queries timing out |
| Stale DNS configuration | Wrong DNS server IPs in resolv.conf |
| pcap interface mismatch | Passive monitor on wrong interface |
| Test URL not resolvable | Configured URL does not resolve |

### Debug Steps
```bash
# 1. Check feature status
dmcli eRT getv Device.Diagnostics.X_RDK_DNSInternet.Enable
dmcli eRT getv Device.Diagnostics.X_RDK_DNSInternet.Active

# 2. Test DNS manually
nslookup google.com
dig google.com

# 3. Check configured test URLs
dmcli eRT getv Device.Diagnostics.X_RDK_DNSInternet.TestURL.

# 4. Check WAN interface
ip addr show erouter0
cat /etc/resolv.conf
```

### Resolution
1. Update DNS servers if stale
2. Configure valid, reliable test URLs
3. Verify WAN interface name matches configuration

---

## 7. Hardware Self-Test Failures

### Symptom
`Device.X_RDK_hwHealthTest.Results` returns error or empty.

### Logs
```
grep "hwselftest\|hwHealthTest" /rdklogs/logs/ArmConsolelog.txt.0
cat /tmp/hwselftest.results
```

### Root Cause
| Cause | Indicator |
|-------|-----------|
| Insufficient /tmp space | Free space < 200KB → test skipped |
| hwselftest binary missing | `/usr/bin/hwselftest_run.sh` not found |
| Prior test still running | `/tmp/.hwst_run` lock file exists |
| Result file not generated | `/tmp/hwselftest.results` missing |

### Debug Steps
```bash
# 1. Check /tmp space
df -h /tmp

# 2. Check for lock file
ls -la /tmp/.hwst_run

# 3. Check result files
cat /tmp/hwselftest.results
cat /nvram/hwselftest.results

# 4. Run test manually
dmcli eRT setv Device.X_RDK_hwHealthTest.executeTest bool true
sleep 30
dmcli eRT getv Device.X_RDK_hwHealthTest.Results
```

### Resolution
1. Free /tmp space (clear temp files, logs)
2. Remove stale lock file: `rm /tmp/.hwst_run`
3. Verify hwselftest binary is installed

---

## 8. SpeedTest Not Working

### Symptom
`Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.Status` shows error or empty.

### Logs
```
grep -i "speedtest\|speed_test" /rdklogs/logs/ArmConsolelog.txt.0
```

### Root Cause
| Cause | Indicator |
|-------|-----------|
| SpeedTest not enabled | `Enable_Speedtest` = false |
| Missing credentials | Server Key/Username/Password empty |
| Client binary missing | `speedtest-client` not installed |
| Authentication failure | Status = "Error_Authentication" |
| Server unreachable | Status = "Error_InitConnectionFailed" |

### Debug Steps
```bash
# 1. Check enable and configuration
dmcli eRT getv Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.Enable_Speedtest
dmcli eRT getv Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.Server.

# 2. Check client version
cat /tmp/.speedtest-client-version.log

# 3. Check PSM for server config
psmcli get dmsb.Speedtest.Server.

# 4. Test connectivity to speed test server
ping <speedtest_server_ip>
```

### Resolution
1. Enable SpeedTest: set `Enable_Speedtest` to `true`
2. Configure server credentials via PSM or TR-181
3. Verify network connectivity to speed test infrastructure

---

## 9. Syscfg Corruption

### Symptom
Self-heal configuration reset to defaults; syscfg commands return empty or error.

### Logs
```
grep "syscfg\|SYSCFG" /rdklogs/logs/ArmConsolelog.txt.0
grep "syscfg_recover" /rdklogs/logs/SelfHeal*.txt
```

### Root Cause
| Cause | Indicator |
|-------|-----------|
| NVRAM flash wear | Frequent writes leading to corruption |
| Power loss during write | Incomplete syscfg commit |
| Shared memory corruption | syscfg_get returns garbage |
| Database file deletion | `/opt/secure/data/syscfg.db` missing |

### Debug Steps
```bash
# 1. Test syscfg
syscfg get selfheal_enable
syscfg show | wc -l   # Should be > 0

# 2. Check database file
ls -la /opt/secure/data/syscfg.db

# 3. Check shared memory
ipcs -m | grep syscfg

# 4. Run recovery manually
/usr/ccsp/tad/syscfg_recover.sh
```

### Resolution
1. Run `syscfg_recover.sh` to rebuild shared memory
2. If database file lost, factory defaults will be used
3. Re-apply critical configuration via TR-181

---

## 10. Fan/Thermal Alert

### Symptom
Telemetry reports `THERMAL:Fan_Rotor_Lock`; device may overheat.

### Logs
```
grep "THERMAL\|Fan_Rotor_Lock\|RotorLock" /rdklogs/logs/ArmConsolelog.txt.0
```

### Debug Steps
```bash
# 1. Check fan status
dmcli eRT getv Device.Thermal.Fan.1.Status
dmcli eRT getv Device.Thermal.Fan.1.Speed
dmcli eRT getv Device.Thermal.Fan.1.RotorLock

# 2. For dual-fan devices
dmcli eRT getv Device.Thermal.Fan.2.RotorLock

# 3. Check platform HAL
# Fan data comes from platform_hal_GetFanStatus/Speed/RotorLock
```

### Resolution
1. Hardware issue — fan may need replacement
2. Check for dust/obstruction blocking airflow
3. Verify platform_hal returns correct data (HAL bug check)
