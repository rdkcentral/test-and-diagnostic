# Developer Guide

## 1. Build Instructions

### Prerequisites
- RDK-B build environment with `meta-rdk` layer
- GNU Autotools (autoconf ≥ 2.65, automake, libtool)
- Cross-compilation toolchain for target platform

### Build Steps

```bash
# Generate configure script
autoreconf -i

# Configure (example with common options)
./configure \
    --prefix=/usr \
    --host=arm-linux-gnueabihf \
    --enable-device_prioritization \
    --enable-rdk_scheduler

# Build
make -j$(nproc)

# Build outputs:
#   .libs/libdiagnostic.so         - BBHM diagnostic plugin
#   source/TandDSsp/CcspTandDSsp   - Main daemon binary
#   source/LatencyMeasurement/xNetSniffer/xNetSniffer
#   source/LatencyMeasurement/xNetDP/xNetDP
#   source/ImageHealthChecker/ImageHealthChecker
#   source/xle_selfheal/xle_selfheal
#   source/util/Selfhealutil
#   source/util/Sub64
#   source/util/RxTx100
```

### Feature Flags

| Flag | Effect |
|------|--------|
| `--enable-resourceoptimization` | Strips ARP/Download/Upload/UDPEcho for constrained devices |
| `--enable-device_prioritization` | Builds DevicePrioritization module |
| `--enable-rdk_scheduler` | Adds time-based QoS scheduling |
| `--enable-mta` | Includes MTA telephony support |
| `--enable-warehousediagnostics` | Factory test diagnostics |
| `--enable-unitTestDockerSupport` | Docker-based unit tests |

### Unit Tests

```bash
./configure --enable-unitTestDockerSupport
make
cd source/test
make check
```

## 2. Key Log Files and Locations

| Log File | Content |
|----------|---------|
| `/rdklogs/logs/SelfHeal.txt.0` | Self-heal script output (connectivity, resource, task health) |
| `/rdklogs/logs/SelfHealAggressive.txt.0` | Aggressive self-heal (DHCP, interfaces, WAN) |
| `/rdklogs/logs/ArmConsolelog.txt.0` | CcspTandDSsp process logs (CcspTrace* output) |
| `/rdklogs/logs/CPUInfo.txt.0` | CPU/memory stats, buddyinfo |
| `/rdklogs/logs/Consolelog.txt.0` | General system console logs |
| `/nvram/tadssp_backtrace` | Crash backtrace from signal handler |
| `/tmp/hwselftest.results` | Hardware self-test output |
| `/tmp/.speedtest-client-version.log` | SpeedTest client version |

### Log Grep Patterns

```bash
# Self-heal events
grep "RDKB_SELFHEAL\|RDKB_REBOOT\|RDKB_PROCESS_CRASHED" /rdklogs/logs/SelfHeal*.txt

# Diagnostic activity
grep "DiagSchedule\|DiagComplete\|COSA_Diag" /rdklogs/logs/ArmConsolelog.txt.0

# Connectivity test results
grep "PING_FAILED\|GW_HEALTH\|CONNECTIVITY" /rdklogs/logs/SelfHeal*.txt

# Resource monitoring
grep "AvgCPU\|AvgMemory\|THRESHOLD" /rdklogs/logs/SelfHeal*.txt

# WAN connectivity check
grep "WANCNCTVTYCHK\|DNSInternet" /rdklogs/logs/ArmConsolelog.txt.0

# Latency measurement
grep "LatencyMeasure\|xNetSniffer\|xNetDP" /rdklogs/logs/ArmConsolelog.txt.0

# Telemetry markers
grep "SYS_SH_\|RDKB_REBOOT\|THERMAL\|IHC_" /rdklogs/logs/*.txt*
```

## 3. Debug Commands

### Process Status

```bash
# Check all TAD-related processes
pidof CcspTandDSsp xNetSniffer xNetDP ImageHealthChecker

# Check component health
dmcli eRT getv com.cisco.spvtg.ccsp.tdm.Health
# Expected: Green

# Check all self-heal script instances
ps aux | grep -E "selfheal|resource_monitor|connectivity_test|task_health"
```

### TR-181 Parameter Queries

```bash
# IP Ping diagnostic
dmcli eRT getv Device.IP.Diagnostics.IPPing.

# Traceroute
dmcli eRT getv Device.IP.Diagnostics.TraceRoute.

# NSLookup
dmcli eRT getv Device.DNS.Diagnostics.NSLookupDiagnostics.

# Self-Heal configuration
dmcli eRT getv Device.SelfHeal.

# Self-Heal connectivity test
dmcli eRT getv Device.SelfHeal.ConnectivityTest.

# Ping servers
dmcli eRT getv Device.SelfHeal.ConnectivityTest.PingServerList.

# Resource monitor
dmcli eRT getv Device.SelfHeal.ResourceMonitor.

# SpeedTest
dmcli eRT getv Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.

# WAN Connectivity
dmcli eRT getv Device.Diagnostics.X_RDK_DNSInternet.

# Hardware test
dmcli eRT getv Device.X_RDK_hwHealthTest.

# Fan/Thermal
dmcli eRT getv Device.Thermal.Fan.

# Latency
rbuscli getvalues Device.QOS.X_RDK_LatencyMeasure_IPv4Enable
```

### Running Diagnostics

```bash
# Run an IP Ping test
dmcli eRT setv Device.IP.Diagnostics.IPPing.Host string 8.8.8.8
dmcli eRT setv Device.IP.Diagnostics.IPPing.NumberOfRepetitions uint 5
dmcli eRT setv Device.IP.Diagnostics.IPPing.DiagnosticsState string Requested
sleep 10
dmcli eRT getv Device.IP.Diagnostics.IPPing.

# Run NSLookup
dmcli eRT setv Device.DNS.Diagnostics.NSLookupDiagnostics.HostName string google.com
dmcli eRT setv Device.DNS.Diagnostics.NSLookupDiagnostics.DiagnosticsState string Requested
sleep 5
dmcli eRT getv Device.DNS.Diagnostics.NSLookupDiagnostics.

# Trigger hardware self-test
dmcli eRT setv Device.X_RDK_hwHealthTest.executeTest bool true
sleep 30
dmcli eRT getv Device.X_RDK_hwHealthTest.Results
```

### Syscfg Inspection

```bash
# Self-heal status
syscfg get selfheal_enable
syscfg get SelfHealCronEnable
syscfg get Selfheal_DiagnosticMode
syscfg get todays_reboot_count
syscfg get todays_reset_count
syscfg get max_reboot_count
syscfg get last_reboot_reason
syscfg get ConnTest_PingInterval
syscfg get resource_monitor_interval
syscfg get avg_cpu_threshold
syscfg get avg_memory_threshold

# Ping servers
syscfg get Ipv4PingServer_Count
syscfg get Ipv4_PingServer_1

# Latency config
syscfg get LatencyMeasure_IPv4Enable
syscfg get LatencyMeasure_TCP_ReportInterval
```

### Cron Status

```bash
# View all TAD-related cron entries
crontab -l | grep -E "selfheal|resource|connectivity|health|hourly|buddyinfo"
```

## 4. Validation Steps

### After Code Changes

1. **Build verification**: `make clean && make` succeeds without errors
2. **Process startup**: `CcspTandDSsp -c` (console mode) starts, Health reaches Green
3. **Data model registration**: `dmcli eRT getv Device.IP.Diagnostics.IPPing.Host` returns value
4. **Diagnostic test**: Run a ping diagnostic end-to-end (set state → results available)
5. **Self-heal config**: `dmcli eRT getv Device.SelfHeal.` shows expected config
6. **Process self-heal**: Kill a monitored process, verify auto-restart within maintenance window
7. **Syscfg persistence**: Set a config value, reboot, verify it persists

### Integration Checks

```bash
# 1. TAD registered with CR?
dmcli eRT getv Device.IP.Diagnostics.IPPing.Host
# Should NOT return "Can't find destination component"

# 2. Self-heal scripts scheduled?
crontab -l | grep -c "ccsp/tad"
# Should be > 0 (in CRON mode)

# 3. Latency measurement operational?
pidof xNetSniffer && echo "Sniffer running" || echo "Sniffer NOT running"
pidof xNetDP && echo "DP running" || echo "DP NOT running"

# 4. rbus elements registered?
rbuscli getvalues Device.QOS.X_RDK_LatencyMeasure_IPv4Enable

# 5. WAN connectivity check?
dmcli eRT getv Device.Diagnostics.X_RDK_DNSInternet.Enable
```

## 5. Adding a New TR-181 Parameter

### Step-by-Step

1. **Define in XML**: Add parameter to `config/TestAndDiagnostic_arm.XML`
   ```xml
   <parameter name="MyNewParam" access="readWrite" type="string" />
   ```

2. **Add DML callbacks** in appropriate `cosa_*_dml.c`:
   ```c
   // In GetParamStringValue:
   if (strcmp(ParamName, "MyNewParam") == 0) {
       AnscCopyString(pValue, pMyContext->MyNewParam);
       return 0;
   }

   // In SetParamStringValue:
   if (strcmp(ParamName, "MyNewParam") == 0) {
       rc = strcpy_s(pMyContext->MyNewParam, sizeof(pMyContext->MyNewParam), pString);
       ERR_CHK(rc);
       return TRUE;
   }
   ```

3. **Add persistence** (if needed) in `*_apis.c`:
   ```c
   syscfg_set_commit(NULL, "my_new_param", value);
   ```

4. **Register callbacks** in `plugin_main.c` (if new object):
   ```c
   pPlugInfo->RegisterFunction(pPlugInfo->hContext, "MyObject_GetParamStringValue", MyObject_GetParamStringValue);
   ```

5. **Rebuild** and test via `dmcli`

### Code Conventions

- Use `CcspTraceInfo` / `CcspTraceWarning` / `CcspTraceError` for logging
- Use `v_secure_system` / `v_secure_popen` instead of `system()` / `popen()`
- Use `strcpy_s` / `sprintf_s` with `ERR_CHK(rc)` for string operations
- Use `AnscAllocateMemory` / `AnscFreeMemory` for heap allocations
- Check all return values; log and handle gracefully
- Use `errno_t rc = -1;` idiom for Safe-C operations

## 6. Adding a New Self-Heal Check

### Step-by-Step

1. **Choose the right script** based on check frequency:
   - `selfheal_aggressive.sh` — fast checks (5 min)
   - `resource_monitor.sh` → `task_health_monitor.sh` — process checks (maintenance window)
   - `self_heal_connectivity_test.sh` — network checks (hourly)

2. **Add the check** in the appropriate script:
   ```bash
   # Example: Check if myprocess is running
   MYPROC_PID=$(pidof myprocess)
   if [ -z "$MYPROC_PID" ]; then
       echo_t "RDKB_PROCESS_CRASHED : myprocess is not running, restarting"
       t2CountNotify "SYS_SH_myprocess_restart"
       resetNeeded myprocess myprocess
   fi
   ```

3. **Use corrective_action.sh functions**:
   - `resetNeeded(folder, process)` — restart a process
   - `rebootNeeded(source, reason)` — full device reboot
   - `checkConditionsbeforeAction()` — safety checks

4. **Add telemetry markers** for field tracking:
   ```bash
   t2CountNotify "SYS_SH_MyCheck_split"
   ```

5. **Test**: Kill the process, wait for script execution, verify restart

## 7. File Layout Reference

| Directory | Contents |
|-----------|----------|
| `source/TandDSsp/` | SSP main, signal handling, bus connect, rbus, time sync |
| `source/dmltad/` | All TR-181 DML callbacks and backend APIs |
| `source/diagnostic/` | BBHM diagnostic engine (libdiagnostic.so plugin) |
| `source/diagnostic/include/` | All BBHM headers (interfaces, properties, OIDs) |
| `source/LatencyMeasurement/` | Latency capture and reporting |
| `source/DevicePrioritization/` | QoS per-client DSCP marking |
| `source/xle_selfheal/` | XLE extender-specific self-heal binary |
| `source/ImageHealthChecker/` | Post-upgrade image verification |
| `source/CpuMemFrag/` | Memory fragmentation monitoring scripts |
| `source/ThermalCtrl/` | Fan monitoring scripts |
| `source/util/` | Helper binaries (Sub64, Selfhealutil, RxTx100) |
| `source-arm/` | ARM platform-specific overrides |
| `scripts/` | Self-heal and monitoring shell scripts |
| `config/` | TR-181 data model XML definitions |
