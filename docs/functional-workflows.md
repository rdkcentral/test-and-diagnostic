# Functional Workflows

## 1. Initialization Workflows

### 1.1 CcspTandDSsp Daemon Startup

```
1. Process starts (launched by systemd or cosa_start.sh)
2. t2_init("CcspTandDSsp") — initialize telemetry 2.0
3. Parse command-line: -subsys <subsystem_prefix>, -c (console mode)
4. Daemonize (fork, setsid, redirect stdio to /dev/null)
5. Install signal handlers
6. Connect to D-Bus message bus (CCSP_Message_Bus_Init)
7. Wait for PSM (Persistent Storage Manager) availability on bus
8. Set CcspBaseIf callbacks for TR-181 parameter access
9. Create CPE Controller (DSLH framework)
10. Load libdiagnostic.so plugin, resolve 11 API function pointers
11. Call COSA_Diag_Init(bus_handle) — create all BBHM diagnostic objects
12. Register TR-181 data model with Component Registrar (CR)
13. Health transitions: Red → Yellow → Green
14. Open rbus handle ("TestAndDiagnosticsRbus")
15. Initialize Latency Measurement subsystem
16. Initialize Device Prioritization (if enabled)
17. Start time synchronization thread (EthWAN/Extender mode)
18. Enter main event loop (daemon: sleep forever; console: char dispatch)
```

### 1.2 DML Plugin Initialization

```
1. COSA_Init(bus_handle) called by DSLH framework
2. Acquire bus handle and subsystem prefix into globals
3. CosaBackEndManagerCreate():
   a. CosaDiagCreate() — allocate diagnostic data model
      - Create DSLH info objects for ping/trace/nslookup/download/upload
      - Initialize SpeedTest server config from PSM
      - Load RxTx stats from syscfg
   b. CosaSelfHealCreate() — load self-heal config from syscfg
      - 25+ syscfg key reads for all self-heal parameters
      - Load IPv4/IPv6 ping server lists
      - Start self-heal scripts (if enabled)
   c. CosaWanCnctvtyChk_Init() — WAN connectivity check
      - Open sysevent connection
      - Open rbus handle
      - Register rbus data elements
      - Subscribe to ActiveGateway events
4. Register all DML callback functions with CCSP framework
5. Register ARM-specific additional DM APIs
6. Return success — plugin is operational
```

### 1.3 Self-Heal Subsystem Startup

```
1. CosaSelfHealCreate() loads all config from syscfg
2. start_self_heal_scripts() OR manage_self_heal_cron_state(TRUE)
3. boot_mode.sh determines CRON vs PROCESS mode
4. Scripts added to crontab or started as background processes:
   - selfheal_aggressive.sh (5 min)
   - self_heal_connectivity_test.sh (60 min)
   - resource_monitor.sh (15 min)
   - log_hourly.sh (60 min)
   - start_gw_heath.sh (bootup, one-time)
   - selfheal_bootup.sh (bootup, one-time after 10 min)
5. Each script sources corrective_action.sh for shared functions
6. Each script sources boot_mode.sh for mode awareness
```

## 2. Core Operation Workflows

### 2.1 IP Ping Diagnostic

**Trigger:** `Device.IP.Diagnostics.IPPing.DiagnosticsState` set to `Requested`

```
1. DML SetParamStringValue("DiagnosticsState", "Requested")
2. cosa_ip_dml.c: sets DSLH_DIAG_STATE_TYPE_Requested on DiagInfo
3. DML Commit → CosaDmlDiagScheduleDiagnostic(DSLH_DIAGNOSTIC_TYPE_Ping, hDiagInfo)
4. AnscSpawnTask(_AsyncScheduleDiagnostic) — async execution
5. _AsyncScheduleDiagnostic:
   a. Call BBHM plugin: COSA_Diag_ScheduleDiagnostic(type, ctx, info)
   b. g_DiagIpPingObj->SetDiagParams(info) — copy Host, Interface, NumReps, etc.
   c. g_DiagIpPingObj->StartDiag()
      - Reset property counters (sent/recv/RTT)
      - Resolve destination IP (getaddrinfo)
      - Create ANSC XSocket (RAW, ICMP)
      - Create Sink object for async receive
      - Build ICMP Echo Request packet
      - Start TDO timer (interval=TimeBetween, counter=NumPkts)
      - Send first packet, record echo entry with timestamp
   d. BbhmDiageoStartDiag():
      - Set state to Inprogress
      - Spawn ResultQueryTask thread
6. TDO timer fires → Expire1() → send next packet, decrement counter
7. Sink Recv callback → validate ICMP reply → record stop time, increment PktsRecv
8. When PktsRecv == NumPkts → set COMPLETE
   OR TDO counter reaches 0 → Expire2() → set TIMEOUT
9. ResultQueryTask detects non-Inprogress state:
   a. RetrieveResult() — calculate min/max/avg RTT
   b. CosaSendDiagCompleteSignal() → D-Bus notification
10. Next GetParameterValues returns completed results
```

### 2.2 Traceroute Diagnostic

**Trigger:** `Device.IP.Diagnostics.TraceRoute.DiagnosticsState` set to `Requested`

```
1. DML sets Requested state with Host, MaxHopCount, Timeout, etc.
2. BBHM creates raw ICMP socket
3. For TTL = 1 to MaxHopCount:
   a. Set socket TTL option
   b. Send ICMP Echo Request (or UDP probe)
   c. Wait for ICMP Time Exceeded or Echo Reply
   d. Record hop address, RTT
   e. If destination reached → set COMPLETE
4. If MaxHopCount reached without destination → set COMPLETE (partial results)
5. Results stored as RouteHops.{i} table entries
```

### 2.3 NSLookup Diagnostic

**Trigger:** `Device.DNS.Diagnostics.NSLookupDiagnostics.DiagnosticsState` set to `Requested`

```
1. DML sets Requested state with HostName, DNSServer, Timeout, NumberOfRepetitions
2. BBHM creates UDP socket to DNSServer:53
3. For each repetition:
   a. Construct DNS query packet (A/AAAA record)
   b. Send via UDP
   c. Start TDO timer for timeout
   d. XSink receives DNS response
   e. Parse response: answer count, authoritative flag, resolved IPs
   f. Record result entry: Status, AnswerType, HostNameReturned, IPAddresses, ResponseTime
4. Set COMPLETE/TIMEOUT after all repetitions
5. Results available as Result.{i} table
```

### 2.4 Self-Heal Connectivity Test

```
1. Script starts (cron or process loop)
2. Source corrective_action.sh, boot_mode.sh
3. Check guards: uptime > 15 min, selfheal enabled, not in diagnostic mode
4. Wait random delay (10-59 min) to stagger across fleet
5. Read ping server configuration from syscfg/dmcli:
   - Ipv4PingServer_Count, Ipv4_PingServer_1..N
   - Ipv6PingServer_Count, Ipv6_PingServer_1..N
6. Test IPv4 connectivity:
   a. Ping default gateway on WAN interface
   b. If fail → ping each configured IPv4 server
   c. Score: pass_count vs MinNumPingServer
7. Test IPv6 connectivity (same pattern)
8. Test DNS (if dns_pingtest_enable):
   a. nslookup selfheal_dns_pingtest_url
9. If all fail → connectivity lost:
   a. Log connectivity failure
   b. If CorrectiveAction enabled:
      - Check daily limit (todays_reset_count < max_reset_count)
      - resetNeeded("", "PING") → router soft-reset
10. Log results, wait for next interval
```

### 2.5 Process Health Monitoring

```
task_health_monitor.sh (called from maintenance window):

For each critical process (CrSsp, PsmSsp, PandMSsp, WifiSsp, ...):
  1. pidof <process>
  2. If not running:
     a. Log "RDKB_PROCESS_CRASHED: <process>"
     b. resetNeeded(<folder>, <process>) → restart
  3. If running but potentially hung:
     a. Probe via dmcli (e.g., getv Device.WiFi.SSID.1.Status)
     b. If timeout (30s) → process is hung
     c. Kill and restart

Special checks:
  - meshAgent: CPU > 20% → restart
  - telemetry2_0: memory > 30MB → kill + restart
  - brlan0/brlan1: interface exists, has IP
  - erouter0: exists, has valid IP based on last-erouter-mode
  - Peer (Atom) ping: 3 retries, then reboot
  - dnsmasq: alive + not zombie
  - dibbler-server/client: running if IPv6 enabled
  - dropbear: running, listening on IPv6
```

## 3. Recovery Workflows

### 3.1 Process Crash Recovery

```
1. task_health_monitor.sh detects process not running
2. Call resetNeeded(folder, processName):
   a. Check todays_reset_count < max_reset_count
   b. Kill any zombie instances
   c. Start process: /usr/bin/<process> -subsys eRT.
      OR systemctl restart <service>
   d. Increment todays_reset_count
   e. Log telemetry marker
3. Special handling per process:
   - PandMSsp → also check captive portal
   - WifiSsp → also restart hostapd/wpa_supplicant
   - CrSsp → device reboot (too critical to just restart)
```

### 3.2 Device Reboot Recovery

```
1. rebootNeeded(source, reason) triggered
2. Pre-reboot safety chain:
   a. Diagnostic mode check → skip if enabled
   b. Daily limit check → skip if exceeded
   c. Voice call check → wait if active
   d. eCM registration check → skip if not registered
3. Pre-reboot logging:
   a. storeInformation() → CPU, memory, WiFi, MoCA stats
   b. Set reboot reason in syscfg
4. Log backup: /rdklogger/backupLogs.sh
5. Execute: reboot -f
6. On next boot:
   a. selfheal_bootup.sh verifies all processes started
   b. start_gw_heath.sh verifies WAN connectivity
   c. ImageHealthChecker validates system integrity (if Software_upgrade)
```

### 3.3 WAN Link Recovery

```
1. check_gw_health.sh detects WAN connectivity loss:
   a. CM Status check: not OPERATIONAL → wait 3 min, retry
   b. WAN IP check: no valid IP on erouter0
   c. DNS check: nslookup fails for WebPA/Xconf/NTP URLs
2. If unhealthy:
   a. rebootNeeded("RM", "", "wan_link_heal", 1)
   b. Single attempt (count=1) — reboots device
3. selfheal_aggressive.sh WAN recovery:
   a. erouter0 missing → reboot
   b. WAN status stuck "starting" → wan-restart after 2 cycles
   c. EthWAN failover → bring down/up Ethernet port
   d. IPv6 DAD failure → kill dibbler-client
```

### 3.4 Memory Recovery

```
1. resource_monitor.sh detects high memory usage
2. If threshold exceeded → rebootNeeded("RM", "MEM")
3. check_memory_health.sh (maintenance window):
   a. check_min_mem(): if free < MinMemoryThreshold_Value
      → echo 3 > /proc/sys/vm/drop_caches
   b. check_frag_mem(): if fragmentation > MemFragThreshold_Value
      → echo 1 > /proc/sys/vm/compact_memory
      → log_buddyinfo.sh (telemetry)
```

### 3.5 Syscfg Database Recovery

```
syscfg_recover.sh:
1. Check if syscfg database file exists and is valid
2. Verify shared memory segment integrity
3. If corrupted:
   a. Log warning
   b. Recreate shared memory segment
   c. Reload database from file
4. Run periodically via cron to prevent cascading failures
```
