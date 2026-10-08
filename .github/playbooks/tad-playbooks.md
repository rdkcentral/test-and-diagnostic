# Playbooks: Test and Diagnostic (TAD)

## Playbook 1: Issue Triage

### Input
- Issue report (symptom, logs, device model)

### Steps

1. **Classify by area:**
   | Keyword in Issue | Area | First File to Check |
   |-----------------|------|---------------------|
   | ping, traceroute, nslookup, download, upload | Network Diagnostics | `source/dmltad/cosa_ip_dml.c` |
   | self-heal, reboot, process crash, reset | Self-Heal | `scripts/corrective_action.sh`, `task_health_monitor.sh` |
   | latency, xNetSniffer, xNetDP, QoS | Latency/QoS | `source/LatencyMeasurement/` |
   | WAN, DNS, connectivity check | WAN Monitoring | `source/dmltad/cosa_wanconnectivity_*.c` |
   | fan, thermal, temperature | Hardware | `source/ThermalCtrl/check_fan.sh` |
   | speedtest | SpeedTest | `source/dmltad/cosa_ip_dml.c` (SpeedTest section) |
   | CcspTandDSsp crash, backtrace | SSP Crash | `source/TandDSsp/ssp_main.c` |
   | image health, upgrade | Post-Upgrade | `source/ImageHealthChecker/` |

2. **Assess severity:**
   - P1: CcspTandDSsp crash, reboot loop, self-heal causing excessive reboots
   - P2: Diagnostic feature broken, self-heal not running, WAN false positives
   - P3: Telemetry missing, non-critical script failure, cosmetic log issues

3. **Gather data:**
   - Device model (XB6, XB7, XLE, etc.)
   - Firmware version
   - Relevant log sections
   - `syscfg show` output (for config-related issues)
   - `dmcli eRT getv Device.SelfHeal.` (for self-heal issues)

4. **Route to specialist:**
   - BBHM engine issues → diagnostic subsystem expert
   - Self-heal script issues → shell script / RDK-B platform expert
   - Latency/QoS → networking expert
   - HAL failures → platform team

---

## Playbook 2: Log Analysis

### Input
- Log file(s) from device

### Analysis Steps

1. **Identify log source:**
   | File | Content |
   |------|---------|
   | SelfHeal.txt | Self-heal events, corrective actions |
   | SelfHealAggressive.txt | DHCP/interface/WAN healing |
   | ArmConsolelog.txt | CcspTandDSsp process output |
   | CPUInfo.txt | CPU/memory resource data |

2. **Extract key events (grep patterns):**
   ```
   RDKB_PROCESS_CRASHED    → process died, check which one
   RDKB_REBOOT             → self-heal triggered reboot
   SYS_SH_*_split          → specific self-heal action
   RDKB_SELFHEAL           → general self-heal activity
   DiagSchedule             → diagnostic was requested
   DiagComplete             → diagnostic finished
   WANCNCTVTYCHK            → WAN connectivity check event
   THERMAL                  → fan/thermal alert
   ```

3. **Build timeline:**
   - Sort events by timestamp
   - Identify first error
   - Correlate across log files
   - Check for patterns (recurring at fixed intervals = cron-triggered)

4. **Check for known patterns:**
   - Reboot at exactly N-min intervals → self-heal loop
   - Process crash + restart + crash → persistent bug
   - "dailyLimit reached" → safety mechanism triggered
   - "DiagnosticMode is true" → all actions suppressed

---

## Playbook 3: Recovery Procedures

> For detailed step-by-step recovery procedures with log patterns and root cause analysis, see `docs/troubleshooting-guide.md`.

### Quick Recovery Commands

| Scenario | Command |
|----------|---------|
| TAD not running | `systemctl restart CcspTandDSsp` or `/usr/bin/CcspTandDSsp -subsys eRT. &` |
| Self-heal stopped | `dmcli eRT setv Device.SelfHeal.X_RDKCENTRAL-COM_Enable bool true` + restart TAD |
| Reboot loop | `dmcli eRT setv Device.SelfHeal.X_RDKCENTRAL-COM_DiagnosticMode bool true` |
| Syscfg corrupt | `/usr/ccsp/tad/syscfg_recover.sh` |
| Stuck diagnostic | `dmcli eRT setv Device.IP.Diagnostics.IPPing.DiagnosticsState string None` |
| Stale lock files | `rm /tmp/*selfheal*.lock` |
| Daily limit reset | `syscfg set todays_reboot_count 0 && syscfg commit` |
