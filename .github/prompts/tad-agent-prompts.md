# AI Agent Prompts: Test and Diagnostic (TAD)

## Debugging Prompt

You are debugging an issue in the RDK-B test-and-diagnostic (TAD) component. TAD is a CCSP service running as `CcspTandDSsp` that provides network diagnostics (IP Ping, Traceroute, NSLookup, Download/Upload), self-healing, latency measurement, WAN connectivity monitoring, and hardware diagnostics.

**Context required before debugging:**
1. Which sub-feature is affected? (diagnostics / self-heal / latency / WAN check / thermal / image health)
2. What is the observed symptom?
3. What logs are available? (SelfHeal.txt, ArmConsolelog.txt, SelfHealAggressive.txt)

**Debugging approach:**
1. Identify the affected module from the symptom
2. Check process status: `pidof CcspTandDSsp xNetSniffer xNetDP`
3. Check component health: `dmcli eRT getv com.cisco.spvtg.ccsp.tdm.Health` (must be Green)
4. Examine relevant logs with these patterns:
   - Self-heal: `grep "RDKB_SELFHEAL\|RDKB_REBOOT\|RDKB_PROCESS_CRASHED" /rdklogs/logs/SelfHeal*.txt`
   - Diagnostics: `grep "DiagSchedule\|DiagComplete\|COSA_Diag" /rdklogs/logs/ArmConsolelog.txt.0`
   - Latency: `grep "LatencyMeasure\|xNetSniffer\|xNetDP" /rdklogs/logs/ArmConsolelog.txt.0`
   - WAN check: `grep "WANCNCTVTYCHK\|DNSInternet" /rdklogs/logs/ArmConsolelog.txt.0`
5. Check syscfg for configuration state
6. For crashes, check `/nvram/tadssp_backtrace`

**Key files by module:**
- SSP init: `source/TandDSsp/ssp_main.c`, `ssp_action.c`
- DML layer: `source/dmltad/cosa_ip_dml.c`, `cosa_selfheal_dml.c`, `cosa_dns_dml.c`
- BBHM engine: `source/diagnostic/BbhmDiagIpPing/`, `BbhmDiagIpTraceroute/`, `BbhmDiagNSLookup/`
- Self-heal scripts: `scripts/self_heal_connectivity_test.sh`, `resource_monitor.sh`, `task_health_monitor.sh`, `selfheal_aggressive.sh`
- Shared functions: `scripts/corrective_action.sh`
- WAN check: `source/dmltad/cosa_wanconnectivity_apis.c`, `cosa_wanconnectivity_operations.c`

---

## Root Cause Analysis (RCA) Prompt

You are performing root cause analysis on a TAD component issue. Follow this structured approach:

**Step 1 — Classify the failure:**
- Process crash (check `/nvram/tadssp_backtrace`, core dumps)
- Diagnostic failure (check DiagnosticsState, BBHM state machine)
- Self-heal malfunction (check cron, lock files, daily limits, diagnostic mode)
- Configuration loss (check syscfg database integrity)
- Inter-component failure (check D-Bus, rbus, sysevent)

**Step 2 — Trace the code path:**
- For diagnostics: DML callback → `cosa_ip_dml.c` Commit → `CosaDmlDiagScheduleDiagnostic()` → BBHM `SetDiagParams` → `StartDiag` → socket operations → `ResultQueryTask` → `CosaSendDiagCompleteSignal`
- For self-heal: cron/process trigger → script guards (uptime, enable, diagnostic mode) → health checks → `corrective_action.sh` functions → safety chain → action
- For WAN check: `CosaWanCnctvtyChk_Init()` → rbus registration → passive/active monitor threads → DNS query → event publish

**Step 3 — Check failure boundaries:**
- TAD internal (code bug, resource leak)
- Dependency failure (D-Bus down, syscfg corrupt, HAL error)
- Environmental (network down, hardware fault, memory exhausted)

**Step 4 — Build timeline from logs:**
- Correlate timestamps across SelfHeal.txt, ArmConsolelog.txt, SelfHealAggressive.txt
- Identify first error occurrence
- Determine if issue is persistent or intermittent

---

## Feature Development Prompt

You are implementing a new feature in the TAD component. Follow these patterns:

**For a new TR-181 parameter:**
1. Add to `config/TestAndDiagnostic_arm.XML`
2. Add DML callbacks in `source/dmltad/cosa_*_dml.c`
3. Add backend API in `source/dmltad/cosa_*_apis.c`
4. Add syscfg persistence if needed
5. Register in `source/dmltad/plugin_main.c` (if new object)
6. Update ARM-specific `source-arm/dmltad/plugin_main_priv.c` if needed

**For a new self-heal check:**
1. Choose script by frequency: aggressive (5min), resource (15min), task_health (maintenance)
2. Use `corrective_action.sh` functions: `resetNeeded()`, `rebootNeeded()`
3. Respect safety chain: daily limits, diagnostic mode, voice call check
4. Add telemetry: `t2CountNotify "SYS_SH_<marker>"`

**For a new diagnostic type:**
1. Follow BBHM object pattern: create base/interface/operation/process/states files
2. Inherit from `BBHM_DIAG_EXEC_OBJECT` using `CLASS_CONTENT` macro
3. Implement virtual methods: `StartDiag`, `StopDiag`, `CopyDiagParams`, `RetrieveResult`
4. Create TDO and Sink objects if async I/O needed
5. Register factory function in `bbhm_diag_lib.c`
6. Add DML callbacks in `cosa_ip_dml.c` or new file

**Coding standards:**
- Use `CcspTraceInfo/Warning/Error` for logging
- Use `v_secure_system`/`v_secure_popen` for shell commands
- Use `strcpy_s`/`sprintf_s` with `ERR_CHK(rc)` for strings
- Use `AnscAllocateMemory`/`AnscFreeMemory` for heap
- Follow CCSP DML callback return conventions
