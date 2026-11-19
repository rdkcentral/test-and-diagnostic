# AI Workflows: Test and Diagnostic (TAD)

## Workflow 1: Automated Triage

### Trigger
New issue filed mentioning TAD, CcspTandDSsp, self-heal, diagnostic, latency, or related keywords.

### Steps

```yaml
triage:
  input: issue_description, attached_logs
  
  step_1_classify:
    action: keyword_match
    rules:
      - keywords: [ping, traceroute, nslookup, download, upload, DiagnosticsState]
        area: network_diagnostics
        severity: P2
      - keywords: [crash, backtrace, SIGSEGV, core dump, CcspTandDSsp]
        area: process_crash
        severity: P1
      - keywords: [reboot loop, excessive reboot, SYS_SH, RDKB_REBOOT]
        area: self_heal_reboot_loop
        severity: P1
      - keywords: [self-heal, selfheal, RDKB_PROCESS_CRASHED, resetNeeded]
        area: self_heal
        severity: P2
      - keywords: [latency, xNetSniffer, xNetDP, QoS, DSCP]
        area: latency_qos
        severity: P2
      - keywords: [WAN, connectivity check, DNSInternet, WANCNCTVTYCHK]
        area: wan_monitoring
        severity: P2
      - keywords: [fan, thermal, temperature, RotorLock]
        area: hardware
        severity: P2
      - keywords: [speedtest, speed test]
        area: speedtest
        severity: P3
      - keywords: [image health, IHC, post-upgrade]
        area: image_health
        severity: P3

  step_2_data_request:
    action: request_info
    required:
      - device_model
      - firmware_version
      - relevant_log_sections
    conditional:
      self_heal: [syscfg_show_output, crontab_listing]
      process_crash: [backtrace_file, core_dump]
      network_diagnostics: [diagnostic_state_values]

  step_3_route:
    action: assign
    mapping:
      network_diagnostics: diagnostic_debug_workflow
      process_crash: crash_analysis_workflow
      self_heal: selfheal_debug_workflow
      self_heal_reboot_loop: reboot_loop_workflow
      latency_qos: latency_debug_workflow
      wan_monitoring: wan_check_debug_workflow
      hardware: hardware_debug_workflow
```

## Workflow 2: Automated Debug

### Trigger
Issue classified and data available.

### Steps

```yaml
debug:
  input: area, logs, device_info

  step_1_process_check:
    commands:
      - pidof CcspTandDSsp
      - pidof xNetSniffer xNetDP  # if latency area
      - dmcli eRT getv com.cisco.spvtg.ccsp.tdm.Health
    expect:
      CcspTandDSsp: running
      Health: Green

  step_2_log_analysis:
    patterns:
      network_diagnostics:
        - "grep 'DiagSchedule\\|DiagComplete\\|COSA_Diag\\|Error_' ArmConsolelog.txt"
      self_heal:
        - "grep 'RDKB_SELFHEAL\\|RDKB_REBOOT\\|RDKB_PROCESS_CRASHED' SelfHeal*.txt"
      latency_qos:
        - "grep 'LatencyMeasure\\|xNet' ArmConsolelog.txt"
      wan_monitoring:
        - "grep 'WANCNCTVTYCHK\\|DNSInternet' ArmConsolelog.txt"
    output: timeline_of_events

  step_3_config_check:
    commands:
      self_heal:
        - syscfg get selfheal_enable
        - syscfg get Selfheal_DiagnosticMode
        - syscfg get todays_reboot_count
        - syscfg get max_reboot_count
        - crontab -l | grep selfheal
      network_diagnostics:
        - dmcli eRT getv Device.IP.Diagnostics.IPPing.DiagnosticsState
      latency_qos:
        - syscfg get LatencyMeasure_IPv4Enable
        - rbuscli getvalues Device.QOS.X_RDK_LatencyMeasure_IPv4Enable

  step_4_root_cause:
    action: correlate
    inputs: [process_status, timeline, config_state]
    output: root_cause_hypothesis

  step_5_resolution:
    action: propose_fix
    based_on: root_cause_hypothesis
    reference: knowledge_base/tad-knowledge-base.md
```

## Workflow 3: Automated RCA

### Trigger
Post-incident analysis request.

### Steps

```yaml
rca:
  input: incident_description, full_logs, device_state

  step_1_timeline:
    action: build_event_timeline
    sources:
      - SelfHeal.txt.0
      - SelfHealAggressive.txt.0
      - ArmConsolelog.txt.0
      - CPUInfo.txt.0
    method: extract_timestamped_events, sort_chronologically

  step_2_first_failure:
    action: identify_first_error
    patterns:
      - "RDKB_PROCESS_CRASHED"
      - "Error_"
      - "RDKB_REBOOT"
      - "SIGSEGV\\|SIGBUS\\|SIGFPE"
      - "failed\\|FAILED"

  step_3_trace_code_path:
    action: map_to_source
    mapping:
      RDKB_PROCESS_CRASHED: scripts/task_health_monitor.sh
      DiagnosticsState_Error: source/diagnostic/BbhmDiag*/
      RDKB_REBOOT: scripts/corrective_action.sh → rebootNeeded()
      bus_init_failed: source/TandDSsp/ssp_messagebus_interface.c
      plugin_load_failed: source/TandDSsp/ssp_action.c

  step_4_classify:
    categories:
      - internal_bug: code defect in TAD component
      - dependency_failure: external service/library issue
      - configuration_error: wrong syscfg/TR-181 settings
      - environmental: network/hardware/resource issue
      - race_condition: timing-dependent failure

  step_5_document:
    template: |
      ## Root Cause Analysis
      **Incident:** {description}
      **Timeline:** {timeline}
      **First Error:** {first_error}
      **Code Path:** {code_path}
      **Root Cause:** {classification} — {detailed_cause}
      **Resolution:** {fix_or_workaround}
      **Prevention:** {recommended_changes}
```

## Workflow 4: Code Review Assist

### Trigger
PR modifying TAD component files.

### Checks

```yaml
code_review:
  input: changed_files, diff

  check_1_dml_conventions:
    if_files: ["cosa_*_dml.c"]
    verify:
      - GetParamBoolValue returns TRUE/FALSE (not 0/1 confusion)
      - GetParamStringValue returns 0/1/-1
      - SetParam* validates input before syscfg write
      - strcpy_s/sprintf_s used with ERR_CHK
      - No raw system()/popen() — must use v_secure_*

  check_2_selfheal_safety:
    if_files: ["scripts/*.sh"]
    verify:
      - Uses resetNeeded/rebootNeeded (not direct reboot)
      - Sources corrective_action.sh
      - Has uptime guard
      - Has selfheal_enable check
      - Has diagnostic mode check
      - Adds telemetry markers

  check_3_bbhm_pattern:
    if_files: ["source/diagnostic/**"]
    verify:
      - Follows CLASS_CONTENT inheritance pattern
      - Implements all virtual methods
      - Proper lock/unlock around shared state
      - Socket cleanup in StopDiag
      - Timer cleanup in StopDiag

  check_4_memory_safety:
    if_files: ["*.c"]
    verify:
      - AnscAllocateMemory results checked for NULL
      - No buffer overflows (check sizes)
      - AnscFreeMemory on all paths (no leaks)
      - Safe-C functions used for string ops

  check_5_xml_consistency:
    if_files: ["config/TestAndDiagnostic_arm.XML"]
    verify:
      - New parameters have matching DML callbacks
      - Access rights (readOnly vs readWrite) match implementation
      - Type matches callback parameter type
```
