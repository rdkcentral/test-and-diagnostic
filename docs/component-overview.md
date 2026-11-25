# Test and Diagnostic (TAD) — Component Overview

## Purpose

The **Test and Diagnostic (TAD)** component is a core RDK-B (Reference Design Kit — Broadband) service responsible for:

1. **Network Diagnostics** — TR-181/TR-143 compliant IP Ping, Traceroute, NSLookup, Download/Upload throughput tests, and UDP Echo services.
2. **Self-Healing** — Multi-layered health monitoring and automated corrective actions for connectivity, processes, CPU/memory, and hardware.
3. **Latency Measurement** — Per-client TCP handshake latency monitoring via packet capture.
4. **Device Prioritization** — Per-client QoS DSCP marking with cloud-driven scheduling.
5. **WAN Connectivity Checking** — Passive and active DNS-based WAN health monitoring.
6. **Hardware Diagnostics** — Fan/thermal monitoring, eMMC flash health, hardware self-tests.
7. **Image Health Checking** — Post-firmware-upgrade validation of WiFi, Ethernet, and client state.

## Component Identity

| Property | Value |
|----------|-------|
| CCSP Component ID | `com.cisco.spvtg.ccsp.tdm` |
| D-Bus Path | `/com/cisco/spvtg/ccsp/tdm` |
| Binary | `CcspTandDSsp` |
| Telemetry ID | `CcspTandDSsp` |
| Rbus Name | `TestAndDiagnosticsRbus` |
| Plugin Library | `libdiagnostic.so` |
| DML Library | `libdmltad` |
| License | Apache 2.0 |

## Repository Structure

```
test-and-diagnostic/
├── config/                          # TR-181 data model XML definitions
│   └── TestAndDiagnostic_arm.XML
├── scripts/                         # Self-heal, monitoring, and utility shell scripts
│   ├── self_heal_connectivity_test.sh
│   ├── resource_monitor.sh
│   ├── task_health_monitor.sh
│   ├── selfheal_aggressive.sh
│   ├── corrective_action.sh         # Shared self-heal library (sourced)
│   ├── boot_mode.sh                 # CRON/PROCESS mode selection
│   └── ... (40+ scripts)
├── source/
│   ├── TandDSsp/                    # Main SSP (Service Setup Program)
│   ├── dmltad/                      # TR-181 Data Model Library
│   ├── diagnostic/                  # BBHM diagnostic engine (libdiagnostic.so)
│   │   ├── BbhmDiagIpPing/
│   │   ├── BbhmDiagIpTraceroute/
│   │   ├── BbhmDiagNSLookup/
│   │   ├── BbhmDiagDownload/
│   │   ├── BbhmDiagUpload/
│   │   ├── BbhmUdpEchoServer/
│   │   └── include/
│   ├── LatencyMeasurement/
│   │   ├── ServiceMonitor/
│   │   ├── TR-181/
│   │   ├── xNetSniffer/
│   │   └── xNetDP/
│   ├── DevicePrioritization/
│   ├── xle_selfheal/               # XLE (Extender) self-heal binary
│   ├── ImageHealthChecker/          # Post-upgrade image verification
│   ├── CpuMemFrag/                  # Memory fragmentation monitoring
│   ├── ThermalCtrl/                 # Fan/thermal monitoring
│   └── util/                        # Helper binaries (Sub64, Selfhealutil, RxTx100)
├── source-arm/                      # ARM platform-specific overrides
│   ├── diagnostic/
│   └── dmltad/
└── Makefile.am / configure.ac       # Build system
```

## Build Configuration

The component uses GNU Autotools. Key build-time feature flags:

| Flag | Effect |
|------|--------|
| `--enable-resourceoptimization` | Excludes ARP table, Download/Upload, UDPEcho (for constrained devices) |
| `--enable-device_prioritization` | Includes DevicePrioritization module |
| `--enable-rdk_scheduler` | Enables time-based QoS scheduling |
| `--enable-mta` | Includes MTA (telephony) support |
| `--enable-warehousediagnostics` | Includes factory/warehouse diagnostics |
| `--enable-unitTestDockerSupport` | Builds unit tests in Docker |
| `--enable-core_net_lib_feature_support` | Links libnet for WAN connectivity |

## Build Outputs

| Output | Type | Purpose |
|--------|------|---------|
| `CcspTandDSsp` | Binary | Main daemon process |
| `libdiagnostic.so` | Shared Library | BBHM diagnostic plugin |
| `libdmltad` | Static Library | TR-181 DML plugin |
| `xNetSniffer` | Binary | Packet capture for latency measurement |
| `xNetDP` | Binary | Latency data plane processor |
| `ImageHealthChecker` | Binary | Post-upgrade image verification |
| `xle_selfheal` | Binary | XLE extender self-heal utility |
| `Selfhealutil` | Binary | Battery/power mode query |
| `Sub64` | Binary | 64-bit counter subtraction |
| `RxTx100` | Binary | Per-port RX/TX statistics |

## Runtime Location

Scripts and binaries are deployed to `/usr/ccsp/tad/` on the target device.
