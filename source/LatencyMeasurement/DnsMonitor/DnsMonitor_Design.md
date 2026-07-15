# DnsMonitor — Design and Developer Reference

**Component:** TestAndDiagnostic → LatencyMeasurement → DnsMonitor  
**Type:** Proof-of-Concept (POC)  
**Language:** C (C99)  
**Key dependency:** libpcap  

---

## 1. Purpose

`DnsMonitor` is a lightweight daemon that passively captures all DNS traffic on a
network interface and produces two categories of output:

| Output | Destination | Description |
|---|---|---|
| Structured log lines | stdout → RDK log pipeline | One line per DNS event with consistent tag prefix |
| Telemetry markers | Telemetry-2 (`telemetry_busmessage_sender`) | Aggregate counters emitted per report interval |

The goal is to give network operations and field-support engineers actionable,
grep-friendly DNS health data without requiring any additional tooling on the
device.

---

## 2. Background — Why libpcap?

The existing `xNetSniffer` binary in the same component (`source/LatencyMeasurement/xNetSniffer/`)
already uses libpcap to capture TCP SYN/ACK packets for latency measurement.
`DnsMonitor` follows the same pattern and links the same `-lpcap` library that is
already approved in the RDK build.

Passive capture with libpcap was chosen over an active probe approach (e.g. extending
`BbhmDiagNSLookup`) because:

- It observes **all** DNS traffic, not just on-demand diagnostics.
- It requires no changes to the DNS resolver or stub resolver configuration.
- Latency is measured from the actual packet timestamps provided by the kernel,
  not from application-level timers which can drift under load.
- Failure detection is independent of the client; even third-party application
  DNS queries are visible.

---

## 3. Repository Location

```
source/LatencyMeasurement/
├── Makefile.am                  ← DnsMonitor added to SUBDIRS
└── DnsMonitor/
    ├── DnsMonitor.c             ← full implementation
    └── Makefile.am              ← links -lpcap -ltelemetry_msgsender
```

The parallel telemetry hook added to the existing diagnostic object lives in:

```
source/diagnostic/BbhmDiagNSLookup/
├── bbhm_diagns_operation.c      ← BbhmDiagnsStop() emits T2 markers
└── bbhm_diagns_global.h         ← adds #include <telemetry_busmessage_sender.h>
```

---

## 4. Architecture Overview

```
 NIC (erouter0)
      │
      │  UDP port 53 traffic (BPF kernel filter)
      ▼
 ┌──────────────────────────────────┐
 │         libpcap                  │
 │  pcap_open_live()                │
 │  BPF: "udp port 53"              │
 │  pcap_dispatch() → packet_cb()   │
 └──────────────────┬───────────────┘
                    │ per-packet callback
                    ▼
 ┌──────────────────────────────────────────────────────┐
 │  packet_cb()                                         │
 │                                                      │
 │  1. Parse Ethernet → IP(v4/v6) → UDP → DNS headers  │
 │  2. Extract: src_ip, dst_ip, txid, flags, RCODE      │
 │  3. Parse QNAME (wire format → dotted string)        │
 │  4. Parse QTYPE (A, AAAA, MX …)                      │
 │  5. Expire timed-out pending queries                 │
 │                                                      │
 │  If QR=0 (query):                                    │
 │    pending_insert(txid, client_ip, …)                │
 │    stats.query_count++                               │
 │                                                      │
 │  If QR=1 (response):                                 │
 │    e = pending_remove(txid, client_ip)               │
 │    latency_ms = response_ts − e->query_ts            │
 │    RCODE==0  → [DNS_RESP_OK] / [DNS_SLOW]            │
 │    RCODE!=0  → [DNS_FAIL]  + server_bump_fail()      │
 └──────────────────┬───────────────────────────────────┘
                    │ every report_sec
                    ▼
 ┌──────────────────────────────────────────────────────┐
 │  report_and_reset()                                  │
 │  • Force-expire all pending → [DNS_TIMEOUT] lines    │
 │  • Print [DNS_SUMMARY] log line                      │
 │  • Emit Telemetry-2 markers                          │
 │  • Zero all accumulators                             │
 └──────────────────────────────────────────────────────┘
```

---

## 5. Data Structures

### 5.1 Pending-query table

Each outgoing DNS query is stored until the matching response arrives or it times out.

```c
typedef struct pending_entry {
    uint16_t       txid;               // DNS transaction ID
    char           client_ip[46];      // source of the query
    char           server_ip[46];      // destination (upstream DNS server)
    char           qname[256];         // parsed hostname e.g. "www.google.com"
    uint16_t       qtype;              // record type (1=A, 28=AAAA, 15=MX …)
    struct timeval query_ts;           // kernel timestamp of the query packet
    struct pending_entry *next;        // hash-chain next pointer
} pending_entry_t;
```

**Hash key:** `mix(client_ip, txid)` — a polynomial hash over the client IP string
XOR'd with the txid value. Using both fields prevents two clients with the same
transaction ID from colliding in the table (a real scenario on a gateway device
where many LAN clients share one WAN interface).

**Table size:** 4096 buckets, maximum 4096 concurrent pending entries. Both values
are compile-time constants (`DNS_HASH_BUCKETS`, `MAX_PENDING`).

### 5.2 Per-interval accumulators

```c
typedef struct {
    uint64_t query_count;        // total queries seen
    uint64_t success_count;      // responses with RCODE=0
    uint64_t slow_count;         // success but latency >= slow_thresh_ms
    uint64_t total_latency_ms;   // sum of successful latencies
    uint64_t max_latency_ms;     // peak successful latency
    uint64_t nxdomain;           // RCODE=3
    uint64_t servfail;           // RCODE=2
    uint64_t refused;            // RCODE=5
    uint64_t other_rcode;        // any other non-zero RCODE
    uint64_t timeout;            // queries expired with no response
} stats_t;
```

Reset to zero at the end of every `report_and_reset()` call.

### 5.3 Per-server failure tracker

```c
#define MAX_SERVER_TRACK 8
typedef struct { char ip[46]; uint64_t fail_count; } server_stat_t;
static server_stat_t g_servers[MAX_SERVER_TRACK];
```

Tracks up to 8 upstream DNS server IPs. Each RCODE failure or timeout increments
the counter for the responsible server. Reported in `[DNS_SUMMARY]` as
`server_fails=[8.8.8.8:12,1.1.1.1:3]`.

---

## 6. Log Line Format

All lines follow this pattern:

```
[TAG] ts=<ISO-8601ms> iface=<iface> <key=value> ...
```

- **ISO-8601 timestamps** include milliseconds and a `Z` suffix (UTC).
  Format: `2026-07-10T14:32:01.123Z`
- Every field is `key=value` with no spaces inside a value — safe to parse with
  `awk -F'[ =]'` or any structured log parser.
- Fields never change position within a tag type, making column-based awk scripts
  reliable.

### 6.1 Tag reference

#### `[DNS_QUERY]`
Emitted for every outgoing DNS query. Only written when `-v` (verbose) is active.

```
[DNS_QUERY] ts=2026-07-10T14:32:01.045Z iface=erouter0
  client=192.168.0.5 server=8.8.8.8 txid=0x1a2b
  qname=www.google.com qtype=A
```

| Field | Description |
|---|---|
| `client` | LAN IP that issued the query |
| `server` | Upstream DNS server IP |
| `txid` | DNS transaction ID (hex) |
| `qname` | Hostname being resolved |
| `qtype` | Record type name (A, AAAA, MX, CNAME, PTR, SRV, TXT, ANY, OTHER) |

#### `[DNS_RESP_OK]`
Emitted for a successful response (RCODE=0, latency within threshold). Only written
when `-v` is active.

```
[DNS_RESP_OK] ts=2026-07-10T14:32:01.089Z iface=erouter0
  client=192.168.0.5 server=8.8.8.8 txid=0x1a2b
  qname=www.google.com qtype=A latency_ms=44
```

| Field | Description |
|---|---|
| `latency_ms` | Round-trip time from query packet to response packet (milliseconds) |

#### `[DNS_SLOW]`
Emitted when RCODE=0 but latency ≥ `slow_thresh_ms`. **Always written regardless
of verbose mode.** This is the most important signal for detecting a degraded DNS
server before users notice.

```
[DNS_SLOW] ts=2026-07-10T14:32:05.310Z iface=erouter0
  client=192.168.0.5 server=8.8.8.8 txid=0x2c3d
  qname=api.example.com qtype=AAAA latency_ms=387
```

#### `[DNS_FAIL]`
Emitted when the DNS server returns a non-zero RCODE. **Always written.** The
`rcode` field includes both the numeric code and its name.

```
[DNS_FAIL] ts=2026-07-10T14:32:07.001Z iface=erouter0
  client=192.168.0.8 server=8.8.8.8 txid=0x3e4f
  qname=nonexistent.local qtype=A rcode=3(NXDOMAIN) latency_ms=21
```

| RCODE | Name | Meaning |
|---|---|---|
| 1 | FORMERR | Malformed query |
| 2 | SERVFAIL | Server internal failure |
| 3 | NXDOMAIN | Domain does not exist |
| 4 | NOTIMP | Query type not implemented |
| 5 | REFUSED | Server refused the query |
| 6–9 | YXDOMAIN … NOTZONE | Zone management errors |

#### `[DNS_TIMEOUT]`
Emitted when a tracked query receives no response within `query_timeout` seconds.
**Always written.**

```
[DNS_TIMEOUT] ts=2026-07-10T14:32:15.000Z iface=erouter0
  client=192.168.0.5 server=8.8.8.8 txid=0x4f50
  qname=slow.example.com qtype=MX
```

#### `[DNS_SUMMARY]`
Emitted once per report interval and once at START/STOP. **Always written.**
This is also the point where Telemetry-2 markers are sent.

```
[DNS_SUMMARY] ts=2026-07-10T14:37:01.000Z iface=erouter0
  queries=842 success=829 slow=4
  fail_total=13
  nxdomain=8 servfail=2 refused=1 other_rcode=0 timeout=2
  avg_ms=38 max_ms=412
  server_fails=[8.8.8.8:3,1.1.1.1:2]
```

---

## 7. Telemetry Markers

All markers are emitted inside `report_and_reset()` via the Telemetry-2 API.

| Marker name | Type | Condition | Description |
|---|---|---|---|
| `NET_DNS_PCAP_QUERY_CNT_split` | int | always | Total DNS queries seen in the interval |
| `NET_DNS_PCAP_LATENCY_AVG_ms_split` | int | success_count > 0 | Average round-trip latency (ms) |
| `NET_DNS_PCAP_LATENCY_MAX_ms_split` | int | success_count > 0 | Peak round-trip latency (ms) |
| `NET_DNS_PCAP_SLOW_CNT_split` | int | always | Queries that succeeded but exceeded slow threshold |
| `NET_DNS_PCAP_FAIL_CNT_split` | int | always | Total failures (rcode errors + timeouts) |
| `NET_DNS_PCAP_FAIL_TYPE_split` | string | fail_total > 0 | `"nxdomain=N,servfail=N,refused=N,other_rcode=N,timeout=N"` |

These markers complement the existing `BbhmDiagNSLookup` telemetry markers
(`NET_DNS_LATENCY_AVG_ms_split`, `NET_DNS_FAIL_CNT_split`, `NET_DNS_FAIL_TYPE_split`)
which are emitted only when an explicit NSLookup diagnostic is triggered.
`DnsMonitor` markers reflect **live ambient traffic** continuously.

---

## 8. Command-Line Interface

```
DnsMonitor -i <iface> [-r <report_sec>] [-t <timeout_sec>] [-s <slow_ms>] [-v]
```

| Option | Default | Description |
|---|---|---|
| `-i <iface>` | *(required)* | Network interface to capture (e.g. `erouter0`) |
| `-r <report_sec>` | 300 | Telemetry reporting interval in seconds |
| `-t <timeout_sec>` | 5 | Seconds before an unanswered query is declared a timeout |
| `-s <slow_ms>` | 200 | Latency threshold in ms above which a `[DNS_SLOW]` line is emitted |
| `-v` | off | Verbose mode — also logs `[DNS_QUERY]` and `[DNS_RESP_OK]` |

### Example invocations

```bash
# Production: report every 5 minutes, log only failures/slow/timeouts
DnsMonitor -i erouter0

# Debug: log everything, short report interval, tight slow threshold
DnsMonitor -i erouter0 -r 60 -t 3 -s 50 -v

# Field triage: default except more sensitive slow threshold
DnsMonitor -i erouter0 -s 100
```

---

## 9. Log Analysis Cookbook

### Find all DNS failures in a log file
```bash
grep '\[DNS_FAIL\]' /rdklogs/logs/TDMlog.txt
```

### Count SERVFAIL errors by DNS server
```bash
grep '\[DNS_FAIL\].*SERVFAIL' /rdklogs/logs/TDMlog.txt \
  | awk '{for(i=1;i<=NF;i++) if($i~/^server=/) print $i}' \
  | sort | uniq -c | sort -rn
```

### Show all slow queries ordered by latency
```bash
grep '\[DNS_SLOW\]' /rdklogs/logs/TDMlog.txt \
  | awk '{for(i=1;i<=NF;i++) if($i~/^latency_ms=/) print $i, $0}' \
  | sort -t= -k2 -rn | head -20
```

### Extract per-interval summary stats as CSV
```bash
grep '\[DNS_SUMMARY\]' /rdklogs/logs/TDMlog.txt \
  | grep -v 'event=START\|event=STOP' \
  | awk '{
      for(i=1;i<=NF;i++){
        split($i,a,"=");
        kv[a[1]]=a[2]
      }
      print kv["ts"]","kv["queries"]","kv["fail_total"]","kv["avg_ms"]","kv["max_ms"]
    }'
```

### Show all domains that failed NXDOMAIN more than once
```bash
grep '\[DNS_FAIL\].*NXDOMAIN' /rdklogs/logs/TDMlog.txt \
  | awk '{for(i=1;i<=NF;i++) if($i~/^qname=/) print $i}' \
  | sort | uniq -c | sort -rn | awk '$1 > 1'
```

### Watch live failures only (during a debug session)
```bash
DnsMonitor -i erouter0 -v 2>/dev/null | grep -E '\[DNS_FAIL\]|\[DNS_SLOW\]|\[DNS_TIMEOUT\]'
```

---

## 10. Latency Measurement Method

```
Time ──────────────────────────────────────────────►

  query_ts (pcap timestamp of UDP query packet)
      │
      │◄──── latency_ms ────────────────►│
      │                                  │
   [DNS_QUERY pkt]              [DNS_RESPONSE pkt]
                                         │
                                    response_ts (pcap timestamp)

latency_ms = (response_ts.tv_sec  - query_ts.tv_sec)  * 1000
           + (response_ts.tv_usec - query_ts.tv_usec) / 1000
```

Timestamps come directly from the kernel's `pcap_pkthdr.ts` field, which is set at
interrupt time when the packet DMA completes into the ring buffer. This is more
accurate than application-level `gettimeofday()` calls because it is not affected
by scheduler latency between the packet arrival and the application processing it.

---

## 11. Failure Classification

```
DNS Response received?
│
├── YES
│    └── RCODE == 0?
│         ├── YES → latency >= slow_thresh? → [DNS_SLOW]
│         │                               else [DNS_RESP_OK]
│         └── NO  → [DNS_FAIL]
│              ├── RCODE=2  → stats.servfail++
│              ├── RCODE=3  → stats.nxdomain++
│              ├── RCODE=5  → stats.refused++
│              └── other   → stats.other_rcode++
│
└── NO (after query_timeout seconds)
     └── [DNS_TIMEOUT] → stats.timeout++
```

---

## 12. Build Integration

### Makefile.am (DnsMonitor/)
```makefile
bin_PROGRAMS   = DnsMonitor
DnsMonitor_SOURCES = DnsMonitor.c
DnsMonitor_CFLAGS  = $(AM_CFLAGS) -I$(CCSP_HOME)/usr/include
DnsMonitor_LDFLAGS = -lpcap -ltelemetry_msgsender
```

### Makefile.am (LatencyMeasurement/)
```makefile
SUBDIRS = TR-181 xNetSniffer xNetDP ServiceMonitor DnsMonitor
```

### configure.ac
If not already present, `libpcap` availability should be checked:
```m4
PKG_CHECK_MODULES([PCAP], [libpcap], [], [
  AC_CHECK_LIB([pcap], [pcap_open_live], [],
    [AC_MSG_ERROR([libpcap not found])])
])
```
*(xNetSniffer already relies on libpcap so this check is likely already present.)*

---

## 13. Integration with ServiceMonitor

`DnsMonitor` is intended to be launched and health-monitored by
`ServiceMonitor.c` alongside `xNetSniffer` and `xNetDP`. A future integration
step would add:

1. A new `syscfg` key `DNS_MONITOR_ENABLE` (boolean).
2. A TR-181 parameter `Device.X_RDK_DNSMonitor.Enable` to control it via CWMP/USP.
3. A `CheckDnsMonitorServiceStatus()` call inside
   `MonitorLatencyMeasurementServices()` in `ServiceMonitor.c` that starts/stops
   the binary the same way `xNetDP` and `xNetSniffer` are managed today.

---

## 14. Limitations and Known POC Constraints

| Limitation | Impact | Suggested fix |
|---|---|---|
| UDP only (BPF filter `"udp port 53"`) | TCP DNS (large responses, zone transfers) is not captured | Change BPF to `"port 53"` and add TCP stream reassembly |
| No DNS-over-TLS / DNS-over-HTTPS | Encrypted DNS to port 853/443 is invisible | Requires separate TLS flow tracking |
| No EDNS0 / extended RCODE parsing | Extended RCODEs (> 15) are counted as `other_rcode` | Parse OPT RR in additional section |
| Per-server tracker limited to 8 entries | More than 8 upstream servers: oldest entries are dropped | Use a proper hash map |
| Single-threaded | Very high DNS rates (> ~50k qps) may cause dropped packets | Use `pcap_loop` with ring buffer or AF_PACKET |
| txid collision on duplicate queries | Retransmitted query overwrites the earlier timestamp | Add retransmit counter and keep earliest timestamp |

---

## 15. Testing on Technicolor XB8 (CGM4981COM)

This section documents the complete end-to-end procedure for cross-compiling
`DnsMonitor` using the XB8 Yocto toolchain and running it on a physical device.

### 15.1 Prerequisites

| Requirement | How to check |
|---|---|
| XB8 build tree checked out at `~/tchxb8` | `ls ~/tchxb8/build-tchxb8/conf/local.conf` |
| Device reachable over SSH | `ssh root@<device-ip>` |
| Device in gateway/router mode (not bridge) | `sysevent get bridge_mode` → should return `0` |
| WAN (erouter0) interface up | On device: `ifconfig erouter0` |
| libpcap 1.10.1 runtime present on device | On device: `ls /usr/lib/libpcap.so*` |

> **Note:** libpcap is already deployed on XB8 as a runtime dependency of the
> existing `xNetSniffer` binary. No additional package installation is needed.

---

### 15.2 Build Environment Variables

All paths below are derived from the confirmed XB8 Yocto build tree.

```bash
# Cross-compiler (GCC 11.3.0 for ARM Cortex-A15 hard-float NEON)
export CC=/mnt/home/rirfha948/tchxb8/build-tchxb8/tmp/sysroots-components/x86_64/gcc-cross-arm/usr/bin/arm-rdk-linux-gnueabi/arm-rdk-linux-gnueabi-gcc

# Sysroot base (cortexa15hf-neon)
export SYSROOT_BASE=/mnt/home/rirfha948/tchxb8/build-tchxb8/tmp/sysroots-components/cortexa15hf-neon

# libpcap include and lib
export PCAP_INC=${SYSROOT_BASE}/libpcap/usr/include
export PCAP_LIB=${SYSROOT_BASE}/libpcap/usr/lib

# Telemetry include and lib
export T2_INC=${SYSROOT_BASE}/telemetry/usr/include
export T2_LIB=${SYSROOT_BASE}/telemetry/usr/lib
```

---

### 15.3 Step 1 — Cross-Compile DnsMonitor

Run from the repository root or any writable directory on the build host:

```bash
cd /mnt/home/rirfha948/github/new/test-and-diagnostic/source/LatencyMeasurement/DnsMonitor

$CC \
  -std=c99 \
  -Wall -Wextra \
  -march=armv7-a -mfpu=neon -mfloat-abi=hard \
  -I${PCAP_INC} \
  -I${T2_INC} \
  -o DnsMonitor \
  DnsMonitor.c \
  -L${PCAP_LIB} -lpcap \
  -L${T2_LIB}  -ltelemetry_msgsender \
  -Wl,-rpath-link,${PCAP_LIB} \
  -Wl,-rpath-link,${T2_LIB}

echo "Build result: $?"
file DnsMonitor
```

Expected output:
```
Build result: 0
DnsMonitor: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV),
            dynamically linked, interpreter /lib/ld-linux-armhf.so.3, ...
```

> **POC tip:** If you want a self-contained binary with no library dependency
> (useful for quick drop-and-run testing), link libpcap statically and stub out
> the telemetry calls:
> ```bash
> $CC -std=c99 -march=armv7-a -mfpu=neon -mfloat-abi=hard \
>   -I${PCAP_INC} -I${T2_INC} \
>   -DDNS_MONITOR_STUB_TELEMETRY \
>   -o DnsMonitor DnsMonitor.c \
>   ${PCAP_LIB}/libpcap.a \
>   -L${T2_LIB} -ltelemetry_msgsender \
>   -Wl,-rpath-link,${T2_LIB}
> ```
> Add `#ifdef DNS_MONITOR_STUB_TELEMETRY` guards around the `t2_event_*` calls
> in `DnsMonitor.c` if telemetry is not needed during early POC testing.

---

### 15.4 Step 2 — Copy Binary to Device

Replace `<device-ip>` with the actual IP address of your XB8 (visible in the
lab setup or via `arp -n` after the device connects).

```bash
# From build host
scp DnsMonitor root@<device-ip>:/tmp/DnsMonitor
```

Confirm the copy succeeded:
```bash
ssh root@<device-ip> "ls -lh /tmp/DnsMonitor && file /tmp/DnsMonitor"
```

Expected:
```
-rwxr-xr-x  1 root root  48K Jul 14 10:00 /tmp/DnsMonitor
/tmp/DnsMonitor: ELF 32-bit LSB executable, ARM ...
```

---

### 15.5 Step 3 — Verify Device Readiness

SSH into the device and run these checks before starting the tool:

```bash
ssh root@<device-ip>

# 1. Confirm WAN interface is up and has an IP
ifconfig erouter0
# Expected: erouter0 should have an inet addr (IPv4 WAN IP)

# 2. Confirm bridge_mode = 0 (router mode)
sysevent get bridge_mode
# Expected: 0

# 3. Confirm libpcap is present
ls -la /usr/lib/libpcap.so*
# Expected: libpcap.so.1 -> libpcap.so.1.10.1

# 4. Confirm libtelemetry is present
ls -la /usr/lib/libtelemetry_msgsender.so*

# 5. Confirm BPF / raw socket capability (pcap needs it)
cat /proc/net/packet 2>/dev/null && echo "AF_PACKET available"

# 6. Check current DNS server(s) the device is using
cat /etc/resolv.conf
# or
sysevent get wan_dns_server
```

---

### 15.6 Step 4 — Run DnsMonitor

#### 4a. Basic run (failures + slow queries + summary only)

```bash
# On the device
chmod +x /tmp/DnsMonitor
/tmp/DnsMonitor -i erouter0 -r 60 -s 100 2>&1 | tee /tmp/dnsmon.log
```

`-r 60` gives a summary every 60 seconds (useful for POC rather than waiting 5 min).  
`-s 100` flags any response taking > 100 ms as slow.

#### 4b. Verbose run (log every query and response)

```bash
/tmp/DnsMonitor -i erouter0 -r 60 -s 100 -v 2>&1 | tee /tmp/dnsmon_verbose.log
```

#### 4c. Run in background and redirect to a dedicated log file

```bash
/tmp/DnsMonitor -i erouter0 -r 300 -s 200 \
  >> /rdklogs/logs/dnsmon.log 2>&1 &
echo "DnsMonitor PID: $!"
```

Stop it with:
```bash
kill $(pidof DnsMonitor)
```

---

### 15.7 Step 5 — Generate DNS Traffic for Testing

Open a second SSH session to the device (or use a connected LAN client) and
run these commands to generate different types of DNS events:

#### Normal queries (produces [DNS_RESP_OK] / [DNS_QUERY] in verbose)
```bash
# From the device itself or any LAN client
nslookup www.google.com
nslookup www.amazon.com
nslookup api.github.com
```

#### NXDOMAIN failures (produces [DNS_FAIL] with rcode=3(NXDOMAIN))
```bash
nslookup this-domain-does-not-exist-xyz123.com
nslookup nonexistent.local
```

#### Bulk queries to stress-test latency measurement
```bash
for i in $(seq 1 20); do
  nslookup host${i}.example.com &
done
wait
```

#### Simulate timeout (block DNS temporarily, then query)
```bash
# Drop DNS on erouter0 for 10 seconds using iptables
iptables -I OUTPUT -o erouter0 -p udp --dport 53 -j DROP
sleep 6   # wait longer than the query timeout (-t default is 5s)
nslookup www.google.com &
sleep 7
iptables -D OUTPUT -o erouter0 -p udp --dport 53 -j DROP
# Expect [DNS_TIMEOUT] lines in the log
```

> **Warning:** The `iptables` command above temporarily breaks WAN DNS for
> all clients. Run it only in a lab environment.

---

### 15.8 Step 6 — Interpret the Output

Run the following analysis commands directly on the device during or after a test session:

```bash
LOG=/tmp/dnsmon.log   # adjust if using a different path

# --- How many queries captured? ---
grep '\[DNS_SUMMARY\]' $LOG | grep -v 'event=' \
  | awk '{for(i=1;i<=NF;i++) if($i~/^queries=/) print $i}'

# --- Any failures? ---
grep '\[DNS_FAIL\]' $LOG

# --- Any slow queries? ---
grep '\[DNS_SLOW\]' $LOG

# --- Any timeouts? ---
grep '\[DNS_TIMEOUT\]' $LOG

# --- Summary line (all stats) ---
grep '\[DNS_SUMMARY\]' $LOG | grep -v 'event='

# --- Which DNS server had most failures? ---
grep '\[DNS_FAIL\]' $LOG \
  | awk '{for(i=1;i<=NF;i++) if($i~/^server=/) print $i}' \
  | sort | uniq -c | sort -rn

# --- Average latency per interval ---
grep '\[DNS_SUMMARY\]' $LOG | grep -v 'event=' \
  | awk '{for(i=1;i<=NF;i++) if($i~/^avg_ms=/) print $i}'
```

#### What healthy output looks like

```
[DNS_SUMMARY] ts=2026-07-14T10:05:00.000Z iface=erouter0
  queries=47 success=45 slow=0 fail_total=2
  nxdomain=2 servfail=0 refused=0 other_rcode=0 timeout=0
  avg_ms=32 max_ms=89 server_fails=[]
```

- `slow=0` and `timeout=0` — good
- `nxdomain=2` — expected (the two intentional `nslookup nonexistent.*` calls)
- `avg_ms=32` — healthy DNS latency for a residential gateway

#### What a problematic output looks like

```
[DNS_SUMMARY] ts=2026-07-14T10:10:00.000Z iface=erouter0
  queries=50 success=20 slow=8 fail_total=30
  nxdomain=2 servfail=15 refused=0 other_rcode=3 timeout=10
  avg_ms=340 max_ms=4812 server_fails=[75.75.75.75:18]
```

- High `servfail` + high `timeout` → upstream DNS server `75.75.75.75` is unreachable or overloaded
- High `avg_ms` / `max_ms` → network path to DNS server is congested

---

### 15.9 Step 7 — Verify Telemetry Markers (Optional)

If the device has the Telemetry-2 daemon running, verify that markers are being
sent by checking the telemetry log:

```bash
# Check if telemetry2_0 is running
pidof telemetry2_0 && echo "T2 running" || echo "T2 not running"

# After DnsMonitor emits a [DNS_SUMMARY], look for the marker in T2 logs
grep 'NET_DNS_PCAP' /rdklogs/logs/telemetry2_0.log 2>/dev/null \
  | tail -20

# Alternatively, use the telemetry client to query
/usr/bin/telemetry2_0_client get NET_DNS_PCAP_QUERY_CNT_split 2>/dev/null
```

> If Telemetry-2 is not running (common in a partial dev build), the binary will
> still work — only the `t2_event_*` calls will silently fail (they return an
> error code that `DnsMonitor` does not check). All log lines will still appear.

---

### 15.10 Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `pcap_open_live: erouter0: No such device` | WAN interface not up | Run `ifconfig erouter0 up` or wait for WAN init |
| `pcap_open_live: Permission denied` | Not running as root | `ssh root@<ip>` not `admin@<ip>` |
| Binary fails with `not found` / `SIGILL` | Wrong architecture compiled | Confirm `file DnsMonitor` shows ARM not x86 |
| `libpcap.so.1: cannot open shared object` | Library not on device | Run `find /usr/lib -name 'libpcap*'`; install package if missing |
| No `[DNS_QUERY]` lines even with `-v` | DNS traffic not going through erouter0 | Check: `sysevent get wan_ifname`; the WAN may use a different iface name |
| `[DNS_TIMEOUT]` for all queries | DNS queries going out but responses not arriving on erouter0 | Confirm with `tcpdump -i erouter0 udp port 53` on device |
| Only seeing response packets, no queries | Device is a DNS forwarder; queries stay on LAN side | Run on `brlan0` instead: `DnsMonitor -i brlan0` |
| Binary killed after a few seconds | `/tmp` has noexec mount flag | Copy to `/var/tmp` or `/usr/bin` instead |

#### Quick sanity check — raw tcpdump comparison

Before running `DnsMonitor`, validate that DNS traffic is actually visible on `erouter0`:

```bash
# On device — should see DNS packets when you do nslookup from any client
tcpdump -i erouter0 -n udp port 53 -c 10
```

If `tcpdump` shows packets but `DnsMonitor` does not, the issue is in the cross-compile
(wrong arch, missing symbol, etc.).

---

## 16. File Index

| File | Description |
|---|---|
| `source/LatencyMeasurement/DnsMonitor/DnsMonitor.c` | Full POC implementation |
| `source/LatencyMeasurement/DnsMonitor/Makefile.am` | Build rules |
| `source/LatencyMeasurement/DnsMonitor/DnsMonitor_Design.md` | This document |
| `source/LatencyMeasurement/Makefile.am` | Parent SUBDIRS (updated) |
| `source/diagnostic/BbhmDiagNSLookup/bbhm_diagns_operation.c` | `BbhmDiagnsStop()` — existing diag object telemetry (updated) |
| `source/diagnostic/BbhmDiagNSLookup/bbhm_diagns_global.h` | Added `#include <telemetry_busmessage_sender.h>` |
