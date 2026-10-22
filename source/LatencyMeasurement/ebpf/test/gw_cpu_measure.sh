#!/bin/sh
# gw_cpu_measure.sh - Measure CPU usage of one or two processes over a fixed
#                     window using /proc/[pid]/stat — no observer effect.
#
# Run this on the gateway DURING the stress_test.sh window on the LAN client.
#
# Usage:
#   sh gw_cpu_measure.sh <TOOL_NAME> <DURATION_SEC> [PID2_NAME]
#
# Examples:
#   # eBPF round: measure tcp_loader for 60 seconds
#   sh gw_cpu_measure.sh tcp_loader 60
#
#   # xNetSniffer round: measure both xNetSniffer and xNetDP for 60 seconds
#   sh gw_cpu_measure.sh xNetSniffer 60 xNetDP
#
# Output:
#   Process CPU% (user+sys combined), system-wide idle%, and a summary line.

PROC1_NAME="${1:-tcp_loader}"
DURATION="${2:-60}"
PROC2_NAME="${3:-}"

# ---- Kill competing tools to isolate CPU measurement ----
kill_procs() {
    for name in "$@"; do
        local pid
        pid=$(pidof "$name" | awk '{print $1}')
        if [ -n "$pid" ]; then
            echo "[setup] Stopping $name (pid=$pid) to isolate measurement"
            kill "$pid" 2>/dev/null
        fi
    done
}

if [ "$PROC1_NAME" = "tcp_loader" ]; then
    kill_procs xNetSniffer xNetDP
elif [ "$PROC1_NAME" = "xNetSniffer" ]; then
    kill_procs tcp_loader
fi
# Brief settle: let killed processes exit and CPU counters stabilise
sleep 2

# ---- Resolve PIDs ----
PROC1_PID=$(pidof "$PROC1_NAME" | awk '{print $1}')
[ -z "$PROC1_PID" ] && echo "ERROR: $PROC1_NAME not running" && exit 1

PROC2_PID=""
if [ -n "$PROC2_NAME" ]; then
    PROC2_PID=$(pidof "$PROC2_NAME" | awk '{print $1}')
    [ -z "$PROC2_PID" ] && echo "WARNING: $PROC2_NAME not found, ignoring"
fi

NUM_CPUS=$(grep -c '^processor' /proc/cpuinfo)

# ---- Read /proc/[pid]/stat: fields 14(utime) + 15(stime) ----
read_proc_jiffies() {
    local pid=$1
    awk '{print $14+$15}' /proc/"$pid"/stat 2>/dev/null || echo 0
}

# ---- Read RSS (physical memory) from /proc/[pid]/status, in kB ----
read_rss_kb() {
    local pid=$1
    awk '/^VmRSS/{print $2}' /proc/"$pid"/status 2>/dev/null || echo 0
}

# ---- Read total system jiffies from /proc/stat line 1 ----
read_sys_jiffies() {
    awk 'NR==1{t=0; for(i=2;i<=NF;i++) t+=$i; print t}' /proc/stat
}

# ---- Read individual /proc/stat fields for breakdown ----
# cpu user nice system idle iowait irq softirq steal ...
read_sys_fields() {
    awk 'NR==1{print $2, $3, $4, $5, $6, $7, $8}' /proc/stat
    # outputs: user nice system idle iowait irq softirq
}

# ---- Read system idle jiffies ----
read_idle_jiffies() {
    awk 'NR==1{print $5}' /proc/stat
}

echo "============================================================"
echo " CPU measurement: $PROC1_NAME${PROC2_NAME:+ + $PROC2_NAME}"
echo " Duration: ${DURATION}s   CPUs: $NUM_CPUS"
echo "============================================================"
echo "Sampling start..."

T0_P1=$(read_proc_jiffies "$PROC1_PID")
T0_P2=0; [ -n "$PROC2_PID" ] && T0_P2=$(read_proc_jiffies "$PROC2_PID")
T0_SYS=$(read_sys_jiffies)
T0_IDLE=$(read_idle_jiffies)
T0_FIELDS=$(read_sys_fields)
MEM0_P1=$(read_rss_kb "$PROC1_PID")
MEM0_P2=0; [ -n "$PROC2_PID" ] && MEM0_P2=$(read_rss_kb "$PROC2_PID")

printf "  %-20s  pid=%-6s  start_jiffies=%s\n" "$PROC1_NAME" "$PROC1_PID" "$T0_P1"
[ -n "$PROC2_PID" ] && \
    printf "  %-20s  pid=%-6s  start_jiffies=%s\n" "$PROC2_NAME" "$PROC2_PID" "$T0_P2"
echo ""
echo "Running for ${DURATION}s... (run stress_test.sh on LAN client now if not started)"
sleep "$DURATION"

T1_P1=$(read_proc_jiffies "$PROC1_PID")
T1_P2=0; [ -n "$PROC2_PID" ] && T1_P2=$(read_proc_jiffies "$PROC2_PID")
T1_SYS=$(read_sys_jiffies)
T1_IDLE=$(read_idle_jiffies)
T1_FIELDS=$(read_sys_fields)
MEM1_P1=$(read_rss_kb "$PROC1_PID")
MEM1_P2=0; [ -n "$PROC2_PID" ] && MEM1_P2=$(read_rss_kb "$PROC2_PID")

# ---- Compute deltas ----
D_P1=$((T1_P1 - T0_P1))
D_P2=$((T1_P2 - T0_P2))
D_COMBINED=$((D_P1 + D_P2))
D_SYS=$((T1_SYS - T0_SYS))
D_IDLE=$((T1_IDLE - T0_IDLE))

# Extract individual field deltas
# T0 fields at positions 1-7: user nice system idle iowait irq softirq
# T1 fields at positions 8-14 (same order, shifted by +7)
D_USER=$(echo "$T0_FIELDS $T1_FIELDS" | awk '{print $8-$1}')
D_NICE=$(echo "$T0_FIELDS $T1_FIELDS" | awk '{print $9-$2}')
D_SYS_T=$(echo "$T0_FIELDS $T1_FIELDS" | awk '{print $10-$3}')
D_IRQ=$(echo "$T0_FIELDS $T1_FIELDS" | awk '{print $13-$6}')
D_SOFTIRQ=$(echo "$T0_FIELDS $T1_FIELDS" | awk '{print $14-$7}')

# ---- Print results ----
MEM_COMBINED_END=$((MEM1_P1 + MEM1_P2))
MEM_COMBINED_START=$((MEM0_P1 + MEM0_P2))
IS_EBPF=0; [ "$PROC1_NAME" = "tcp_loader" ] && IS_EBPF=1

echo ""
echo "============================================================"
awk -v p1="$PROC1_NAME" -v d1="$D_P1" \
    -v p2="$PROC2_NAME" -v d2="$D_P2" \
    -v dc="$D_COMBINED" \
    -v ds="$D_SYS" -v di="$D_IDLE" -v nc="$NUM_CPUS" \
    -v du="$D_USER" -v dsys="$D_SYS_T" \
    -v dirq="$D_IRQ" -v dsoftirq="$D_SOFTIRQ" \
    -v m0p1="$MEM0_P1" -v m1p1="$MEM1_P1" \
    -v m0p2="$MEM0_P2" -v m1p2="$MEM1_P2" \
    -v ms="$MEM_COMBINED_START" -v me="$MEM_COMBINED_END" \
    -v is_ebpf="$IS_EBPF" \
'BEGIN {
    pct1 = (ds>0) ? (d1/ds)*nc*100 : 0
    pct2 = (ds>0) ? (d2/ds)*nc*100 : 0
    pctc = (ds>0) ? (dc/ds)*nc*100 : 0
    idle    = (ds>0) ? (di/ds)*100 : 0
    busy    = 100 - idle
    usr_pct = (ds>0) ? (du/ds)*100 : 0
    sys_pct = (ds>0) ? (dsys/ds)*100 : 0
    irq_pct = (ds>0) ? (dirq/ds)*100 : 0
    sirq_pct= (ds>0) ? (dsoftirq/ds)*100 : 0

    printf " %-22s CPU: %6.2f%%  (userspace process)\n", p1, pct1
    if (p2 != "") {
        printf " %-22s CPU: %6.2f%%  (userspace process)\n", p2, pct2
        printf " %-22s CPU: %6.2f%%  (combined process)\n", "TOTAL tool", pctc
    }
    printf "\n"
    printf " --- System CPU breakdown (all processes + kernel) ---\n"
    printf " User (all processes) : %6.2f%%\n", usr_pct
    printf " Kernel/sys           : %6.2f%%\n", sys_pct
    printf " HW interrupts (irq)  : %6.2f%%\n", irq_pct
    printf " SW interrupts (sirq) : %6.2f%%  ← AF_PACKET / kprobe overhead\n", sirq_pct
    printf " System busy (total)  : %6.2f%%\n", busy
    printf " System idle          : %6.2f%%\n", idle
    printf "\n"
    printf " --- Memory (RSS = physical pages resident) ---\n"
    printf " %-22s RSS: %4d kB  →  %4d kB  (start → end of test)\n", p1, m0p1, m1p1
    if (p2 != "")
        printf " %-22s RSS: %4d kB  →  %4d kB\n", p2, m0p2, m1p2
    if (p2 != "")
        printf " %-22s RSS: %4d kB  →  %4d kB  (combined)\n", "TOTAL tool", ms, me
    if (is_ebpf == 1) {
        printf " BPF kernel maps (fixed):  ~5.1 MB raw  (syn ~384K + synack ~768K + ring 4096K)\n"
        printf "   NOTE: BPF maps live in KERNEL space - not counted in RSS above.\n"
        printf "   Measure the real kernel cost with gw_ebpf_launch.sh (before/after meminfo).\n"
    }
    printf "============================================================\n"
}'
