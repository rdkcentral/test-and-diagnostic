#!/bin/sh
# gw_ebpf_launch.sh - Run on the gateway to launch tcp_loader for a test round.
#
# Analogue of gw_xnetsniffer.sh (which launches the xNet apps), but for the eBPF
# tool.  In addition to starting tcp_loader, it snapshots KERNEL memory BEFORE and
# AFTER the load so you can see how much RAM the BPF program + maps actually cost.
#
# WHY KERNEL memory (not just process RSS): the eBPF maps (two LRU hashes + the
# ring buffer) live in KERNEL space, charged to the regular allocator on kernel
# 5.11+ (exempt from RLIMIT_MEMLOCK).  They do NOT show up in tcp_loader's VmRSS,
# so gw_cpu_measure.sh's RSS figure understates the real footprint.  The
# before/after /proc/meminfo delta captures the kernel cost.
#
# NOTE: MemFree/MemAvailable deltas are slightly noisy (other processes allocate
#       during the window).  Slab/Percpu/Vmalloc growth and the theoretical map
#       size below are the more reliable indicators; treat the delta as ±100 kB.
#
# Usage:
#   Launch:  sh gw_ebpf_launch.sh [path/to/tcp_loader] [CONSUME_INTERVAL_SEC] [OUTPUT_FILE]
#            sh gw_ebpf_launch.sh /usr/bin/ebpf/tcp_loader 30 /tmp/ebpf_results.txt
#   Stop:    sh gw_ebpf_launch.sh -k [path/to/tcp_loader]
#            -> kills the loader and confirms the kernel memory (maps + program)
#               is reclaimed, comparing against the pre-launch baseline (leak check).
#
# After launch the loader stays running in the background until you stop it.

BASELINE_FILE="/tmp/ebpf_mem_baseline"

# --- Kernel memory snapshot: prints "MemFree MemAvailable Slab Percpu VmallocUsed"
#     (any field missing on this kernel prints as 0) ---
mem_snapshot() {
    awk '
        /^MemFree:/      {mf=$2}
        /^MemAvailable:/ {ma=$2}
        /^Slab:/         {sl=$2}
        /^Percpu:/       {pc=$2}
        /^VmallocUsed:/  {vu=$2}
        END { printf "%d %d %d %d %d\n", mf, ma, sl, pc, vu }
    ' /proc/meminfo
}

# --- Parse mode: default "launch"; "-k"/"stop" kills the loader and verifies the
#     kernel memory is released on exit. ---
MODE="launch"
case "$1" in
    -k|--kill|stop) MODE="stop"; shift ;;
esac

LOADER="${1:-/usr/bin/ebpf/tcp_loader}"
INTERVAL="${2:-30}"
OUT="${3:-/tmp/ebpf_results.txt}"
LOADER_NAME=$(basename "$LOADER")

# ============================================================================
# STOP MODE: kill the loader, then confirm kernel memory returns to baseline.
# ============================================================================
if [ "$MODE" = "stop" ]; then
    PID=$(pidof "$LOADER_NAME" | awk '{print $1}')
    echo "Stopping $LOADER_NAME (pid=${PID:-none}) and checking kernel memory reclaim..."

    sync; RUNNING=$(mem_snapshot)
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    echo "Waiting 3s for BPF map teardown (RCU free)..."
    sleep 3
    sync; AFTERKILL=$(mem_snapshot)

    set -- $RUNNING;   R_FREE=$1; R_SLAB=$3; R_VMAP=$5
    set -- $AFTERKILL; K_FREE=$1; K_SLAB=$3; K_VMAP=$5

    printf "RUNNING    MemFree=%s kB  Slab=%s kB  Vmalloc=%s kB\n" "$R_FREE" "$R_SLAB" "$R_VMAP"
    printf "AFTER KILL MemFree=%s kB  Slab=%s kB  Vmalloc=%s kB\n" "$K_FREE" "$K_SLAB" "$K_VMAP"
    echo ""
    echo "--- Kernel memory reclaimed on loader exit ---"
    printf " MemFree recovered : %d kB\n" "$((K_FREE - R_FREE))"
    printf " Slab freed        : %d kB\n" "$((R_SLAB - K_SLAB))"
    printf " Vmalloc freed     : %d kB\n" "$((R_VMAP - K_VMAP))"

    if [ -f "$BASELINE_FILE" ]; then
        read -r P_FREE P_AVAIL P_SLAB P_PCPU P_VMAP < "$BASELINE_FILE"
        echo ""
        echo "--- Leak check vs pre-launch baseline (Vmalloc) ---"
        # Vmalloc is where the BPF map structures live and, unlike MemFree, is
        # NOT polluted by page cache / conntrack / other churn during the test.
        # So the Vmalloc residual is the reliable leak signal; a MemFree-based
        # comparison across a long test run is meaningless (it drifts by MBs from
        # conntrack + page cache and would show a false "leak").
        printf " Pre-launch Vmalloc : %s kB\n" "$P_VMAP"
        printf " Post-kill  Vmalloc : %s kB\n" "$K_VMAP"
        printf " Vmalloc residual   : %d kB  (near 0 = clean; BPF maps fully released)\n" "$((K_VMAP - P_VMAP))"
        echo " (+/-100 kB is normal noise.  MemFree is NOT used here: it drifts by"
        echo "  MBs during a test from conntrack/page cache and is not a leak signal.)"
        rm -f "$BASELINE_FILE"
    else
        echo "(no pre-launch baseline at $BASELINE_FILE - run launch mode first for a leak check)"
    fi
    exit 0
fi

# ============================================================================
# LAUNCH MODE
# ============================================================================
[ -x "$LOADER" ] || { echo "ERROR: loader not found/executable: $LOADER" >&2; exit 1; }

# --- Kill any existing tcp_loader to avoid duplicate maps/attachments ---
OLDPID=$(pidof "$LOADER_NAME" | awk '{print $1}')
if [ -n "$OLDPID" ]; then
    echo "Stopping existing $LOADER_NAME (pid=$OLDPID)"
    kill "$OLDPID" 2>/dev/null
    sleep 2
fi

echo "============================================================"
echo " eBPF launch + kernel memory measurement"
echo " Loader   : $LOADER"
echo " Interval : ${INTERVAL}s   Output: $OUT"
echo "============================================================"

# --- BEFORE snapshot ---
sync
BEFORE=$(mem_snapshot)
echo "$BEFORE" > "$BASELINE_FILE"   # saved for the -k reclaim/leak check later
set -- $BEFORE
B_FREE=$1; B_AVAIL=$2; B_SLAB=$3; B_PCPU=$4; B_VMAP=$5
printf "BEFORE  MemFree=%s kB  MemAvail=%s kB  Slab=%s kB  Percpu=%s kB  Vmalloc=%s kB\n" \
    "$B_FREE" "$B_AVAIL" "$B_SLAB" "$B_PCPU" "$B_VMAP"

# --- Launch tcp_loader in the background ---
"$LOADER" "$INTERVAL" -o "$OUT" >/dev/null 2>&1 &
LPID=$!
echo "Launched $LOADER_NAME pid=$LPID"

# Give it time to load the object, create maps, and attach the kprobes.
echo "Waiting 3s for map creation + kprobe attach..."
sleep 3

# Verify it survived startup (verifier/attach failures exit early).
if ! kill -0 "$LPID" 2>/dev/null; then
    echo "ERROR: $LOADER_NAME exited during startup — re-running in foreground to show the error:" >&2
    "$LOADER" "$INTERVAL" 2>&1 | head -n 20
    exit 1
fi

# --- AFTER snapshot ---
sync
AFTER=$(mem_snapshot)
set -- $AFTER
A_FREE=$1; A_AVAIL=$2; A_SLAB=$3; A_PCPU=$4; A_VMAP=$5
printf "AFTER   MemFree=%s kB  MemAvail=%s kB  Slab=%s kB  Percpu=%s kB  Vmalloc=%s kB\n" \
    "$A_FREE" "$A_AVAIL" "$A_SLAB" "$A_PCPU" "$A_VMAP"

# --- Deltas (positive number = memory consumed by the eBPF load) ---
echo ""
echo "--- Kernel memory consumed by eBPF program + maps ---"
printf " MemFree drop      : %d kB\n" "$((B_FREE  - A_FREE))"
printf " MemAvailable drop : %d kB\n" "$((B_AVAIL - A_AVAIL))"
printf " Slab growth       : %d kB\n" "$((A_SLAB  - B_SLAB))"
printf " Percpu growth     : %d kB\n" "$((A_PCPU  - B_PCPU))"
printf " Vmalloc growth    : %d kB\n" "$((A_VMAP  - B_VMAP))"
echo ""
echo " Theoretical BPF map size (raw, excl. hash node overhead):"
echo "   syn_timestamps LRU  : (40 key + 8 val)  x 8192 =  ~384 kB"
echo "   synack_states  LRU  : (40 key + 56 val) x 8192 =  ~768 kB"
echo "   rtt_events ring buf :                             4096 kB"
echo "   raw total           :                            ~5248 kB (~5.1 MB)"
echo "   (actual is higher: LRU hashes add bucket + per-entry node overhead.)"
echo "   BPF maps are exempt from RLIMIT_MEMLOCK on kernel 5.11+."
echo ""
echo "$LOADER_NAME running (pid=$LPID).  RTT events -> $OUT"
echo "Stop it + verify kernel memory is reclaimed:  sh $0 -k"
echo "(or just: kill $LPID)"
