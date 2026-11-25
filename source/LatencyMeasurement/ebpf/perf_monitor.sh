#!/bin/sh
# If not stated otherwise in this file or this component's Licenses.txt file
# the following copyright and licenses apply:
#
# Copyright 2026 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# perf_monitor.sh - Compare BPF (tcp_loader) vs libpcap (xNetSniffer) overhead
#
# Usage:
#   ./perf_monitor.sh tcp_loader   30    # monitor BPF approach for 30s
#   ./perf_monitor.sh xNetSniffer  30    # monitor libpcap approach for 30s
#
# Requires: only /proc (no external stat tools needed)
# Deploy to gateway: scp perf_monitor.sh root@gateway:/tmp/

TOOL=${1:-tcp_loader}
DURATION=${2:-30}

# ── identify method ──────────────────────────────────────────────────────────
case "$TOOL" in
    tcp_loader)  METHOD="eBPF kprobe  (ip_forward/ip6_forward)" ;;
    xNetSniffer) METHOD="libpcap AF_PACKET (socket_filter)"      ;;
    *)           METHOD="unknown"                                 ;;
esac

# ── find PID ─────────────────────────────────────────────────────────────────
PID=$(pidof "$TOOL" 2>/dev/null | awk '{print $1}')
if [ -z "$PID" ]; then
    printf "ERROR: '%s' is not running.\n" "$TOOL"
    printf "       Start it first, then run this script.\n"
    exit 1
fi

NCPU=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)
TMPFILE="/tmp/_perf_mon_$$"
> "$TMPFILE"

# ── helpers ──────────────────────────────────────────────────────────────────
sys_stat()  { awk 'NR==1{print $2,$3,$4,$5,$6,$7,$8}' /proc/stat; }
pid_jiff()  { awk '{print $14+$15}' /proc/"$PID"/stat 2>/dev/null || echo 0; }
pid_mem()   { awk '/VmRSS/{print $2}' /proc/"$PID"/status 2>/dev/null || echo 0; }

# IPv4 forwarded packets (ip_forward calls) from /proc/net/snmp
fwd4() {
    awk '
        /^Ip:/ && !header_done {
            for (i=1; i<=NF; i++) if ($i=="ForwDatagrams") col=i
            header_done=1; next
        }
        /^Ip:/ { print $col; exit }
    ' /proc/net/snmp 2>/dev/null || echo 0
}

# IPv6 forwarded packets (ip6_forward calls)
fwd6() {
    awk '/Ip6InForwDatagrams/{print $2}' /proc/net/snmp6 2>/dev/null || echo 0
}

# ── summary (called on exit / Ctrl+C) ────────────────────────────────────────
show_summary() {
    printf "\n"
    printf "══════════════════════════════════════════════════════════\n"
    printf "  SUMMARY  %-20s  [%s]\n" "$TOOL" "$METHOD"
    printf "══════════════════════════════════════════════════════════\n"
    awk -v ncpu="$NCPU" '
    {
        n++
        sp+=$1;  if($1>mp)  mp=$1
        ss+=$2;  if($2>ms)  ms=$2
        ssi+=$3
        srss+=$4; mrss=$4
        sfwd+=$5
    }
    END {
        if (n == 0) { print "  No samples collected."; exit }
        printf "  Samples        : %d s\n", n
        printf "\n"
        printf "  Process CPU\n"
        printf "    avg          : %.2f%%  (userspace work of %s)\n", sp/n, ENVIRON["TOOL"]
        printf "    peak         : %.2f%%\n", mp
        printf "\n"
        printf "  Kernel (sy) CPU\n"
        printf "    avg          : %.2f%%  (BPF exec / pcap copies run here)\n", ss/n
        printf "    peak         : %.2f%%\n", ms
        printf "\n"
        printf "  Softirq (si) CPU\n"
        printf "    avg          : %.2f%%  (packet receive path)\n", ssi/n
        printf "\n"
        printf "  Memory (RSS)   : %d KB\n", mrss
        printf "\n"
        printf "  Forwarded pkts : avg %.0f pkts/s  (ip_forward + ip6_forward)\n", sfwd/n
        printf "\n"
        printf "  NOTE: proc_cpu = userspace overhead of the tool\n"
        printf "        sy       = kernel overhead  (BPF or pcap copying)\n"
        printf "        si       = always-present packet receive cost\n"
        printf "══════════════════════════════════════════════════════════\n"
    }' "$TMPFILE"
}

trap 'show_summary; rm -f "$TMPFILE"; exit 0' INT TERM

# ── header ───────────────────────────────────────────────────────────────────
printf "\n"
printf "══════════════════════════════════════════════════════════\n"
printf "  Tool    : %-20s  PID=%s\n"   "$TOOL"    "$PID"
printf "  Method  : %s\n"               "$METHOD"
printf "  CPUs    : %s   Duration: %ds\n" "$NCPU"  "$DURATION"
printf "══════════════════════════════════════════════════════════\n"
printf "%-5s  %-10s %-10s %-10s %-8s %-10s\n" \
       "time" "proc_cpu%" "sys_cpu%" "softirq%" "rss_kb" "fwd_pps"
printf "%-5s  %-10s %-10s %-10s %-8s %-10s\n" \
       "-----" "----------" "----------" "----------" "--------" "----------"

# ── initial snapshot ─────────────────────────────────────────────────────────
PSYS=$(sys_stat)
PREV_PID=$(pid_jiff)
PF4=$(fwd4)
PF6=$(fwd6)

# ── sampling loop ────────────────────────────────────────────────────────────
i=0
while [ "$i" -lt "$DURATION" ]; do
    sleep 1
    i=$((i+1))

    CSYS=$(sys_stat)
    CPID=$(pid_jiff)
    CF4=$(fwd4)
    CF6=$(fwd6)
    RSS=$(pid_mem)

    # Check process still running
    if [ ! -d "/proc/$PID" ]; then
        printf "  [%ds] %s exited.\n" "$i" "$TOOL"
        break
    fi

    LINE=$(awk \
        -v ps="$PSYS" -v cs="$CSYS" \
        -v pp="$PREV_PID" -v cp="$CPID" \
        -v pf4="$PF4" -v cf4="$CF4" \
        -v pf6="$PF6" -v cf6="$CF6" \
        -v rss="$RSS" -v sec="$i" \
    'BEGIN {
        split(ps,a); split(cs,b)
        dt=0; for(j=1;j<=7;j++) dt+=(b[j]-a[j])
        if (dt < 1) dt = 1

        # cpu columns: usr nice sys idle iowait irq softirq
        proc_cpu = (cp - pp) / dt * 100;  if (proc_cpu < 0) proc_cpu = 0
        sys_cpu  = (b[3]-a[3]) / dt * 100
        si_cpu   = (b[7]-a[7]) / dt * 100
        fwd      = (cf4-pf4) + (cf6-pf6)

        # row for live display
        printf "%4ds   %7.2f    %7.2f    %7.2f   %6d   %6d\n",
               sec, proc_cpu, sys_cpu, si_cpu, rss, fwd

        # compact row for summary accumulation (no labels)
        printf "SAMPLE %.2f %.2f %.2f %d %d\n",
               proc_cpu, sys_cpu, si_cpu, rss, fwd > "/dev/stderr"
    }' /dev/null 2>"$TMPFILE.row")

    printf "%-5s  %-10s %-10s %-10s %-8s %-10s\n" \
        $(echo "$LINE")

    # append sample to summary file
    grep "^SAMPLE" "$TMPFILE.row" | sed 's/^SAMPLE //' >> "$TMPFILE"
    rm -f "$TMPFILE.row"

    PSYS="$CSYS"; PREV_PID="$CPID"; PF4="$CF4"; PF6="$CF6"
done

show_summary
rm -f "$TMPFILE"
