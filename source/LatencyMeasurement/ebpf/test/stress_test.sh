#!/bin/sh
# stress_test.sh - Run on the LAN client to generate rapid TCP connections.
#
# Opens COUNT TCP-handshake-only connections (HEAD, no body download) spread
# across a rotating list of TARGETS, in bursts of PARALLEL concurrent curls.
# Each connection completes a full SYN/SYN-ACK/ACK — exactly what the eBPF PoC
# measures — without transferring a response body.  Used to stress the gateway
# while gw_cpu_measure.sh samples CPU on the GW.
#
# WHY MULTIPLE SERVERS: a single public server rate-limits / throttles after a
# few thousand rapid connections, which silently starves the handshake stream
# and corrupts CPU/coverage comparisons.  Rotating across several servers keeps
# the load steady.  Rotate this list again between separate test rounds.
#
# BEST PRACTICE: for the definitive benchmark, point at your OWN server with
#       -l (e.g. `python3 -m http.server 80` on a box you control, or a second
#       gateway).  One unlimited local server never throttles, giving fully
#       repeatable numbers.  The public pool is only a fallback.
#
# NOTE: every TARGET must serve HTTP on port 80 and complete a TCP handshake.
#       Do NOT use 1.1.1.1 (Cloudflare DNS — refuses port 80 -> no handshake,
#       so no RTT events are produced).  Prefer IPs to avoid DNS variance.
#
# Usage:
#   sh stress_test.sh [-l LOCAL_SERVER] [COUNT] [PARALLEL] [TARGET ...]
#   sh stress_test.sh 60000 50                       # default 8-server pool
#   sh stress_test.sh -l 192.168.0.50 60000 50       # your own server only
#   sh stress_test.sh 60000 50 142.251.41.163 104.16.133.229   # custom pool

# --- optional -l/--local flag: use a single local server exclusively ---------
LOCAL_SERVER=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -l|--local) LOCAL_SERVER="$2"; shift 2 ;;
        -l*)        LOCAL_SERVER="${1#-l}"; shift ;;
        --)         shift; break ;;
        -*)         echo "Unknown option: $1" >&2; exit 1 ;;
        *)          break ;;
    esac
done

COUNT="${1:-300}"
PARALLEL="${2:-30}"
[ "$#" -ge 1 ] && shift
[ "$#" -ge 1 ] && shift

# Target selection priority: -l local server > positional custom pool > default.
# Using IPs avoids DNS caching/variance during the run.
if [ -n "$LOCAL_SERVER" ]; then
    TARGETS="$LOCAL_SERVER"
elif [ "$#" -gt 0 ]; then
    TARGETS="$*"
else
    TARGETS="connectivitycheck.gstatic.com cp.cloudflare.com detectportal.firefox.com \
www.msftconnecttest.com neverssl.com captive.apple.com clients3.google.com ifconfig.me"
fi

# Count servers for round-robin.
set -- $TARGETS
NSERVERS=$#

echo "Stress test: $COUNT connections, ${PARALLEL} parallel"
echo "Server pool ($NSERVERS): $TARGETS"
echo "Start time: $(date '+%H:%M:%S')"

# Round-robin each connection across the server pool so no single host is flooded.
# We test the TCP HANDSHAKE ONLY (-I / HEAD): the 3-way handshake still completes
# in full — SYN, SYN-ACK, and the ACK that curl sends to finish connect() — which
# is exactly what the eBPF program keys on (WAN RTT from SYN->SYN-ACK, LAN RTT from
# SYN-ACK->ACK).  Using HEAD instead of GET skips the response-body download, so the
# gateway load reflects handshakes rather than bulk transfer.
# -w '%{time_connect}' reports how long the handshake took; curl measures this for
# free (no extra round-trip / no gateway load), so a NONZERO value means the
# SYN/SYN-ACK/ACK actually completed.  We tally connected vs attempted so a throttled
# server (silent handshake starvation) is caught instead of corrupting the coverage
# comparison.  (time_connect stays nonzero even if the HEAD response itself errors.)
seq 1 "$COUNT" | xargs -P"$PARALLEL" -I{} sh -c '
    set -- '"$TARGETS"'
    idx=$(( ($1 % $#) + 1 ))
    eval target=\${$idx}
    curl -4 -I -o /dev/null -s --connect-timeout 5 --max-time 10 \
         -w "%{time_connect}\n" "http://$target"
' _ {} | awk -v attempted="$COUNT" '
    { total++; if ($1 + 0 > 0) connected++ }
    END {
        failed = attempted - connected
        printf "Handshakes:  %d connected / %d attempted", connected, attempted
        if (attempted > 0) printf "  (%.1f%%)", connected * 100 / attempted
        printf "\n"
        if (failed > 0)
            printf "WARNING:     %d connection(s) never handshook — a server may be throttling; add more/local servers.\n", failed
    }'

echo "End time:   $(date '+%H:%M:%S')"
echo "Done — $COUNT connections completed across $NSERVERS servers."

