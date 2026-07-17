#!/bin/sh
# stress_test.sh - Run on the LAN client to generate rapid TCP connections.
#
# Opens COUNT connections spread across a rotating list of TARGETS, in bursts
# of PARALLEL concurrent curls.  Used to stress the gateway while
# gw_cpu_measure.sh samples CPU on the GW.
#
# WHY MULTIPLE SERVERS: a single public server rate-limits / throttles after a
# few thousand rapid connections, which silently starves the handshake stream
# and corrupts CPU/coverage comparisons.  Rotating across several servers keeps
# the load steady.  Rotate this list again between separate test rounds.
#
# NOTE: every TARGET must serve HTTP on port 80 and complete a TCP handshake.
#       Do NOT use 1.1.1.1 (Cloudflare DNS — refuses port 80 -> no handshake,
#       so no RTT events are produced).  Prefer IPs to avoid DNS variance.
#
# Usage:
#   sh stress_test.sh [COUNT] [PARALLEL] [TARGET ...]
#   sh stress_test.sh 60000 50
#   sh stress_test.sh 60000 50 142.251.41.163 104.16.133.229

COUNT="${1:-300}"
PARALLEL="${2:-30}"
shift 2 2>/dev/null

# Default rotating server pool (verified to accept port 80 handshakes).
# Using IPs avoids DNS caching/variance during the run.
if [ "$#" -gt 0 ]; then
    TARGETS="$*"
else
    TARGETS="connectivitycheck.gstatic.com cp.cloudflare.com detectportal.firefox.com ifconfig.me"
fi

# Count servers for round-robin.
set -- $TARGETS
NSERVERS=$#

echo "Stress test: $COUNT connections, ${PARALLEL} parallel"
echo "Server pool ($NSERVERS): $TARGETS"
echo "Start time: $(date '+%H:%M:%S')"

# Round-robin each connection across the server pool so no single host is flooded.
seq 1 "$COUNT" | xargs -P"$PARALLEL" -I{} sh -c '
    set -- '"$TARGETS"'
    idx=$(( ($1 % $#) + 1 ))
    eval target=\${$idx}
    curl -4 -o /dev/null -s --connect-timeout 5 "http://$target"
' _ {}

echo "End time:   $(date '+%H:%M:%S')"
echo "Done — $COUNT connections completed across $NSERVERS servers."

