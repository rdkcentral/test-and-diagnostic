#!/bin/sh
# stress_test.sh - Run on the LAN client to generate rapid TCP connections.
#
# Opens COUNT connections to TARGET in bursts of PARALLEL concurrent curls.
# Used to stress the gateway while gw_cpu_measure.sh samples CPU on the GW.
#
# Usage:
#   sh stress_test.sh [TARGET] [COUNT] [PARALLEL]
#   sh stress_test.sh 1.1.1.1 300 30

TARGET="${1:-1.1.1.1}"
COUNT="${2:-300}"
PARALLEL="${3:-30}"

echo "Stress test: $COUNT connections to http://$TARGET  (${PARALLEL} parallel)"
echo "Start time: $(date '+%H:%M:%S')"

seq 1 "$COUNT" | xargs -P"$PARALLEL" -I{} \
    curl -4 -o /dev/null -s --connect-timeout 5 "http://$TARGET"

echo "End time:   $(date '+%H:%M:%S')"
echo "Done — $COUNT connections completed."
