#!/bin/sh
# client_test.sh - Run on the LAN client (e.g. 10.0.0.58)
#
# Measures TCP connect time for N connections to TARGET, logs
# source port + time_connect_ms so the gateway scripts can correlate.
#
# Usage:
#   sh client_test.sh [TARGET] [COUNT] [INTERVAL_SEC]
#   sh client_test.sh 1.1.1.1 20 3

TARGET="${1:-1.1.1.1}"
COUNT="${2:-20}"
INTERVAL="${3:-3}"
OUT="/tmp/client_results.txt"

echo "port  client_ms" > "$OUT"
echo "Connecting to http://$TARGET  ($COUNT times, ${INTERVAL}s apart)"
echo "Results -> $OUT"
echo ""

i=1
while [ "$i" -le "$COUNT" ]; do
    result=$(curl -4 -o /dev/null -s \
        -w "%{time_connect} %{local_port}" \
        --connect-timeout 10 \
        "http://$TARGET")
    ms=$(echo "$result" | awk '{printf "%.2f", $1*1000}')
    port=$(echo "$result" | awk '{print $2}')
    echo "$port  $ms" | tee -a "$OUT"
    i=$((i + 1))
    [ "$i" -le "$COUNT" ] && sleep "$INTERVAL"
done

echo ""
echo "Done. $COUNT results saved to $OUT"
