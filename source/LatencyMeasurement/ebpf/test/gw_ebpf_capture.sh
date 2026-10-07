#!/bin/sh
# gw_ebpf_capture.sh - Run on the gateway BEFORE starting client_test.sh
#
# Captures tcp_loader RTT events and timestamps each line.
# Stop with Ctrl+C after client_test.sh finishes.
#
# Usage:
#   sh gw_ebpf_capture.sh [path/to/tcp_loader]

LOADER="${1:-/usr/bin/ebpf/tcp_loader}"
OUT="/tmp/ebpf_results.txt"

echo "Capturing eBPF RTT events from $LOADER"
echo "Output -> $OUT"
echo "Stop with Ctrl+C when client_test.sh finishes."
echo ""

"$LOADER" 2>/dev/null | while IFS= read -r line; do
    printf "%s  %s\n" "$(date '+%H:%M:%S.%3N')" "$line"
done | tee "$OUT"
