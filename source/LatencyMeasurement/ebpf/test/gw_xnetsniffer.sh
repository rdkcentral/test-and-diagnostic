#!/bin/sh
# gw_xnetsniffer.sh - Run on the gateway BEFORE starting client_test.sh
#
# Starts xNetSniffer + xNetDP with a short report interval (60s) so that
# the TR-181 latency report is available quickly for comparison with eBPF.
#
# CAUTION: Kills the production xNetDP (which has -i 1800).  xNetSniffer
# is left running — only xNetDP is replaced.  The production xNetDP may
# be restarted by the process manager after this script exits; that is
# harmless (it will have a fresh message queue).
#
# Usage:
#   sh gw_xnetsniffer.sh [REPORT_INTERVAL_SEC]
#   sh gw_xnetsniffer.sh 60
#
# After the client test finishes, wait for one report interval, then run:
#   dmcli eRT getv Device.QOS.X_RDK_LatencyMeasure_TCP_Stats_Report

INTERVAL="${1:-60}"
TR181_PARAM="Device.QOS.X_RDK_LatencyMeasure_TCP_Stats_Report"

# --- Resolve LAN interface and network prefix ---
LAN_IF=$(syscfg get lan_ifname 2>/dev/null || echo "brlan0")

# Get IP+mask from interface (e.g. "10.0.0.1/24")
IP_MASK=$(ip addr show "$LAN_IF" 2>/dev/null | awk '/inet /{print $2}' | head -n 1)
if [ -z "$IP_MASK" ]; then
    echo "ERROR: Could not determine IP address of $LAN_IF"
    exit 1
fi

# Convert gateway IP+mask -> network prefix (works for /8, /16, /24)
IP=$(echo "$IP_MASK" | cut -d/ -f1)
CIDR=$(echo "$IP_MASK" | cut -d/ -f2)
LAN_PREFIX=$(awk -v ip="$IP" -v cidr="$CIDR" 'BEGIN {
    n = split(ip, o, ".")
    mask = (2^cidr - 1) * 2^(32-cidr)   # Not shell-portable; use octets
    # Simpler: zero out host bits based on /8 /16 /24 /32
    if (cidr >= 24) net = o[1]"."o[2]"."o[3]".0"
    else if (cidr >= 16) net = o[1]"."o[2]".0.0"
    else if (cidr >= 8)  net = o[1]".0.0.0"
    else net = "0.0.0.0"
    print net"/"cidr
}')

echo "LAN interface : $LAN_IF"
echo "Network prefix: $LAN_PREFIX  (for xNetSniffer -p)"
echo "Report interval: ${INTERVAL}s"
echo ""

# --- Kill production xNetDP to avoid split message queue ---
PROD_XDP=$(pgrep -f "xNetDP" | head -n 1)
if [ -n "$PROD_XDP" ]; then
    echo "Stopping production xNetDP (pid=$PROD_XDP, it uses -i 1800)"
    kill "$PROD_XDP" 2>/dev/null
    sleep 1
fi

# --- Start xNetDP with short interval ---
/usr/bin/xNetDP -t 1 -i "$INTERVAL" -n "$TR181_PARAM" &
XDPID=$!
echo "Started xNetDP  pid=$XDPID  interval=${INTERVAL}s"

# Drain any stale messages left in the IPC queue by the previous xNetDP.
# xNetDP needs ~2s to open the queue and start consuming.
echo "Waiting 3s for xNetDP to drain stale queue messages..."
sleep 3

# --- Start xNetSniffer only if not already running ---
if ! pgrep -f "xNetSniffer" > /dev/null 2>&1; then
    /usr/bin/xNetSniffer -i "$LAN_IF" -f IPv4 -p "$LAN_PREFIX" &
    XNPID=$!
    echo "Started xNetSniffer pid=$XNPID"
else
    echo "xNetSniffer already running — reusing it"
fi

echo ""
echo "Now run client_test.sh on the LAN client."
echo "After it finishes, wait ${INTERVAL}s, then read the report:"
echo "  dmcli eRT getv $TR181_PARAM"
echo ""
echo "To stop the test xNetDP when done:"
echo "  kill $XDPID"

