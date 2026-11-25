#!/bin/sh
# analyze.sh - Compare eBPF vs xNetSniffer/xNetDP RTT measurements
#              against the client-side ground truth (curl time_connect).
#
# Usage:
#   sh analyze.sh <client_results> <ebpf_results> [client_ip]
#   sh analyze.sh /tmp/client_results.txt /tmp/ebpf_results.txt 10.0.0.58
#
# After this, run with --xnetsniffer to also parse the dmcli report:
#   sh analyze.sh /tmp/client_results.txt /tmp/ebpf_results.txt 10.0.0.58 --xnetsniffer
#
# xNetDP report format (values in microseconds):
#   Private,AnyDSCP,AnyECN,AnyPort,IPv4,N
#   ;MAC;flows,synack_min,synack_max,synack_avg,synack_pct,ack_min,ack_max,ack_avg,ack_pct;ports

CLIENT_FILE="${1:-/tmp/client_results.txt}"
EBPF_FILE="${2:-/tmp/ebpf_results.txt}"
CLIENT_IP="${3:-10.0.0.58}"
XNETSNIFFER_FLAG="${4:-}"
TR181_PARAM="Device.QOS.X_RDK_LatencyMeasure_TCP_Stats_Report"

# ---- eBPF per-connection comparison ----
echo "==========================================================="
echo " eBPF accuracy: per-connection delta vs client time_connect"
echo "==========================================================="
printf "%-8s  %-12s  %-11s  %-10s  %-10s  %-10s\n" \
    "port" "client_ms" "ebpf_wan_ms" "ebpf_lan_ms" "ebpf_sum_ms" "delta_ms"
echo "--------------------------------------------------------------"

DELTA_FILE="/tmp/ebpf_deltas.txt"
> "$DELTA_FILE"

tail -n +2 "$CLIENT_FILE" | while read port ms; do
    row=$(grep "${CLIENT_IP}:${port} " "$EBPF_FILE" | head -n 1)
    if [ -z "$row" ]; then
        printf "%-8s  %-12s  (no eBPF match)\n" "$port" "$ms"
        continue
    fi
    wan=$(echo "$row" | grep -oE 'WAN RTT:[[:space:]]+[0-9.]+' | grep -oE '[0-9.]+$')
    lan=$(echo "$row" | grep -oE 'LAN RTT:[[:space:]]+[0-9.]+' | grep -oE '[0-9.]+$')
    sum=$(awk "BEGIN{printf \"%.2f\", $wan+$lan}")
    delta=$(awk "BEGIN{printf \"%.2f\", $ms - $sum}")
    printf "%-8s  %-12s  %-11s  %-10s  %-10s  %-10s\n" \
        "$port" "$ms" "$wan" "$lan" "$sum" "$delta"
    echo "$delta" >> "$DELTA_FILE"
done

echo ""
echo "=== eBPF delta statistics ==="
awk '{s+=$1; s2+=$1*$1; n++}
END {
    if(n==0){print "No data"; exit}
    m=s/n; sd=sqrt(s2/n - m*m)
    printf "Samples    : %d\nMean delta : %.2f ms\nStddev     : %.2f ms\n",n,m,sd
}' "$DELTA_FILE"

# ---- xNetSniffer/xNetDP aggregated comparison (optional) ----
if [ "$XNETSNIFFER_FLAG" = "--xnetsniffer" ]; then
    echo ""
    echo "==========================================================="
    echo " xNetSniffer/xNetDP: aggregated SYN-ACK RTT from TR-181"
    echo "==========================================================="
    REPORT=$(dmcli eRT getv "$TR181_PARAM" 2>/dev/null | grep "value:" | sed 's/.*value://')
    if [ -z "$REPORT" ]; then
        echo "TR-181 report is empty — xNetDP may not have flushed yet."
        echo "Wait for the report interval (60s) and re-run with --xnetsniffer."
    else
        echo "Raw report: $REPORT"
        echo ""
        # Parse the xNetDP report format:
        #   Private,AnyDSCP,AnyECN,AnyPort,IPv4,N;MAC;flows,min,max,avg,...;ports|...
        # The stats block is the semicolon-field AFTER the MAC (a 9-field CSV).
        # We extract it by splitting on ';' and selecting lines starting with a digit
        # (flows count) with exactly 9 comma-separated fields — avoiding the
        # header and port fields.
        echo "$REPORT" | tr ';' '\n' | \
        awk -F',' 'NF==9 && $1+0==$1 {
            printf "SYN-ACK avg (xNetSniffer): %.2f ms  [min=%.2f max=%.2f]  flows=%s\n",
                $4/1000, $2/1000, $3/1000, $1
        }'

        # Client average for comparison
        CLIENT_AVG=$(tail -n +2 "$CLIENT_FILE" | awk '{s+=$2;n++} END{printf "%.2f",s/n}')
        echo ""
        echo "Client time_connect average : ${CLIENT_AVG} ms"

        EBPF_AVG=$(awk '{s+=$1;n++} END{if(n>0)printf "%.2f",s/n}' "$DELTA_FILE")
        echo "eBPF mean delta vs client   : ${EBPF_AVG} ms"
        echo ""
        echo "=> Compare xNetSniffer SYN-ACK avg to client avg to see the measurement offset"
    fi
fi
