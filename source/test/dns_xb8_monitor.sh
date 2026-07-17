#!/bin/sh
##########################################################################
# dns_xb8_monitor.sh  —  Run on XB8 (Docsis-Gateway)
#
# Starts DnsMonitor on brlan0, waits for Latitude test traffic,
# analyzes the log, and generates a pass/fail report + HTML file.
#
# Run this FIRST on the XB8, THEN run dns_latitude_test.sh on Latitude.
#
# Usage:
#   On XB8:      sh /tmp/dns_xb8_monitor.sh
#   HTML report: sh /tmp/dns_xb8_monitor.sh --html > /tmp/DnsReport.html
##########################################################################

IFACE="brlan0"
CLIENT_IP="10.0.0.58"
LOG="/tmp/dnsmon_xb8.log"
RESULTS="/tmp/xb8_results.txt"
HTML_MODE=0
[ "$1" = "--html" ] && HTML_MODE=1

# DnsMonitor flags — adjust thresholds to match your environment
#   -r 120  : report interval (2 min — gives time for all Latitude tests)
#   -s 100  : [DNS_SLOW] threshold in ms (100ms — catches ~260ms latency)
#   -d 200  : [NET_DEGRADED] avg threshold (200ms — fires given ~260ms avg)
#   -f 20   : flood threshold (20 qps)
#   -v      : verbose (log every query and response)
DNSMON_FLAGS="-i $IFACE -r 120 -s 100 -d 200 -f 20 -v"

PASS=0; FAIL=0; TOTAL=0

ts() { date -u '+%H:%M:%S'; }

# ── check: assert a pattern exists in log, report PASS/FAIL ──────────
check() {
    TOTAL=$((TOTAL+1))
    ID=$(printf "TC-%03d" $TOTAL)
    SUBJ="$1"; SCEN="$2"; EXP="$3"; ACT="$4"; STATUS="$5"
    [ "$STATUS" = "PASS" ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
    [ "$HTML_MODE" -eq 0 ] && {
        [ "$STATUS" = "PASS" ] \
            && printf "  \033[32m[PASS]\033[0m %s  %s\n" "$ID" "$SCEN" \
            || printf "  \033[31m[FAIL]\033[0m %s  %s\n        Actual: %s\n" "$ID" "$SCEN" "$ACT"
    }
    printf "%s|%s|%s|%s|%s|%s\n" "$ID" "$SUBJ" "$SCEN" "$EXP" "$ACT" "$STATUS" >> "$RESULTS"
}

cnt() { grep -c "$1" "$LOG" 2>/dev/null | tr -d ' '; }
has() { grep -q "$1" "$LOG" 2>/dev/null && echo PASS || echo FAIL; }
val() { grep "$1" "$LOG" | grep -o "$2" | tail -n 1; }

# ── Start ─────────────────────────────────────────────────────────────
[ "$HTML_MODE" -eq 0 ] && {
    printf "============================================================\n"
    printf " XB8 DnsMonitor — brlan0 LAN Client Test\n"
    printf " Client expected: %s\n" "$CLIENT_IP"
    printf "============================================================\n"
    printf "\n STEP 1: DnsMonitor starting on %s...\n" "$IFACE"
}

rm -f "$LOG" "$RESULTS"; touch "$RESULTS"
DnsMonitor $DNSMON_FLAGS >> "$LOG" 2>&1 &
DNSMON_PID=$!
sleep 2

kill -0 "$DNSMON_PID" 2>/dev/null || { echo "ERROR: DnsMonitor failed to start"; exit 1; }

[ "$HTML_MODE" -eq 0 ] && {
    printf " DnsMonitor PID=%s  log=%s\n" "$DNSMON_PID" "$LOG"
    printf "\n\033[1m STEP 2: NOW run on Latitude (10.0.0.58):\033[0m\n"
    printf "   ssh rdkb-corenw@%s\n" "$CLIENT_IP"
    printf "   bash /tmp/dns_latitude_test.sh\n\n"
    printf " Waiting 90s for Latitude test traffic"
    i=0; while [ $i -lt 90 ]; do sleep 5; printf "."; i=$((i+5)); done
    printf " done\n\n"
}

[ "$HTML_MODE" -eq 1 ] && sleep 90

# ── Stop DnsMonitor and collect final summary ─────────────────────────
kill -TERM "$DNSMON_PID" 2>/dev/null
sleep 3

[ "$HTML_MODE" -eq 0 ] && printf " STEP 3: Analyzing log...\n"

SUMMARY=$(grep "\[DNS_SUMMARY\]" "$LOG" | grep -v "event=" | tail -n 1)

# ════════════════════════════════════════════════════════════════════════
# TEST GROUP 1 — DnsMonitor Startup
# ════════════════════════════════════════════════════════════════════════
[ "$HTML_MODE" -eq 0 ] && printf "\n[Group 1: Startup]\n"

# TC-001: START event
ST=$(has "event=START")
check "1. Startup" \
    "DnsMonitor emits [DNS_SUMMARY] event=START on launch" \
    "[DNS_SUMMARY] event=START in log" \
    "$(grep 'event=START' $LOG | head -n 1 | cut -c1-60)" "$ST"

# TC-002: Interface name in log
ST=$(has "iface=$IFACE")
check "1. Startup" \
    "All log lines contain iface=$IFACE" \
    "iface=brlan0 present" \
    "$(grep 'iface=brlan0' $LOG | wc -l | tr -d ' ') lines" "$ST"

# ════════════════════════════════════════════════════════════════════════
# TEST GROUP 2 — LAN Client Traffic Capture
# ════════════════════════════════════════════════════════════════════════
[ "$HTML_MODE" -eq 0 ] && printf "\n[Group 2: LAN Client Traffic]\n"

# TC-003: Queries captured from client IP
CNT=$(grep "client=$CLIENT_IP" "$LOG" | wc -l | tr -d ' ')
[ "${CNT:-0}" -ge 1 ] && ST="PASS" || ST="FAIL"
check "2. Client Capture" \
    "DNS queries from Latitude ($CLIENT_IP) captured on brlan0" \
    "client=$CLIENT_IP lines >= 1" \
    "$CNT lines with client=$CLIENT_IP" "$ST"

# TC-004: qname field present
ST=$(has "qname=www.google.com")
check "2. Client Capture" \
    "www.google.com A query captured from client" \
    "qname=www.google.com in log" \
    "$(grep 'qname=www.google.com' $LOG | wc -l | tr -d ' ') lines" "$ST"

# TC-005: qtype=A captured
ST=$(has "qtype=A")
check "2. Client Capture" \
    "A record query type correctly identified" \
    "qtype=A in log" \
    "$(grep 'qtype=A' $LOG | head -n 1 | grep -o 'qtype=A')" "$ST"

# TC-006: qtype=AAAA captured (from TC-002 on Latitude)
ST=$(has "qtype=AAAA")
check "2. Client Capture" \
    "AAAA record query type identified (dual-stack)" \
    "qtype=AAAA in log" \
    "$(grep 'qtype=AAAA' $LOG | wc -l | tr -d ' ') lines" "$ST"

# ════════════════════════════════════════════════════════════════════════
# TEST GROUP 3 — Latency Measurement
# ════════════════════════════════════════════════════════════════════════
[ "$HTML_MODE" -eq 0 ] && printf "\n[Group 3: Latency Measurement]\n"

# TC-007: latency_ms field present
ST=$(has "latency_ms=")
LAT=$(grep "latency_ms=" "$LOG" | grep -o "latency_ms=[0-9]*" | head -n 1)
check "3. Latency" \
    "latency_ms= field present in response lines" \
    "latency_ms= present" "$LAT" "$ST"

# TC-008: [DNS_SLOW] triggered (latency > 100ms threshold)
SLOW_CNT=$(cnt "\[DNS_SLOW\]")
[ "${SLOW_CNT:-0}" -ge 1 ] && ST="PASS" || ST="FAIL"
check "3. Latency" \
    "[DNS_SLOW] emitted for responses > slow_thresh_ms=100" \
    "[DNS_SLOW] count >= 1" \
    "[DNS_SLOW] count=$SLOW_CNT" "$ST"

# TC-009: Slow latency value exceeds threshold
SLOW_VAL=$(grep "\[DNS_SLOW\]" "$LOG" | grep -o "latency_ms=[0-9]*" | head -n 1 | cut -d= -f2)
[ "${SLOW_VAL:-0}" -ge 100 ] && ST="PASS" || ST="FAIL"
check "3. Latency" \
    "latency_ms in [DNS_SLOW] >= 100ms" \
    "latency_ms >= 100" \
    "latency_ms=${SLOW_VAL:-0}" "$ST"

# ════════════════════════════════════════════════════════════════════════
# TEST GROUP 4 — Failure Detection
# ════════════════════════════════════════════════════════════════════════
[ "$HTML_MODE" -eq 0 ] && printf "\n[Group 4: Failure Detection]\n"

# TC-010: [DNS_FAIL] emitted
FAIL_CNT=$(cnt "\[DNS_FAIL\]")
[ "${FAIL_CNT:-0}" -ge 1 ] && ST="PASS" || ST="FAIL"
check "4. Failures" \
    "[DNS_FAIL] emitted for NXDOMAIN/failed domains" \
    "[DNS_FAIL] count >= 1" \
    "[DNS_FAIL] count=$FAIL_CNT" "$ST"

# TC-011: NXDOMAIN rcode decoded as string (not raw number)
ST=$(grep "\[DNS_FAIL\]" "$LOG" | grep -q "NXDOMAIN" && echo PASS || echo FAIL)
RCODE=$(grep "\[DNS_FAIL\]" "$LOG" | grep -o "rcode=[^)]*)" | head -n 1)
check "4. Failures" \
    "RCODE decoded as NXDOMAIN string (not raw integer)" \
    "rcode=3(NXDOMAIN)" "$RCODE" "$ST"

# TC-012: latency measured even for failures
ST=$(grep "\[DNS_FAIL\]" "$LOG" | grep -q "latency_ms=" && echo PASS || echo FAIL)
FAIL_LAT=$(grep "\[DNS_FAIL\]" "$LOG" | grep -o "latency_ms=[0-9]*" | head -n 1)
check "4. Failures" \
    "latency_ms recorded even for NXDOMAIN (server responded, just with error)" \
    "latency_ms= in [DNS_FAIL]" "$FAIL_LAT" "$ST"

# TC-013: failure attributed to correct client IP
ST=$(grep "\[DNS_FAIL\]" "$LOG" | grep -q "client=$CLIENT_IP" && echo PASS || echo FAIL)
check "4. Failures" \
    "Failure correctly attributed to client=$CLIENT_IP" \
    "client=$CLIENT_IP in [DNS_FAIL]" \
    "$(grep '\[DNS_FAIL\]' $LOG | grep -o 'client=[^ ]*' | head -n 1)" "$ST"

# ════════════════════════════════════════════════════════════════════════
# TEST GROUP 5 — PTR Reverse Lookup
# ════════════════════════════════════════════════════════════════════════
[ "$HTML_MODE" -eq 0 ] && printf "\n[Group 5: PTR Lookup]\n"

# TC-014: PTR query type captured
ST=$(has "qtype=PTR")
check "5. PTR" \
    "PTR (reverse DNS) query type captured as qtype=PTR" \
    "qtype=PTR in log" \
    "$(grep 'qtype=PTR' $LOG | wc -l | tr -d ' ') PTR lines" "$ST"

# TC-015: in-addr.arpa format present
ST=$(has "in-addr.arpa")
check "5. PTR" \
    "Reverse lookup qname contains in-addr.arpa" \
    "in-addr.arpa in qname" \
    "$(grep 'in-addr.arpa' $LOG | wc -l | tr -d ' ') lines" "$ST"

# ════════════════════════════════════════════════════════════════════════
# TEST GROUP 6 — Slow Internet / Degraded Detection
# ════════════════════════════════════════════════════════════════════════
[ "$HTML_MODE" -eq 0 ] && printf "\n[Group 6: Slow Internet Detection]\n"

# TC-016: [NET_DEGRADED] triggered
ST=$(has "\[NET_DEGRADED\]")
check "6. Degraded" \
    "[NET_DEGRADED] emitted — avg latency exceeded degrade_avg_ms=200" \
    "[NET_DEGRADED] in log" \
    "$(grep '\[NET_DEGRADED\]' $LOG | tail -n 1 | cut -c1-80)" "$ST"

# TC-017: reason=high_latency
ST=$(grep "\[NET_DEGRADED\]" "$LOG" | grep -q "high_latency" && echo PASS || echo FAIL)
check "6. Degraded" \
    "[NET_DEGRADED] reason=high_latency (avg latency too high)" \
    "reason=high_latency" \
    "$(grep '\[NET_DEGRADED\]' $LOG | grep -o 'reason=[^ ]*' | tail -n 1)" "$ST"

# TC-018: avg_ms in degraded event
AVG=$(grep "\[NET_DEGRADED\]" "$LOG" | grep -o "avg_ms=[0-9]*" | tail -n 1 | cut -d= -f2)
[ "${AVG:-0}" -ge 200 ] && ST="PASS" || ST="FAIL"
check "6. Degraded" \
    "avg_ms in [NET_DEGRADED] >= degrade threshold (200ms)" \
    "avg_ms >= 200" \
    "avg_ms=${AVG:-0}" "$ST"

# ════════════════════════════════════════════════════════════════════════
# TEST GROUP 7 — Per-Client Tracking
# ════════════════════════════════════════════════════════════════════════
[ "$HTML_MODE" -eq 0 ] && printf "\n[Group 7: Per-Client Tracking]\n"

# TC-019: top_client in summary shows Latitude IP
ST=$(echo "$SUMMARY" | grep -q "top_client=$CLIENT_IP" && echo PASS || echo FAIL)
TOP=$(echo "$SUMMARY" | tr ' ' '\n' | grep "^top_client=")
check "7. Client Track" \
    "top_client in [DNS_SUMMARY] identifies Latitude as busiest client" \
    "top_client=$CLIENT_IP:N" "$TOP" "$ST"

# TC-020: server_fails field present in summary
ST=$(echo "$SUMMARY" | grep -q "server_fails=" && echo PASS || echo FAIL)
check "7. Client Track" \
    "server_fails= field tracks which DNS server had failures" \
    "server_fails= in summary" \
    "$(echo $SUMMARY | grep -o 'server_fails=\[[^]]*\]')" "$ST"

# ════════════════════════════════════════════════════════════════════════
# TEST GROUP 8 — Summary Format and Telemetry Fields
# ════════════════════════════════════════════════════════════════════════
[ "$HTML_MODE" -eq 0 ] && printf "\n[Group 8: Summary and Telemetry]\n"

for FIELD in queries= success= slow= fail_total= nxdomain= timeout_pct= avg_ms= max_ms= degrade_events= flood_events= top_client=; do
    ST=$(echo "$SUMMARY" | grep -q "$FIELD" && echo PASS || echo FAIL)
    check "8. Summary" \
        "[DNS_SUMMARY] contains field: $FIELD" \
        "$FIELD present" \
        "$(echo $SUMMARY | tr ' ' '\n' | grep "^$FIELD")" "$ST"
done

# TC: avg_ms > 0 (latency actually measured)
AVG_VAL=$(echo "$SUMMARY" | tr ' ' '\n' | grep "^avg_ms=" | cut -d= -f2)
[ "${AVG_VAL:-0}" -gt 0 ] && ST="PASS" || ST="FAIL"
check "8. Summary" \
    "avg_ms > 0 — DNS latency measured and reported" \
    "avg_ms > 0" "avg_ms=${AVG_VAL:-0}" "$ST"

# TC: timestamp is ISO-8601
TS=$(echo "$SUMMARY" | grep -o "ts=[^ ]*" | head -n 1)
ST=$(echo "$TS" | grep -q "T" && echo "$TS" | grep -q "Z" && echo PASS || echo FAIL)
check "8. Summary" \
    "Timestamp ISO-8601 UTC format (contains T and Z)" \
    "ts=YYYY-MM-DDTHH:MM:SS.mmmZ" "$TS" "$ST"

# ════════════════════════════════════════════════════════════════════════
# FINAL RESULT
# ════════════════════════════════════════════════════════════════════════
if [ "$HTML_MODE" -eq 1 ]; then
    NOW=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%H:%M:%S')
    RATE=0; [ "$TOTAL" -gt 0 ] && RATE=$(awk "BEGIN{printf \"%d\",$PASS*100/$TOTAL}")
    cat << EOF
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>DnsMonitor XB8 Test Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;color:#333;}
.hdr{background:linear-gradient(135deg,#1a3a5c,#2d6a9f);color:#fff;padding:20px 28px;}
.hdr h1{font-size:20px;}.hdr p{font-size:12px;opacity:.8;margin-top:4px;}
.sum{display:flex;gap:14px;padding:16px 28px;flex-wrap:wrap;}
.card{background:#fff;border-radius:6px;padding:14px 20px;min-width:120px;text-align:center;box-shadow:0 2px 6px rgba(0,0,0,.08);}
.card .n{font-size:28px;font-weight:700;}.card .l{font-size:11px;color:#777;text-transform:uppercase;}
.total .n{color:#1a3a5c;}.passed .n{color:#27ae60;}.failed .n{color:#e74c3c;}.rate .n{color:#f39c12;}
.wrap{padding:0 28px 28px;overflow-x:auto;}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:6px;box-shadow:0 2px 6px rgba(0,0,0,.08);font-size:12px;}
thead tr{background:#1a3a5c;color:#fff;}thead th{padding:10px 12px;text-align:left;font-weight:600;}
tbody tr:nth-child(even){background:#f8fafc;}tbody tr:hover{background:#eaf3ff;}
td{padding:8px 12px;vertical-align:top;border-bottom:1px solid #e8ecf0;}
.tid{font-family:monospace;font-weight:600;color:#555;white-space:nowrap;}
.subj{font-weight:600;color:#1a3a5c;white-space:nowrap;}.exp{color:#2c3e50;font-size:11px;}
.ok{color:#27ae60;font-size:11px;}.err{color:#e74c3c;font-weight:600;font-size:11px;}
.pass{color:#27ae60;font-weight:700;white-space:nowrap;}.fail{color:#e74c3c;font-weight:700;white-space:nowrap;}
</style></head><body>
<div class='hdr'><h1>DnsMonitor XB8 + Latitude Integration Test Report</h1>
<p>XB8 brlan0 &nbsp;|&nbsp; Client: $CLIENT_IP &nbsp;|&nbsp; $NOW</p></div>
<div class='sum'>
<div class='card total'><div class='n'>$TOTAL</div><div class='l'>Total</div></div>
<div class='card passed'><div class='n'>$PASS</div><div class='l'>Passed</div></div>
<div class='card failed'><div class='n'>$FAIL</div><div class='l'>Failed</div></div>
<div class='card rate'><div class='n'>${RATE}%</div><div class='l'>Pass Rate</div></div>
</div>
<div class='wrap'><table><thead><tr>
<th>Test ID</th><th>Subject</th><th>Test Scenario</th>
<th>Expected</th><th>Actual Result</th><th>Status</th>
</tr></thead><tbody>
EOF
    while IFS='|' read -r id subj scen exp act status; do
        [ -z "$id" ] && continue
        [ "$status" = "PASS" ] \
            && printf "<tr><td class='tid'>%s</td><td class='subj'>%s</td><td>%s</td><td class='exp'>%s</td><td class='ok'>%s</td><td class='pass'>&#10003; PASS</td></tr>\n" "$id" "$subj" "$scen" "$exp" "$act" \
            || printf "<tr><td class='tid'>%s</td><td class='subj'>%s</td><td>%s</td><td class='exp'>%s</td><td class='err'>%s</td><td class='fail'>&#10007; FAIL</td></tr>\n" "$id" "$subj" "$scen" "$exp" "$act"
    done < "$RESULTS"
    printf "</tbody></table></div>\n"
    printf "<div style='padding:8px 28px;font-size:11px;color:#888;'>Log: %s</div>\n" "$LOG"
    printf "</body></html>\n"
else
    printf "\n============================================================\n"
    printf " Results: %d/%d passed" "$PASS" "$TOTAL"
    [ "$FAIL" -eq 0 ] \
        && printf "  \033[32m[ALL PASS]\033[0m\n" \
        || printf "  \033[31m[%d FAILED]\033[0m\n" "$FAIL"
    printf "============================================================\n"
    printf "\nLog file    : %s\n" "$LOG"
    printf "HTML report : sh %s --html > /tmp/DnsReport.html\n" "$0"
    printf "\nKey log lines:\n"
    printf "  [DNS_SLOW]    : %s lines\n" "$(cnt '\[DNS_SLOW\]')"
    printf "  [DNS_FAIL]    : %s lines\n" "$(cnt '\[DNS_FAIL\]')"
    printf "  [NET_DEGRADED]: %s lines\n" "$(cnt '\[NET_DEGRADED\]')"
    printf "  Summary       : %s\n" "$(echo $SUMMARY | cut -c1-120)"
fi
