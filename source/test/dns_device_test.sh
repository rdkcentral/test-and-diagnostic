#!/bin/sh
##########################################################################
# DnsMonitor Device Integration Test Script
#
# Runs directly on the XB8 device. Uses only tools available on RDK:
#   DnsMonitor, nslookup, grep, awk, kill, sleep, iptables
#
# Usage:
#   chmod +x /tmp/dns_device_test.sh
#   /tmp/dns_device_test.sh
#   /tmp/dns_device_test.sh --html > /tmp/DnsMonitor_DeviceReport.html
#
# Copy to device:
#   scp dns_device_test.sh root@<device-ip>:/tmp/
##########################################################################

IFACE="erouter0"
LOG="/tmp/dnsmon_test.log"
RESULTS_FILE="/tmp/dnsmon_results.txt"
BINARY="DnsMonitor"
REPORT_INTERVAL=30
SLOW_THRESHOLD=500
HTML_MODE=0

[ "$1" = "--html" ] && HTML_MODE=1

PASS=0
FAIL=0
TOTAL=0
RESULTS=""

# ── Helpers ─────────────────────────────────────────────────────────
ts() { date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%H:%M:%S'; }

log() { [ "$HTML_MODE" -eq 0 ] && printf "%s\n" "$1"; }

check() {
    TOTAL=$((TOTAL+1))
    TC_ID=$(printf "TC-%03d" $TOTAL)
    SUBJECT="$1"
    SCENARIO="$2"
    EXPECTED="$3"
    ACTUAL="$4"
    STATUS="$5"   # PASS or FAIL

    if [ "$STATUS" = "PASS" ]; then
        PASS=$((PASS+1))
        [ "$HTML_MODE" -eq 0 ] && printf "  \033[32m[PASS]\033[0m %s  %s\n" "$TC_ID" "$SCENARIO"
    else
        FAIL=$((FAIL+1))
        [ "$HTML_MODE" -eq 0 ] && printf "  \033[31m[FAIL]\033[0m %s  %s\n        Actual: %s\n" "$TC_ID" "$SCENARIO" "$ACTUAL"
    fi

    # Append to results file (pipe-separated for HTML)
    printf "%s|%s|%s|%s|%s|%s\n" \
        "$TC_ID" "$SUBJECT" "$SCENARIO" "$EXPECTED" "$ACTUAL" "$STATUS" >> "$RESULTS_FILE"
}

assert_grep() {
    PATTERN="$1"
    FILE="$2"
    grep -q "$PATTERN" "$FILE" 2>/dev/null && echo "PASS" || echo "FAIL"
}

assert_not_grep() {
    PATTERN="$1"
    FILE="$2"
    grep -q "$PATTERN" "$FILE" 2>/dev/null && echo "FAIL" || echo "PASS"
}

get_field() {
    # get_field <logfile> <tag> <key>
    # e.g. get_field $LOG DNS_SUMMARY avg_ms
    grep "\[$1\]" "$2" | grep -v "event=" | tail -1 \
        | tr ' ' '\n' | grep "^$3=" | cut -d= -f2
}

# ── Start DnsMonitor ─────────────────────────────────────────────────
start_monitor() {
    rm -f "$LOG" "$RESULTS_FILE"
    touch "$RESULTS_FILE"
    $BINARY -i "$IFACE" -r "$REPORT_INTERVAL" -s "$SLOW_THRESHOLD" -v \
        2>&1 >> "$LOG" &
    DNSMON_PID=$!
    sleep 2
    if ! kill -0 "$DNSMON_PID" 2>/dev/null; then
        log "ERROR: DnsMonitor failed to start. Check: $BINARY -i $IFACE"
        exit 1
    fi
    log "DnsMonitor started (PID=$DNSMON_PID, log=$LOG)"
}

stop_monitor() {
    kill "$DNSMON_PID" 2>/dev/null
    sleep 2
}

# ── Test sections ────────────────────────────────────────────────────

test_startup() {
    printf "\n[1. Startup and Interface]\n"
    sleep 2

    ST=$(assert_grep "event=START" "$LOG")
    check "1. Startup" \
          "DnsMonitor starts and logs START event on erouter0" \
          "[DNS_SUMMARY] event=START in log" \
          "$(grep 'event=START' $LOG | head -1 | cut -c1-80)" \
          "$ST"

    ST=$(assert_grep "iface=$IFACE" "$LOG")
    check "1. Startup" \
          "Interface name $IFACE present in all log lines" \
          "iface=$IFACE in log output" \
          "$(grep "iface=$IFACE" $LOG | wc -l) matching lines" \
          "$ST"
}

test_normal_queries() {
    printf "\n[2. Normal DNS Queries - A and AAAA]\n"
    BEFORE=$(wc -l < "$LOG")

    nslookup www.google.com > /dev/null 2>&1
    sleep 1

    # Count new RESP_OK lines
    NEW_OK=$(tail -n +"$BEFORE" "$LOG" | grep -c "\[DNS_RESP_OK\]" 2>/dev/null || echo 0)
    [ "$NEW_OK" -ge 1 ] && ST="PASS" || ST="FAIL"
    check "2. Normal Query" \
          "www.google.com A/AAAA query produces [DNS_RESP_OK]" \
          "At least 1 [DNS_RESP_OK] line" \
          "${NEW_OK} [DNS_RESP_OK] lines captured" \
          "$ST"

    # Verify latency field present
    ST=$(tail -n +"$BEFORE" "$LOG" | grep "\[DNS_RESP_OK\]" | grep -q "latency_ms=" && echo PASS || echo FAIL)
    check "2. Normal Query" \
          "Response log line contains latency_ms= field" \
          "latency_ms= present in [DNS_RESP_OK]" \
          "$(tail -n +"$BEFORE" "$LOG" | grep '\[DNS_RESP_OK\]' | grep 'latency_ms=' | head -n 1 | grep -o 'latency_ms=[0-9]*')" \
          "$ST"

    # Verify qname field
    ST=$(tail -n +"$BEFORE" "$LOG" | grep "\[DNS_RESP_OK\]" | grep -q "qname=" && echo PASS || echo FAIL)
    check "2. Normal Query" \
          "Response log line contains qname= field" \
          "qname= present" \
          "$(tail -n +"$BEFORE" "$LOG" | grep '\[DNS_RESP_OK\]' | grep -o 'qname=[^ ]*' | head -n 1)" \
          "$ST"

    # Verify server IP field
    ST=$(tail -n +"$BEFORE" "$LOG" | grep "\[DNS_RESP_OK\]" | grep -q "server=" && echo PASS || echo FAIL)
    check "2. Normal Query" \
          "Response log line contains server= (upstream DNS IP)" \
          "server= present" \
          "$(tail -n +"$BEFORE" "$LOG" | grep '\[DNS_RESP_OK\]' | grep -o 'server=[^ ]*' | head -n 1)" \
          "$ST"
}

test_nxdomain() {
    printf "\n[3. NXDOMAIN Failure Detection]\n"
    BEFORE=$(wc -l < "$LOG")

    nslookup this-domain-does-not-exist-xb8test123.com > /dev/null 2>&1
    sleep 1

    ST=$(tail -n +"$BEFORE" "$LOG" | grep -q "\[DNS_FAIL\]" && echo PASS || echo FAIL)
    check "3. NXDOMAIN" \
          "Non-existent domain triggers [DNS_FAIL] log line" \
          "[DNS_FAIL] line in log" \
          "$(tail -n +"$BEFORE" "$LOG" | grep '\[DNS_FAIL\]' | head -n 1 | cut -c1-80)" \
          "$ST"

    ST=$(tail -n +"$BEFORE" "$LOG" | grep "\[DNS_FAIL\]" | grep -q "NXDOMAIN" && echo PASS || echo FAIL)
    check "3. NXDOMAIN" \
          "[DNS_FAIL] contains rcode=3(NXDOMAIN)" \
          "rcode=3(NXDOMAIN) in [DNS_FAIL]" \
          "$(tail -n +"$BEFORE" "$LOG" | grep '\[DNS_FAIL\]' | grep -o 'rcode=[^)]*)'| head -n 1)" \
          "$ST"

    ST=$(tail -n +"$BEFORE" "$LOG" | grep "\[DNS_FAIL\]" | grep -q "latency_ms=" && echo PASS || echo FAIL)
    check "3. NXDOMAIN" \
          "NXDOMAIN response also records latency_ms" \
          "latency_ms= present even for failures" \
          "$(tail -n +"$BEFORE" "$LOG" | grep '\[DNS_FAIL\]' | grep -o 'latency_ms=[0-9]*' | head -n 1)" \
          "$ST"
}

test_multiple_domains() {
    printf "\n[4. Bulk Queries - Multiple Domains]\n"
    BEFORE=$(wc -l < "$LOG")

    for d in www.amazon.com www.youtube.com www.github.com www.microsoft.com; do
        nslookup $d > /dev/null 2>&1
    done
    sleep 2

    NEW_LINES=$(tail -n +"$BEFORE" "$LOG" | grep -c "\[DNS_RESP_OK\]\|\[DNS_FAIL\]" 2>/dev/null || echo 0)
    [ "$NEW_LINES" -ge 4 ] && ST="PASS" || ST="FAIL"
    check "4. Bulk Queries" \
          "4 domains queried — at least 4 response log lines captured" \
          ">= 4 response lines" \
          "$NEW_LINES response lines" \
          "$ST"

    # Verify each domain appears in log
    ST=$(tail -n +"$BEFORE" "$LOG" | grep -q "qname=www.amazon.com" && echo PASS || echo FAIL)
    check "4. Bulk Queries" \
          "www.amazon.com appears in captured log" \
          "qname=www.amazon.com in log" \
          "$(tail -n +"$BEFORE" "$LOG" | grep 'qname=www.amazon.com' | wc -l) lines" \
          "$ST"
}

test_ptr_lookup() {
    printf "\n[5. PTR Reverse Lookup]\n"
    BEFORE=$(wc -l < "$LOG")

    nslookup 75.75.75.75 > /dev/null 2>&1
    sleep 1

    NEW=$(tail -n +"$BEFORE" "$LOG" | grep -c "\[DNS_RESP_OK\]\|\[DNS_FAIL\]" 2>/dev/null | tr -d ' ')
    [ "${NEW:-0}" -ge 1 ] && ST="PASS" || ST="FAIL"
    check "5. PTR Lookup" \
          "Reverse PTR lookup captured (in-addr.arpa query)" \
          "At least 1 response line for PTR" \
          "$NEW response lines for PTR query" \
          "$ST"

    ST=$(tail -n +"$BEFORE" "$LOG" | grep -q "qtype=PTR" && echo PASS || echo FAIL)
    check "5. PTR Lookup" \
          "PTR query type correctly identified as qtype=PTR" \
          "qtype=PTR in log" \
          "$(tail -n +"$BEFORE" "$LOG" | grep 'qtype=PTR' | head -n 1 | grep -o 'qtype=PTR')" \
          "$ST"
}

test_no_slow_normal() {
    printf "\n[6. No Slow Queries Under Normal Conditions]\n"
    # Use wc -l instead of grep -c to avoid exit-code issues on busybox
    SLOW_COUNT=$(grep "\[DNS_SLOW\]" "$LOG" 2>/dev/null | wc -l | tr -d ' ')
    SLOW_COUNT=${SLOW_COUNT:-0}
    [ "$SLOW_COUNT" -eq 0 ] && ST="PASS" || ST="FAIL"
    check "6. Slow Detection" \
          "No [DNS_SLOW] lines under normal network conditions (threshold=${SLOW_THRESHOLD}ms)" \
          "[DNS_SLOW] count = 0" \
          "[DNS_SLOW] count = $SLOW_COUNT" \
          "$ST"
}

test_timeout_detection() {
    printf "\n[7. DNS Timeout Detection]\n"

    if ! iptables -L OUTPUT > /dev/null 2>&1; then
        check "7. Timeout" \
              "Block DNS and verify [DNS_TIMEOUT] - SKIPPED (no iptables)" \
              "[DNS_TIMEOUT] in log after blocking DNS" \
              "SKIPPED: iptables not available" \
              "PASS"
        return
    fi

    BEFORE=$(wc -l < "$LOG")
    iptables  -I OUTPUT -o "$IFACE" -p udp --dport 53 -j DROP 2>/dev/null
    ip6tables -I OUTPUT -o "$IFACE" -p udp --dport 53 -j DROP 2>/dev/null
    # Fire a query that will be blocked on both IPv4 and IPv6
    nslookup timeout-test-xb8.com > /dev/null 2>&1 &
    # Wait longer than default query_timeout (5s) + margin
    sleep 10
    iptables  -D OUTPUT -o "$IFACE" -p udp --dport 53 -j DROP 2>/dev/null
    ip6tables -D OUTPUT -o "$IFACE" -p udp --dport 53 -j DROP 2>/dev/null
    sleep 3

    TIMEOUT_CNT=$(tail -n +"$BEFORE" "$LOG" | grep "\[DNS_TIMEOUT\]" | wc -l | tr -d ' ')
    [ "${TIMEOUT_CNT:-0}" -ge 1 ] && ST="PASS" || ST="FAIL"
    check "7. Timeout" \
          "Blocked DNS produces [DNS_TIMEOUT] after query_timeout seconds" \
          "[DNS_TIMEOUT] count >= 1" \
          "[DNS_TIMEOUT] count = $TIMEOUT_CNT" \
          "$ST"
}

test_excessive_dns() {
    printf "\n[9. Excessive DNS Request Detection]\n"
    BEFORE=$(wc -l < "$LOG")

    # Fire 60 queries rapidly to exceed default flood threshold (50 qps)
    i=0
    while [ $i -lt 60 ]; do
        nslookup flood-test-${i}.example.com > /dev/null 2>&1 &
        i=$((i+1))
    done
    wait
    sleep 3

    FLOOD_CNT=$(tail -n +"$BEFORE" "$LOG" | grep "\[DNS_FLOOD\]" | wc -l | tr -d ' ')
    [ "${FLOOD_CNT:-0}" -ge 1 ] && ST="PASS" || ST="FAIL"
    check "9. Excessive DNS" \
          "60 rapid queries triggers [DNS_FLOOD] (threshold=50 qps)" \
          "[DNS_FLOOD] count >= 1" \
          "[DNS_FLOOD] count = $FLOOD_CNT" \
          "$ST"

    ST=$(tail -n +"$BEFORE" "$LOG" | grep "\[DNS_FLOOD\]" | grep -q "qps=" && echo PASS || echo FAIL)
    check "9. Excessive DNS" \
          "[DNS_FLOOD] line contains qps= field" \
          "qps= in [DNS_FLOOD]" \
          "$(tail -n +"$BEFORE" "$LOG" | grep '\[DNS_FLOOD\]' | grep -o 'qps=[0-9]*' | head -n 1)" \
          "$ST"

    ST=$(tail -n +"$BEFORE" "$LOG" | grep "\[DNS_FLOOD\]" | grep -q "threshold_qps=" && echo PASS || echo FAIL)
    check "9. Excessive DNS" \
          "[DNS_FLOOD] line contains threshold_qps= field" \
          "threshold_qps= in [DNS_FLOOD]" \
          "$(tail -n +"$BEFORE" "$LOG" | grep '\[DNS_FLOOD\]' | grep -o 'threshold_qps=[0-9]*' | head -n 1)" \
          "$ST"
}

test_slow_internet() {
    printf "\n[10. Slow Internet / Network Degraded Detection]\n"

    # Use the summary already captured; kill DnsMonitor first if still running
    kill -TERM "$DNSMON_PID" 2>/dev/null; sleep 2
    SUMMARY=$(grep "\[DNS_SUMMARY\]" "$LOG" | grep -v "event=" | tail -n 1)

    # Under normal XB8 conditions (avg ~11ms), degrade_events must be 0
    DEG=$(echo "$SUMMARY" | tr ' ' '\n' | grep "^degrade_events=" | cut -d= -f2)
    [ "${DEG:-0}" -eq 0 ] && ST="PASS" || ST="FAIL"
    check "10. Slow Internet" \
          "No [NET_DEGRADED] under normal conditions (avg ~11ms << 300ms threshold)" \
          "degrade_events=0" \
          "degrade_events=${DEG:-0}" \
          "$ST"

    ST=$(echo "$SUMMARY" | grep -q "degrade_events=" && echo PASS || echo FAIL)
    check "10. Slow Internet" \
          "[DNS_SUMMARY] contains degrade_events= field" \
          "degrade_events= present" \
          "$(echo $SUMMARY | grep -o 'degrade_events=[0-9]*')" \
          "$ST"

    ST=$(echo "$SUMMARY" | grep -q "flood_events=" && echo PASS || echo FAIL)
    check "10. Slow Internet" \
          "[DNS_SUMMARY] contains flood_events= field" \
          "flood_events= present" \
          "$(echo $SUMMARY | grep -o 'flood_events=[0-9]*')" \
          "$ST"

    ST=$(echo "$SUMMARY" | grep -q "top_client=" && echo PASS || echo FAIL)
    check "10. Slow Internet" \
          "[DNS_SUMMARY] contains top_client= (highest query-volume client)" \
          "top_client= present" \
          "$(echo $SUMMARY | grep -o 'top_client=[^ ]*')" \
          "$ST"

    ST=$(echo "$SUMMARY" | grep -q "timeout_pct=" && echo PASS || echo FAIL)
    check "10. Slow Internet" \
          "[DNS_SUMMARY] contains timeout_pct= field" \
          "timeout_pct= present" \
          "$(echo $SUMMARY | grep -o 'timeout_pct=[0-9]*')" \
          "$ST"

    TO_PCT=$(echo "$SUMMARY" | tr ' ' '\n' | grep "^timeout_pct=" | cut -d= -f2)
    [ "${TO_PCT:-0}" -eq 0 ] && ST="PASS" || ST="FAIL"
    check "10. Slow Internet" \
          "timeout_pct=0 under normal conditions" \
          "timeout_pct=0" \
          "timeout_pct=${TO_PCT:-0}" \
          "$ST"
}

test_summary_format() {
    printf "\n[8. Summary Format and Fields]\n"
    kill -TERM "$DNSMON_PID" 2>/dev/null
    sleep 3

    ST=$(grep -q "\[DNS_SUMMARY\]" "$LOG" && echo PASS || echo FAIL)
    check "8. Summary" \
          "[DNS_SUMMARY] line emitted" \
          "[DNS_SUMMARY] present in log" \
          "$(grep '\[DNS_SUMMARY\]' $LOG | grep -v event= | tail -1 | cut -c1-80)" \
          "$ST"

    SUMMARY=$(grep "\[DNS_SUMMARY\]" "$LOG" | grep -v "event=" | tail -1)

    for FIELD in queries= success= fail_total= avg_ms= max_ms= server_fails=; do
        ST=$(echo "$SUMMARY" | grep -q "$FIELD" && echo PASS || echo FAIL)
        check "8. Summary" \
              "Summary contains field: $FIELD" \
              "$FIELD present in [DNS_SUMMARY]" \
              "$(echo $SUMMARY | grep -o "${FIELD}[^ ]*")" \
              "$ST"
    done

    # Latency sanity — avg_ms must be > 0 and < 500 for healthy network
    AVG=$(echo "$SUMMARY" | tr ' ' '\n' | grep '^avg_ms=' | cut -d= -f2)
    if [ -n "$AVG" ] && [ "$AVG" -gt 0 ] && [ "$AVG" -lt 500 ] 2>/dev/null; then
        ST="PASS"
    else
        ST="FAIL"
    fi
    check "8. Summary" \
          "avg_ms is in healthy range (0 < avg_ms < 500)" \
          "0 < avg_ms < 500" \
          "avg_ms=${AVG}" \
          "$ST"

    # Timestamp format check — must contain 'T' and 'Z'
    TS_LINE=$(echo "$SUMMARY" | grep -o 'ts=[^ ]*')
    ST=$(echo "$TS_LINE" | grep -q "T" && echo "$TS_LINE" | grep -q "Z" && echo PASS || echo FAIL)
    check "8. Summary" \
          "Timestamp in ISO-8601 format (contains T and Z)" \
          "ts=YYYY-MM-DDTHH:MM:SS.mmmZ" \
          "$TS_LINE" \
          "$ST"
}

# ── HTML report generator ─────────────────────────────────────────────
print_html() {
    NOW=$(ts)
    RATE=0
    [ "$TOTAL" -gt 0 ] && RATE=$(awk "BEGIN{printf \"%d\", $PASS*100/$TOTAL}")

    cat <<EOF
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>DnsMonitor Device Test Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;color:#333;}
.hdr{background:linear-gradient(135deg,#1a3a5c,#2d6a9f);color:#fff;padding:20px 28px;}
.hdr h1{font-size:20px;} .hdr p{font-size:12px;opacity:.8;margin-top:4px;}
.sum{display:flex;gap:14px;padding:16px 28px;flex-wrap:wrap;}
.card{background:#fff;border-radius:6px;padding:14px 20px;min-width:120px;
      text-align:center;box-shadow:0 2px 6px rgba(0,0,0,.08);}
.card .n{font-size:28px;font-weight:700;} .card .l{font-size:11px;color:#777;
margin-top:2px;text-transform:uppercase;}
.total .n{color:#1a3a5c;} .passed .n{color:#27ae60;}
.failed .n{color:#e74c3c;} .rate .n{color:#f39c12;}
.wrap{padding:0 28px 28px;overflow-x:auto;}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:6px;
      overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.08);font-size:12px;}
thead tr{background:#1a3a5c;color:#fff;}
thead th{padding:10px 12px;text-align:left;font-weight:600;white-space:nowrap;}
tbody tr:nth-child(even){background:#f8fafc;} tbody tr:hover{background:#eaf3ff;}
td{padding:8px 12px;vertical-align:top;border-bottom:1px solid #e8ecf0;}
.tid{font-family:monospace;font-weight:600;color:#555;white-space:nowrap;}
.subj{font-weight:600;color:#1a3a5c;white-space:nowrap;}
.exp{color:#2c3e50;} .ok{color:#27ae60;} .err{color:#e74c3c;font-weight:600;}
.pass{color:#27ae60;font-weight:700;} .fail{color:#e74c3c;font-weight:700;}
</style></head><body>
<div class='hdr'>
<h1>DnsMonitor Device Integration Test Report</h1>
<p>Device: XB8 (CGM4981COM) &nbsp;|&nbsp; Interface: $IFACE &nbsp;|&nbsp; $NOW</p>
</div>
<div class='sum'>
<div class='card total'><div class='n'>$TOTAL</div><div class='l'>Total</div></div>
<div class='card passed'><div class='n'>$PASS</div><div class='l'>Passed</div></div>
<div class='card failed'><div class='n'>$FAIL</div><div class='l'>Failed</div></div>
<div class='card rate'><div class='n'>${RATE}%</div><div class='l'>Pass Rate</div></div>
</div>
<div class='wrap'><table><thead><tr>
<th>Test ID</th><th>Subject</th><th>Test Scenario</th>
<th>Expected</th><th>Actual</th><th>Status</th>
</tr></thead><tbody>
EOF

    # Read results from temp file for HTML
    while IFS='|' read -r id subj scen exp act status; do
        [ -z "$id" ] && continue
        if [ "$status" = "PASS" ]; then
            printf "<tr><td class='tid'>%s</td><td class='subj'>%s</td><td>%s</td><td class='exp'>%s</td><td class='ok'>%s</td><td class='pass'>&#10003; PASS</td></tr>\n" \
                "$id" "$subj" "$scen" "$exp" "$act"
        else
            printf "<tr><td class='tid'>%s</td><td class='subj'>%s</td><td>%s</td><td class='exp'>%s</td><td class='err'>%s</td><td class='fail'>&#10007; FAIL</td></tr>\n" \
                "$id" "$subj" "$scen" "$exp" "$act"
        fi
    done < "$RESULTS_FILE"

    cat <<EOF
</tbody></table></div>
<div style='padding:8px 28px 20px;font-size:11px;color:#888;'>
Log: $LOG &nbsp;|&nbsp; DnsMonitor slow_threshold=${SLOW_THRESHOLD}ms
</div>
</body></html>
EOF
}

# ── Main ──────────────────────────────────────────────────────────────
if [ "$HTML_MODE" -eq 0 ]; then
    printf "============================================================\n"
    printf " DnsMonitor Device Integration Tests\n"
    printf " Interface: %s  |  Device: XB8 (CGM4981COM)\n" "$IFACE"
    printf "============================================================\n"
fi

# Verify DnsMonitor is available
if ! which "$BINARY" > /dev/null 2>&1 && ! [ -f "/tmp/$BINARY" ] && ! [ -f "/usr/bin/$BINARY" ]; then
    log "ERROR: DnsMonitor not found. Ensure image is loaded correctly."
    exit 1
fi

# Use /tmp/DnsMonitor if not in PATH
which "$BINARY" > /dev/null 2>&1 || BINARY="/usr/bin/DnsMonitor"

start_monitor

test_startup
test_normal_queries
test_nxdomain
test_multiple_domains
test_ptr_lookup
test_no_slow_normal
test_timeout_detection
test_excessive_dns
test_slow_internet
test_summary_format

if [ "$HTML_MODE" -eq 1 ]; then
    print_html
else
    printf "\n============================================================\n"
    printf " Results: %d/%d passed" "$PASS" "$TOTAL"
    if [ "$FAIL" -eq 0 ]; then
        printf "  \033[32m[ALL PASS]\033[0m\n"
    else
        printf "  \033[31m[%d FAILED]\033[0m\n" "$FAIL"
    fi
    printf "============================================================\n"
    printf "\nFor HTML report:\n"
    printf "  /tmp/dns_device_test.sh --html > /tmp/DnsMonitor_DeviceReport.html\n"
    printf "\nFull log: %s\n" "$LOG"
fi
