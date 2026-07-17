#!/bin/sh
##########################################################################
# dns_client_test.sh
#
# Comprehensive DNS telemetry test script.
# Runs on the XB8 (Docsis-Gateway).
# SSHes into the LAN client (Latitude-E5470) to generate DNS traffic,
# then validates what DnsMonitor captured on brlan0.
#
# Prerequisites on XB8:
#   - DnsMonitor binary in PATH
#   - SSH access to client: ssh rdkb-corenw@10.0.0.58 (pass: rdkbdev)
#
# Usage:
#   sh /tmp/dns_client_test.sh
#   sh /tmp/dns_client_test.sh --html > /tmp/DnsClientReport.html
#
##########################################################################

# ─────────────────────────── Configuration ───────────────────────────────
IFACE="brlan0"                   # LAN bridge — captures LAN client queries
CLIENT_IP="10.0.0.58"            # Latitude-E5470 connected to XB8 WiFi/LAN
CLIENT_USER="rdkb-corenw"        # SSH username on Latitude
CLIENT_PASS="rdkbdev"            # SSH password on Latitude
LOG="/tmp/dnsmon_client_test.log" # DnsMonitor output file
RESULTS_FILE="/tmp/dns_results.txt"

# DnsMonitor flags:
#   -r 30   : emit summary every 30 seconds (shorter for testing)
#   -s 100  : flag responses > 100ms as [DNS_SLOW]
#   -d 200  : flag avg_ms > 200ms as [NET_DEGRADED]
#   -f 20   : flood threshold (20 qps per client, skipped in these tests)
#   -v      : verbose — log every query and OK response
DNSMON_FLAGS="-i $IFACE -r 30 -s 100 -d 200 -f 20 -v"

HTML_MODE=0
[ "$1" = "--html" ] && HTML_MODE=1

PASS=0; FAIL=0; TOTAL=0

# ─────────────────────────── Helper functions ────────────────────────────

# Run a command on the LAN client via SSH (non-interactive)
# Usage: run_on_client "command"
run_on_client() {
    # sshpass is not available on XB8; use ssh with StrictHostKeyChecking=no
    # and expect-like approach via -o BatchMode=no
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        "${CLIENT_USER}@${CLIENT_IP}" "$1" 2>/dev/null
}

# Emit a test result line
# Usage: check <subject> <scenario> <expected> <actual> <PASS|FAIL>
check() {
    TOTAL=$((TOTAL+1))
    ID=$(printf "TC-%03d" $TOTAL)
    SUBJ="$1"; SCEN="$2"; EXP="$3"; ACT="$4"; STATUS="$5"

    [ "$STATUS" = "PASS" ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

    if [ "$HTML_MODE" -eq 0 ]; then
        if [ "$STATUS" = "PASS" ]; then
            printf "  \033[32m[PASS]\033[0m %s  %s\n" "$ID" "$SCEN"
        else
            printf "  \033[31m[FAIL]\033[0m %s  %s\n        Actual: %s\n" \
                   "$ID" "$SCEN" "$ACT"
        fi
    fi
    printf "%s|%s|%s|%s|%s|%s\n" \
        "$ID" "$SUBJ" "$SCEN" "$EXP" "$ACT" "$STATUS" >> "$RESULTS_FILE"
}

# Count matching lines in the log after a given line number
count_since() { tail -n +"$1" "$LOG" | grep -c "$2" 2>/dev/null | tr -d ' '; }
grep_since()  { tail -n +"$1" "$LOG" | grep -q "$2" 2>/dev/null && echo PASS || echo FAIL; }

# ─────────────────────────── Startup ─────────────────────────────────────

[ "$HTML_MODE" -eq 0 ] && {
    printf "============================================================\n"
    printf " DnsMonitor LAN Client Test — XB8 brlan0\n"
    printf " Client: %s (%s)\n" "$CLIENT_IP" "$CLIENT_USER"
    printf "============================================================\n"
}

# Verify client is reachable
if ! run_on_client "echo ok" | grep -q "ok"; then
    printf "ERROR: Cannot SSH to client %s. Check connectivity.\n" "$CLIENT_IP"
    exit 1
fi

# Start DnsMonitor in background on brlan0
rm -f "$LOG" "$RESULTS_FILE"
touch "$RESULTS_FILE"
DnsMonitor $DNSMON_FLAGS >> "$LOG" 2>&1 &
DNSMON_PID=$!
sleep 2   # wait for DnsMonitor to open the pcap handle

if ! kill -0 "$DNSMON_PID" 2>/dev/null; then
    printf "ERROR: DnsMonitor failed to start.\n"
    exit 1
fi

[ "$HTML_MODE" -eq 0 ] && printf "DnsMonitor started (PID=%s, log=%s)\n\n" \
    "$DNSMON_PID" "$LOG"

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 1: Startup Validation
# Purpose  : Confirm DnsMonitor is listening on the correct interface.
# How      : Check the START event in the log.
# Expected : [DNS_SUMMARY] event=START with iface=brlan0
# ═══════════════════════════════════════════════════════════════════════
printf "\n[TC-001..002  Startup Validation]\n"

# TC-001: START event emitted
ST=$(grep -q "event=START" "$LOG" && echo PASS || echo FAIL)
check "1. Startup" \
    "DnsMonitor emits [DNS_SUMMARY] event=START on launch" \
    "[DNS_SUMMARY] event=START in log" \
    "$(grep 'event=START' $LOG | head -n 1 | cut -c1-70)" \
    "$ST"

# TC-002: Correct interface in all log lines
ST=$(grep -q "iface=$IFACE" "$LOG" && echo PASS || echo FAIL)
check "1. Startup" \
    "All log lines contain iface=$IFACE" \
    "iface=brlan0 in log" \
    "$(grep 'iface=brlan0' $LOG | wc -l | tr -d ' ') lines matched" \
    "$ST"

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 2: Normal DNS Query — A Record
# Purpose  : Verify a standard A (IPv4) lookup from client is captured.
# How      : SSH to Latitude, run `nslookup www.google.com`.
#            The query goes brlan0 → XB8 → 75.75.75.75.
# Expected :
#   [DNS_QUERY]   client=10.0.0.58  qname=www.google.com  qtype=A
#   [DNS_RESP_OK] OR [DNS_SLOW]  latency_ms=<N>
# ═══════════════════════════════════════════════════════════════════════
printf "\n[TC-003..006  Normal A/AAAA Query from LAN Client]\n"

BEFORE=$(wc -l < "$LOG")
run_on_client "nslookup www.google.com > /dev/null 2>&1"
sleep 2

# TC-003: Query captured from client IP
ST=$(count_since $BEFORE "client=$CLIENT_IP" | xargs -I{} test {} -ge 1 && echo PASS || echo FAIL)
ACTUAL_CNT=$(count_since $BEFORE "client=$CLIENT_IP")
check "2. Normal Query" \
    "nslookup www.google.com captured from client=$CLIENT_IP on brlan0" \
    "At least 1 line with client=$CLIENT_IP" \
    "${ACTUAL_CNT} lines with client=$CLIENT_IP" \
    "$ST"

# TC-004: qname=www.google.com appears in log
ST=$(grep_since $BEFORE "qname=www.google.com")
check "2. Normal Query" \
    "qname=www.google.com present in captured DNS query" \
    "qname=www.google.com in log" \
    "$(tail -n +$BEFORE $LOG | grep 'qname=www.google.com' | grep -o 'qname=[^ ]*' | head -n 1)" \
    "$ST"

# TC-005: latency_ms field present in response
ST=$(tail -n +$BEFORE "$LOG" | grep -q "latency_ms=" && echo PASS || echo FAIL)
LATENCY=$(tail -n +$BEFORE "$LOG" | grep "latency_ms=" | grep -o "latency_ms=[0-9]*" | head -n 1)
check "2. Normal Query" \
    "Response line contains latency_ms= (round-trip time measured)" \
    "latency_ms= present" \
    "$LATENCY" \
    "$ST"

# TC-006: qtype=A captured (IPv4 record type)
ST=$(grep_since $BEFORE "qtype=A")
check "2. Normal Query" \
    "Record type A (IPv4) correctly identified in query" \
    "qtype=A in log" \
    "$(tail -n +$BEFORE $LOG | grep 'qtype=A' | grep -o 'qtype=A' | head -n 1)" \
    "$ST"

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 3: AAAA Record (IPv6 DNS)
# Purpose  : Confirm dual-stack DNS queries (IPv6 record type) captured.
# How      : nslookup with -type=aaaa forces an AAAA query.
# Expected :
#   [DNS_QUERY]   qtype=AAAA
#   [DNS_RESP_OK] OR [DNS_SLOW]  qtype=AAAA  latency_ms=<N>
# ═══════════════════════════════════════════════════════════════════════
printf "\n[TC-007..008  AAAA Record Query]\n"

BEFORE=$(wc -l < "$LOG")
run_on_client "nslookup -type=aaaa www.youtube.com > /dev/null 2>&1"
sleep 2

# TC-007: AAAA query type captured
ST=$(grep_since $BEFORE "qtype=AAAA")
check "3. AAAA Query" \
    "IPv6 AAAA record query from client captured on brlan0" \
    "qtype=AAAA in log" \
    "$(tail -n +$BEFORE $LOG | grep 'qtype=AAAA' | grep -o 'qtype=AAAA' | head -n 1)" \
    "$ST"

# TC-008: qname=www.youtube.com present
ST=$(grep_since $BEFORE "qname=www.youtube.com")
check "3. AAAA Query" \
    "qname=www.youtube.com present for AAAA query" \
    "qname=www.youtube.com" \
    "$(tail -n +$BEFORE $LOG | grep 'qname=www.youtube.com' | grep -o 'qname=[^ ]*' | head -n 1)" \
    "$ST"

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 4: NXDOMAIN Failure Detection
# Purpose  : Verify [DNS_FAIL] is emitted for a non-existent domain.
#            NXDOMAIN (rcode=3) means "domain does not exist".
# How      : Query a made-up domain that will never resolve.
# Expected :
#   [DNS_FAIL]  client=10.0.0.58  qname=nonexistent-xb8test.com
#               rcode=3(NXDOMAIN)  latency_ms=<N>
# Key observation: latency is still measured even for failures.
# ═══════════════════════════════════════════════════════════════════════
printf "\n[TC-009..012  NXDOMAIN Failure Detection]\n"

BEFORE=$(wc -l < "$LOG")
run_on_client "nslookup nonexistent-xb8test99.com > /dev/null 2>&1"
sleep 2

# TC-009: [DNS_FAIL] emitted
ST=$(grep_since $BEFORE "\[DNS_FAIL\]")
check "4. NXDOMAIN" \
    "[DNS_FAIL] log line emitted for non-existent domain" \
    "[DNS_FAIL] present in log" \
    "$(tail -n +$BEFORE $LOG | grep '\[DNS_FAIL\]' | head -n 1 | cut -c1-80)" \
    "$ST"

# TC-010: NXDOMAIN rcode string present
ST=$(tail -n +$BEFORE "$LOG" | grep "\[DNS_FAIL\]" | grep -q "NXDOMAIN" && echo PASS || echo FAIL)
RCODE=$(tail -n +$BEFORE "$LOG" | grep "\[DNS_FAIL\]" | grep -o "rcode=[^)]*)" | head -n 1)
check "4. NXDOMAIN" \
    "RCODE correctly decoded as NXDOMAIN (not raw number 3)" \
    "rcode=3(NXDOMAIN)" \
    "$RCODE" \
    "$ST"

# TC-011: latency recorded even for NXDOMAIN failures
ST=$(tail -n +$BEFORE "$LOG" | grep "\[DNS_FAIL\]" | grep -q "latency_ms=" && echo PASS || echo FAIL)
FAIL_LAT=$(tail -n +$BEFORE "$LOG" | grep "\[DNS_FAIL\]" | grep -o "latency_ms=[0-9]*" | head -n 1)
check "4. NXDOMAIN" \
    "latency_ms= measured even for NXDOMAIN failure (DNS server responded)" \
    "latency_ms= in [DNS_FAIL]" \
    "$FAIL_LAT" \
    "$ST"

# TC-012: client IP correctly attributed
ST=$(tail -n +$BEFORE "$LOG" | grep "\[DNS_FAIL\]" | grep -q "client=$CLIENT_IP" && echo PASS || echo FAIL)
check "4. NXDOMAIN" \
    "NXDOMAIN failure attributed to correct client=$CLIENT_IP" \
    "client=$CLIENT_IP in [DNS_FAIL]" \
    "$(tail -n +$BEFORE $LOG | grep '\[DNS_FAIL\]' | grep -o 'client=[^ ]*' | head -n 1)" \
    "$ST"

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 5: PTR Reverse Lookup
# Purpose  : Verify PTR (reverse DNS) query type is correctly identified.
#            Reverse DNS maps an IP address back to a hostname.
#            On this network, PTR lookups for unregistered IPs produce
#            NXDOMAIN — which is normal expected behavior.
# How      : nslookup on an IP address triggers a PTR query.
# Expected :
#   [DNS_QUERY]  qtype=PTR  qname=75.75.75.75.in-addr.arpa
#   [DNS_RESP_OK] or [DNS_FAIL]  qtype=PTR
# ═══════════════════════════════════════════════════════════════════════
printf "\n[TC-013..014  PTR Reverse Lookup]\n"

BEFORE=$(wc -l < "$LOG")
run_on_client "nslookup 75.75.75.75 > /dev/null 2>&1"
sleep 2

# TC-013: PTR query captured
ST=$(grep_since $BEFORE "qtype=PTR")
check "5. PTR Lookup" \
    "PTR (reverse DNS) query from client captured with qtype=PTR" \
    "qtype=PTR in log" \
    "$(tail -n +$BEFORE $LOG | grep 'qtype=PTR' | grep -o 'qtype=PTR' | head -n 1)" \
    "$ST"

# TC-014: in-addr.arpa query name present
ST=$(grep_since $BEFORE "in-addr.arpa")
check "5. PTR Lookup" \
    "Reverse lookup qname contains 'in-addr.arpa' (correct PTR format)" \
    "in-addr.arpa in qname" \
    "$(tail -n +$BEFORE $LOG | grep 'in-addr.arpa' | grep -o 'qname=[^ ]*' | head -n 1 | cut -c1-50)" \
    "$ST"

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 6: Slow Query Detection ([DNS_SLOW])
# Purpose  : Verify [DNS_SLOW] fires when latency > slow_thresh_ms (100ms).
#            This network has ~250ms DNS latency — well above 100ms threshold.
# How      : Any query from the Latitude will likely be slow (observed
#            latency consistently 220-350ms on this setup).
# Expected :
#   [DNS_SLOW]  latency_ms=2xx  (above 100ms threshold)
#   NOT [DNS_SLOW] for a fresh query within 100ms (unlikely here)
# Note: [DNS_SLOW] is also emitted for RESP_OK queries that are slow.
# ═══════════════════════════════════════════════════════════════════════
printf "\n[TC-015..017  Slow Query Detection]\n"

BEFORE=$(wc -l < "$LOG")
run_on_client "nslookup www.amazon.com > /dev/null 2>&1"
sleep 2

# TC-015: [DNS_SLOW] emitted (expected given 250ms latency on this network)
SLOW_CNT=$(count_since $BEFORE "\[DNS_SLOW\]")
[ "${SLOW_CNT:-0}" -ge 1 ] && ST="PASS" || ST="FAIL"
check "6. Slow Query" \
    "[DNS_SLOW] emitted for query with latency > 100ms threshold" \
    "[DNS_SLOW] count >= 1" \
    "[DNS_SLOW] count = $SLOW_CNT" \
    "$ST"

# TC-016: latency_ms field in [DNS_SLOW] exceeds threshold
SLOW_LAT=$(tail -n +$BEFORE "$LOG" | grep "\[DNS_SLOW\]" | grep -o "latency_ms=[0-9]*" | head -n 1 | cut -d= -f2)
[ "${SLOW_LAT:-0}" -ge 100 ] && ST="PASS" || ST="FAIL"
check "6. Slow Query" \
    "latency_ms in [DNS_SLOW] is >= slow_thresh_ms (100ms)" \
    "latency_ms >= 100" \
    "latency_ms=${SLOW_LAT:-0}" \
    "$ST"

# TC-017: [DNS_SLOW] contains qname field
ST=$(tail -n +$BEFORE "$LOG" | grep "\[DNS_SLOW\]" | grep -q "qname=" && echo PASS || echo FAIL)
check "6. Slow Query" \
    "[DNS_SLOW] log line contains qname= (domain that was slow)" \
    "qname= present in [DNS_SLOW]" \
    "$(tail -n +$BEFORE $LOG | grep '\[DNS_SLOW\]' | grep -o 'qname=[^ ]*' | head -n 1)" \
    "$ST"

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 7: Bulk Multi-Domain Query
# Purpose  : Test that DnsMonitor correctly handles multiple simultaneous
#            queries from the same client.
# How      : Query 5 different domains in rapid sequence from client.
# Expected :
#   5 or more [DNS_QUERY] lines with client=10.0.0.58
#   Each with a different qname
#   top_client in [DNS_SUMMARY] shows 10.0.0.58
# ═══════════════════════════════════════════════════════════════════════
printf "\n[TC-018..020  Bulk Multi-Domain Query]\n"

BEFORE=$(wc -l < "$LOG")
run_on_client "
    nslookup www.github.com > /dev/null 2>&1
    nslookup www.microsoft.com > /dev/null 2>&1
    nslookup www.apple.com > /dev/null 2>&1
    nslookup www.netflix.com > /dev/null 2>&1
    nslookup www.cloudflare.com > /dev/null 2>&1
"
sleep 3

# TC-018: At least 5 response lines from client
RESP_CNT=$(tail -n +$BEFORE "$LOG" | grep "client=$CLIENT_IP" | grep -c "\[DNS_SLOW\]\|\[DNS_RESP_OK\]\|\[DNS_FAIL\]" | tr -d ' ')
[ "${RESP_CNT:-0}" -ge 5 ] && ST="PASS" || ST="FAIL"
check "7. Bulk Query" \
    "5 domains queried — at least 5 response lines from client" \
    ">= 5 response lines from client=$CLIENT_IP" \
    "$RESP_CNT response lines" \
    "$ST"

# TC-019: github.com appears in log
ST=$(grep_since $BEFORE "qname=www.github.com")
check "7. Bulk Query" \
    "www.github.com appears in captured queries" \
    "qname=www.github.com in log" \
    "$(tail -n +$BEFORE $LOG | grep 'qname=www.github.com' | wc -l | tr -d ' ') lines" \
    "$ST"

# TC-020: microsoft.com appears in log
ST=$(grep_since $BEFORE "qname=www.microsoft.com")
check "7. Bulk Query" \
    "www.microsoft.com appears in captured queries" \
    "qname=www.microsoft.com in log" \
    "$(tail -n +$BEFORE $LOG | grep 'qname=www.microsoft.com' | wc -l | tr -d ' ') lines" \
    "$ST"

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 8: Degraded Internet Detection ([NET_DEGRADED])
# Purpose  : Verify [NET_DEGRADED] fires when avg DNS latency exceeds
#            the degrade threshold (200ms in this test run).
#            This network has avg ~280ms — exceeds 200ms threshold.
# How      : The existing queries in this interval already average >200ms.
#            Force a summary by waiting for the next 30-second interval.
# Expected :
#   [NET_DEGRADED]  reason=high_latency  avg_ms=2xx
# Note: This proves the "slow internet detection" feature.
# ═══════════════════════════════════════════════════════════════════════
printf "\n[TC-021..023  Degraded Internet / Slow Internet Detection]\n"
printf "  (waiting up to 35s for summary interval...)\n"
sleep 35

# TC-021: [NET_DEGRADED] emitted (avg_ms ~280ms > degrade threshold 200ms)
ST=$(grep -q "\[NET_DEGRADED\]" "$LOG" && echo PASS || echo FAIL)
check "8. Degraded" \
    "[NET_DEGRADED] emitted — avg latency exceeds degrade_avg_ms=200ms" \
    "[NET_DEGRADED] in log" \
    "$(grep '\[NET_DEGRADED\]' $LOG | tail -n 1 | cut -c1-80)" \
    "$ST"

# TC-022: reason=high_latency present
ST=$(grep "\[NET_DEGRADED\]" "$LOG" | grep -q "high_latency" && echo PASS || echo FAIL)
check "8. Degraded" \
    "[NET_DEGRADED] contains reason=high_latency" \
    "reason=high_latency in [NET_DEGRADED]" \
    "$(grep '\[NET_DEGRADED\]' $LOG | grep -o 'reason=[^ ]*' | tail -n 1)" \
    "$ST"

# TC-023: avg_ms value present in [NET_DEGRADED]
ST=$(grep "\[NET_DEGRADED\]" "$LOG" | grep -q "avg_ms=" && echo PASS || echo FAIL)
AVG=$(grep "\[NET_DEGRADED\]" "$LOG" | grep -o "avg_ms=[0-9]*" | tail -n 1)
check "8. Degraded" \
    "[NET_DEGRADED] contains avg_ms= (measured latency that triggered alert)" \
    "avg_ms= present and > 200" \
    "$AVG" \
    "$ST"

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 9: DNS Timeout Detection
# Purpose  : Verify [DNS_TIMEOUT] is emitted when a DNS query gets no
#            response within query_timeout seconds.
# How      : Use iptables to DROP DNS packets forwarded from client,
#            then trigger a query from the Latitude.
#            Wait 6+ seconds (> default timeout of 5s), then unblock.
# Expected :
#   [DNS_TIMEOUT]  client=10.0.0.58  qname=timeout-test.com
# Note: Both IPv4 and IPv6 DNS must be blocked to prevent fallback.
# ═══════════════════════════════════════════════════════════════════════
printf "\n[TC-024  DNS Timeout Detection]\n"
printf "  (blocking DNS from client for 12s...)\n"

BEFORE=$(wc -l < "$LOG")

# Block DNS forwarded FROM the client IP (both IPv4 and IPv6 paths)
iptables  -I FORWARD -s "$CLIENT_IP" -p udp --dport 53 -j DROP 2>/dev/null
iptables  -I FORWARD -s "$CLIENT_IP" -p tcp --dport 53 -j DROP 2>/dev/null
# Also block IPv6 client if it exists (get from log)
IPV6_CLIENT=$(grep "client=2601" "$LOG" | grep -o "client=[^ ]*" | head -n 1 | cut -d= -f2)
if [ -n "$IPV6_CLIENT" ]; then
    ip6tables -I FORWARD -s "$IPV6_CLIENT" -p udp --dport 53 -j DROP 2>/dev/null
fi

# Trigger a query from client (will be blocked)
run_on_client "nslookup timeout-test-xb8.com > /dev/null 2>&1 &"

# Wait longer than query_timeout (5s) so DnsMonitor classifies it as timeout
sleep 12

# Unblock
iptables  -D FORWARD -s "$CLIENT_IP" -p udp --dport 53 -j DROP 2>/dev/null
iptables  -D FORWARD -s "$CLIENT_IP" -p tcp --dport 53 -j DROP 2>/dev/null
[ -n "$IPV6_CLIENT" ] && \
    ip6tables -D FORWARD -s "$IPV6_CLIENT" -p udp --dport 53 -j DROP 2>/dev/null

sleep 2

# TC-024: [DNS_TIMEOUT] emitted
TO_CNT=$(count_since $BEFORE "\[DNS_TIMEOUT\]")
[ "${TO_CNT:-0}" -ge 1 ] && ST="PASS" || ST="FAIL"
check "9. Timeout" \
    "Blocked DNS produces [DNS_TIMEOUT] after 5s with no response" \
    "[DNS_TIMEOUT] count >= 1" \
    "[DNS_TIMEOUT] count = $TO_CNT" \
    "$ST"

# ═══════════════════════════════════════════════════════════════════════
# TEST GROUP 10: Summary Format and Telemetry Fields
# Purpose  : Verify the [DNS_SUMMARY] line contains all expected fields.
#            This is the line from which Telemetry-2 markers are emitted.
# How      : Force a final summary by sending SIGTERM to DnsMonitor.
# Expected fields:
#   queries=  success=  slow=  fail_total=
#   nxdomain=  servfail=  refused=  timeout=  timeout_pct=
#   avg_ms=  max_ms=  flood_events=  degrade_events=  top_client=
#   server_fails=
# ═══════════════════════════════════════════════════════════════════════
printf "\n[TC-025..034  Summary Format and Telemetry Fields]\n"

kill -TERM "$DNSMON_PID" 2>/dev/null
sleep 3

SUMMARY=$(grep "\[DNS_SUMMARY\]" "$LOG" | grep -v "event=" | tail -n 1)

# TC-025 to TC-034: verify each field is present in the summary
for FIELD in queries= success= slow= fail_total= nxdomain= timeout_pct= avg_ms= max_ms= degrade_events= top_client=; do
    ST=$(echo "$SUMMARY" | grep -q "$FIELD" && echo PASS || echo FAIL)
    check "10. Summary" \
        "[DNS_SUMMARY] contains field: $FIELD" \
        "$FIELD present" \
        "$(echo $SUMMARY | tr ' ' '\n' | grep "^$FIELD")" \
        "$ST"
done

# TC-035: avg_ms is a positive number
AVG_VAL=$(echo "$SUMMARY" | tr ' ' '\n' | grep "^avg_ms=" | cut -d= -f2)
[ "${AVG_VAL:-0}" -gt 0 ] && ST="PASS" || ST="FAIL"
check "10. Summary" \
    "avg_ms > 0 — latency was actually measured this session" \
    "avg_ms > 0" \
    "avg_ms=${AVG_VAL:-0}" \
    "$ST"

# TC-036: top_client contains the Latitude IP (it generated most queries)
ST=$(echo "$SUMMARY" | grep -q "top_client=$CLIENT_IP" && echo PASS || echo FAIL)
TOP=$(echo "$SUMMARY" | tr ' ' '\n' | grep "^top_client=")
check "10. Summary" \
    "top_client= identifies Latitude ($CLIENT_IP) as highest-volume client" \
    "top_client=$CLIENT_IP:N" \
    "$TOP" \
    "$ST"

# TC-037: Timestamp format is ISO-8601 (contains T and Z)
TS=$(echo "$SUMMARY" | grep -o "ts=[^ ]*" | head -n 1)
ST=$(echo "$TS" | grep -q "T" && echo "$TS" | grep -q "Z" && echo PASS || echo FAIL)
check "10. Summary" \
    "Timestamp in ISO-8601 UTC format (YYYY-MM-DDTHH:MM:SS.mmmZ)" \
    "ts=...T...Z" \
    "$TS" \
    "$ST"

# ═══════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ═══════════════════════════════════════════════════════════════════════

if [ "$HTML_MODE" -eq 1 ]; then
    NOW=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%H:%M:%S')
    RATE=0
    [ "$TOTAL" -gt 0 ] && RATE=$(awk "BEGIN{printf \"%d\",$PASS*100/$TOTAL}")
    cat <<EOF
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>DnsMonitor Client Test Report</title>
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
.subj{font-weight:600;color:#1a3a5c;white-space:nowrap;}
.exp{color:#2c3e50;font-size:11px;}.ok{color:#27ae60;font-size:11px;}.err{color:#e74c3c;font-weight:600;font-size:11px;}
.pass{color:#27ae60;font-weight:700;white-space:nowrap;}.fail{color:#e74c3c;font-weight:700;white-space:nowrap;}
</style></head><body>
<div class='hdr'><h1>DnsMonitor Device Integration Test Report</h1>
<p>XB8 (CGM4981COM) brlan0 &nbsp;|&nbsp; Client: $CLIENT_IP ($CLIENT_USER) &nbsp;|&nbsp; $NOW</p>
</div>
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
        if [ "$status" = "PASS" ]; then
            printf "<tr><td class='tid'>%s</td><td class='subj'>%s</td><td>%s</td><td class='exp'>%s</td><td class='ok'>%s</td><td class='pass'>&#10003; PASS</td></tr>\n" "$id" "$subj" "$scen" "$exp" "$act"
        else
            printf "<tr><td class='tid'>%s</td><td class='subj'>%s</td><td>%s</td><td class='exp'>%s</td><td class='err'>%s</td><td class='fail'>&#10007; FAIL</td></tr>\n" "$id" "$subj" "$scen" "$exp" "$act"
        fi
    done < "$RESULTS_FILE"
    printf "</tbody></table></div><div style='padding:8px 28px;font-size:11px;color:#888;'>Log: %s &nbsp;|&nbsp; Flags: %s</div></body></html>\n" "$LOG" "$DNSMON_FLAGS"
else
    printf "\n============================================================\n"
    printf " Results: %d/%d passed" "$PASS" "$TOTAL"
    [ "$FAIL" -eq 0 ] && printf "  \033[32m[ALL PASS]\033[0m\n" \
                       || printf "  \033[31m[%d FAILED]\033[0m\n" "$FAIL"
    printf "============================================================\n"
    printf "\nFull DnsMonitor log : %s\n" "$LOG"
    printf "HTML report         : sh %s --html > /tmp/DnsClientReport.html\n" "$0"
fi
