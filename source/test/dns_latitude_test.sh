#!/bin/bash
##########################################################################
# dns_latitude_test.sh  —  Run on Latitude (10.0.0.58)
#
# Generates DNS test traffic for all test scenarios.
# Run this AFTER starting dns_xb8_monitor.sh on the XB8.
#
# Usage:
#   On Latitude:  bash /tmp/dns_latitude_test.sh
##########################################################################

LOG="/tmp/lat_test.log"
exec 2>&1 | tee "$LOG"

ts() { date -u '+%H:%M:%S'; }

pass() { printf "\033[32m[PASS]\033[0m %s  %s\n" "$(ts)" "$1"; }
info() { printf "\033[34m[INFO]\033[0m %s  %s\n" "$(ts)" "$1"; }
step() { printf "\n\033[1m>>> %s\033[0m\n" "$1"; }

step "TC-001: Normal A Record Query"
# Purpose: verify a standard A (IPv4) lookup is captured on brlan0
# Expected on XB8: [DNS_QUERY] qtype=A  [DNS_SLOW] or [DNS_RESP_OK]
info "Running: nslookup www.google.com"
nslookup www.google.com > /dev/null 2>&1 && pass "www.google.com A query sent" || echo "nslookup failed"
sleep 1

step "TC-002: AAAA Record Query (IPv6)"
# Purpose: verify IPv6 record type is correctly identified as qtype=AAAA
# Expected on XB8: [DNS_QUERY] qtype=AAAA
info "Running: nslookup -type=aaaa www.youtube.com"
nslookup -type=aaaa www.youtube.com > /dev/null 2>&1
pass "www.youtube.com AAAA query sent"
sleep 1

step "TC-003: NXDOMAIN Failure Detection"
# Purpose: trigger [DNS_FAIL] with rcode=3(NXDOMAIN) for non-existent domain
# Expected on XB8: [DNS_FAIL] rcode=3(NXDOMAIN) latency_ms=2xx
info "Running: nslookup notexistent-xb8test99.com"
nslookup notexistent-xb8test99.com > /dev/null 2>&1
pass "NXDOMAIN query sent for notexistent-xb8test99.com"
sleep 1

step "TC-004: PTR Reverse Lookup"
# Purpose: verify PTR query type is captured with qtype=PTR
# Expected on XB8: [DNS_QUERY] qtype=PTR qname=75.75.75.75.in-addr.arpa
info "Running: nslookup 75.75.75.75"
nslookup 75.75.75.75 > /dev/null 2>&1
pass "PTR query sent for 75.75.75.75"
sleep 1

step "TC-005: Another NXDOMAIN (IPv4 reverse)"
# Purpose: PTR lookups for unknown IPs always return NXDOMAIN — expected behavior
# Expected on XB8: [DNS_FAIL] qtype=PTR rcode=3(NXDOMAIN)
info "Running: nslookup 192.168.99.254"
nslookup 192.168.99.254 > /dev/null 2>&1
pass "PTR NXDOMAIN query sent"
sleep 1

step "TC-006: Bulk Multi-Domain Query"
# Purpose: test multiple simultaneous queries from same client
# Expected on XB8: 5+ response lines with client=10.0.0.58
info "Querying 5 domains..."
for d in www.github.com www.microsoft.com www.apple.com www.netflix.com www.cloudflare.com; do
    info "  nslookup $d"
    nslookup "$d" > /dev/null 2>&1
    sleep 0.5
done
pass "5 bulk queries sent"
sleep 1

step "TC-007: SERVFAIL Simulation"
# Purpose: trigger servfail by querying a domain that causes server-side failure
# Use a query that may hit SERVFAIL on misconfigured DNS
info "Running: nslookup -type=any test.local"
nslookup -type=any test.local > /dev/null 2>&1
pass "SERVFAIL/NXDOMAIN query sent"
sleep 1

step "TC-008: Rapid Consecutive Queries (Slow Internet Stress)"
# Purpose: generate enough queries to accumulate avg_ms data for [NET_DEGRADED]
# With avg latency ~260ms this will trigger [NET_DEGRADED] with -d 200
info "Sending 10 rapid queries to build latency average..."
for d in amazon.com ebay.com reddit.com twitter.com linkedin.com \
          spotify.com dropbox.com slack.com zoom.us docker.com; do
    nslookup "$d" > /dev/null 2>&1 &
done
wait
pass "10 rapid queries complete"
sleep 2

step "TC-009: MX Record Query"
# Purpose: verify MX record type captured as qtype=MX
# Expected on XB8: [DNS_QUERY] qtype=MX
info "Running: nslookup -type=mx gmail.com"
nslookup -type=mx gmail.com > /dev/null 2>&1
pass "MX record query sent"
sleep 1

step "TC-010: CNAME Resolution"
# Purpose: verify CNAME resolution chain captured
info "Running: nslookup www.amazon.com  (resolves via CNAME)"
nslookup www.amazon.com > /dev/null 2>&1
pass "CNAME resolution query sent"
sleep 1

printf "\n\033[1m============================================================\033[0m\n"
printf "\033[1m All test traffic sent from Latitude.\033[0m\n"
printf " Wait ~30s for the XB8 summary interval, then check:\n"
printf "   grep '\\[DNS_SUMMARY\\]' /tmp/dnsmon_xb8.log\n"
printf "   grep '\\[NET_DEGRADED\\]' /tmp/dnsmon_xb8.log\n"
printf "   grep '\\[DNS_FAIL\\]' /tmp/dnsmon_xb8.log\n"
printf "\033[1m============================================================\033[0m\n"
