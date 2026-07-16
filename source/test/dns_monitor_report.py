#!/usr/bin/env python3
"""
dns_monitor_report.py
=====================
Parses GoogleTest XML output and generates an HTML test report for
CcspTandD_DnsMonitor_Test with columns:
  Test ID | Suite | Test Scenario | Expected Behaviour | Actual Result | Status | Duration

Usage:
    python3 dns_monitor_report.py [--xml <path>] [--out <html_path>]

Default:
    --xml  gtest_results.xml
    --out  DnsMonitor_TestReport.html
"""

import sys
import os
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime

# ---------------------------------------------------------------------------
# Human-readable metadata for each test case
# Format: "SuiteName.TestName": (scenario, expected_behaviour)
# ---------------------------------------------------------------------------
TEST_METADATA = {
    # --- 1. rcode_name() ---
    "CcspTandD_DnsMonitor_Test.RcodeName_NOERROR": (
        "Verify RCODE 0 maps to 'NOERROR'",
        "rcode_name(0) returns 'NOERROR'"
    ),
    "CcspTandD_DnsMonitor_Test.RcodeName_SERVFAIL": (
        "Verify RCODE 2 maps to 'SERVFAIL' — observed servfail=0 on XB8",
        "rcode_name(2) returns 'SERVFAIL'"
    ),
    "CcspTandD_DnsMonitor_Test.RcodeName_NXDOMAIN": (
        "Verify RCODE 3 maps to 'NXDOMAIN' — 44 NXDOMAIN seen on XB8 PTR lookups",
        "rcode_name(3) returns 'NXDOMAIN'"
    ),
    "CcspTandD_DnsMonitor_Test.RcodeName_REFUSED": (
        "Verify RCODE 5 maps to 'REFUSED'",
        "rcode_name(5) returns 'REFUSED'"
    ),
    "CcspTandD_DnsMonitor_Test.RcodeName_FORMERR": (
        "Verify RCODE 1 maps to 'FORMERR'",
        "rcode_name(1) returns 'FORMERR'"
    ),
    "CcspTandD_DnsMonitor_Test.RcodeName_UNKNOWN": (
        "Verify unknown RCODE returns 'UNKNOWN'",
        "rcode_name(99) returns 'UNKNOWN'"
    ),
    # --- 2. qtype_name() ---
    "CcspTandD_DnsMonitor_Test.QtypeName_A": (
        "Verify QTYPE 1 (A record) seen in XB8: www.google.com A query",
        "qtype_name(1) returns 'A'"
    ),
    "CcspTandD_DnsMonitor_Test.QtypeName_AAAA": (
        "Verify QTYPE 28 (AAAA) seen in XB8: dual-stack IPv6 queries",
        "qtype_name(28) returns 'AAAA'"
    ),
    "CcspTandD_DnsMonitor_Test.QtypeName_PTR": (
        "Verify QTYPE 12 (PTR) — all 44 NXDOMAIN failures on XB8 were PTR",
        "qtype_name(12) returns 'PTR'"
    ),
    "CcspTandD_DnsMonitor_Test.QtypeName_MX": (
        "Verify QTYPE 15 (MX record)",
        "qtype_name(15) returns 'MX'"
    ),
    "CcspTandD_DnsMonitor_Test.QtypeName_CNAME": (
        "Verify QTYPE 5 (CNAME record)",
        "qtype_name(5) returns 'CNAME'"
    ),
    "CcspTandD_DnsMonitor_Test.QtypeName_OTHER": (
        "Verify unknown QTYPE returns 'OTHER'",
        "qtype_name(99) returns 'OTHER'"
    ),
    # --- 3. parse_qname() ---
    "CcspTandD_DnsMonitor_Test.ParseQname_GoogleCom": (
        "Parse wire-format DNS name for 'www.google.com' — queried on XB8, latency_ms=14",
        "parse_qname() returns 'www.google.com'"
    ),
    "CcspTandD_DnsMonitor_Test.ParseQname_XfinityTime": (
        "Parse 'global-time.xfinity.com' — NTP time sync query seen on XB8",
        "parse_qname() returns 'global-time.xfinity.com'"
    ),
    "CcspTandD_DnsMonitor_Test.ParseQname_RdktelEndpoint": (
        "Parse 'rdktel-oi.stb.r53.xcal.tv' — RDK telemetry endpoint seen on XB8",
        "parse_qname() returns 'rdktel-oi.stb.r53.xcal.tv'"
    ),
    "CcspTandD_DnsMonitor_Test.ParseQname_EmptyPayload": (
        "Parse DNS payload with only a zero-length label (root)",
        "parse_qname() returns '<root>' without crash"
    ),
    "CcspTandD_DnsMonitor_Test.ParseQname_TruncatedPayload": (
        "Parse truncated DNS payload — must not crash or return null",
        "parse_qname() returns non-null pointer"
    ),
    # --- 4. make_hash() ---
    "CcspTandD_DnsMonitor_Test.MakeHash_SameTxidDifferentClients": (
        "txid=0xac9a seen from IPv4 and IPv6 client simultaneously on XB8 "
        "(dual-stack rdktel-oi.stb.r53.xcal.tv query). Hash must differ.",
        "make_hash(IPv4_client, txid) != make_hash(IPv6_client, txid)"
    ),
    "CcspTandD_DnsMonitor_Test.MakeHash_SameClientDifferentTxid": (
        "Same client different txids must produce valid in-bounds hash values",
        "Both hash values < DNS_HASH_BUCKETS (4096)"
    ),
    # --- 5. Pending table ---
    "CcspTandD_DnsMonitor_Test.PendingInsertRemove_BasicRoundtrip": (
        "Insert www.google.com query (txid=0x07ac, server=75.75.75.75) "
        "and remove it — verify all fields preserved",
        "pending_remove() returns entry with correct txid, qname, server_ip, qtype"
    ),
    "CcspTandD_DnsMonitor_Test.PendingRemove_WrongClientReturnsNull": (
        "Remove with wrong client IP must not find the entry "
        "(prevents cross-client false match)",
        "pending_remove() returns nullptr for mismatched client"
    ),
    "CcspTandD_DnsMonitor_Test.PendingDualStack_SameTxidTwoClients": (
        "XB8 dual-stack: txid=0xac9a from IPv4 client (75.75.75.75) and "
        "IPv6 client (2001:558:feed::1) must coexist without collision",
        "Both entries independently removable; g_pending_count reaches 0"
    ),
    "CcspTandD_DnsMonitor_Test.PendingExpire_TimedOutEntries": (
        "Two queries older than timeout_sec=5 must both be expired",
        "pending_expire() returns 2; g_pending_count=0"
    ),
    "CcspTandD_DnsMonitor_Test.PendingExpire_OnlyOldEntries": (
        "Only entries older than timeout are expired; newer ones survive",
        "pending_expire() returns 1; g_pending_count=1 (new entry remains)"
    ),
    # --- 6. Stats accumulation ---
    "CcspTandD_DnsMonitor_Test.Stats_LatencyAccumulation_MatchXB8Average": (
        "Accumulate 47 latency values from XB8 range (8–88ms). "
        "Average must fall in observed range 18–35ms. Max must be 88ms.",
        "success_count=47, max_latency_ms=88, avg in [18,35]"
    ),
    "CcspTandD_DnsMonitor_Test.Stats_NxdomainCount_MatchXB8": (
        "Simulate 44 NXDOMAIN failures (matching XB8 first interval). "
        "Verify breakdown: nxdomain=44, servfail=0, timeout=0",
        "fail_total=44, nxdomain=44, servfail=0, timeout=0"
    ),
    "CcspTandD_DnsMonitor_Test.Stats_QueryCount_MatchXB8Summary": (
        "Verify queries=91, success=47, fail=44 consistency: "
        "success + fail_total must equal query_count",
        "query_count == success_count + fail_total (91 = 47 + 44)"
    ),
    "CcspTandD_DnsMonitor_Test.Stats_SecondInterval_CleanSummary": (
        "Second XB8 interval: queries=8 success=6 nxdomain=2 avg=18ms max=30ms slow=0 timeout=0",
        "avg_ms=18, max_ms=30, fail_total=2, slow_count=0"
    ),
    "CcspTandD_DnsMonitor_Test.Stats_SlowQueryThreshold": (
        "XB8 max=88ms is not slow at threshold=100ms. "
        "Hypothetical 387ms query IS slow.",
        "88ms < 100ms threshold = not slow; 387ms >= 100ms = slow"
    ),
    "CcspTandD_DnsMonitor_Test.Stats_NoSuccessAvoidsDivisionByZero": (
        "When success_count=0, average computation must return 0 not crash",
        "avg_ms = 0 when success_count = 0"
    ),
    # --- 7. Server failure tracking ---
    "CcspTandD_DnsMonitor_Test.ServerFail_TrackComcastDnsServers": (
        "XB8 server_fails=[75.75.76.76:2,75.75.75.75:42]. "
        "Verify correct per-server failure counts.",
        "g_servers[0].ip='75.75.75.75' fail=42; g_servers[1].ip='75.75.76.76' fail=2"
    ),
    "CcspTandD_DnsMonitor_Test.ServerFail_IncrementExistingEntry": (
        "Multiple failures on same server must increment existing entry, "
        "not create duplicates",
        "g_server_count=1 after 3 failures on same IP; fail_count=3"
    ),
    "CcspTandD_DnsMonitor_Test.ServerFail_IPv6DnsServer": (
        "XB8 IPv6 DNS servers 2001:558:feed::1 and ::2 tracked separately",
        "g_server_count=2; feed::1 fail=2; feed::2 fail=1"
    ),
    "CcspTandD_DnsMonitor_Test.ServerFail_MaxTrackerNotExceeded": (
        "Inserting more than MAX_SERVER_TRACK (8) unique servers must not overflow",
        "g_server_count <= MAX_SERVER_TRACK (8)"
    ),
    # --- 8. iso_ts() ---
    "CcspTandD_DnsMonitor_Test.IsoTs_FormatMatchesXB8Output": (
        "Verify timestamp format matches XB8 output: 2026-07-16T04:50:18.999Z "
        "(UTC, 24 chars, 'T' at pos 10, 'Z' at pos 23)",
        "strlen=24, result[10]='T', result[23]='Z', starts with '2026'"
    ),
    "CcspTandD_DnsMonitor_Test.IsoTs_MillisecondPrecision": (
        "tv_usec=27000 → '027' ms digits; tv_usec=999000 → '999' ms digits",
        "Correct 3-digit millisecond field in both cases"
    ),
    # --- 9. Latency calculation ---
    "CcspTandD_DnsMonitor_Test.LatencyCalc_TypicalXB8Response": (
        "www.google.com: query at .773s, response at .788s → 14ms "
        "(exact value from XB8 log)",
        "latency_ms = 14"
    ),
    "CcspTandD_DnsMonitor_Test.LatencyCalc_FastestXB8Response": (
        "rdktel-oi.stb.r53.xcal.tv on 75.75.76.76: 8ms "
        "(fastest response seen on XB8 dual-stack)",
        "latency_ms = 8"
    ),
    "CcspTandD_DnsMonitor_Test.LatencyCalc_CrossSecondBoundary": (
        "Query at .999s, response at next second .027s → 28ms",
        "latency_ms = 28"
    ),
    "CcspTandD_DnsMonitor_Test.LatencyCalc_NegativeGuard": (
        "If clock gives negative delta (anomaly), clamp to 0",
        "latency_ms = 0 when raw delta is -5"
    ),
    # --- 10. PTR NXDOMAIN ---
    "CcspTandD_DnsMonitor_Test.PtrLookup_NxdomainNotTimeout": (
        "IPv6 PTR lookup NXDOMAIN classified as nxdomain counter "
        "(not timeout), qtype=PTR confirmed",
        "g_stats.nxdomain=1, g_stats.timeout=0"
    ),
    "CcspTandD_DnsMonitor_Test.PtrLookup_IPv4ReverseNxdomain": (
        "119.154.251.142.in-addr.arpa PTR NXDOMAIN — exact entry from XB8 log. "
        "Verify qname and qtype are preserved.",
        "e->qname='119.154.251.142.in-addr.arpa', e->qtype=12 (PTR)"
    ),
}

SUBJECT_MAP = {
    "RcodeName":       "1. RCODE Name Mapping",
    "QtypeName":       "2. QTYPE Name Mapping",
    "ParseQname":      "3. DNS Wire-Format Name Parsing",
    "MakeHash":        "4. Hash Key Collision Avoidance",
    "Pending":         "5. Pending Query Table",
    "Stats":           "6. Statistics Accumulation",
    "ServerFail":      "7. Per-Server Failure Tracking",
    "IsoTs":           "8. ISO-8601 Timestamp Format",
    "LatencyCalc":     "9. Latency Calculation",
    "PtrLookup":       "10. PTR Reverse Lookup Classification",
}

def get_subject(test_name: str) -> str:
    for prefix, label in SUBJECT_MAP.items():
        if test_name.startswith(prefix):
            return label
    return "General"

def parse_xml(xml_path: str):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    results = []
    tid = 1
    for suite in root.iter("testsuite"):
        suite_name = suite.get("name", "")
        for tc in suite.iter("testcase"):
            tc_name   = tc.get("name", "")
            full_name = f"{suite_name}.{tc_name}"
            duration  = float(tc.get("time", "0")) * 1000  # ms
            failure   = tc.find("failure")
            status    = "FAIL" if failure is not None else "PASS"
            actual    = failure.get("message", "").split("\n")[0] if failure else "As expected"
            meta      = TEST_METADATA.get(full_name,
                          (tc_name.replace("_", " "), "See test code"))
            results.append({
                "id":       f"TC-{tid:03d}",
                "suite":    suite_name,
                "name":     tc_name,
                "subject":  get_subject(tc_name),
                "scenario": meta[0],
                "expected": meta[1],
                "actual":   actual,
                "status":   status,
                "duration": f"{duration:.1f} ms",
            })
            tid += 1
    return results

def generate_html(results, out_path: str, xml_path: str):
    total  = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = total - passed
    rate   = (passed / total * 100) if total else 0
    ts     = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    rows = ""
    for r in results:
        status_cell = (
            '<td class="pass">&#10003; PASS</td>' if r["status"] == "PASS"
            else f'<td class="fail">&#10007; FAIL</td>'
        )
        actual_cell = (
            f'<td class="actual-ok">{r["actual"]}</td>' if r["status"] == "PASS"
            else f'<td class="actual-fail">{r["actual"]}</td>'
        )
        rows += f"""
        <tr>
            <td class="tid">{r['id']}</td>
            <td class="subject">{r['subject']}</td>
            <td>{r['scenario']}</td>
            <td class="expected">{r['expected']}</td>
            {actual_cell}
            {status_cell}
            <td class="dur">{r['duration']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DnsMonitor Unit Test Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #333; }}
  .header {{ background: linear-gradient(135deg, #1a3a5c, #2d6a9f); color: white;
             padding: 24px 32px; }}
  .header h1 {{ font-size: 22px; font-weight: 600; }}
  .header p  {{ font-size: 13px; opacity: 0.8; margin-top: 4px; }}
  .summary {{ display: flex; gap: 16px; padding: 20px 32px;
              flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 18px 24px;
           min-width: 140px; text-align: center;
           box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  .card .num {{ font-size: 32px; font-weight: 700; }}
  .card .lbl {{ font-size: 12px; color: #777; margin-top: 4px; text-transform: uppercase; }}
  .card.total  .num {{ color: #1a3a5c; }}
  .card.passed .num {{ color: #27ae60; }}
  .card.failed .num {{ color: #e74c3c; }}
  .card.rate   .num {{ color: #f39c12; }}
  .meta {{ padding: 0 32px 8px; font-size: 12px; color: #666; }}
  .table-wrap {{ padding: 0 32px 32px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; background: white;
           border-radius: 8px; overflow: hidden;
           box-shadow: 0 2px 8px rgba(0,0,0,0.08); font-size: 13px; }}
  thead tr {{ background: #1a3a5c; color: white; }}
  thead th {{ padding: 12px 14px; text-align: left; font-weight: 600;
              white-space: nowrap; }}
  tbody tr:nth-child(even) {{ background: #f8fafc; }}
  tbody tr:hover {{ background: #eaf3ff; }}
  td {{ padding: 10px 14px; vertical-align: top; border-bottom: 1px solid #e8ecf0; }}
  .tid      {{ font-family: monospace; font-weight: 600; color: #555; white-space: nowrap; }}
  .subject  {{ font-weight: 600; color: #1a3a5c; white-space: nowrap; }}
  .expected {{ color: #2c3e50; font-size: 12px; }}
  .actual-ok   {{ color: #27ae60; font-size: 12px; }}
  .actual-fail {{ color: #e74c3c; font-size: 12px; font-weight: 600; }}
  .pass {{ color: #27ae60; font-weight: 700; white-space: nowrap; }}
  .fail {{ color: #e74c3c; font-weight: 700; white-space: nowrap; }}
  .dur  {{ color: #888; font-size: 12px; white-space: nowrap; text-align: right; }}
  .legend {{ padding: 8px 32px 16px; font-size: 12px; color: #888; }}
</style>
</head>
<body>

<div class="header">
  <h1>DnsMonitor Unit Test Report</h1>
  <p>Component: TestAndDiagnostic &rarr; LatencyMeasurement &rarr; DnsMonitor &nbsp;|&nbsp;
     Device: Technicolor XB8 (CGM4981COM) &nbsp;|&nbsp;
     Generated: {ts}</p>
</div>

<div class="summary">
  <div class="card total" ><div class="num">{total}</div> <div class="lbl">Total</div></div>
  <div class="card passed"><div class="num">{passed}</div><div class="lbl">Passed</div></div>
  <div class="card failed"><div class="num">{failed}</div><div class="lbl">Failed</div></div>
  <div class="card rate"  ><div class="num">{rate:.0f}%</div><div class="lbl">Pass Rate</div></div>
</div>

<div class="meta">Source XML: {xml_path}</div>

<div class="table-wrap">
<table>
  <thead>
    <tr>
      <th>Test ID</th>
      <th>Subject</th>
      <th>Test Scenario</th>
      <th>Expected Behaviour</th>
      <th>Actual Result</th>
      <th>Status</th>
      <th>Duration</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
</div>

<div class="legend">
  Test data derived from actual XB8 device output (2026-07-16):
  queries=91 &nbsp;|&nbsp; success=47 &nbsp;|&nbsp; nxdomain=44 &nbsp;|&nbsp;
  avg_ms=25 &nbsp;|&nbsp; max_ms=88 &nbsp;|&nbsp;
  server_fails=[75.75.76.76:2, 75.75.75.75:42]
</div>

</body>
</html>"""

    with open(out_path, "w") as f:
        f.write(html)

def main():
    ap = argparse.ArgumentParser(description="Generate DnsMonitor HTML test report")
    ap.add_argument("--xml", default="gtest_results.xml",
                    help="Path to GoogleTest XML output file")
    ap.add_argument("--out", default="DnsMonitor_TestReport.html",
                    help="Output HTML file path")
    args = ap.parse_args()

    if not os.path.exists(args.xml):
        print(f"ERROR: XML file not found: {args.xml}")
        print("Run the test binary first with:")
        print("  ./CcspTandD_Dml_Test_gtest.bin "
              "--gtest_filter=CcspTandD_DnsMonitor_Test.* "
              "--gtest_output=xml:gtest_results.xml")
        sys.exit(1)

    results = parse_xml(args.xml)
    generate_html(results, args.out, args.xml)

    total  = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    print(f"Report generated: {args.out}")
    print(f"Results: {passed}/{total} passed")

if __name__ == "__main__":
    main()
