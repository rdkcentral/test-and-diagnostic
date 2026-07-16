#!/bin/bash
##########################################################################
# run_dns_monitor_tests.sh
#
# Builds, runs, and generates an HTML report for DnsMonitor unit tests.
#
# Usage:
#   ./run_dns_monitor_tests.sh [--filter <pattern>] [--no-build]
#
# Output:
#   gtest_results.xml          - raw GoogleTest XML
#   DnsMonitor_TestReport.html - human-readable HTML report
##########################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_DIR="${REPO_ROOT}/source/test/CcspTandD_Dml_Test"
REPORT_DIR="${SCRIPT_DIR}"
BINARY="CcspTandD_Dml_Test_gtest.bin"
XML_OUT="${REPORT_DIR}/gtest_results.xml"
HTML_OUT="${REPORT_DIR}/DnsMonitor_TestReport.html"
FILTER="CcspTandD_DnsMonitor_Test.*"
NO_BUILD=0

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --filter)   FILTER="$2"; shift 2 ;;
        --no-build) NO_BUILD=1;  shift   ;;
        *)          echo "Unknown arg: $1"; exit 1 ;;
    esac
done

echo "============================================================"
echo " DnsMonitor Unit Test Runner"
echo " Repository: ${REPO_ROOT}"
echo " Filter:     ${FILTER}"
echo "============================================================"

# ── Step 1: Build ────────────────────────────────────────────────
if [[ ${NO_BUILD} -eq 0 ]]; then
    echo ""
    echo "[1/3] Building test binary..."
    cd "${REPO_ROOT}"
    if [[ ! -f "configure" ]]; then
        echo "  Running autogen.sh..."
        ./autogen.sh
    fi
    if [[ ! -f "Makefile" ]]; then
        echo "  Running configure..."
        ./configure --enable-unit-test
    fi
    make -C "${TEST_DIR}" -j"$(nproc)" 2>&1 | tail -5
    echo "  Build done."
else
    echo "[1/3] Build skipped (--no-build)"
fi

# ── Step 2: Run tests ────────────────────────────────────────────
echo ""
echo "[2/3] Running tests..."
cd "${TEST_DIR}"

if [[ ! -f "${BINARY}" ]]; then
    echo "ERROR: Binary not found: ${TEST_DIR}/${BINARY}"
    echo "  Run without --no-build to compile first."
    exit 1
fi

./"${BINARY}" \
    --gtest_filter="${FILTER}" \
    --gtest_output="xml:${XML_OUT}" \
    --gtest_color=yes \
    2>&1

echo ""
echo "  XML output: ${XML_OUT}"

# ── Step 3: Generate HTML report ────────────────────────────────
echo ""
echo "[3/3] Generating HTML report..."

if ! command -v python3 &>/dev/null; then
    echo "WARNING: python3 not found — skipping HTML report."
    echo "  Install python3 and rerun to get the HTML report."
    exit 0
fi

python3 "${SCRIPT_DIR}/dns_monitor_report.py" \
    --xml  "${XML_OUT}" \
    --out  "${HTML_OUT}"

echo ""
echo "============================================================"
echo " DONE"
echo " HTML Report: ${HTML_OUT}"
echo " Open in browser:"
echo "   xdg-open ${HTML_OUT}"
echo "   firefox  ${HTML_OUT}"
echo "============================================================"
