#!/bin/bash
# Master script to run all CVE tests for jobs.dnv.com
# Concrete CMS 8.5.6 vulnerabilities (unauthenticated tests only)

echo "=========================================="
echo "  Concrete CMS 8.5.6 CVE Test Suite"
echo "  Target: jobs.dnv.com"
echo "  Testing unauthenticated vulnerabilities"
echo "=========================================="
echo ""

# Make all test scripts executable
chmod +x test_cve_*.sh

# Priority order: Most likely to succeed without auth
echo "[1/6] Testing CVE-2021-40106 (Unauth XSS in Blog Comments)..."
./test_cve_2021_40106.sh 2>&1 | tee results_cve_2021_40106.txt
echo ""

echo "[2/6] Testing CVE-2021-40103 (Path Traversal & SSRF)..."
./test_cve_2021_40103.sh 2>&1 | tee results_cve_2021_40103.txt
echo ""

echo "[3/6] Testing CVE-2021-40107 (XSS via view_inline)..."
./test_cve_2021_40107.sh 2>&1 | tee results_cve_2021_40107.txt
echo ""

echo "[4/6] Testing CVE-2021-40100 (XSS in Conversations)..."
./test_cve_2021_40100.sh 2>&1 | tee results_cve_2021_40100.txt
echo ""

echo "[5/6] Testing CVE-2021-40108 (CSRF on Calendar)..."
./test_cve_2021_40108.sh 2>&1 | tee results_cve_2021_40108.txt
echo ""

echo "[6/6] Testing CVE-2021-40099 (Insecure Update Check)..."
./test_cve_2021_40099.sh 2>&1 | tee results_cve_2021_40099.txt
echo ""

echo "=========================================="
echo "  Test Complete!"
echo "=========================================="
echo "Results saved to: results_cve_*.txt"
echo ""
echo "SUMMARY OF TESTABLE CVEs:"
echo "  ✓ CVE-2021-40106 - Unauth XSS in blog comments (BEST CANDIDATE)"
echo "  ✓ CVE-2021-40103 - Path traversal & SSRF"
echo "  ✓ CVE-2021-40107 - XSS via file view_inline"
echo "  ~ CVE-2021-40100 - XSS in conversations (may need auth)"
echo "  ~ CVE-2021-40108 - CSRF calendar event (needs calendar enabled)"
echo "  ~ CVE-2021-40099 - Update mechanism (needs network analysis)"
echo ""
echo "Review results files for findings!"
