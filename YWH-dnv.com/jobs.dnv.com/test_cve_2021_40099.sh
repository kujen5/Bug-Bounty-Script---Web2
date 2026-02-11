#!/bin/bash
# CVE-2021-40099: RCE via insecure update check (HTTP vs HTTPS)
# Severity: High
# Affected: < 8.5.6

echo "=== CVE-2021-40099: Testing Insecure Update Mechanism ==="

echo -e "\n[1] Checking if update endpoint is accessible..."
curl -s "https://jobs.dnv.com/index.php/ccm/system/update%00" -v

echo -e "\n[2] Checking for update check requests..."
# Monitor network traffic to see if site makes HTTP requests to:
# http://www.concrete5.org/tools/required/version/check
# This would require MITM or traffic analysis

echo -e "\n[3] Checking dashboard update page..."
curl -s "https://jobs.dnv.com/index.php/dashboard/system/update%00" -v

echo -e "\n[*] This CVE requires:"
echo "    1. Admin access to trigger update check, OR"
echo "    2. Network position to intercept HTTP traffic"
echo "    3. If site makes HTTP requests to concrete5.org for updates,"
echo "       an attacker could MITM and inject malicious update package"
echo ""
echo "    DETECTION: Check if outbound HTTP requests are made to:"
echo "    - http://www.concrete5.org/tools/required/version/check"
echo "    - http://www.concretecms.org/api/marketplace/"
