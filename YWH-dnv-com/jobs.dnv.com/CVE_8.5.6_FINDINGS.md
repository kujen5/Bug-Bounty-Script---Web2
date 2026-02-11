# Concrete CMS 8.5.6 CVE Testing Results
**Target:** jobs.dnv.com
**Date:** 2026-02-11
**Tested Version:** < 8.5.6

---

## ✅ Site Configuration

### Confirmed Features
- **Login Form:** cID=156 → `https://jobs.dnv.com/login/authenticate/concrete`
- **Dashboard:** Accessible (redirects to login) → `/index.php/dashboard`
- **Download Files:** cID=163
- **WAF:** Present but bypassable with null byte `%00`

### Disabled/Not Found Features
- ❌ Blog/Conversations (CVE-2021-40106 target)
- ❌ Calendar (CVE-2021-40108 target)
- ❌ File Upload (public-facing)
- ❌ Registration page

---

## 🎯 CVEs Testable Without Authentication

### CVE-2021-40106: Unauthenticated XSS in Blog Comments ❌ NOT TESTABLE
**Status:** ❌ Site does not have blog/conversation feature enabled
**Severity:** Medium
**Description:** Stored XSS via blog comment "website" field
**Why Not Testable:** No conversation endpoints found (all return 404):
```
/index.php/ccm/system/dialogs/conversation/subscribe → 404
/index.php/ccm/system/dialogs/conversation/add_message → 404
/index.php/tools/required/conversations → 404
```

### CVE-2021-40103: Path Traversal & SSRF ⚠️ PARTIALLY TESTABLE
**Status:** ⚠️ Needs authentication to access file import tools
**Severity:** Medium
**Description:** Path traversal to read arbitrary files + SSRF
**Test Results:**
```bash
# File import endpoint (primary target) - requires auth
/index.php/tools/required/files/importers/remote → 404 (blocked)

# Download endpoint - no path traversal vulnerability
/index.php/download_file/view_inline/1?file=../../../../etc/passwd → Returns normal HTML page (not vulnerable)
```

**Action Required:** Test these endpoints AFTER authentication:
- `/index.php/tools/required/files/importers/remote` - POST with `url` parameter
- Try SSRF payloads: `http://169.254.169.254/latest/meta-data/`
- Try path traversal: `../../../../application/config/database.php`

### CVE-2021-40107: XSS via view_inline ⚠️ LIMITED TESTING
**Status:** ⚠️ Requires file upload capability
**Severity:** Medium
**Description:** Filename not sanitized when viewed via view_inline
**Test Method:**
1. Upload file with XSS payload in filename: `test<img src=x onerror=alert(1)>.jpg`
2. Access via: `/index.php/download_file/view_inline/[fID]`
3. Check if filename is reflected unsanitized in response

**Current Finding:** Cannot test without upload access

### CVE-2021-40108: Missing CSRF Token on Calendar ❌ NOT TESTABLE
**Status:** ❌ Calendar feature not enabled
**Severity:** Medium
**Description:** CSRF on `/index.php/ccm/calendar/dialogs/event/add/save`
**Test Results:** All calendar endpoints return 404

### CVE-2021-40100: XSS in Conversations (Rich Text) ❌ NOT TESTABLE
**Status:** ❌ Conversations feature not enabled
**Severity:** High
**Description:** Stored XSS when "Rich Text" editor is enabled for conversations
**Test Results:** No conversation feature found on site

### CVE-2021-40099: Insecure Update Check (HTTP) ⚠️ REQUIRES NETWORK ANALYSIS
**Status:** ⚠️ Requires network traffic monitoring or admin access
**Severity:** High
**Description:** Site fetches update info via HTTP (not HTTPS), allowing MITM attacks
**How to Test:**
1. Monitor outbound traffic from the server
2. Check if requests are made to:
   - `http://www.concrete5.org/tools/required/version/check`
   - `http://www.concretecms.org/api/marketplace/`
3. If HTTP is used → Attacker can inject malicious update packages via MITM

**Action Required:**
- Use network monitoring (if you have server access)
- OR trigger update check via dashboard (requires admin login)

---

## 🔐 Authenticated Testing Required

The following high-value CVEs require authentication to test:

### 1. CVE-2021-40097: Path Traversal to RCE ⚠️ HIGH SEVERITY
**Severity:** High
**Auth:** Yes (authenticated user)
**Description:** Path traversal vulnerability leading to RCE
**Test After Login:**
- External form submissions with path traversal payloads
- File upload with traversal in file path

### 2. CVE-2021-40098: Path Traversal via External Form to RCE ⚠️ HIGH SEVERITY
**Severity:** High
**Auth:** Yes
**Description:** RCE via external form with path traversal
**Test After Login:**
- Create/submit external forms with malicious file paths
- Check `/index.php/dashboard/reports/forms`

### 3. CVE-2021-40102: Arbitrary File Delete via PHAR ⚠️ HIGH SEVERITY
**Severity:** High
**Auth:** Yes
**Description:** PHAR deserialization leading to arbitrary file deletion
**Test After Login:**
- Upload PHAR file with malicious metadata
- Trigger deserialization via file operations

### 4. CVE-2021-36766: PHAR Protocol in Directory Input ⚠️ MEDIUM
**Severity:** Medium
**Auth:** Yes
**Description:** Security issues when `phar://` is allowed in directory fields
**Test After Login:**
- Dashboard → File Manager → Try `phar://` in directory path
- Look for directory input fields in forms

### 5. CVE-2021-40104: SVG Sanitizer Bypass ⚠️ MEDIUM
**Severity:** Medium
**Auth:** Yes (to upload SVG)
**Description:** XSS via malicious SVG file
**Test After Login:**
```xml
<!-- Upload this SVG file -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

### 6. CVE-2021-40105: XSS in Markdown Editor ⚠️ MEDIUM
**Severity:** Medium
**Auth:** Yes
**Description:** XSS in conversation options Markdown Editor
**Test After Login:**
- Enable Markdown editor for conversations
- Inject XSS payload in markdown content

---

## 📋 Recommended Test Plan

### Phase 1: Pre-Authentication Tests ✅ COMPLETED
- [x] WAF bypass confirmed (null byte `%00`)
- [x] Version fingerprinting (8.5.x confirmed)
- [x] Feature enumeration (blog/calendar/conversations not enabled)
- [x] Path traversal attempts (not vulnerable on public endpoints)

### Phase 2: Authentication Required (NEXT STEPS)
To fully test the 8.5.6 CVEs, you need:

1. **Obtain Valid Credentials**
   - Request test account from DNV
   - OR check for user registration functionality
   - OR attempt password reset enumeration

2. **Priority Tests After Login:**
   - ✅ CVE-2021-40097 - Path traversal to RCE (HIGH)
   - ✅ CVE-2021-40098 - External form path traversal (HIGH)
   - ✅ CVE-2021-40102 - PHAR deserialization (HIGH)
   - ⚠️ CVE-2021-40103 - SSRF via file import (MEDIUM)
   - ⚠️ CVE-2021-36766 - PHAR protocol abuse (MEDIUM)
   - ⚠️ CVE-2021-40104 - SVG sanitizer bypass (MEDIUM)

---

## 🎓 Alternative Approach: Create Test Credentials

### Check Registration Page
```bash
# Try to find registration endpoint
curl -s "https://jobs.dnv.com/index.php/register%00"
curl -s "https://jobs.dnv.com/register%00"

# Check if self-registration is enabled
curl -s "https://jobs.dnv.com/index.php?cID=156%00" | grep -i "register\|sign up\|create account"
```

### Forgot Password Enumeration
```bash
# Get token from login page
TOKEN=$(curl -c cookies.txt -s "https://jobs.dnv.com/index.php?cID=156%00" | grep -oP 'name="ccm_token" value="\K[^"]+')

# Test user enumeration
curl -b cookies.txt -X POST "https://jobs.dnv.com/login/concrete/forgot_password" \
  -d "uEmail=admin@dnv.com&ccm_token=$TOKEN" \
  -v
```

### OAuth/SSO Check
```bash
# Check login page for SSO options
curl -s "https://jobs.dnv.com/index.php?cID=156%00" | grep -i -E "(oauth|saml|sso|microsoft|google|linkedin)"
```

---

## 💡 Key Findings Summary

| CVE | Severity | Testable? | Auth Required | Status |
|-----|----------|-----------|---------------|--------|
| CVE-2021-40106 | Medium | ❌ No | No | Feature not enabled |
| CVE-2021-40103 | Medium | ⚠️ Partial | Yes | Needs auth for file import |
| CVE-2021-40107 | Medium | ⚠️ Limited | Yes | Needs upload access |
| CVE-2021-40108 | Medium | ❌ No | No | Feature not enabled |
| CVE-2021-40100 | High | ❌ No | Yes | Feature not enabled |
| CVE-2021-40099 | High | ⚠️ Partial | Indirect | Needs network analysis |
| CVE-2021-40097 | High | ✅ Yes | Yes | **Priority: Auth required** |
| CVE-2021-40098 | High | ✅ Yes | Yes | **Priority: Auth required** |
| CVE-2021-40102 | High | ✅ Yes | Yes | **Priority: Auth required** |
| CVE-2021-36766 | Medium | ✅ Yes | Yes | Testable after auth |
| CVE-2021-40104 | Medium | ✅ Yes | Yes | Testable after auth |
| CVE-2021-40105 | Medium | ✅ Yes | Yes | Testable after auth |

**Conclusion:** Most 8.5.6 CVEs require authentication. Focus on obtaining valid credentials to test the HIGH severity RCE vulnerabilities.

---

## 🔥 Next Steps

1. **Contact DNV:** Request test account for security testing
2. **Check for self-registration:** Search site for "create account" functionality
3. **Alternative:** Focus on previously identified vulnerabilities:
   - WAF bypass (null byte)
   - End-of-life software (no security support)
   - jQuery 1.12.2 CVEs
   - S3 bucket misconfiguration (from to_test.md)

4. **If credentials obtained:** Run authenticated CVE test suite:
```bash
./test_authenticated_cves.sh [username] [password]
```
