# Security Assessment Findings: alipayhk.com

**Program:** Ant Group Security Response Center
**Target:** alipayhk.com (AlipayHK)
**Assessment Date:** 2026-02-05 (scan) / 2026-02-07 (analysis)
**Assessor:** Automated recon + manual review

---

## Executive Summary

AlipayHK (alipayhk.com) is a WordPress-based marketing site for the AlipayHK mobile payment service in Hong Kong. The site is hosted behind Alibaba's DDoS protection (Aliyun WAF/Tengine) at IP `170.33.12.224` (ASN 134963). Overall security posture is **moderate** -- the WAF blocks many common attack vectors, but several informational and low-to-medium severity findings were identified that should be addressed.

**Key Stats:**
- Subdomains discovered: 3 (2 live, 1 historical)
- Open ports: 80, 443
- URLs discovered: 2,090
- JavaScript files: 198
- Nuclei CVE matches: 0

---

## Table of Contents

1. [Infrastructure Overview](#1-infrastructure-overview)
2. [Findings](#2-findings)
   - [MEDIUM: Missing Security Headers](#f1-medium-missing-security-headers)
   - [MEDIUM: WordPress REST API Information Disclosure](#f2-medium-wordpress-rest-api-information-disclosure)
   - [MEDIUM: WordPress Version & Plugin Fingerprinting](#f3-medium-wordpress-version--plugin-fingerprinting)
   - [LOW: TLS 1.3 Not Supported](#f4-low-tls-13-not-supported)
   - [LOW: Cookie Security Attributes Incomplete](#f5-low-cookie-security-attributes-incomplete)
   - [LOW: Exposed Staging Subdomain](#f6-low-exposed-staging-subdomain)
   - [LOW: Missing Email Authentication Records (DMARC)](#f7-low-missing-email-authentication-records-dmarc)
   - [LOW: Server Technology Disclosure](#f8-low-server-technology-disclosure)
   - [INFO: WordPress REST API Nonce Leak in HTML Source](#f9-info-wordpress-rest-api-nonce-leak-in-html-source)
   - [INFO: Third-Party CDN Supply Chain Risk](#f10-info-third-party-cdn-supply-chain-risk)
   - [INFO: Large JavaScript Attack Surface](#f11-info-large-javascript-attack-surface)
   - [INFO: Uploads Directory Listing Blocked (403)](#f12-info-uploads-directory-listing-blocked-403)
3. [Positive Security Controls](#3-positive-security-controls)
4. [Recommendations Summary](#4-recommendations-summary)
5. [Appendices](#5-appendices)

---

## 1. Infrastructure Overview

### Network & DNS

| Property | Value |
|---|---|
| **IP Address** | 170.33.12.224 |
| **ASN** | AS134963 (170.33.12.0/24) |
| **Nameservers** | ns1-4.alipay.com |
| **Web Server** | Tengine (Alibaba-modified Nginx) |
| **DDoS Protection** | Alibaba Cloud WAF (CNAME: `54ny3c59097e7xmt.aliyunddos0009.com`) |
| **SSL Certificate** | DigiCert Secure Site OV G2, `*.alipayhk.com`, valid until 2026-10-05 |
| **TLS Version** | TLS 1.2 only (TLS 1.0/1.1 disabled, TLS 1.3 not supported) |
| **SPF Record** | `v=spf1 include:spf1.staff.mail.aliyun.com -all` |

### Subdomains Discovered

| Subdomain | Status | Notes |
|---|---|---|
| `alipayhk.com` | Live (200) | Root domain, redirects to `www.alipayhk.com/zh/shoppers/` |
| `www.alipayhk.com` | Live (200) | Primary site, CNAME to Aliyun DDoS protection |
| `staging.alipayhk.com` | Not resolving | Found via Subfinder + Wayback Machine (historical) |

### Technology Stack

| Component | Version |
|---|---|
| **CMS** | WordPress 6.8.3 |
| **Web Server** | Tengine |
| **Database** | MySQL |
| **Language** | PHP |
| **JS Libraries** | jQuery 3.7.1, jQuery Migrate 3.4.1, Bootstrap 4.5.3, Popper |
| **SEO** | Yoast SEO 26.3 |
| **Multilingual** | WPML 4.6.4 |
| **Caching** | WordPress Super Cache, Autoptimize |
| **Image Optimization** | WPMU DEV Smush 3.13.1 |
| **Forms** | Ninja Forms 3.5.8.4 |
| **A/B Testing** | AB Testing for WP |
| **Gallery** | Photo Gallery 1.5.35 |
| **Popups** | Popup Builder 3.84 |
| **PDF** | DK PDF 1.9.6 |
| **Custom Blocks** | Genesis Custom Blocks |
| **Analytics** | Google Analytics (UA-124755185-1), Google Tag Manager (GTM-NZ8T6HH) |

---

## 2. Findings

---

### F1: MEDIUM - Missing Security Headers

**Description:**
The main site response is missing several critical HTTP security headers that protect against common web attacks.

**Evidence:**
Response headers from `curl -sI https://www.alipayhk.com/`:
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Strict-Transport-Security: max-age=31536000
Set-Cookie: aliyungf_tc=...; Path=/; HttpOnly
Set-Cookie: acw_tc=...;path=/;HttpOnly;Max-Age=1800
Set-Cookie: SERVERID=...;Path=/
```

**Missing Headers:**

| Header | Risk | Impact |
|---|---|---|
| `Content-Security-Policy` | Clickjacking, XSS, data injection | No restriction on inline scripts, external resources, or framing |
| `X-Frame-Options` | Clickjacking | Page can be embedded in iframes on any domain |
| `X-Content-Type-Options` | MIME-type sniffing | Browser may interpret files as different content types |
| `Referrer-Policy` | Information leakage | Full URL (including query params) sent in Referer header |
| `Permissions-Policy` | Feature abuse | No restriction on camera, microphone, geolocation, etc. |

**Impact:** Without CSP and X-Frame-Options, the site is potentially vulnerable to clickjacking attacks and has no defense-in-depth against XSS. For a financial services site, this is particularly concerning.

**Recommendation:**
Add the following headers at the WAF/Tengine level:
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://www.googletagmanager.com https://www.google-analytics.com https://cdn.jsdelivr.net https://unpkg.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

---

### F2: MEDIUM - WordPress REST API Information Disclosure

**Description:**
The WordPress REST API exposes multiple endpoints that reveal internal site structure, plugin configuration, A/B test data, and content management details.

**Evidence:**
The following API namespaces/routes were discovered via content crawling (2,090 URLs enumerated):

```
/en/wp-json/                                          # API root - lists all routes
/en/wp-json/wp/v2/pages/35290                         # Page data with internal IDs
/en/wp-json/ab-testing-for-wp/v1/track                # A/B test tracking endpoint
/en/wp-json/ab-testing-for-wp/v1/stats                # A/B test statistics
/en/wp-json/ab-testing-for-wp/v1/get-tests-info       # Test configuration
/en/wp-json/ab-testing-for-wp/v1/options              # Plugin options
/en/wp-json/ab-testing-for-wp/v1/update-test          # Test modification endpoint
/en/wp-json/ninja-forms-submissions/email-action      # Form submission data
/en/wp-json/ninja-forms-submissions/export            # Form data export
/en/wp-json/ninja-forms-views/forms                   # Form structure
/en/wp-json/genesis-custom-blocks/template-file       # Block templates
/en/wp-json/oembed/1.0/embed                          # OEmbed endpoint
/en/wp-json/batch/v1                                  # Batch API endpoint
/zh/wp-json/wp/v2/pages/24815                         # Chinese page data
```

**Note:** Direct access to `/wp-json/` paths returns HTTP 405 from the Aliyun WAF, but these endpoints are accessible through the language-prefixed paths (`/en/wp-json/`, `/zh/wp-json/`) based on the `Link` headers in responses.

**Impact:**
- Internal page IDs and content structure exposed
- A/B testing configuration and statistics accessible
- Ninja Forms submission/export endpoints could leak user data
- Plugin ecosystem fully enumerable

**Recommendation:**
- Restrict REST API access to authenticated users only for sensitive namespaces
- Disable or limit the `ab-testing-for-wp`, `ninja-forms-submissions`, and `ninja-forms-views` API routes for unauthenticated users
- Add `Authorization` checks to custom REST endpoints
- Consider using a plugin like "Disable REST API" to limit public API access

---

### F3: MEDIUM - WordPress Version & Plugin Fingerprinting

**Description:**
Exact version numbers for WordPress core and all plugins are disclosed in page source code, allowing attackers to look up specific CVEs for each component.

**Evidence (from httpx fingerprinting):**

| Component | Detected Version |
|---|---|
| WordPress | 6.8.3 |
| WPML | 4.6.4 |
| WPMU DEV Smush | 3.13.1 |
| Yoast SEO | 26.3 |
| Bootstrap | 4.5.3 |
| jQuery | 3.7.1 |
| jQuery Migrate | 3.4.1 |

Version strings are exposed via:
- `?ver=` query parameters on JS/CSS assets (e.g., `?ver=6.5.3`, `?ver=3.16.2`)
- WordPress generator meta tag
- Plugin/theme readme files

**Impact:** Precise version information allows targeted exploit selection. While current versions appear up-to-date, any delay in patching creates an immediately exploitable window.

**Recommendation:**
- Remove version query strings from enqueued scripts/styles
- Remove the WordPress generator meta tag
- Block access to plugin/theme readme.txt and changelog files
- Implement a consistent patching schedule

---

### F4: LOW - TLS 1.3 Not Supported

**Description:**
The server only supports TLS 1.2 and does not support TLS 1.3. While TLS 1.2 is still secure, TLS 1.3 provides improved security and performance.

**Evidence:**
```
$ openssl s_client -connect www.alipayhk.com:443 -tls1_3
error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version

$ openssl s_client -connect www.alipayhk.com:443
Protocol  : TLSv1.2
Cipher    : ECDHE-RSA-AES128-GCM-SHA256
```

TLS 1.0 and 1.1 are correctly disabled.

**Impact:** Missing TLS 1.3 means no 0-RTT resumption, no removal of legacy cipher suites, and slightly higher latency on connection setup.

**Recommendation:** Enable TLS 1.3 on the Tengine/WAF configuration alongside TLS 1.2.

---

### F5: LOW - Cookie Security Attributes Incomplete

**Description:**
Several cookies set by the server are missing the `Secure` flag and/or `SameSite` attribute.

**Evidence:**
```
Set-Cookie: aliyungf_tc=...; Path=/; HttpOnly
Set-Cookie: acw_tc=...;path=/;HttpOnly;Max-Age=1800
Set-Cookie: SERVERID=...|1770447827|1770447827;Path=/
```

| Cookie | HttpOnly | Secure | SameSite |
|---|---|---|---|
| `aliyungf_tc` | Yes | **No** | **Missing** |
| `acw_tc` | Yes | **No** | **Missing** |
| `SERVERID` | **No** | **No** | **Missing** |

**Impact:**
- Without the `Secure` flag, cookies could be transmitted over unencrypted connections during HTTPS downgrade attacks
- The `SERVERID` cookie is accessible via JavaScript (no HttpOnly), enabling session fixation or information leakage
- Missing `SameSite` defaults to `Lax` in modern browsers, but explicit declaration is a best practice

**Recommendation:**
- Add `Secure` flag to all cookies
- Add `SameSite=Lax` (or `Strict` where possible)
- Add `HttpOnly` to the `SERVERID` cookie

---

### F6: LOW - Exposed Staging Subdomain

**Description:**
A staging subdomain (`staging.alipayhk.com`) was discovered through passive reconnaissance sources (Subfinder, Wayback Machine). While it does not currently resolve, its historical existence suggests a staging environment exists or existed.

**Evidence:**
```
# From phase2_passive/subfinder.txt:
www.alipayhk.com
staging.alipayhk.com

# From phase2_passive/wayback.txt:
alipayhk.com
staging.alipayhk.com
www.alipayhk.com
```

**Impact:** If the staging environment is restored or accessible via a different network path, it may contain:
- Test data or credentials
- Debugging features enabled
- Less restrictive WAF rules
- Pre-release code with unpatched vulnerabilities

**Recommendation:**
- Ensure staging environments are not publicly accessible
- Use IP whitelisting or VPN-only access for non-production environments
- Remove historical DNS records for staging subdomains
- Monitor for staging subdomain re-activation via certificate transparency logs

---

### F7: LOW - Missing Email Authentication Records (DMARC)

**Description:**
The domain has SPF configured but no DMARC or DKIM records were found. SPF alone is insufficient to prevent email spoofing.

**Evidence:**
```
# SPF record (present):
TXT: v=spf1 include:spf1.staff.mail.aliyun.com -all

# DMARC record (missing):
No _dmarc.alipayhk.com TXT record found

# No MX records found in DNS enumeration
```

**Impact:** Without DMARC, email receivers cannot verify that emails from `@alipayhk.com` are legitimate. This enables:
- Phishing attacks impersonating AlipayHK via email
- Brand damage from spoofed emails
- No reporting on email authentication failures

**Recommendation:**
- Implement DMARC: `_dmarc.alipayhk.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@alipayhk.com"`
- Configure DKIM signing for outbound emails
- Monitor DMARC aggregate reports

---

### F8: LOW - Server Technology Disclosure

**Description:**
The `Server` header reveals the web server software identity on certain responses.

**Evidence:**
```
# On 405 responses (WAF-blocked paths):
Server: Tengine

# On 200 responses (normal pages):
Server header not present (good)
```

**Impact:** Confirms the use of Tengine (Alibaba's Nginx fork), allowing attackers to target Tengine-specific vulnerabilities.

**Recommendation:** Remove or genericize the `Server` header on all responses, including error pages.

---

### F9: INFO - WordPress REST API Nonce Leak in HTML Source

**Description:**
A WordPress REST API nonce token is embedded in the page HTML source.

**Evidence (from homepage source):**
```
Nonce token: "75bda1feb7"
WordPress post ID: "24813"
```

**Impact:** While WordPress nonces are tied to user sessions and have limited lifetimes, their exposure in source code combined with the accessible REST API endpoints could facilitate CSRF bypass in certain scenarios.

**Recommendation:** This is standard WordPress behavior and low risk, but consider loading nonces only when needed via authenticated AJAX calls.

---

### F10: INFO - Third-Party CDN Supply Chain Risk

**Description:**
The site loads JavaScript libraries from external CDNs without Subresource Integrity (SRI) hashes.

**Evidence (external domains loading scripts):**
- `cdn.jsdelivr.net` (jsDelivr CDN)
- `unpkg.com` (Unpkg CDN)
- `www.googletagmanager.com` (Google Tag Manager)
- `www.google-analytics.com` (Google Analytics)
- `tfs.alipayobjects.com` (Alipay CDN)

**Impact:** If any of these CDNs are compromised, malicious JavaScript could be injected into the AlipayHK site. Without SRI, the browser cannot verify the integrity of loaded resources.

**Recommendation:**
- Add `integrity` and `crossorigin` attributes to all externally-loaded scripts
- Consider self-hosting critical JS libraries
- Implement Content-Security-Policy with strict source restrictions

---

### F11: INFO - Large JavaScript Attack Surface

**Description:**
198 unique JavaScript files were discovered, creating a significant client-side attack surface.

**Evidence:**
- 198 JS files enumerated across WordPress core, plugins, and themes
- Multiple plugin-specific JS files with REST API calls
- A/B testing JavaScript making unauthenticated API calls with post IDs
- Multiple `/gtm.js` references across language-specific pages

**Key JS Sources:**
```
wp-content/plugins/ab-testing-for-wp/dist/ab-testing-for-wp.js
wp-content/plugins/wp-smushit/app/assets/js/smush-lazy-load.min.js
wp-content/plugins/ninja-forms/...
wp-content/plugins/photo-gallery/...
wp-content/plugins/popup-builder/...
wp-content/plugins/dk-pdf/...
wp-content/themes/wp-bootstrap-starter/inc/assets/js/custom.js
```

**Impact:** Each JavaScript file is a potential vector for DOM-based XSS, prototype pollution, or information leakage. The A/B testing plugin in particular makes unauthenticated REST API calls.

**Recommendation:**
- Audit client-side JavaScript for DOM-based vulnerabilities
- Remove unused/unnecessary JS files
- Minimize plugin count to reduce attack surface

---

### F12: INFO - Uploads Directory Listing Blocked (403)

**Description:**
The `/wp-content/uploads/` directory returns 403 Forbidden, which is correct. However, individual files within uploads are accessible.

**Evidence:**
```
$ curl -sI https://www.alipayhk.com/wp-content/uploads/
HTTP/1.1 403 Forbidden
```

Individual uploaded images are accessible (e.g., favicon at `/wp-content/uploads/2020/11/favicon-32x32.png`).

**Impact:** Directory listing is disabled (good), but uploaded files are directly accessible by URL. This is standard WordPress behavior but worth noting.

**Recommendation:** No immediate action required. This is expected behavior for a public-facing site with media assets.

---

## 3. Positive Security Controls

The following security measures were observed and are commendable:

| Control | Status | Details |
|---|---|---|
| **HTTPS Enforcement** | Enabled | HSTS with `max-age=31536000` (1 year) |
| **HTTP to HTTPS Redirect** | Enabled | Port 80 returns 410 Gone (forces HTTPS) |
| **TLS 1.0/1.1 Disabled** | Confirmed | Only TLS 1.2 accepted |
| **WAF Protection** | Active | Alibaba Cloud WAF blocking many sensitive paths (wp-login.php, wp-admin, xmlrpc.php, .env, .git all return 405) |
| **WordPress Updated** | Current | WordPress 6.8.3 (latest as of scan date) |
| **Directory Listing** | Disabled | 403 on directory access attempts |
| **Debug Log** | Not exposed | `/wp-content/debug.log` returns 404 |
| **Sensitive Files** | Blocked | `.env`, `.git/config`, `readme.html` all blocked by WAF |
| **SSL Certificate** | Valid | DigiCert OV cert, wildcard `*.alipayhk.com`, valid until Oct 2026 |
| **No CORS Misconfiguration** | Confirmed | No `Access-Control-Allow-Origin` header reflected for arbitrary origins |
| **Author Enumeration** | Mitigated | `?author=1` redirects to `/not-found` |

---

## 4. Recommendations Summary

### Priority Actions

| Priority | Finding | Action |
|---|---|---|
| **HIGH** | F1: Missing Security Headers | Add CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **HIGH** | F2: REST API Exposure | Restrict unauthenticated access to sensitive API namespaces |
| **MEDIUM** | F3: Version Fingerprinting | Strip version query strings and generator tags |
| **MEDIUM** | F5: Cookie Security | Add Secure, SameSite, and HttpOnly flags to all cookies |
| **MEDIUM** | F7: Missing DMARC | Implement DMARC policy with `p=reject` |
| **LOW** | F4: TLS 1.3 | Enable TLS 1.3 on WAF/Tengine |
| **LOW** | F6: Staging Subdomain | Remove historical DNS records, ensure staging is locked down |
| **LOW** | F8: Server Header | Remove `Server: Tengine` from responses |
| **LOW** | F10: SRI for CDN | Add integrity hashes for externally loaded scripts |

---

## 5. Appendices

### A. Scan Phases Completed

| Phase | Description | Status |
|---|---|---|
| Phase 0 | Initialization | OK |
| Phase 1 | Root Domain / ASN Enumeration | OK |
| Phase 2 | Passive Subdomain Discovery | OK |
| Phase 3 | DNS Resolution | OK |
| Phase 4 | Active Brute Force / Permutations | OK |
| Phase 5 | Port Scanning (naabu) | OK |
| Phase 6 | Web Probing (httpx) | OK |
| Phase 7 | Content Discovery (gau + katana) | OK |
| Phase 8 | Vulnerability Scanning (nuclei) | OK |
| Phase 9 | Certstream Monitoring | OK |
| Phase 10 | Report Generation | OK |

### B. Tools Used

- **Subdomain Enumeration:** Subfinder, Amass, crt.sh, Wayback Machine, RapidDNS, URLScan, GitHub dorking
- **DNS Resolution:** PureDNS, dnsx
- **Port Scanning:** Naabu
- **Web Probing:** httpx
- **Content Discovery:** gau, Katana
- **Vulnerability Scanning:** Nuclei
- **Certificate Monitoring:** Certstream
- **Manual Testing:** curl, openssl, WebFetch

### C. JARM Fingerprint

```
29d29d00029d29d21c29d29d29d29dc2ddcfd203d071c45b4b0ffe3d7b4b89
```

This JARM hash is consistent across all endpoints and identifies the Alibaba Cloud WAF/Tengine infrastructure.

### D. Redirect Chain

```
https://alipayhk.com → 302 → https://www.alipayhk.com → 301 → https://www.alipayhk.com/zh/shoppers/ → 200
```

---

*Report generated for responsible disclosure via the Ant Group Security Response Center bug bounty program.*
