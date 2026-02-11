# 🚀 QUICK START - Brute Force Testing

## ⚡ Fast Setup (60 seconds)

```bash
# 1. Install dependencies
pip3 install requests colorama

# 2. Run the test
python3 bruteforce_login.py \
  -t https://jobs.dnv.com \
  -u sample_users.txt \
  -p sample_passwords.txt \
  -d 3
```

## 📊 What You'll See

```
======================================================================
  Concrete5 Authentication Testing Tool
  Target: https://jobs.dnv.com
  Delay: 3s between requests
======================================================================

[*] Loading wordlists...
[*] Loaded 19 usernames and 19 passwords
[*] Total combinations: 361
[*] Estimated time: 18.1 minutes

Continue? (y/n): y

[*] Starting brute force...

[+] CSRF Token obtained: 1770782899:2aada82526...
[1/361] Testing: admin:password ✗ Failed
[2/361] Testing: admin:Password1 ✗ Failed
[3/361] Testing: admin:admin123 ✓ SUCCESS

======================================================================
[+] SUCCESS! Valid credentials found!
    Username: admin
    Password: admin123
    Status: 302
    Final URL: https://jobs.dnv.com/dashboard
======================================================================
```

## 🎯 What the Script Tests

| Test | Description | Finding |
|------|-------------|---------|
| **Weak Credentials** | Common username/password combos | If found = HIGH severity |
| **Rate Limiting** | Are failed attempts blocked? | If missing = MEDIUM severity |
| **Account Lockout** | Do accounts lock after X attempts? | If missing = MEDIUM severity |
| **CSRF Protection** | Is token validated? | If missing = MEDIUM severity |

## 💰 Bounty Estimates

| Finding | Bounty |
|---------|--------|
| Admin account with weak password | $1,500 - $3,000 |
| Multiple weak accounts | $1,000 - $2,500 |
| No rate limiting | $300 - $1,000 |
| No account lockout | $200 - $800 |

## 🎁 Files Created

```
bruteforce_login.py              - Main script
sample_users.txt                 - Sample usernames (19 entries)
sample_passwords.txt             - Sample passwords (19 entries)
BRUTEFORCE_GUIDE.md             - Complete documentation
QUICK_START.md                  - This file

After running:
bruteforce_results_*.txt        - Log of all attempts
success_USERNAME_*.html         - HTML of successful logins
```

## 🔧 Common Commands

### Basic test (recommended):
```bash
python3 bruteforce_login.py -t https://jobs.dnv.com -u sample_users.txt -p sample_passwords.txt
```

### Slower/stealthier:
```bash
python3 bruteforce_login.py -t https://jobs.dnv.com -u sample_users.txt -p sample_passwords.txt -d 5
```

### With your own wordlists:
```bash
python3 bruteforce_login.py -t https://jobs.dnv.com -u your_users.txt -p your_passwords.txt
```

### Show help:
```bash
python3 bruteforce_login.py --help
```

## 🛡️ Responsible Testing Checklist

Before starting:
- [ ] I have authorization to test this target
- [ ] I'm using small wordlists (< 50 entries)
- [ ] I have delay set to 2+ seconds
- [ ] I understand this is for security testing only

After finding credentials:
- [ ] Stop the script immediately
- [ ] Document the finding
- [ ] Do NOT access user data
- [ ] Report to bug bounty program
- [ ] Do NOT share credentials publicly

## ⚠️ Important Notes

**DO:**
- ✅ Use for authorized bug bounty targets only
- ✅ Start with small wordlists
- ✅ Use delays of 2-5 seconds
- ✅ Stop when credentials found
- ✅ Report findings responsibly

**DON'T:**
- ❌ Test without authorization
- ❌ Use massive wordlists (thousands of passwords)
- ❌ Use delays < 1 second (DoS risk)
- ❌ Access user data after finding credentials
- ❌ Share found credentials publicly

## 📞 Getting Help

**Script errors?**
- Read `BRUTEFORCE_GUIDE.md` troubleshooting section
- Check if site is accessible: `curl -I https://jobs.dnv.com/login`
- Try with higher timeout: `--timeout 30`

**False positives?**
- Check the `success_*.html` file manually
- Verify login actually worked in browser

**Rate limited?**
- Script will auto-pause for 60 seconds
- Increase delay: `-d 5` or `-d 10`

## 🎓 Next Steps

1. **Run the test** with sample wordlists
2. **Check results** in `bruteforce_results_*.txt`
3. **If credentials found:**
   - Take screenshots
   - Document the finding
   - Submit to bug bounty program
4. **If no credentials found:**
   - Good! System is secure
   - Test for rate limiting (it should have kicked in)
   - Report if no rate limiting exists

## 📝 Example Report Template

**If you find weak credentials:**

```
Title: Default Administrator Credentials

Severity: HIGH

Description:
The login panel at https://jobs.dnv.com/login accepts
default credentials for the admin account.

Steps to Reproduce:
1. Go to https://jobs.dnv.com/login
2. Username: admin
3. Password: admin123
4. Click Login
5. Successfully authenticated as administrator

Impact:
- Full administrative access
- Ability to modify job listings
- Potential access to applicant data

Proof:
- Screenshot of admin dashboard
- Log file: bruteforce_results_*.txt

Recommended Fix:
- Force password change for default accounts
- Implement strong password policy
- Add multi-factor authentication

Bounty Request: $2,000 (HIGH severity)
```

## 🏆 Success Metrics

**Good Security (No bugs):**
```
✅ No weak credentials found
✅ Rate limited after 10-20 attempts
✅ Clear error messages
✅ CSRF tokens validated
```

**Bad Security (Report these):**
```
❌ Found: admin:admin123
❌ No rate limiting after 361 attempts
❌ No account lockout
❌ CSRF tokens not validated
```

## 🚨 Emergency Stop

**If something goes wrong:**

1. **Press CTRL+C** - Stops the script immediately
2. **Check results file** - See what was attempted
3. **Wait 5 minutes** - Let rate limits reset
4. **Contact target** - If you accidentally caused issues

**Warning Signs:**
- Site becomes slow/unresponsive = STOP IMMEDIATELY
- Getting HTTP 503 errors = You're causing DoS, STOP
- Script attempts > 1000 = Wordlist too large, STOP

## 📚 Files to Read

1. **START HERE:** `QUICK_START.md` (this file)
2. **Full guide:** `BRUTEFORCE_GUIDE.md` (complete documentation)
3. **Main findings:** `CRITICAL_FINDINGS_REPORT.md` (your Algolia findings)

## 🎯 The Complete Picture

You already found:
- ✅ Algolia API keys ($2k-$5k)
- ✅ Vendor exposure ($1.5k-$3k)
- ✅ S3 bucket info ($300-$1k)

**Now testing:**
- ⏳ Weak credentials (?)
- ⏳ Rate limiting (?)
- ⏳ Account lockout (?)

**Potential total bounty:** $4,100 - $10,000+ 💰

---

**Good luck! 🚀**

*Read the full guide in `BRUTEFORCE_GUIDE.md` for detailed documentation.*
