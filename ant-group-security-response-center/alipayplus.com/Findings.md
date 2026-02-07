# Finding 1

## Title
Captcha bypass and information disclosure leading to Continuous Account Lockout
## summary

the forgot password flow at global.alipay.com has multiple issues that when chained together allow an attacker to continuously lock out any merchant
account for an indefinite period.

## the chain

### 1 - captcha bypass on checkEmail endpoint

the endpoint `POST /merchant/proxyapi/member/checkEmail.json` is protected by an invisible captcha (antCaptchaToken) that requires browser-side
fingerprinting via the JS SDK at iantcaptchaqk.alipay.com.

however, the server accepts the literal string `dummy_token` as a valid captcha token. this completely bypasses the captcha without needing any browser
interaction or fingerprint data. this looks like a debug/test bypass that was left in production.

request:
POST /merchant/proxyapi/member/checkEmail.json?_route=QK&ctoken=lryb1T619p2sp8uG HTTP/2
Host: global.alipay.com
Content-Type: application/json;charset=UTF-8
```json
{"email":"target@example.com","antCaptchaToken":"dummy_token","bizNo":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","rdsAppId":"imhom
e_resetLoginPwd_qk"}
```
this works with any session cookies from the forgot password page - no valid captcha solve needed.

### 2 - email enumeration via different server responses

using the bypassed captcha, the checkEmail endpoint returns clearly different responses depending on whether an email is registered or not:

**registered email:**
```json
{"data":{"validated":true},"success":true}
```

unregistered email:
```json
{"success":false,"resultCode":"IPAY_RS_510550101","resultMessage":"this email is not registered"}
```

this lets an attacker build a list of valid merchant emails at scale with no rate limiting or captcha protection.

3 - account lockout after 3 failed login attempts

on the login page (/ilogin/account_login.htm), entering a wrong password 3 times locks the account for 3 hours. the lockout message says: "Your account
has been locked, please try again in 3 hours"

full attack chain

1. attacker opens the forgot password page once to get session cookies
2. attacker sends automated requests to checkEmail.json using dummy_token as the captcha token to enumerate which emails are registered
3. for each discovered email, attacker submits 3 wrong passwords on the login page
4. every targeted account is now locked for 3 hours
5. attacker repeats step 3 every 3 hours → permanent lockout

i wrote a python PoC that automates steps 1-2 (email enumeration with captcha bypass). tested against my own accounts:

======================================================================
```bash
PoC: Email Enumeration + Captcha Bypass
Target : https://global.alipay.com
Bypass token : dummy_token
Emails to check: 4
```
======================================================================
```
[001] 0xkujen-ywh-fdd598ecef7c9f7b@yeswehack.ninja REGISTERED
[002] fouedsaidi665@gmail.com REGISTERED
[003] randomtestxyz999@gmail.com NOT REGISTERED
[004] doesnotexist12345@gmail.com NOT REGISTERED
```
no captcha was solved - all requests used dummy_token as the antCaptchaToken value.

---

**Vulnerability impact:**

an attacker can lock out any merchant account on global.alipay.com indefinitely, without knowing the account password. the attack is fully automated and
requires no user interaction.

the captcha bypass (dummy_token) removes the only automated-request protection on the checkEmail endpoint, which means an attacker can enumerate valid
merchant emails at scale with simple http requests. once valid emails are discovered, each account can be locked out by sending just 3 wrong login
attempts - and this can be repeated every 3 hours to keep accounts permanently locked.

this is particularly impactful because:
- it targets the alipay global merchant portal where account access = business operations
- merchants locked out of their accounts cannot process payments, manage their stores, or access their funds
- a single attacker could lock out hundreds or thousands of merchant accounts simultaneously
- there is no way for the victim to prevent or stop the attack
- the attack costs the attacker almost nothing (a few http requests per account)

---

**Repair suggestion:**

1. remove the "dummy_token" captcha bypass from production immediately. the antCaptchaToken validation should reject any token that wasn't actually issued
 by the captcha service.
2. return a generic response on checkEmail regardless of whether the email is registered. something like "if this email is associated with an account, you
 will receive a password reset link." both registered and unregistered emails should return the same response structure and status code.
3. implement rate limiting on checkEmail.json - limit requests per IP/session to prevent bulk enumeration even if the captcha is somehow bypassed again.
4. for the account lockout, consider using progressive delays (1min, 5min, 15min) instead of a hard 3-hour lock after just 3 attempts. alternatively, use
captcha challenges after failed attempts instead of full lockout, or require additional verification (like email confirmation) to unlock.