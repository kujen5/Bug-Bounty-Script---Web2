#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Standalone JS Analyzer
Reads a TXT file containing JS URLs and analyzes their contents
using the same logic as the Burp JS Analyzer extension.
"""

import re
import sys
import requests
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

# ==================== ENDPOINT PATTERNS ====================

ENDPOINT_PATTERNS = [
    re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.I),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.I),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.I),
    re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.I),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.I),
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.I),
]

URL_PATTERNS = [
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
]

SECRET_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS"),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), "Google API"),
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), "Stripe"),
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'), "GitHub"),
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), "Slack"),
    (re.compile(r'(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'), "JWT"),
]

EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}')

FILE_PATTERNS = re.compile(
    r'["\']([a-zA-Z0-9_/.-]+\.(sql|env|json|yaml|yml|log|bak|zip|tar|gz|pem|key))["\']',
    re.I
)

NOISE_DOMAINS = {
    "example.com", "localhost", "127.0.0.1", "w3.org", "schemas.microsoft.com"
}

seen = set()


# ==================== VALIDATORS ====================

def valid_endpoint(v):
    return v.startswith("/") and len(v) > 3

def valid_url(v):
    return not any(d in v.lower() for d in NOISE_DOMAINS)

def mask_secret(v):
    return v[:8] + "..." + v[-4:]

# ==================== ANALYSIS ====================

def analyze_js(js, source):
    findings = []

    for pat in ENDPOINT_PATTERNS:
        for m in pat.finditer(js):
            v = m.group(1)
            key = "endpoint:" + v
            if valid_endpoint(v) and key not in seen:
                seen.add(key)
                findings.append(("endpoint", v, source))

    for pat in URL_PATTERNS:
        for m in pat.finditer(js):
            v = m.group(1)
            key = "url:" + v
            if valid_url(v) and key not in seen:
                seen.add(key)
                findings.append(("url", v, source))

    for pat, name in SECRET_PATTERNS:
        for m in pat.finditer(js):
            v = m.group(1)
            key = "secret:" + v
            if key not in seen:
                seen.add(key)
                findings.append(("secret", f"{name}: {mask_secret(v)}", source))

    for m in EMAIL_PATTERN.finditer(js):
        v = m.group(0)
        key = "email:" + v
        if key not in seen:
            seen.add(key)
            findings.append(("email", v, source))

    for m in FILE_PATTERNS.finditer(js):
        v = m.group(1)
        key = "file:" + v
        if key not in seen:
            seen.add(key)
            findings.append(("file", v, source))

    return findings


# ==================== MAIN ====================

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} js_urls.txt")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        urls = [l.strip() for l in f if l.strip()]

    for url in urls:
        print(f"\n[+] Fetching: {url}")
        try:
            r = requests.get(url, timeout=15, verify=False)
            if r.status_code != 200 or len(r.text) < 100:
                print("  [-] Skipped (empty or non-200)")
                continue

            name = urlparse(url).path.split("/")[-1]
            results = analyze_js(r.text, name)

            for cat, val, src in results:
                print(f"  [{cat.upper()}] {val}")

        except Exception as e:
            print(f"  [!] Error: {e}")


if __name__ == "__main__":
    main()
