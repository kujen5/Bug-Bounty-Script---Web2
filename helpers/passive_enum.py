#!/usr/bin/env python3
"""
Aggregate free passive subdomain APIs.

Queries multiple free APIs in parallel:
  - RapidDNS
  - AlienVault OTX
  - HackerTarget
  - URLScan.io

Usage:
    python3 passive_enum.py <domain> [-o output_file]
"""

import sys
import argparse
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


def query_rapiddns(domain, timeout=30):
    """Query RapidDNS for subdomains."""
    subs = set()
    try:
        resp = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=timeout)
        if resp.status_code == 200:
            pattern = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+' + re.escape(domain))
            for match in pattern.finditer(resp.text):
                sub = match.group(0).lower()
                subs.add(sub)
    except Exception as e:
        print(f"[passive] RapidDNS error: {e}", file=sys.stderr)
    print(f"[passive] RapidDNS: {len(subs)} subdomains", file=sys.stderr)
    return subs


def query_alienvault(domain, timeout=30):
    """Query AlienVault OTX for subdomains."""
    subs = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").lower().rstrip(".")
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subs.add(hostname)
    except Exception as e:
        print(f"[passive] AlienVault error: {e}", file=sys.stderr)
    print(f"[passive] AlienVault: {len(subs)} subdomains", file=sys.stderr)
    return subs


def query_hackertarget(domain, timeout=30):
    """Query HackerTarget for subdomains."""
    subs = set()
    try:
        resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=timeout)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().splitlines():
                parts = line.split(",")
                if parts:
                    hostname = parts[0].strip().lower()
                    if hostname.endswith(f".{domain}") or hostname == domain:
                        subs.add(hostname)
    except Exception as e:
        print(f"[passive] HackerTarget error: {e}", file=sys.stderr)
    print(f"[passive] HackerTarget: {len(subs)} subdomains", file=sys.stderr)
    return subs


def query_urlscan(domain, timeout=30):
    """Query URLScan.io for subdomains."""
    subs = set()
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                hostname = page.get("domain", "").lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subs.add(hostname)
    except Exception as e:
        print(f"[passive] URLScan error: {e}", file=sys.stderr)
    print(f"[passive] URLScan: {len(subs)} subdomains", file=sys.stderr)
    return subs


def main():
    parser = argparse.ArgumentParser(description="Aggregate passive subdomain APIs")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--timeout", type=int, default=30, help="Per-request timeout")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    all_subs = set()

    sources = [
        ("RapidDNS", query_rapiddns),
        ("AlienVault", query_alienvault),
        ("HackerTarget", query_hackertarget),
        ("URLScan", query_urlscan),
    ]

    print(f"[passive] Querying {len(sources)} passive sources for {domain}...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn, domain, args.timeout): name for name, fn in sources}
        for future in as_completed(futures):
            name = futures[future]
            try:
                subs = future.result()
                all_subs.update(subs)
            except Exception as e:
                print(f"[passive] {name} failed: {e}", file=sys.stderr)

    sorted_subs = sorted(all_subs)
    print(f"[passive] Total unique subdomains from all sources: {len(sorted_subs)}", file=sys.stderr)

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(sorted_subs) + "\n" if sorted_subs else "")
        print(f"[passive] Results written to {args.output}", file=sys.stderr)
    else:
        for sub in sorted_subs:
            print(sub)


if __name__ == "__main__":
    main()
