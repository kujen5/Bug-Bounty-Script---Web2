#!/usr/bin/env python3
"""
GitHub code search for subdomain discovery.

Searches GitHub code for references to the target domain
and extracts subdomains from matching files.

Requires a GitHub personal access token.

Usage:
    python3 github_dorking.py <domain> --token <github_token> [-o output_file]
    GITHUB_TOKEN=ghp_xxx python3 github_dorking.py <domain> [-o output_file]
"""

import sys
import os
import argparse
import re
import time
import requests


SEARCH_DORKS = [
    '"{domain}"',
    '"*.{domain}"',
    '"api.{domain}"',
    '"dev.{domain}"',
    '"staging.{domain}"',
    '"internal.{domain}"',
]


def github_code_search(query, token, timeout=30):
    """Perform GitHub code search and return items."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.text-match+json",
    }
    params = {
        "q": query,
        "per_page": 100,
    }
    try:
        resp = requests.get(
            "https://api.github.com/search/code",
            headers=headers,
            params=params,
            timeout=timeout,
        )
        if resp.status_code == 403:
            # Rate limited
            reset = resp.headers.get("X-RateLimit-Reset")
            if reset:
                wait = max(int(reset) - int(time.time()), 1)
                print(f"[github] Rate limited. Waiting {wait}s...", file=sys.stderr)
                time.sleep(min(wait, 60))
            return []
        if resp.status_code == 200:
            return resp.json().get("items", [])
        else:
            print(f"[github] Search returned status {resp.status_code}", file=sys.stderr)
    except Exception as e:
        print(f"[github] Search error: {e}", file=sys.stderr)
    return []


def extract_subdomains_from_matches(items, domain):
    """Extract subdomains from GitHub text match fragments."""
    subdomains = set()
    pattern = re.compile(
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+' + re.escape(domain),
        re.IGNORECASE,
    )

    for item in items:
        for match in item.get("text_matches", []):
            fragment = match.get("fragment", "")
            for m in pattern.finditer(fragment):
                sub = m.group(0).lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subdomains.add(sub)

    return subdomains


def main():
    parser = argparse.ArgumentParser(description="GitHub code search for subdomains")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--token", help="GitHub personal access token (or set GITHUB_TOKEN env)")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[github] ERROR: No GitHub token provided.", file=sys.stderr)
        print("[github] Use --token or set GITHUB_TOKEN environment variable.", file=sys.stderr)
        sys.exit(1)

    domain = args.domain.strip().lower()
    all_subs = set()

    dorks = [d.format(domain=domain) for d in SEARCH_DORKS]

    for i, dork in enumerate(dorks, 1):
        print(f"[github] [{i}/{len(dorks)}] Searching: {dork}", file=sys.stderr)
        items = github_code_search(dork, token)
        subs = extract_subdomains_from_matches(items, domain)
        all_subs.update(subs)
        # Respect rate limits
        if i < len(dorks):
            time.sleep(3)

    sorted_subs = sorted(all_subs)
    print(f"[github] Found {len(sorted_subs)} unique subdomains", file=sys.stderr)

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(sorted_subs) + "\n" if sorted_subs else "")
        print(f"[github] Results written to {args.output}", file=sys.stderr)
    else:
        for sub in sorted_subs:
            print(sub)


if __name__ == "__main__":
    main()
