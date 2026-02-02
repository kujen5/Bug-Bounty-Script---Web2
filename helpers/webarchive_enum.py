#!/usr/bin/env python3
"""
Wayback Machine CDX API subdomain extraction.

Queries the Wayback Machine's CDX API to discover subdomains
that have been historically crawled.

Usage:
    python3 webarchive_enum.py <domain> [-o output_file]
"""

import sys
import argparse
import requests
from urllib.parse import urlparse


def query_wayback(domain, timeout=60):
    """Query Wayback Machine CDX API for URLs matching domain."""
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "output": "text",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "50000",
    }
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
        return resp.text.strip().splitlines()
    except requests.exceptions.Timeout:
        print(f"[wayback] Timeout querying Wayback Machine for {domain}", file=sys.stderr)
        return []
    except requests.exceptions.RequestException as e:
        print(f"[wayback] Error querying Wayback Machine: {e}", file=sys.stderr)
        return []


def extract_subdomains(urls, domain):
    """Extract unique subdomains from a list of URLs."""
    subdomains = set()
    for raw_url in urls:
        raw_url = raw_url.strip()
        if not raw_url:
            continue
        # Ensure URL has a scheme for urlparse
        if not raw_url.startswith(("http://", "https://")):
            raw_url = "http://" + raw_url
        try:
            parsed = urlparse(raw_url)
            hostname = parsed.hostname
            if hostname:
                hostname = hostname.lower().rstrip(".")
                if hostname.endswith(f".{domain}") or hostname == domain:
                    if "*" not in hostname and " " not in hostname:
                        subdomains.add(hostname)
        except Exception:
            continue
    return sorted(subdomains)


def main():
    parser = argparse.ArgumentParser(description="Wayback Machine subdomain enumeration")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--timeout", type=int, default=60, help="Request timeout in seconds")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    print(f"[wayback] Querying Wayback Machine for *.{domain}...", file=sys.stderr)

    urls = query_wayback(domain, timeout=args.timeout)
    print(f"[wayback] Got {len(urls)} URLs from Wayback Machine", file=sys.stderr)

    subdomains = extract_subdomains(urls, domain)
    print(f"[wayback] Extracted {len(subdomains)} unique subdomains", file=sys.stderr)

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(subdomains) + "\n" if subdomains else "")
        print(f"[wayback] Results written to {args.output}", file=sys.stderr)
    else:
        for sub in subdomains:
            print(sub)


if __name__ == "__main__":
    main()
