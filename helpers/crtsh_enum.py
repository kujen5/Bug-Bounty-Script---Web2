#!/usr/bin/env python3
"""
crt.sh Certificate Transparency subdomain enumeration.
Queries the crt.sh database for certificates matching a domain
and extracts unique subdomains.

Usage:
    python3 crtsh_enum.py <domain> [-o output_file]
"""

import sys
import argparse
import re
import requests


def query_crtsh(domain, timeout=30):
    """Query crt.sh for certificate entries matching domain."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        print(f"[crtsh] Timeout querying crt.sh for {domain}", file=sys.stderr)
        return []
    except requests.exceptions.RequestException as e:
        print(f"[crtsh] Error querying crt.sh: {e}", file=sys.stderr)
        return []
    except ValueError:
        print("[crtsh] Failed to parse JSON response from crt.sh", file=sys.stderr)
        return []


def extract_subdomains(entries, domain):
    """Extract unique subdomains from crt.sh JSON entries."""
    subdomains = set()
    domain_pattern = re.compile(r'(?:^|\s|\*\.?)([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.' + re.escape(domain) + ')$', re.IGNORECASE)

    for entry in entries:
        name_value = entry.get("name_value", "")
        for line in name_value.splitlines():
            line = line.strip().lstrip("*.")
            if line.endswith(f".{domain}") or line == domain:
                # Basic validation: no spaces, no wildcards remaining
                if " " not in line and "*" not in line:
                    subdomains.add(line.lower())

    return sorted(subdomains)


def main():
    parser = argparse.ArgumentParser(description="crt.sh subdomain enumeration")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    entries = query_crtsh(domain, timeout=args.timeout)
    subdomains = extract_subdomains(entries, domain)

    print(f"[crtsh] Found {len(subdomains)} unique subdomains for {domain}", file=sys.stderr)

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(subdomains) + "\n" if subdomains else "")
        print(f"[crtsh] Results written to {args.output}", file=sys.stderr)
    else:
        for sub in subdomains:
            print(sub)


if __name__ == "__main__":
    main()
