#!/usr/bin/env python3
"""
ASN Enumeration: Domain -> Org -> ASN -> IP Ranges -> Reverse DNS.

Uses free APIs (HackerTarget, BGPView) to discover IP ranges
owned by the target organization and performs reverse DNS lookups.

Usage:
    python3 asn_enum.py <domain> -o <output_dir>
"""

import sys
import argparse
import json
import socket
import subprocess
import requests


def get_org_from_whois(domain, timeout=15):
    """Extract organization name from whois via HackerTarget API."""
    try:
        resp = requests.get(f"https://api.hackertarget.com/whois/?q={domain}", timeout=timeout)
        if resp.status_code == 200:
            text = resp.text
            for line in text.splitlines():
                line_lower = line.lower()
                if "org-name:" in line_lower or "orgname:" in line_lower or "organization:" in line_lower:
                    return line.split(":", 1)[1].strip()
    except Exception as e:
        print(f"[asn] Whois lookup error: {e}", file=sys.stderr)
    return None


def get_ip_for_domain(domain):
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_asn_from_ip(ip, timeout=15):
    """Get ASN info for an IP using HackerTarget."""
    try:
        resp = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=timeout)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            lines = resp.text.strip().splitlines()
            results = []
            for line in lines:
                parts = line.split(",")
                if len(parts) >= 3:
                    results.append({
                        "ip": parts[0].strip(),
                        "asn": parts[1].strip(),
                        "org": parts[2].strip() if len(parts) > 2 else ""
                    })
            return results
    except Exception as e:
        print(f"[asn] ASN lookup error: {e}", file=sys.stderr)
    return []


def get_prefixes_for_asn(asn_number, timeout=15):
    """Get IP prefixes announced by an ASN using BGPView."""
    prefixes = []
    asn_num = asn_number.replace("AS", "").replace("as", "")
    try:
        resp = requests.get(f"https://api.bgpview.io/asn/{asn_num}/prefixes", timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            for prefix in data.get("data", {}).get("ipv4_prefixes", []):
                prefixes.append(prefix.get("prefix", ""))
            for prefix in data.get("data", {}).get("ipv6_prefixes", []):
                prefixes.append(prefix.get("prefix", ""))
    except Exception as e:
        print(f"[asn] Prefix lookup error for {asn_number}: {e}", file=sys.stderr)
    return [p for p in prefixes if p]


def reverse_dns_lookup(ip_ranges, domain, timeout=15):
    """Use HackerTarget reverse DNS to find hostnames in IP ranges."""
    subdomains = set()
    for cidr in ip_ranges:
        try:
            resp = requests.get(
                f"https://api.hackertarget.com/reversedns/?q={cidr}",
                timeout=timeout
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().splitlines():
                    parts = line.split(",")
                    if len(parts) >= 2:
                        hostname = parts[1].strip().rstrip(".").lower()
                        if hostname.endswith(f".{domain}") or hostname == domain:
                            subdomains.add(hostname)
        except Exception as e:
            print(f"[asn] Reverse DNS error for {cidr}: {e}", file=sys.stderr)
    return sorted(subdomains)


def main():
    parser = argparse.ArgumentParser(description="ASN-based enumeration")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-o", "--output-dir", required=True, help="Output directory")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    outdir = args.output_dir

    # Step 1: Resolve domain IP
    ip = get_ip_for_domain(domain)
    print(f"[asn] {domain} -> {ip}", file=sys.stderr)

    # Step 2: Get ASN info
    asn_info = []
    if ip:
        asn_info = get_asn_from_ip(ip)
        print(f"[asn] ASN info: {asn_info}", file=sys.stderr)

    # Step 3: Get IP prefixes for each ASN
    all_prefixes = []
    seen_asns = set()
    for info in asn_info:
        asn = info.get("asn", "")
        if asn and asn not in seen_asns:
            seen_asns.add(asn)
            prefixes = get_prefixes_for_asn(asn)
            all_prefixes.extend(prefixes)
            print(f"[asn] {asn} announces {len(prefixes)} prefixes", file=sys.stderr)

    # Step 4: Reverse DNS on prefixes (limit to first 10 to avoid rate limits)
    rdns_subs = []
    if all_prefixes:
        limited = all_prefixes[:10]
        print(f"[asn] Running reverse DNS on {len(limited)} prefixes...", file=sys.stderr)
        rdns_subs = reverse_dns_lookup(limited, domain)
        print(f"[asn] Reverse DNS found {len(rdns_subs)} subdomains", file=sys.stderr)

    # Write outputs
    import os
    os.makedirs(outdir, exist_ok=True)

    with open(os.path.join(outdir, "asn_info.json"), "w") as f:
        json.dump({"domain": domain, "ip": ip, "asns": asn_info, "prefixes": all_prefixes}, f, indent=2)

    with open(os.path.join(outdir, "ip_ranges.txt"), "w") as f:
        f.write("\n".join(all_prefixes) + "\n" if all_prefixes else "")

    with open(os.path.join(outdir, "reverse_dns.txt"), "w") as f:
        f.write("\n".join(rdns_subs) + "\n" if rdns_subs else "")

    # Also print subdomains to stdout for pipeline consumption
    for sub in rdns_subs:
        print(sub)


if __name__ == "__main__":
    main()
