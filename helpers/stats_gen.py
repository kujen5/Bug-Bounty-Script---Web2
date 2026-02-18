#!/usr/bin/env python3
"""
Generate a stats.json file from a completed scan output directory.

Usage:
    python3 stats_gen.py --program <name> --domain <domain>
                         --outdir <path> --output <stats.json>
"""

import argparse
import json
import os
import sys


def count_lines(path: str) -> int:
    """Return number of non-empty lines in a file, or 0 if it doesn't exist."""
    try:
        with open(path) as fh:
            return sum(1 for line in fh if line.strip())
    except OSError:
        return 0


def main():
    parser = argparse.ArgumentParser(description="Generate scan statistics JSON")
    parser.add_argument("--program", required=True, help="Bug bounty program name")
    parser.add_argument("--domain",  required=True, help="Target domain")
    parser.add_argument("--outdir",  required=True, help="Scan output directory")
    parser.add_argument("--output",  required=True, help="Destination stats.json path")
    args = parser.parse_args()

    d = args.outdir

    files_to_count = {
        "passive_subfinder":   f"{d}/phase2_passive/subfinder.txt",
        "passive_amass":       f"{d}/phase2_passive/amass.txt",
        "passive_crtsh":       f"{d}/phase2_passive/crtsh.txt",
        "passive_wayback":     f"{d}/phase2_passive/wayback.txt",
        "passive_apis":        f"{d}/phase2_passive/passive_apis.txt",
        "passive_github":      f"{d}/phase2_passive/github.txt",
        "passive_certstream":  f"{d}/phase2_passive/certstream.txt",
        "passive_merged":      f"{d}/phase2_passive/merged_passive.txt",
        "resolved":            f"{d}/phase3_dns/resolved.txt",
        "wildcards":           f"{d}/phase3_dns/wildcards.txt",
        "cnames":              f"{d}/phase3_dns/cnames.txt",
        "bruteforce":          f"{d}/phase4_active/bruteforce.txt",
        "permutations":        f"{d}/phase4_active/permutations.txt",
        "master":              f"{d}/master_subdomains.txt",
        "ports":               f"{d}/phase5_ports/naabu_scan.txt",
        "hosts_with_ports":    f"{d}/phase5_ports/hosts_with_ports.txt",
        "web_assets":          f"{d}/phase6_web/httpx_output.txt",
        "live_urls":           f"{d}/phase6_web/live_urls.txt",
        "katana_urls":         f"{d}/phase7_content/katana_urls.txt",
        "gau_urls":            f"{d}/phase7_content/gau_urls.txt",
        "all_urls":            f"{d}/phase7_content/all_urls.txt",
        "js_files":            f"{d}/phase7_content/js_files.txt",
        "js_endpoints":        f"{d}/phase7_content/js_endpoints.txt",
        "js_urls":             f"{d}/phase7_content/js_urls.txt",
        "js_secrets":          f"{d}/phase7_content/js_secrets.txt",
        "js_emails":           f"{d}/phase7_content/js_emails.txt",
        "ffuf_results":        f"{d}/phase7_content/ffuf_results.txt",
        "nuclei_all":          f"{d}/phase8_vulns/nuclei_all.txt",
    }

    counts = {key: count_lines(path) for key, path in files_to_count.items()}

    for sev in ("critical", "high", "medium", "low", "info"):
        counts[f"nuclei_{sev}"] = count_lines(f"{d}/phase8_vulns/nuclei_{sev}.json")

    stats = {
        "program":    args.program,
        "domain":     args.domain,
        "output_dir": d,
        "counts":     counts,
    }

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as fh:
        json.dump(stats, fh, indent=2)

    print(f"[stats_gen] Stats written to {args.output}", file=sys.stderr)
    print(f"[stats_gen] Master subdomains: {counts['master']}", file=sys.stderr)
    print(f"[stats_gen] Live URLs: {counts['live_urls']}", file=sys.stderr)
    print(f"[stats_gen] Nuclei findings: {counts['nuclei_all']}", file=sys.stderr)


if __name__ == "__main__":
    main()
