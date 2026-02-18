#!/usr/bin/env python3
"""
Parse nuclei NDJSON output into a text summary and per-severity JSON files.

Usage:
    python3 nuclei_parse.py <json_file>
        --text-out <file>
        --severity-dir <directory>
"""

import argparse
import json
import os
import sys


def main():
    parser = argparse.ArgumentParser(description="Parse nuclei JSON output")
    parser.add_argument("json_file", help="Path to nuclei -json output file")
    parser.add_argument("--text-out", help="Write human-readable summary to this file")
    parser.add_argument("--severity-dir", help="Write per-severity JSON files into this directory")
    args = parser.parse_args()

    if not os.path.isfile(args.json_file):
        print(f"[nuclei_parse] File not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    entries = []
    with open(args.json_file) as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entries.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                print(f"[nuclei_parse] JSON parse error on line {lineno}: {exc}", file=sys.stderr)

    if not entries:
        print("[nuclei_parse] No valid JSON entries found in input file.", file=sys.stderr)
        sys.exit(0)

    # ── text summary ──────────────────────────────────────────────────────────
    if args.text_out:
        with open(args.text_out, "w") as fh:
            for obj in entries:
                tid     = obj.get("template-id", "")
                sev     = obj.get("info", {}).get("severity", "")
                matched = obj.get("matched-at", "")
                fh.write(f"[{sev}] [{tid}] {matched}\n")

    # ── per-severity files ────────────────────────────────────────────────────
    if args.severity_dir:
        os.makedirs(args.severity_dir, exist_ok=True)
        by_severity: dict[str, list] = {}
        for obj in entries:
            sev = obj.get("info", {}).get("severity", "unknown").lower()
            by_severity.setdefault(sev, []).append(obj)
        for sev, items in by_severity.items():
            path = os.path.join(args.severity_dir, f"nuclei_{sev}.json")
            with open(path, "w") as fh:
                for item in items:
                    fh.write(json.dumps(item) + "\n")

    print(f"[nuclei_parse] Parsed {len(entries)} findings successfully.", file=sys.stderr)


if __name__ == "__main__":
    main()
