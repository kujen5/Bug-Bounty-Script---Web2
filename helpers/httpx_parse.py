#!/usr/bin/env python3
"""
Parse httpx NDJSON output into a text summary, live URL list, and
per-status-code URL files.

Usage:
    python3 httpx_parse.py <json_file>
        --text-out <file>
        --urls-out <file>
        --status-dir <directory>
"""

import argparse
import json
import os
import sys


def main():
    parser = argparse.ArgumentParser(description="Parse httpx JSON output")
    parser.add_argument("json_file", help="Path to httpx -json output file")
    parser.add_argument("--text-out", help="Write human-readable summary to this file")
    parser.add_argument("--urls-out", help="Write live URLs (one per line) to this file")
    parser.add_argument("--status-dir", help="Write per-status-code URL files into this directory")
    args = parser.parse_args()

    if not os.path.isfile(args.json_file):
        print(f"[httpx_parse] File not found: {args.json_file}", file=sys.stderr)
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
                print(f"[httpx_parse] JSON parse error on line {lineno}: {exc}", file=sys.stderr)

    if not entries:
        print("[httpx_parse] No valid JSON entries found in input file.", file=sys.stderr)
        sys.exit(0)

    # ── text summary ──────────────────────────────────────────────────────────
    if args.text_out:
        with open(args.text_out, "w") as fh:
            for obj in entries:
                url    = obj.get("url", "")
                status = str(obj.get("status_code", ""))
                title  = obj.get("title", "") or ""
                ip     = obj.get("host", "") or obj.get("ip", "") or ""
                server = obj.get("webserver", "") or ""
                tech   = ",".join(obj.get("tech", []) or [])
                parts  = [p for p in [url, status, title, ip, server, tech] if p]
                fh.write(" | ".join(parts) + "\n")

    # ── live URL list ─────────────────────────────────────────────────────────
    if args.urls_out:
        with open(args.urls_out, "w") as fh:
            for obj in entries:
                url = obj.get("url", "")
                if url:
                    fh.write(url + "\n")

    # ── per-status-code files ─────────────────────────────────────────────────
    if args.status_dir:
        os.makedirs(args.status_dir, exist_ok=True)
        by_status: dict[int, list[str]] = {}
        for obj in entries:
            code = obj.get("status_code")
            url  = obj.get("url", "")
            if code is not None and url:
                by_status.setdefault(int(code), []).append(url)
        for code, urls in sorted(by_status.items()):
            path = os.path.join(args.status_dir, f"{code}.txt")
            with open(path, "w") as fh:
                fh.write("\n".join(urls) + "\n")

    print(f"[httpx_parse] Parsed {len(entries)} entries successfully.", file=sys.stderr)


if __name__ == "__main__":
    main()
