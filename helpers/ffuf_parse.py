#!/usr/bin/env python3
"""
Parse a directory of ffuf JSON output files into a single results file.

ffuf -of json produces a JSON object with a "results" array. This script
walks the given directory, reads every *.json file, and prints one result
per line in the format:

    <url> [<status>] [<length>b] [<words>w]

Usage:
    python3 ffuf_parse.py <ffuf_json_dir> [--output <file>]
"""

import argparse
import json
import os
import sys


def parse_ffuf_file(path: str) -> list[dict]:
    """Return list of result dicts from a single ffuf JSON output file."""
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data.get("results", []) or []
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[ffuf_parse] Skipping {path}: {exc}", file=sys.stderr)
        return []


def main():
    parser = argparse.ArgumentParser(description="Parse ffuf JSON output directory")
    parser.add_argument("ffuf_dir", help="Directory containing ffuf *.json output files")
    parser.add_argument("--output", help="Write results to this file (default: stdout)")
    args = parser.parse_args()

    if not os.path.isdir(args.ffuf_dir):
        print(f"[ffuf_parse] Directory not found: {args.ffuf_dir}", file=sys.stderr)
        sys.exit(1)

    all_results = []
    for fname in sorted(os.listdir(args.ffuf_dir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(args.ffuf_dir, fname)
        results = parse_ffuf_file(fpath)
        all_results.extend(results)

    lines = []
    for r in all_results:
        url    = r.get("url", "")
        status = r.get("status", "")
        length = r.get("length", "")
        words  = r.get("words", "")
        if url:
            lines.append(f"{url} [{status}] [{length}b] [{words}w]")

    output_text = "\n".join(lines) + ("\n" if lines else "")

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(output_text)
    else:
        sys.stdout.write(output_text)

    print(f"[ffuf_parse] Total results: {len(lines)}", file=sys.stderr)


if __name__ == "__main__":
    main()
