# Beast Mode Recon — Architecture Reference

Version: **2.1.0**

---

## Table of Contents

1. [Overview](#overview)
2. [Repository Layout](#repository-layout)
3. [Pipeline Flow](#pipeline-flow)
4. [Phase Breakdown](#phase-breakdown)
   - [Phase 0 — Setup & Dependencies](#phase-0--setup--dependencies)
   - [Phase 1 — Root Domain Intelligence](#phase-1--root-domain-intelligence)
   - [Phase 2 — Passive Subdomain Enumeration](#phase-2--passive-subdomain-enumeration)
   - [Phase 3 — DNS Resolution & Filtering](#phase-3--dns-resolution--filtering)
   - [Phase 4 — Active Discovery](#phase-4--active-discovery)
   - [Phase 5 — Port Scanning](#phase-5--port-scanning)
   - [Phase 6 — Web Probing](#phase-6--web-probing)
   - [Phase 7 — Content Discovery](#phase-7--content-discovery)
   - [Phase 8 — Vulnerability Scanning](#phase-8--vulnerability-scanning)
   - [Phase 9 — Certstream Monitor](#phase-9--certstream-monitor)
   - [Phase 10 — Reporting](#phase-10--reporting)
5. [Helper Scripts](#helper-scripts)
6. [Output File Structure](#output-file-structure)
7. [External Tools & Dependencies](#external-tools--dependencies)
8. [Configuration Reference](#configuration-reference)
9. [Improvements Introduced in v2.1.0](#improvements-introduced-in-v210)

---

## Overview

`recon.sh` is a modular, 10-phase bug bounty reconnaissance pipeline written in Bash.
It orchestrates a standard industry toolchain (subfinder, amass, puredns, httpx, naabu,
katana, gau, ffuf, nuclei) alongside custom Python helpers to go from a bare domain
name to a structured, prioritised attack surface report in a single command.

Key design principles:

- **Parallelism** — passive sources, ASN lookup, and certstream all run in the background
  concurrently; the pipeline waits for all before merging.
- **Modularity** — every phase can be skipped (`--skip-phase`) or run in isolation
  (`--run-phase`), and each phase writes self-contained output that later phases consume.
- **Resumability** — `--resume` finds the latest timestamped output directory and
  continues from where the pipeline left off.
- **Safety** — `set -o pipefail` throughout; `|| true` guards non-critical tool failures
  so a single tool error never aborts the pipeline. A `cleanup_exit` trap ensures the
  background certstream process is always terminated on exit.
- **Multi-domain** — a `--domains-file` flag feeds multiple targets through the full
  pipeline sequentially, each getting its own timestamped output directory.

---

## Repository Layout

```
.
├── recon.sh                          # Main pipeline entry point
├── generate_consolidated_reports.sh  # Standalone report regenerator for old scans
├── jsanalyzer.py                     # Standalone JS file analyzer
├── subdomains-top1million-110000.txt # Default subdomain wordlist (SecLists)
├── raft-medium-directories-lowercase.txt  # Directory bruteforce wordlist (SecLists)
├── resolvers.txt                     # DNS resolver list (trickest/resolvers)
├── domains.txt                       # Example multi-domain input file
├── helpers/
│   ├── asn_enum.py           # ASN/IP-range/reverse-DNS discovery
│   ├── crtsh_enum.py         # crt.sh certificate transparency query
│   ├── webarchive_enum.py    # Wayback Machine CDX API query
│   ├── passive_enum.py       # Aggregate free passive APIs (RapidDNS, AlienVault, HackerTarget, URLScan)
│   ├── github_dorking.py     # GitHub code search for subdomains
│   ├── certstream_monitor.py # Real-time CT log WebSocket monitor
│   ├── httpx_parse.py        # Parse httpx NDJSON output → text + live_urls + by-status files
│   ├── nuclei_parse.py       # Parse nuclei NDJSON output → text + per-severity JSON files
│   ├── stats_gen.py          # Generate report/stats.json from scan output directory
│   └── ffuf_parse.py         # Parse ffuf JSON result directory → unified results file
└── <PROGRAM>/
    └── <DOMAIN>/
        └── <TIMESTAMP>/      # One directory per scan run (see Output File Structure)
```

---

## Pipeline Flow

```
 Domain input
      │
      ▼
 ┌──────────┐
 │ Phase 0  │  Setup: install Go toolchain + all tools, download wordlists
 └────┬─────┘
      │
      ▼
 ┌──────────┐
 │ Phase 1  │  WHOIS + ASN enumeration + reverse DNS on IP ranges
 └────┬─────┘  (runs in background; wait before Phase 2 merge)
      │
      ▼
 ┌──────────┐
 │ Phase 2  │  Parallel passive subdomain enumeration
 └────┬─────┘  subfinder │ amass │ crtsh │ wayback │ passive APIs │ github │ certstream
      │         all run in background, wait, then merge → merged_passive.txt
      ▼
 ┌──────────┐
 │ Phase 3  │  puredns resolve → resolved.txt (alive only)
 └────┬─────┘  dnsx → dns_records.txt / dns_records.json / cnames.txt
      │
      ▼
 ┌──────────┐    if --only-passive: skip → Phase 10
 │ Phase 4  │  puredns bruteforce (110k wordlist) + alterx permutations
 └────┬─────┘
      │
      ▼
  merge_master  → master_subdomains.txt  (resolved ∪ bruteforce ∪ permutations)
      │
      ▼
 ┌──────────┐
 │ Phase 5  │  naabu port scan (top 1000) on master list
 └────┬─────┘
      │
      ▼
 ┌──────────┐
 │ Phase 6  │  httpx web probe (JSON output)
 └────┬─────┘  → httpx_parse.py → httpx_output.txt + live_urls.txt + by_status/*.txt
      │
      ▼
 ┌──────────┐
 │ Phase 7  │  katana spider + gau historical URLs + ffuf directory bruteforce
 └────┬─────┘  jsanalyzer.py on discovered JS files
      │
      ▼
 ┌──────────┐
 │ Phase 8  │  nuclei vuln scan (all severities, JSON)
 └────┬─────┘  → nuclei_parse.py → nuclei_all.txt + nuclei_<sev>.json
      │
      ▼
 ┌──────────┐
 │ Phase 9  │  certstream real-time CT log monitor (60s background sample)
 └────┬─────┘  (started in background; Phase 10 waits for it)
      │
      ▼
 ┌──────────┐
 │ Phase 10 │  stats_gen.py → report/stats.json
 └────┬─────┘  summary.txt + <DOMAIN>_consolidated_report.txt
      │
      ▼
  Results in  <PROGRAM>/<DOMAIN>/<TIMESTAMP>/
```

---

## Phase Breakdown

### Phase 0 — Setup & Dependencies

**Purpose:** Ensure all required tools and wordlists are present before any scanning begins.

**Actions:**
- Prepends `$GOPATH/bin` and `/usr/local/go/bin` to `$PATH`.
- Creates the full output directory tree for all phases.
- Installs `pv` (progress bars) via apt/brew if missing.
- Installs Go 1.24+ if not present (downloads from go.dev).
- Installs `libpcap-dev` (required by naabu).
- Clones and builds `massdns` from source if missing.
- Installs Go tools via `go install`: subfinder, amass, httpx, nuclei, puredns, alterx,
  dnsx, naabu, katana, anew, gau, ffuf.
- Downloads `subdomains-top1million-110000.txt` (SecLists) if missing.
- Downloads `raft-medium-directories-lowercase.txt` (SecLists) for ffuf directory bruteforce.
- Downloads `resolvers.txt` (trickest/resolvers) if missing.
- Installs Python `requests` and `beautifulsoup4`.
- Updates nuclei templates if missing **or older than 7 days**.

**Key outputs:** all tools available in `$PATH`, wordlists on disk.

---

### Phase 1 — Root Domain Intelligence

**Purpose:** Gather IP/ASN/organisation ownership data for the root domain.

**Tools:** `whois` (system), `helpers/asn_enum.py`

**Flow:**
1. `whois <domain>` → `phase1_rootdomain/whois.txt` (background)
2. `asn_enum.py`:
   - Resolves domain → IP via `socket.gethostbyname`
   - HackerTarget `/aslookup` → ASN number + org for that IP
   - BGPView `/asn/<num>/prefixes` → all IPv4/IPv6 CIDR blocks announced
   - HackerTarget `/reversedns` on up to 10 CIDR blocks → hostnames in target domain
   - Writes `asn_info.json`, `ip_ranges.txt`, `reverse_dns.txt`
   - Prints reverse-DNS subdomains to stdout → `asn_subdomains.txt`

**Key outputs:**
```
phase1_rootdomain/
├── whois.txt
├── asn_info.json       # {domain, ip, asns:[{asn, org}], prefixes:[CIDR...]}
├── ip_ranges.txt       # one CIDR per line
├── reverse_dns.txt     # hostnames from reverse DNS
└── asn_subdomains.txt  # subdomains discovered via reverse DNS
```

---

### Phase 2 — Passive Subdomain Enumeration

**Purpose:** Collect as many subdomains as possible without sending any traffic to the target.

**Sources (all run in parallel):**

| Source | Tool | Notes |
|--------|------|-------|
| subfinder | `subfinder -all` | Queries 40+ passive APIs |
| amass (passive) | `amass enum -passive` | 5-min timeout |
| crt.sh | `helpers/crtsh_enum.py` | Certificate Transparency JSON API |
| Wayback Machine | `helpers/webarchive_enum.py` | CDX API, up to 50k URLs |
| Passive APIs | `helpers/passive_enum.py` | RapidDNS, AlienVault OTX, HackerTarget, URLScan.io |
| GitHub dorking | `helpers/github_dorking.py` | Requires `--github-token` |
| Certstream | `helpers/certstream_monitor.py` | Real-time CT log WebSocket; also runs Phase 9 |

All sources merged and deduplicated → `phase2_passive/merged_passive.txt`.

**Key outputs:**
```
phase2_passive/
├── subfinder.txt
├── amass.txt
├── crtsh.txt
├── wayback.txt
├── passive_apis.txt
├── github.txt          # only if --github-token provided
├── certstream.txt      # filled during Phase 9
└── merged_passive.txt  # sorted deduplicated union of all sources
```

---

### Phase 3 — DNS Resolution & Filtering

**Purpose:** Confirm which passive subdomains are actually alive (resolve to an IP).

**Tools:** `puredns`, `dnsx`

**Flow:**
1. `puredns resolve merged_passive.txt` → `resolved.txt` (alive subdomains), `wildcards.txt`
2. `dnsx` on resolved list → `dns_records.txt` (A, AAAA, CNAME, MX, NS, TXT with responses)
3. `dnsx` again with `-json` → `dns_records.json`
4. Extract CNAME lines → `cnames.txt` (manual subdomain takeover investigation candidates)

**Key outputs:**
```
phase3_dns/
├── resolved.txt        # confirmed-alive subdomains
├── wildcards.txt       # wildcard DNS entries detected
├── dns_records.txt     # human-readable DNS records
├── dns_records.json    # machine-readable DNS records
└── cnames.txt          # CNAME records (check for takeover)
```

---

### Phase 4 — Active Discovery

**Purpose:** Find subdomains that passive sources missed via DNS bruteforce and permutation.

**Tools:** `puredns` (bruteforce), `alterx` (permutation), `puredns` (resolve permutations)

**Flow:**
1. `puredns bruteforce subdomains-top1million-110000.txt <domain>` → `bruteforce.txt`
2. `alterx` on the union of resolved + bruteforce results → permutation candidates
3. `puredns resolve` on permutation candidates → `permutations.txt`

**Skipped** if `--only-passive` is set.

**Key outputs:**
```
phase4_active/
├── bruteforce.txt      # subdomains found by wordlist bruteforce
├── permutations.txt    # subdomains found by alterx permutation + resolution
└── *.log               # puredns/alterx debug logs
```

---

### Phase 5 — Port Scanning

**Purpose:** Identify open ports across the entire live subdomain surface.

**Tool:** `naabu`

**Flow:**
1. Scans `master_subdomains.txt` for top 1000 ports at `--rate-limit` packets/sec.
2. Extracts unique hosts with any open port → `hosts_with_ports.txt`.

**Key outputs:**
```
phase5_ports/
├── naabu_scan.txt       # host:port entries (one per line)
└── hosts_with_ports.txt # unique hosts with at least one open port
```

---

### Phase 6 — Web Probing

**Purpose:** Identify HTTP/HTTPS services, collect metadata, and categorise by status code.

**Tool:** `httpx`, parsed by `helpers/httpx_parse.py`

**Input:** `master_subdomains.txt` merged with `naabu_scan.txt` (host:port pairs from Phase 5).

**httpx flags:** `-title -status-code -ip -cname -tech-detect -web-server -content-length -content-type -favicon -jarm -cdn -follow-redirects -random-agent -json`

**Flow:**
1. `httpx` writes NDJSON to `httpx_output.json`.
2. If the JSON file is empty, the phase fails with an error and dumps `httpx.log` to the
   main log for debugging (no silent failure).
3. `httpx_parse.py` derives:
   - `httpx_output.txt` — pipe-delimited human-readable summary
   - `live_urls.txt` — clean URL list consumed by Phases 7 and 8
   - `by_status/<code>.txt` — URLs grouped by HTTP status code

**Key outputs:**
```
phase6_web/
├── httpx_output.json       # raw NDJSON from httpx
├── httpx_output.txt        # human-readable: url | status | title | ip | server | tech
├── live_urls.txt           # one URL per line (all status codes)
├── httpx.log               # httpx stderr
├── httpx_parse.log         # httpx_parse.py stderr
├── by_status/
│   ├── 200.txt
│   ├── 301.txt
│   ├── 302.txt
│   ├── 403.txt
│   ├── 404.txt
│   └── 500.txt
└── screenshots/            # reserved for future eyewitness/gowitness integration
```

---

### Phase 7 — Content Discovery

**Purpose:** Enumerate URLs, crawl JavaScript, bruteforce directories, and extract
intelligence from JS files (endpoints, secrets, emails).

**Tools:** `katana`, `gau`, `ffuf` + `helpers/ffuf_parse.py`, `jsanalyzer.py`

**Flow:**

1. **katana** — active spider of `live_urls.txt` at depth 3, JS-crawl enabled,
   known-files discovery → `katana_urls.txt`

2. **gau** — historical URL fetch from Wayback, CommonCrawl, etc. → `gau_urls.txt`

3. **ffuf directory bruteforce** (new in v2.1.0):
   - Extracts unique base URLs (`scheme://host`) from `by_status/200.txt` and
     `by_status/403.txt`, capped at 20 hosts to stay time-bounded.
   - Runs `ffuf` per host against `raft-medium-directories-lowercase.txt`
     (`-mc 200,301,302,403,500 -rate 100 -of json`).
   - Parses all JSON result files via `helpers/ffuf_parse.py` → `ffuf_results.txt`.

4. Katana + gau merged and deduplicated → `all_urls.txt`

5. JS file URLs extracted from `all_urls.txt` → `js_files.txt`

6. **jsanalyzer.py** fetches each JS file and extracts:
   - API endpoints matching path patterns → `js_endpoints.txt`
   - Full URLs from string literals → `js_urls.txt`
   - Secrets/API keys (AWS, Google, Stripe, GitHub, Slack, JWT) → `js_secrets.txt`
   - Email addresses → `js_emails.txt`
   - Interesting file paths (.sql, .env, .key, etc.) → `js_files_found.txt`

**Key outputs:**
```
phase7_content/
├── katana_urls.txt
├── gau_urls.txt
├── all_urls.txt          # katana + gau merged
├── js_files.txt          # JS URLs extracted from all_urls.txt
├── js_analysis.txt       # raw jsanalyzer output
├── js_endpoints.txt      # extracted API endpoints
├── js_urls.txt           # extracted full URLs
├── js_secrets.txt        # extracted secrets (masked)
├── js_emails.txt         # extracted email addresses
├── js_files_found.txt    # extracted interesting file paths
├── ffuf_results.txt      # all ffuf directory hits (url | status | size | words)
└── ffuf/
    └── <host>.json       # per-host ffuf JSON output
```

---

### Phase 8 — Vulnerability Scanning

**Purpose:** Automated vulnerability detection across all live web assets.

**Tool:** `nuclei` (v3), parsed by `helpers/nuclei_parse.py`

**Flow:**
1. `nuclei` runs on `live_urls.txt` with all severities (info → critical) and writes NDJSON
   to `nuclei_all.json`.
2. `nuclei_parse.py` derives:
   - `nuclei_all.txt` — one finding per line: `[severity] [template-id] matched-at`
   - `nuclei_<severity>.json` — per-severity NDJSON files (info, low, medium, high, critical)

**Key outputs:**
```
phase8_vulns/
├── nuclei_all.json         # raw NDJSON from nuclei
├── nuclei_all.txt          # human-readable finding list
├── nuclei_critical.json
├── nuclei_high.json
├── nuclei_medium.json
├── nuclei_low.json
├── nuclei_info.json
└── nuclei.log              # nuclei stderr
```

---

### Phase 9 — Certstream Monitor

**Purpose:** Sample the live CT log stream for 60 seconds to catch freshly-issued
certificates for the target domain (new subdomains provisioned after scanning began).

**Tool:** `helpers/certstream_monitor.py` (WebSocket to `wss://certstream.calidog.io/`)

**Flow:**
- Spawns `certstream_monitor.py --duration 60` in the background.
- Stores the PID in the global `CERTSTREAM_PID` variable (not only a PID file) so the
  `cleanup_exit` trap can kill it reliably on SIGINT/SIGTERM/EXIT.
- Phase 10 waits up to 90 seconds for it to finish naturally.
- Discovered subdomains are appended to `phase2_passive/certstream.txt` and merged into
  `master_subdomains.txt` by Phase 10.

---

### Phase 10 — Reporting

**Purpose:** Produce structured human-readable and machine-readable summary outputs.

**Tools:** `helpers/stats_gen.py`, bash heredoc-based report generation

**Flow:**
1. Waits for certstream (Phase 9) to finish and merges its findings into `master_subdomains.txt`.
2. Writes `report/summary.txt` — phase-by-phase counts and status table.
3. Calls `stats_gen.py` → `report/stats.json` — machine-readable counts for all key files,
   including per-severity nuclei counts and new ffuf/JS fields.
4. Calls `generate_consolidated_report()` → `<DOMAIN>_consolidated_report.txt` — a
   single self-contained document covering ASN info, subdomain list, live URLs,
   status-code breakdown, port summary, JS analysis, CNAME takeover candidates,
   critical/high vulnerability detail, and recommended next steps.

**Key outputs:**
```
report/
├── summary.txt           # phase status + key metric counts
└── stats.json            # machine-readable stats (all file line counts)

<DOMAIN>_consolidated_report.txt   # single-file human report
recon.log                          # timestamped log of the entire run
```

---

## Helper Scripts

### `helpers/asn_enum.py`
Resolves domain IP → ASN (via HackerTarget) → IP prefixes (via BGPView) → reverse-DNS
subdomains (via HackerTarget, limited to 10 CIDRs to avoid rate limits).

Writes: `asn_info.json`, `ip_ranges.txt`, `reverse_dns.txt`; prints subdomains to stdout.

### `helpers/crtsh_enum.py`
Queries `crt.sh/?q=%.domain&output=json`, extracts and deduplicates subdomain entries from
the `name_value` field (handles wildcard stripping and multi-line SANs).

### `helpers/webarchive_enum.py`
Queries the Wayback Machine CDX API for `*.domain/*`, extracts hostnames from the
`original` URL field, deduplicates.

### `helpers/passive_enum.py`
Queries RapidDNS, AlienVault OTX, HackerTarget hostsearch, and URLScan.io in parallel
via `ThreadPoolExecutor`.

### `helpers/github_dorking.py`
Searches GitHub code API with dorks like `"*.target.com"`, `"api.target.com"`, etc.
Extracts subdomain strings from text-match fragments. Requires a GitHub PAT.

### `helpers/certstream_monitor.py`
Connects to the `certstream.calidog.io` WebSocket, filters CT log entries matching the
target domain(s), writes matches to an output file. Supports `--duration` for timed runs.
Has a daemon watchdog thread for hard-stop after duration.

### `helpers/httpx_parse.py` *(new in v2.1.0)*
Reads httpx NDJSON output and produces:
- `--text-out`: pipe-delimited text summary (url | status | title | ip | server | tech)
- `--urls-out`: plain URL list
- `--status-dir`: per-status-code URL files

Replaces three separate inline `python3 -c` blobs from v2.0.0. Provides proper error
reporting when the JSON file is empty or malformed.

### `helpers/nuclei_parse.py` *(new in v2.1.0)*
Reads nuclei NDJSON output and produces:
- `--text-out`: one-line-per-finding text summary
- `--severity-dir`: per-severity NDJSON files (`nuclei_critical.json`, etc.)

Replaces two inline `python3 -c` blobs from v2.0.0.

### `helpers/stats_gen.py` *(new in v2.1.0)*
Counts non-empty lines in all key output files across all phases and writes `stats.json`.
Includes new fields for ffuf results, JS sub-categories, and per-severity nuclei counts.
Replaces one inline `python3 -c` blob from v2.0.0.

### `helpers/ffuf_parse.py` *(new in v2.1.0)*
Walks a directory of `ffuf -of json` output files and consolidates all results into a
single file with format: `<url> [<status>] [<length>b] [<words>w]`.

### `jsanalyzer.py`
Standalone JS analysis tool. Fetches JS URLs from a file, runs regex patterns for API
endpoints, secrets, URLs, emails, and interesting file paths. Outputs tagged lines
(`[ENDPOINT]`, `[SECRET]`, `[URL]`, `[EMAIL]`, `[FILE]`) which Phase 7 greps to split
into per-category files.

---

## Output File Structure

```
<SCRIPT_DIR>/
└── <PROGRAM>/
    └── <DOMAIN>/
        └── <YYYY-MM-DD_HHMMSS>/
            ├── recon.log
            ├── certstream.pid          # temporary; removed after Phase 10
            ├── master_subdomains.txt   # final deduplicated live subdomain list
            ├── <DOMAIN>_consolidated_report.txt
            ├── phase1_rootdomain/
            │   ├── whois.txt
            │   ├── asn_info.json
            │   ├── ip_ranges.txt
            │   ├── reverse_dns.txt
            │   └── asn_subdomains.txt
            ├── phase2_passive/
            │   ├── subfinder.txt
            │   ├── amass.txt
            │   ├── crtsh.txt
            │   ├── wayback.txt
            │   ├── passive_apis.txt
            │   ├── github.txt
            │   ├── certstream.txt
            │   └── merged_passive.txt
            ├── phase3_dns/
            │   ├── resolved.txt
            │   ├── wildcards.txt
            │   ├── dns_records.txt
            │   ├── dns_records.json
            │   └── cnames.txt
            ├── phase4_active/
            │   ├── bruteforce.txt
            │   └── permutations.txt
            ├── phase5_ports/
            │   ├── naabu_scan.txt
            │   └── hosts_with_ports.txt
            ├── phase6_web/
            │   ├── httpx_output.json
            │   ├── httpx_output.txt
            │   ├── live_urls.txt
            │   ├── httpx.log
            │   ├── httpx_parse.log
            │   ├── by_status/
            │   │   ├── 200.txt
            │   │   ├── 301.txt
            │   │   ├── 302.txt
            │   │   ├── 403.txt
            │   │   ├── 404.txt
            │   │   └── 500.txt
            │   └── screenshots/
            ├── phase7_content/
            │   ├── katana_urls.txt
            │   ├── gau_urls.txt
            │   ├── all_urls.txt
            │   ├── js_files.txt
            │   ├── js_analysis.txt
            │   ├── js_endpoints.txt
            │   ├── js_urls.txt
            │   ├── js_secrets.txt
            │   ├── js_emails.txt
            │   ├── js_files_found.txt
            │   ├── ffuf_results.txt
            │   └── ffuf/
            │       └── <host>.json
            ├── phase8_vulns/
            │   ├── nuclei_all.json
            │   ├── nuclei_all.txt
            │   ├── nuclei_critical.json
            │   ├── nuclei_high.json
            │   ├── nuclei_medium.json
            │   ├── nuclei_low.json
            │   ├── nuclei_info.json
            │   └── nuclei.log
            └── report/
                ├── summary.txt
                └── stats.json
```

---

## External Tools & Dependencies

| Tool | Install method | Purpose |
|------|---------------|---------|
| Go 1.24+ | Downloaded from go.dev if missing | Required for all Go tools |
| massdns | Compiled from source (GitHub) | Fast DNS resolver backend |
| libpcap-dev | apt | Required by naabu for raw packet capture |
| subfinder | `go install` (projectdiscovery) | Passive subdomain enumeration |
| amass | `go install` (owasp-amass) | Passive subdomain enumeration |
| httpx | `go install` (projectdiscovery) | HTTP/HTTPS probing |
| nuclei | `go install` (projectdiscovery) | Vulnerability scanning |
| puredns | `go install` (d3mondev) | Fast DNS resolution + bruteforce |
| alterx | `go install` (projectdiscovery) | Subdomain permutation generation |
| dnsx | `go install` (projectdiscovery) | DNS record collection |
| naabu | `go install` (projectdiscovery) | Port scanning |
| katana | `go install` (projectdiscovery) | Active web crawler |
| anew | `go install` (tomnomnom) | Deduplicating append |
| gau | `go install` (lc) | Historical URL fetching |
| ffuf | `go install` (ffuf) | Directory/content bruteforcing |
| whois | System package | WHOIS lookups |
| python3 | System | Helpers runtime |
| requests | pip3 | HTTP client for helpers |
| beautifulsoup4 | pip3 | HTML parsing (optional) |
| websocket-client | pip3 | Required by certstream_monitor.py |
| pv | apt/brew | Progress bars (optional) |

---

## Configuration Reference

```bash
./recon.sh --program <name> -d <domain> [options]
./recon.sh --program <name> --domains-file <file> [options]

Required:
  --program, -p <name>        Bug bounty program identifier (used for output path)
  -d, --domain <domain>       Single target domain
  --domains-file, -l <file>   File with one domain per line (mutually exclusive with -d)

Optional:
  -t, --threads <n>           Concurrency for tools (default: 50)
  --rate-limit <n>            DNS/port-scan packets per second (default: 300)
  --github-token <token>      GitHub PAT for code dorking in Phase 2
  --wordlist <path>           Override subdomain wordlist (default: subdomains-top1million-110000.txt)
  --resolvers <path>          Override DNS resolver list (default: resolvers.txt)
  --only-passive              Run Phases 0-3 only, then report
  --run-phase <n,n,...>       Run ONLY the listed phases (e.g., --run-phase 2,7,8)
  --skip-phase <n,n,...>      Skip the listed phases (cannot combine with --run-phase)
  --resume                    Find the latest output dir for this domain and continue
  -h, --help                  Show usage
```

---

## Improvements Introduced in v2.1.0

### 1. Extracted inline Python to dedicated helper scripts

v2.0.0 had five `python3 -c "..."` blobs embedded in `recon.sh` with Bash variable
interpolation inside Python string literals — fragile, hard to test, and unreadable.

v2.1.0 extracts these into four new helper scripts:

- `helpers/httpx_parse.py` — Phase 6 JSON parsing (text, live_urls, by_status)
- `helpers/nuclei_parse.py` — Phase 8 JSON parsing (text, per-severity split)
- `helpers/stats_gen.py` — Phase 10 stats.json generation
- `helpers/ffuf_parse.py` — Phase 7 ffuf JSON consolidation

Each helper has proper argument parsing, error messages, and exit codes.

### 2. Fixed ASN info always showing N/A

`asn_info.json` has the structure `{asns: [{asn, org}], prefixes: [...]}`, but the
reporting code was reading top-level keys `asn`, `name`, `description` which don't exist.
Both `recon.sh` and `generate_consolidated_reports.sh` are fixed to correctly read
`data['asns'][0]['asn']` and `data['asns'][0]['org']`, and use the heredoc-to-stdin
pattern to avoid Bash variable interpolation inside Python code.

### 3. Added ffuf directory bruteforcing to Phase 7

ffuf was installed in Phase 0 but never used. Phase 7 now:
- Collects unique base URLs from Phase 6's `by_status/200.txt` and `by_status/403.txt`
  (capped at 20 to keep runtime bounded).
- Runs ffuf per host against `raft-medium-directories-lowercase.txt` at a conservative
  rate (100 req/s, 30 threads).
- Consolidates all JSON results via `helpers/ffuf_parse.py` → `phase7_content/ffuf_results.txt`.
- Adds a Phase 0 step to download the directory wordlist if not present.

### 4. Nuclei templates staleness check

v2.0.0 only checked if `~/nuclei-templates` existed; templates could be months stale.
v2.1.0 checks the directory `mtime` and triggers a refresh if templates are 7+ days old.

### 5. Certstream PID cleanup via EXIT trap

v2.0.0 managed certstream via a PID file and manual wait/kill logic in Phase 10. If the
script was killed mid-run (Ctrl+C, SIGTERM), the certstream process was orphaned.

v2.1.0 adds:
- A global `CERTSTREAM_PID` variable set when the process is spawned.
- A `cleanup_exit()` function registered with `trap cleanup_exit EXIT INT TERM` that
  reliably kills the process on any exit path.
- Phase 10 still waits up to 90 seconds for a natural finish, but relies on the trap
  for the forced-kill fallback rather than duplicating that logic.

### 6. Phase 6 empty-output debugging

Previously, if httpx produced no JSON output (e.g., due to a tool error or flag
incompatibility), Phases 6/7/8/9 all silently failed with "0 URLs". v2.1.0 now:
- Detects an empty `httpx_output.json` immediately after the tool runs.
- Dumps the first 20 lines of `httpx.log` into the main `recon.log` with WARN level.
- Fails Phase 6 explicitly so the issue is visible in the Phase Status table.

### 7. stats.json covers all new fields

`stats_gen.py` tracks 25 output files (vs 9 in v2.0.0), including:
- Per-source passive counts (subfinder, amass, crtsh, etc.)
- `ffuf_results`, JS sub-categories (`js_endpoints`, `js_secrets`, `js_emails`)
- `live_urls` (separate from `web_assets`)
- Per-severity nuclei counts (`nuclei_critical`, `nuclei_high`, etc.)
