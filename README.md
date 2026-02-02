# Beast Mode Recon v2.0.0

A modular 10-phase subdomain enumeration and reconnaissance pipeline for bug bounty and security assessments. Orchestrates 12+ Go tools and 6 Python helpers with parallel execution, error resilience, and structured output.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [CLI Options](#cli-options)
  - [Common Workflows](#common-workflows)
- [Pipeline Phases](#pipeline-phases)
  - [Phase 0: Setup & Dependencies](#phase-0-setup--dependencies)
  - [Phase 1: Root Domain Intelligence](#phase-1-root-domain-intelligence)
  - [Phase 2: Passive Subdomain Enumeration](#phase-2-passive-subdomain-enumeration)
  - [Phase 3: DNS Resolution & Filtering](#phase-3-dns-resolution--filtering)
  - [Phase 4: Active Discovery](#phase-4-active-discovery)
  - [Phase 5: Port Scanning](#phase-5-port-scanning)
  - [Phase 6: Web Probing](#phase-6-web-probing)
  - [Phase 7: Content Discovery](#phase-7-content-discovery)
  - [Phase 8: Vulnerability Scanning](#phase-8-vulnerability-scanning)
  - [Phase 9: Certstream Monitor](#phase-9-certstream-monitor)
  - [Phase 10: Reporting](#phase-10-reporting)
- [Output Structure](#output-structure)
- [Python Helpers](#python-helpers)
  - [crtsh_enum.py](#crtsh_enumpy)
  - [asn_enum.py](#asn_enumpy)
  - [certstream_monitor.py](#certstream_monitorpy)
  - [webarchive_enum.py](#webarchive_enumpy)
  - [passive_enum.py](#passive_enumpy)
  - [github_dorking.py](#github_dorkingpy)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **10-phase pipeline** with per-phase timing, status tracking, and error isolation (a failing phase does not kill the pipeline)
- **6+ passive sources running in parallel**: subfinder, amass, crt.sh, Wayback Machine, 4 free APIs (RapidDNS, AlienVault OTX, HackerTarget, URLScan.io), and optional GitHub code dorking
- **ASN enumeration**: resolves the target domain to its IP, looks up the owning ASN via BGPView, retrieves all announced IP prefixes, and performs reverse DNS to find hidden subdomains
- **Certificate Transparency**: batch crt.sh queries for historical certificates and a real-time certstream WebSocket monitor
- **DNS record collection**: puredns resolution with wildcard filtering, plus dnsx to collect A, AAAA, CNAME, MX, NS, and TXT records
- **Active bruteforce + permutations**: puredns bruteforce with a 110k wordlist, then alterx permutation generation on all known-alive subdomains
- **Port scanning**: naabu top-1000 port scan across all discovered subdomains
- **Web probing**: httpx with JSON output, status codes, titles, IPs, CNAMEs, tech detection, web server, content-length, favicon hash, JARM fingerprint, and CDN detection
- **Content discovery**: katana JS-aware crawl + gau historical URLs + JS file extraction
- **Vulnerability scanning**: nuclei with all severity levels, results split into per-severity JSON files
- **Structured output**: timestamped directories with per-phase folders, a master subdomain list, and a final summary report (text + JSON)
- **Argument parsing**: `--skip-phase`, `--only-passive`, `--resume`, `--threads`, `--rate-limit`, `--github-token`, custom wordlists and resolvers
- **Backward compatible**: `./recon.sh example.com` (positional argument) still works
- **Auto-installs dependencies**: Go, MassDNS, all Go tools, Python packages, wordlists, resolvers, and nuclei templates are installed automatically on first run

---

## Architecture

```
recon.sh (orchestrator, ~1150 lines bash)
  |
  |-- Phase 0: Setup (auto-install Go, tools, wordlists, resolvers)
  |-- Phase 1: Root Domain Intelligence
  |     \-- helpers/asn_enum.py      (HackerTarget + BGPView APIs)
  |-- Phase 2: Passive Enumeration (6+ sources in parallel)
  |     |-- subfinder
  |     |-- amass (passive)
  |     |-- helpers/crtsh_enum.py    (crt.sh JSON API)
  |     |-- helpers/webarchive_enum.py (Wayback CDX API)
  |     |-- helpers/passive_enum.py  (RapidDNS, AlienVault, HackerTarget, URLScan)
  |     \-- helpers/github_dorking.py (GitHub code search, optional)
  |-- Phase 3: DNS Resolution (puredns + dnsx)
  |-- Phase 4: Active Discovery (puredns bruteforce + alterx permutations)
  |-- Master Merge (deduplicated union of phases 3+4)
  |-- Phase 5: Port Scanning (naabu)
  |-- Phase 6: Web Probing (httpx)
  |-- Phase 7: Content Discovery (katana + gau)
  |-- Phase 8: Vulnerability Scanning (nuclei)
  |-- Phase 9: Certstream Monitor (background WebSocket daemon)
  |     \-- helpers/certstream_monitor.py
  \-- Phase 10: Reporting (summary.txt + stats.json)
```

---

## Requirements

**Operating System**: Linux (tested on Kali Linux). Should work on any Debian/Ubuntu-based system.

**System packages** (installed automatically if missing):
- `pv` - progress bar utility
- `whois` - WHOIS lookups
- `git`, `make`, `gcc` - for building MassDNS
- `wget`, `curl` - for downloading resources

**Runtime**:
- **Go 1.24+** (auto-installed if missing)
- **Python 3.8+** with pip
- **Root/sudo access** for installing system packages and MassDNS

---

## Installation

```bash
git clone https://github.com/youruser/Useful-Script---Web2-BB.git
cd Useful-Script---Web2-BB
chmod +x recon.sh helpers/*.py
```

Everything else (Go, tools, wordlists, resolvers, Python packages) is automatically installed on first run during Phase 0. No manual setup required.

### Manual Pre-installation (optional)

If you prefer to install dependencies ahead of time:

```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/anew@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest

# Python packages
pip3 install requests beautifulsoup4 websocket-client

# MassDNS (required by puredns)
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make && sudo make install && cd .. && rm -rf massdns
```

---

## Quick Start

```bash
# Full pipeline on a target
./recon.sh -d example.com

# Passive-only recon (no bruteforce, no port scan, no active probing)
./recon.sh -d example.com --only-passive

# Skip port scanning and vulnerability scanning
./recon.sh -d example.com --skip-phase 5,8

# Full pipeline with GitHub dorking enabled
./recon.sh -d example.com --github-token ghp_your_token_here

# Faster scan with higher thread count and rate limit
./recon.sh -d example.com -t 100 --rate-limit 1000

# Resume the most recent scan for a domain
./recon.sh -d example.com --resume

# Legacy syntax (backward compatible)
./recon.sh example.com
```

---

## Usage

```
Usage: ./recon.sh -d <domain> [options]

Options:
  -d, --domain <domain>       Target domain (required)
  -t, --threads <n>           Thread count for tools (default: 50)
  --rate-limit <n>            DNS query rate limit per second (default: 300)
  --skip-phase <n,n,...>      Skip specific phases by number (e.g., 5,8)
  --only-passive              Run phases 0-3 only (no active scanning)
  --resume                    Resume using the latest output directory for this domain
  --github-token <token>      GitHub personal access token for code dorking
  --wordlist <path>           Custom wordlist file path
  --resolvers <path>          Custom DNS resolvers file path
  -h, --help                  Show help message
```

### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `-d, --domain` | *(required)* | Target root domain to enumerate |
| `-t, --threads` | `50` | Concurrent threads for httpx, dnsx, nuclei, katana, naabu |
| `--rate-limit` | `300` | DNS queries per second for puredns and naabu |
| `--skip-phase` | *(none)* | Comma-separated phase numbers to skip (0-10) |
| `--only-passive` | `false` | Stops after Phase 3; skips bruteforce, ports, probing, vulns |
| `--resume` | `false` | Finds the latest timestamped output dir and continues there |
| `--github-token` | *(none)* | Required for Phase 2 GitHub dorking; accepts `ghp_*` tokens |
| `--wordlist` | `subdomains-top1million-110000.txt` | Subdomain bruteforce wordlist |
| `--resolvers` | `resolvers.txt` | DNS resolver list for puredns |

### Common Workflows

**Bug bounty quick passive recon** - gather subdomains without touching the target:
```bash
./recon.sh -d target.com --only-passive
```

**Full recon without vuln scanning** - useful when you want to run nuclei separately with custom templates:
```bash
./recon.sh -d target.com --skip-phase 8
```

**Maximum coverage** - all sources including GitHub:
```bash
./recon.sh -d target.com --github-token ghp_xxx -t 100 --rate-limit 1000
```

**Resume an interrupted scan**:
```bash
./recon.sh -d target.com --resume
```

---

## Pipeline Phases

### Phase 0: Setup & Dependencies

Sets up the environment and installs any missing tools.

**Actions:**
- Configures `$PATH` so Go binaries (e.g., `httpx` from ProjectDiscovery) take precedence over system binaries (e.g., Kali's unrelated `httpx` package)
- Creates the timestamped output directory structure
- Installs Go 1.24.0 if missing
- Installs MassDNS from source if missing
- Installs 11 Go tools via `go install` if missing: subfinder, httpx, nuclei, puredns, alterx, dnsx, naabu, katana, anew, gau, ffuf
- Downloads the SecLists `subdomains-top1million-110000.txt` wordlist if missing
- Downloads the Trickest `resolvers.txt` resolver list if missing
- Installs Python packages `requests` and `beautifulsoup4` if missing
- Updates nuclei templates if the template directory doesn't exist

**Output:** Configured environment, all tools available on `$PATH`.

---

### Phase 1: Root Domain Intelligence

Gathers organizational information about the target domain.

**Actions:**
- Runs a WHOIS lookup on the domain
- Runs `helpers/asn_enum.py` which:
  1. Resolves the domain to an IP address
  2. Looks up the ASN for that IP via HackerTarget
  3. Retrieves all IP prefixes announced by that ASN via BGPView
  4. Performs reverse DNS on up to 10 prefixes to discover subdomains hosted within the organization's IP space

**Output files:**
| File | Content |
|------|---------|
| `phase1_rootdomain/whois.txt` | Raw WHOIS output |
| `phase1_rootdomain/asn_info.json` | Domain, IP, ASN details, all prefixes |
| `phase1_rootdomain/ip_ranges.txt` | One CIDR per line |
| `phase1_rootdomain/reverse_dns.txt` | Hostnames found via rDNS |
| `phase1_rootdomain/asn_subdomains.txt` | Subdomains matching the target domain |

---

### Phase 2: Passive Subdomain Enumeration

Queries 6+ passive data sources in parallel without touching the target.

**Sources (all run concurrently):**

| Source | Tool/Helper | Notes |
|--------|-------------|-------|
| Subfinder | `subfinder -all` | ProjectDiscovery's passive enumerator; supports API keys in `~/.config/subfinder/provider-config.yaml` |
| Amass | `amass enum -passive` | OWASP passive enumeration (5-minute timeout); skipped if not installed |
| crt.sh | `helpers/crtsh_enum.py` | Certificate Transparency log search via crt.sh JSON API |
| Wayback Machine | `helpers/webarchive_enum.py` | Queries the CDX API for historically crawled URLs, extracts hostnames |
| Passive APIs | `helpers/passive_enum.py` | Queries RapidDNS, AlienVault OTX, HackerTarget, and URLScan.io in parallel |
| GitHub | `helpers/github_dorking.py` | Searches GitHub code for domain references; requires `--github-token` |
| ASN rDNS | *(from Phase 1)* | Subdomains discovered via reverse DNS on ASN IP ranges |

**Output files:**
| File | Content |
|------|---------|
| `phase2_passive/subfinder.txt` | Subfinder results |
| `phase2_passive/amass.txt` | Amass results |
| `phase2_passive/crtsh.txt` | crt.sh results |
| `phase2_passive/wayback.txt` | Wayback Machine results |
| `phase2_passive/passive_apis.txt` | Aggregated API results |
| `phase2_passive/github.txt` | GitHub dorking results (if token provided) |
| `phase2_passive/merged_passive.txt` | Deduplicated union of all sources |

---

### Phase 3: DNS Resolution & Filtering

Resolves passive subdomains to confirm they are alive, and collects detailed DNS records.

**Actions:**
1. **puredns resolve** - Resolves all merged passive subdomains against the resolver list, filters out wildcards
2. **dnsx** - Collects A, AAAA, CNAME, MX, NS, and TXT records for all resolved subdomains
3. Extracts CNAME records separately (useful for subdomain takeover analysis)

**Output files:**
| File | Content |
|------|---------|
| `phase3_dns/resolved.txt` | Live subdomains (one per line) |
| `phase3_dns/wildcards.txt` | Wildcard domains detected |
| `phase3_dns/dns_records.txt` | Human-readable DNS records |
| `phase3_dns/dns_records.json` | JSON DNS records |
| `phase3_dns/cnames.txt` | CNAME records only |

---

### Phase 4: Active Discovery

Bruteforces subdomains and generates permutations from known-alive hosts.

**Actions:**
1. **puredns bruteforce** - Brute-forces subdomain names using the 110k SecLists wordlist
2. **alterx** - Generates permutation candidates (e.g., `dev-api`, `api-v2`, `staging-app`) from the union of resolved + bruteforced subdomains
3. **puredns resolve** - Resolves the permutation candidates

**Skipped when:** `--only-passive` is set or phase 4 is in `--skip-phase`.

**Output files:**
| File | Content |
|------|---------|
| `phase4_active/bruteforce.txt` | Bruteforce-discovered subdomains |
| `phase4_active/permutations.txt` | Permutation-discovered subdomains |

---

### Master Merge

After Phase 4 (or Phase 3 in passive-only mode), all confirmed-alive subdomains are merged into a single deduplicated master list:

```
master_subdomains.txt = resolved.txt + bruteforce.txt + permutations.txt
```

This file is the input for all subsequent phases.

---

### Phase 5: Port Scanning

Discovers open ports on all subdomains in the master list.

**Actions:**
- Runs naabu with the top 1000 ports against every host in `master_subdomains.txt`
- Extracts a list of unique hosts that have at least one open port

**Skipped when:** `--only-passive` is set, phase 5 is in `--skip-phase`, or naabu is not installed.

**Output files:**
| File | Content |
|------|---------|
| `phase5_ports/naabu_scan.txt` | `host:port` pairs |
| `phase5_ports/hosts_with_ports.txt` | Unique hosts with open ports |

---

### Phase 6: Web Probing

Probes all discovered hosts (and specific ports from Phase 5) for HTTP/HTTPS services.

**Actions:**
- If Phase 5 produced results, combines `master_subdomains.txt` with `naabu_scan.txt` host:port pairs
- Runs httpx with: title, status code, IP, CNAME, tech detection, web server, content-length, content-type, favicon hash, JARM fingerprint, CDN detection, redirect following, random user agent
- Outputs both human-readable text and JSON formats
- Categorizes results by HTTP status code (200, 301, 302, 403, 404, 500)
- Extracts live URLs from JSON output for downstream tools

**Output files:**
| File | Content |
|------|---------|
| `phase6_web/httpx_output.txt` | Human-readable httpx output |
| `phase6_web/httpx_output.json` | JSON httpx output (one object per line) |
| `phase6_web/live_urls.txt` | Extracted URLs for downstream tools |
| `phase6_web/by_status/200.txt` | Hosts returning 200 OK |
| `phase6_web/by_status/301.txt` | Hosts returning 301 |
| `phase6_web/by_status/403.txt` | Hosts returning 403 Forbidden |
| `phase6_web/by_status/...` | Other status codes |

---

### Phase 7: Content Discovery

Crawls live web assets and fetches historical URLs.

**Actions:**
1. **katana** - JS-aware web crawler at depth 3 with known-file discovery, runs against all live URLs
2. **gau** (GetAllURLs) - Fetches historical URLs from Wayback Machine, Common Crawl, and other archives
3. Merges all discovered URLs and extracts `.js` file URLs separately

**Skipped when:** `--only-passive` is set, phase 7 is in `--skip-phase`, or no live URLs exist from Phase 6.

**Output files:**
| File | Content |
|------|---------|
| `phase7_content/katana_urls.txt` | URLs discovered by crawling |
| `phase7_content/gau_urls.txt` | Historical URLs from archives |
| `phase7_content/all_urls.txt` | Deduplicated union of all URLs |
| `phase7_content/js_files.txt` | JavaScript file URLs only |

---

### Phase 8: Vulnerability Scanning

Runs nuclei templates against all live web assets.

**Actions:**
- Runs nuclei with all severity levels (`info`, `low`, `medium`, `high`, `critical`) against the live URLs from Phase 6
- Outputs results in both text and JSON formats
- Splits JSON results into per-severity files for easy triage

**Skipped when:** `--only-passive` is set, phase 8 is in `--skip-phase`, nuclei is not installed, or no live URLs exist.

**Output files:**
| File | Content |
|------|---------|
| `phase8_vulns/nuclei_all.txt` | All findings (text) |
| `phase8_vulns/nuclei_all.json` | All findings (JSON) |
| `phase8_vulns/nuclei_critical.json` | Critical severity only |
| `phase8_vulns/nuclei_high.json` | High severity only |
| `phase8_vulns/nuclei_medium.json` | Medium severity only |
| `phase8_vulns/nuclei_low.json` | Low severity only |
| `phase8_vulns/nuclei_info.json` | Informational findings only |

---

### Phase 9: Certstream Monitor

Launches a background Certificate Transparency log monitor.

**Actions:**
- Starts `helpers/certstream_monitor.py` as a background process with a 60-second duration
- Monitors real-time CT logs via WebSocket for any new certificates matching the target domain
- Any new subdomains are written to `phase2_passive/certstream.txt` and merged into the master list during Phase 10

**Note:** The certstream monitor can also be run standalone for continuous monitoring (see [certstream_monitor.py](#certstream_monitorpy)).

**Skipped when:** Phase 9 is in `--skip-phase` or `websocket-client` cannot be installed.

---

### Phase 10: Reporting

Generates a final summary report and JSON statistics.

**Actions:**
- Waits for the certstream background monitor to finish
- Merges any certstream findings into the master subdomain list
- Generates a text summary with counts for every data source, phase status, and key metrics
- Generates a JSON stats file for programmatic consumption
- Prints the summary to the terminal

**Output files:**
| File | Content |
|------|---------|
| `report/summary.txt` | Human-readable summary report |
| `report/stats.json` | Machine-readable statistics |

---

## Output Structure

Each run creates a timestamped directory under the target domain:

```
example.com/
  2026-02-02_143000/
    recon.log                        # Full pipeline log (color-stripped)
    master_subdomains.txt            # Final deduplicated alive subdomains
    certstream.log                   # Certstream monitor stderr
    phase1_rootdomain/
      whois.txt                      # WHOIS output
      asn_info.json                  # ASN details, IP, prefixes
      ip_ranges.txt                  # CIDR ranges
      reverse_dns.txt                # rDNS hostnames
      asn_subdomains.txt             # Matching subdomains from rDNS
      asn_enum.log                   # Helper stderr log
    phase2_passive/
      subfinder.txt
      amass.txt
      crtsh.txt
      wayback.txt
      passive_apis.txt
      github.txt                     # Only if --github-token provided
      certstream.txt                 # From Phase 9 background monitor
      merged_passive.txt             # Union of all sources
      *.log                          # Per-source stderr logs
    phase3_dns/
      resolved.txt                   # Alive subdomains
      wildcards.txt                  # Detected wildcard domains
      dns_records.txt                # Human-readable DNS records
      dns_records.json               # JSON DNS records
      cnames.txt                     # CNAME records
      puredns_resolve.log
    phase4_active/
      bruteforce.txt
      permutations.txt
      *.log
    phase5_ports/
      naabu_scan.txt                 # host:port pairs
      hosts_with_ports.txt           # Unique hosts
      naabu.log
    phase6_web/
      httpx_output.txt               # Human-readable web assets
      httpx_output.json              # JSON web assets
      live_urls.txt                  # Extracted URLs
      httpx.log
      by_status/
        200.txt
        301.txt
        302.txt
        403.txt
        404.txt
        500.txt
      screenshots/                   # Reserved for future use
    phase7_content/
      katana_urls.txt
      gau_urls.txt
      all_urls.txt                   # Merged + deduplicated
      js_files.txt                   # JavaScript URLs
      *.log
    phase8_vulns/
      nuclei_all.txt
      nuclei_all.json
      nuclei_critical.json
      nuclei_high.json
      nuclei_medium.json
      nuclei_low.json
      nuclei_info.json
      nuclei.log
    report/
      summary.txt                    # Text summary
      stats.json                     # JSON statistics
```

---

## Python Helpers

All helpers are standalone scripts in the `helpers/` directory. They can be used independently of `recon.sh` or imported as modules.

Each helper writes status/progress messages to stderr and outputs subdomains (one per line) to stdout. When `-o` is provided, stdout output goes to the file instead.

### crtsh_enum.py

Queries the crt.sh Certificate Transparency database for certificates matching `%.domain` and extracts unique subdomains.

```bash
# Print to stdout
python3 helpers/crtsh_enum.py example.com

# Write to file
python3 helpers/crtsh_enum.py example.com -o output.txt

# Custom timeout
python3 helpers/crtsh_enum.py example.com --timeout 60
```

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `domain` | Yes | - | Target domain |
| `-o, --output` | No | stdout | Output file path |
| `--timeout` | No | `30` | HTTP request timeout in seconds |

---

### asn_enum.py

Performs ASN-based enumeration: resolves the domain IP, looks up the ASN, retrieves announced IP prefixes, and performs reverse DNS.

```bash
python3 helpers/asn_enum.py example.com -o /tmp/asn_output/
```

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `domain` | Yes | - | Target domain |
| `-o, --output-dir` | Yes | - | Output directory (created if missing) |

**Produces three files in the output directory:**
- `asn_info.json` - Full ASN data (domain, IP, ASNs, prefixes)
- `ip_ranges.txt` - Announced CIDR prefixes
- `reverse_dns.txt` - Hostnames found via rDNS

**APIs used:** HackerTarget (WHOIS, ASN lookup, reverse DNS), BGPView (prefix lookup). All free, no API key required. Rate limited to 10 prefix lookups per run to avoid hitting API limits.

---

### certstream_monitor.py

Real-time Certificate Transparency log monitor. Connects to the certstream WebSocket feed and filters for certificates matching specified domains.

```bash
# Monitor for 1 hour, save to file
python3 helpers/certstream_monitor.py --domains example.com -o certs.txt --duration 3600

# Monitor multiple domains indefinitely (Ctrl+C to stop)
python3 helpers/certstream_monitor.py --domains example.com,sub.example.com

# Quick 60-second sample
python3 helpers/certstream_monitor.py --domains example.com --duration 60
```

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--domains` | Yes | - | Comma-separated list of domains to watch |
| `-o, --output` | No | stdout | Output file (appended, not overwritten) |
| `--duration` | No | indefinite | Run duration in seconds |

**Requires:** `pip3 install websocket-client`

**Behavior:**
- Outputs new subdomains to stdout (one per line) as they are discovered
- Deduplicates within a single session
- Automatically reconnects on WebSocket disconnection
- Handles SIGINT/SIGTERM gracefully

---

### webarchive_enum.py

Queries the Wayback Machine CDX API for historically archived URLs matching `*.domain/*` and extracts unique subdomains from the URL hostnames.

```bash
# Print to stdout
python3 helpers/webarchive_enum.py example.com

# Write to file
python3 helpers/webarchive_enum.py example.com -o output.txt

# Longer timeout for large domains
python3 helpers/webarchive_enum.py example.com --timeout 120
```

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `domain` | Yes | - | Target domain |
| `-o, --output` | No | stdout | Output file path |
| `--timeout` | No | `60` | HTTP request timeout in seconds |

**Fetches up to 50,000 URLs** per query from the CDX API with URL key collapsing for deduplication.

---

### passive_enum.py

Aggregates 4 free passive subdomain APIs, querying all of them in parallel:

| API | Endpoint | Auth |
|-----|----------|------|
| RapidDNS | `rapiddns.io/subdomain/{domain}` | None |
| AlienVault OTX | `otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns` | None |
| HackerTarget | `api.hackertarget.com/hostsearch/?q={domain}` | None |
| URLScan.io | `urlscan.io/api/v1/search/?q=domain:{domain}` | None |

```bash
# Print to stdout
python3 helpers/passive_enum.py example.com

# Write to file
python3 helpers/passive_enum.py example.com -o output.txt

# Custom timeout per request
python3 helpers/passive_enum.py example.com --timeout 45
```

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `domain` | Yes | - | Target domain |
| `-o, --output` | No | stdout | Output file path |
| `--timeout` | No | `30` | Per-request timeout in seconds |

---

### github_dorking.py

Searches GitHub code for references to the target domain using multiple dork patterns. Extracts subdomains from text match fragments.

**Dork patterns used:**
1. `"example.com"`
2. `"*.example.com"`
3. `"api.example.com"`
4. `"dev.example.com"`
5. `"staging.example.com"`
6. `"internal.example.com"`

```bash
# With --token flag
python3 helpers/github_dorking.py example.com --token ghp_your_token -o output.txt

# With environment variable
GITHUB_TOKEN=ghp_your_token python3 helpers/github_dorking.py example.com
```

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `domain` | Yes | - | Target domain |
| `--token` | No* | `$GITHUB_TOKEN` | GitHub personal access token |
| `-o, --output` | No | stdout | Output file path |

*Either `--token` or the `GITHUB_TOKEN` environment variable must be set.

**Rate limiting:** Waits 3 seconds between queries and handles GitHub 403 rate-limit responses with automatic backoff.

**Creating a token:** Go to GitHub Settings > Developer settings > Personal access tokens > Tokens (classic) > Generate new token. No special scopes are required for public code search.

---

## Configuration

### Subfinder API Keys

Subfinder supports API keys for various services (Shodan, Censys, VirusTotal, etc.) which significantly increase results. Configure them in:

```
~/.config/subfinder/provider-config.yaml
```

See the [subfinder documentation](https://github.com/projectdiscovery/subfinder#post-installation-instructions) for the full list of supported providers.

### Nuclei Templates

Nuclei templates are automatically downloaded to `~/nuclei-templates/` on first run. To update:

```bash
nuclei -update-templates
```

To use custom templates, run nuclei separately on the `live_urls.txt` output:

```bash
nuclei -l example.com/2026-02-02_143000/phase6_web/live_urls.txt -t /path/to/custom-templates/
```

### Custom Wordlists

```bash
./recon.sh -d example.com --wordlist /path/to/custom-wordlist.txt
```

### Custom Resolvers

```bash
./recon.sh -d example.com --resolvers /path/to/custom-resolvers.txt
```

---

## Troubleshooting

### `httpx` runs the wrong binary

Kali Linux ships a system package called `httpx` (an HTTP toolkit unrelated to ProjectDiscovery's httpx). The script sets `$GOPATH/bin` at the front of `$PATH` to ensure the Go version runs first. If you still see issues:

```bash
# Check which httpx is being used
which httpx

# The Go version should be at ~/go/bin/httpx
ls -la ~/go/bin/httpx
```

### puredns fails with "massdns not found"

puredns requires MassDNS. The script installs it automatically, but if it fails:

```bash
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make && sudo make install
```

### Phase fails but pipeline continues

This is by design. Each phase is wrapped with `|| true` so a single failure doesn't kill the entire pipeline. Check the phase-specific log files for details:

```bash
cat example.com/2026-02-02_143000/phase3_dns/puredns_resolve.log
cat example.com/2026-02-02_143000/recon.log
```

### certstream_monitor.py won't start

Install the WebSocket client:

```bash
pip3 install websocket-client
```

### Rate limiting from free APIs

The passive API helpers (HackerTarget, RapidDNS, etc.) are free services with rate limits. If you see errors:
- HackerTarget: ~100 requests/day for unauthenticated users
- RapidDNS: No documented limit, but may throttle heavy usage
- URLScan.io: ~100 searches/day without an API key

The ASN enumeration helper limits reverse DNS lookups to 10 prefixes per run to stay within free API limits.

### Go tool installation fails

Ensure Go is properly installed and `$GOPATH/bin` is in your `$PATH`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
go version
```

---

## License

This project is provided as-is for authorized security testing, bug bounty programs, and educational purposes. Use responsibly and only against targets you have permission to test.
