#!/bin/bash
# ============================================================================
# Beast Mode Recon - Modular 10-Phase Subdomain Enumeration Pipeline
# ============================================================================
# Usage: ./recon.sh --program <program_name> -d <domain> [options]
#        ./recon.sh --program <program_name> --domains-file <file> [options]
#
# A comprehensive recon pipeline with parallel passive sources, ASN enum,
# certificate transparency, port scanning, content discovery, and vuln scanning.
#
# Output structure: <script_dir>/<program>/<domain>/<timestamp>/
# ============================================================================

set -o pipefail

# ============================================================================
# GLOBALS & DEFAULTS
# ============================================================================
VERSION="2.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPERS_DIR="${SCRIPT_DIR}/helpers"

PROGRAM=""
DOMAIN=""
DOMAINS_FILE=""
THREADS=50
RATE_LIMIT=300
GITHUB_TOKEN=""
SKIP_PHASES=""
RUN_PHASES=""
ONLY_PASSIVE=false
RESUME=false
TIMESTAMP=""
OUTDIR=""
LOGFILE=""

WORDLIST="${SCRIPT_DIR}/subdomains-top1million-110000.txt"
RESOLVERS="${SCRIPT_DIR}/resolvers.txt"
DIRLIST="${SCRIPT_DIR}/raft-medium-directories-lowercase.txt"

# PID of background certstream process (cleaned up on exit)
CERTSTREAM_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Track phase timing
declare -A PHASE_START
declare -A PHASE_STATUS

# ============================================================================
# CLEANUP TRAP
# ============================================================================

cleanup_exit() {
    if [[ -n "$CERTSTREAM_PID" ]] && kill -0 "$CERTSTREAM_PID" 2>/dev/null; then
        log WARN "Killing certstream monitor (PID ${CERTSTREAM_PID})..."
        kill "$CERTSTREAM_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$CERTSTREAM_PID" 2>/dev/null || true
    fi
    # Remove stale PID file if OUTDIR is set
    if [[ -n "$OUTDIR" ]]; then
        rm -f "${OUTDIR}/certstream.pid"
    fi
}

trap cleanup_exit EXIT INT TERM

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║            BEAST MODE RECON v${VERSION}                         ║"
    echo "║         10-Phase Subdomain Enumeration Pipeline             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts="$(date '+%H:%M:%S')"

    case "$level" in
        INFO)  echo -e "${GREEN}[${ts}]${NC} ${msg}" ;;
        WARN)  echo -e "${YELLOW}[${ts}] [!]${NC} ${msg}" ;;
        ERROR) echo -e "${RED}[${ts}] [ERROR]${NC} ${msg}" ;;
        PHASE) echo -e "\n${BLUE}${BOLD}═══════════════════════════════════════════════════${NC}"
               echo -e "${BLUE}${BOLD}  ${msg}${NC}"
               echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════${NC}" ;;
        *)     echo -e "[${ts}] ${msg}" ;;
    esac

    # Also log to file if available
    if [[ -n "$LOGFILE" ]]; then
        echo "[${ts}] [${level}] ${msg}" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOGFILE" 2>/dev/null
    fi
}

phase_start() {
    local phase_num="$1"
    local phase_name="$2"
    PHASE_START[$phase_num]=$(date +%s)
    log PHASE "Phase ${phase_num}: ${phase_name}"
}

phase_end() {
    local phase_num="$1"
    local status="$2"  # OK or FAIL
    local start=${PHASE_START[$phase_num]:-$(date +%s)}
    local elapsed=$(( $(date +%s) - start ))
    PHASE_STATUS[$phase_num]="$status"

    if [[ "$status" == "OK" ]]; then
        log INFO "Phase ${phase_num} completed (${elapsed}s)"
    else
        log WARN "Phase ${phase_num} finished with issues (${elapsed}s)"
    fi
}

should_skip() {
    local phase_num="$1"

    # If --run-phase is specified, skip phases NOT in the list
    if [[ -n "$RUN_PHASES" ]]; then
        # Phase 0 (setup) should always run
        if [[ "$phase_num" == "0" ]]; then
            return 1  # Don't skip
        fi

        # Check if this phase is in the run list
        echo "$RUN_PHASES" | tr ',' '\n' | grep -qx "$phase_num"
        if [[ $? -eq 0 ]]; then
            return 1  # Found in run list, don't skip
        else
            return 0  # Not in run list, skip it
        fi
    fi

    # Otherwise check skip list
    if [[ -n "$SKIP_PHASES" ]]; then
        echo "$SKIP_PHASES" | tr ',' '\n' | grep -qx "$phase_num"
        return $?
    fi
    return 1
}

count_lines() {
    local file="$1"
    if [[ -f "$file" && -s "$file" ]]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

# Merge files into a target, deduplicating
merge_files() {
    local target="$1"
    shift
    local sources=("$@")
    local tmp
    tmp=$(mktemp)

    for src in "${sources[@]}"; do
        if [[ -f "$src" && -s "$src" ]]; then
            cat "$src" >> "$tmp"
        fi
    done

    if [[ -s "$tmp" ]]; then
        sort -u "$tmp" > "$target"
    else
        touch "$target"
    fi
    rm -f "$tmp"
}

# Ensure a command exists
require_cmd() {
    command -v "$1" &>/dev/null
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

usage() {
    echo -e "${BOLD}Usage:${NC} $0 --program <program_name> -d <domain> [options]"
    echo -e "       $0 --program <program_name> --domains-file <file> [options]"
    echo ""
    echo "Options:"
    echo "  --program, -p <name>        Program/bounty name (required)"
    echo "  -d, --domain <domain>       Target domain (use with --program)"
    echo "  --domains-file, -l <file>   File with list of domains (one per line)"
    echo "  -t, --threads <n>           Thread count (default: 50)"
    echo "  --rate-limit <n>            DNS rate limit (default: 300)"
    echo "  --run-phase <n,n,...>       Run ONLY specific phases (e.g., 2,5,7)"
    echo "  --skip-phase <n,n,...>      Skip specific phases (e.g., 5,8)"
    echo "  --only-passive              Run phases 0-3 only"
    echo "  --resume                    Resume using latest output dir"
    echo "  --github-token <token>      GitHub token for code dorking"
    echo "  --wordlist <path>           Custom wordlist path"
    echo "  --resolvers <path>          Custom resolvers file path"
    echo "  -h, --help                  Show this help"
    echo ""
    echo "Output Structure:"
    echo "  Results are saved to: <script_dir>/<program>/<domain>/<timestamp>/"
    echo ""
    echo "Examples:"
    echo "  $0 --program hackerone -d example.com"
    echo "  $0 -p bugcrowd -d target.com --skip-phase 5,8"
    echo "  $0 -p bugcrowd -d target.com --run-phase 2,7,8  # Run only specific phases"
    echo "  $0 -p yahoo --domains-file domains.txt"
    echo "  $0 -p google -d corp.google.com --only-passive"
    echo "  $0 -p meta -d facebook.com -t 100 --rate-limit 1000"
    echo "  $0 -p github -d github.com --github-token ghp_xxx"
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--program)
                PROGRAM="$2"; shift 2 ;;
            -d|--domain)
                DOMAIN="$2"; shift 2 ;;
            -l|--domains-file)
                DOMAINS_FILE="$2"; shift 2 ;;
            -t|--threads)
                THREADS="$2"; shift 2 ;;
            --rate-limit)
                RATE_LIMIT="$2"; shift 2 ;;
            --run-phase)
                RUN_PHASES="$2"; shift 2 ;;
            --skip-phase)
                SKIP_PHASES="$2"; shift 2 ;;
            --only-passive)
                ONLY_PASSIVE=true; shift ;;
            --resume)
                RESUME=true; shift ;;
            --github-token)
                GITHUB_TOKEN="$2"; shift 2 ;;
            --wordlist)
                WORDLIST="$2"; shift 2 ;;
            --resolvers)
                RESOLVERS="$2"; shift 2 ;;
            -h|--help)
                usage ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$PROGRAM" ]]; then
        echo -e "${RED}Error: --program is required.${NC}"
        usage
    fi

    if [[ -z "$DOMAIN" && -z "$DOMAINS_FILE" ]]; then
        echo -e "${RED}Error: Either -d <domain> or --domains-file <file> is required.${NC}"
        usage
    fi

    if [[ -n "$DOMAIN" && -n "$DOMAINS_FILE" ]]; then
        echo -e "${RED}Error: Cannot use both -d and --domains-file at the same time.${NC}"
        usage
    fi

    if [[ -n "$DOMAINS_FILE" && ! -f "$DOMAINS_FILE" ]]; then
        echo -e "${RED}Error: Domains file not found: ${DOMAINS_FILE}${NC}"
        exit 1
    fi

    # Validate conflicting options
    if [[ -n "$RUN_PHASES" && -n "$SKIP_PHASES" ]]; then
        echo -e "${RED}Error: Cannot use both --run-phase and --skip-phase at the same time.${NC}"
        usage
    fi

    if [[ -n "$RUN_PHASES" && "$ONLY_PASSIVE" == true ]]; then
        echo -e "${RED}Error: Cannot use both --run-phase and --only-passive at the same time.${NC}"
        usage
    fi
}

# ============================================================================
# PHASE 0: SETUP & DEPENDENCIES
# ============================================================================

phase0_setup() {
    phase_start 0 "Setup & Dependencies"

    # --- PATH: Ensure Go binaries take precedence ---
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"

    # --- Output directory ---
    # Structure: SCRIPT_DIR/PROGRAM/DOMAIN/TIMESTAMP
    if [[ "$RESUME" == true ]]; then
        # Find latest output dir for this domain under the program
        local latest
        latest=$(ls -dt "${SCRIPT_DIR}/${PROGRAM}/${DOMAIN}/"*/ 2>/dev/null | head -1)
        if [[ -n "$latest" ]]; then
            OUTDIR="${latest%/}"
            log INFO "Resuming from: ${OUTDIR}"
        fi
    fi

    if [[ -z "$OUTDIR" ]]; then
        TIMESTAMP="$(date '+%Y-%m-%d_%H%M%S')"
        OUTDIR="${SCRIPT_DIR}/${PROGRAM}/${DOMAIN}/${TIMESTAMP}"
    fi

    mkdir -p "${OUTDIR}"/{phase1_rootdomain,phase2_passive,phase3_dns,phase4_active,phase5_ports,phase6_web/screenshots,phase6_web/by_status,phase7_content,phase8_vulns,report}
    LOGFILE="${OUTDIR}/recon.log"

    log INFO "Program: ${BOLD}${PROGRAM}${NC}"
    log INFO "Target: ${BOLD}${DOMAIN}${NC}"
    log INFO "Output: ${OUTDIR}"
    log INFO "Threads: ${THREADS} | Rate Limit: ${RATE_LIMIT}"

    # --- Check for pv ---
    if ! require_cmd pv; then
        log WARN "'pv' not installed. Installing..."
        if require_cmd apt; then
            sudo apt-get update -qq && sudo apt-get install -y -qq pv
        elif require_cmd brew; then
            brew install pv
        else
            log WARN "Could not install pv. Progress bars will be unavailable."
        fi
    fi

    # --- Check/Install Go ---
    if ! require_cmd go; then
        log INFO "Go not installed. Installing Go 1.24.0..."
        if curl -fsSL https://go.dev/dl/go1.24.0.linux-amd64.tar.gz -o /tmp/go.tar.gz; then
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf /tmp/go.tar.gz
            rm -f /tmp/go.tar.gz
            export PATH="/usr/local/go/bin:${PATH}"
        else
            log ERROR "Failed to install Go."
            phase_end 0 "FAIL"
            return 1
        fi
    fi
    log INFO "Go: $(go version 2>/dev/null | awk '{print $3}')"

    # --- Check/Install libpcap-dev (needed by naabu) ---
    if ! dpkg -s libpcap-dev &>/dev/null && require_cmd apt-get; then
        log INFO "Installing libpcap-dev (required by naabu)..."
        sudo apt-get install -y -qq libpcap-dev 2>/dev/null || true
    fi

    # --- Check/Install MassDNS ---
    if ! require_cmd massdns; then
        log INFO "Installing MassDNS..."
        (
            cd /tmp || exit
            rm -rf massdns
            git clone --quiet https://github.com/blechschmidt/massdns.git
            cd massdns && make -s && sudo make install -s
            cd /tmp && rm -rf massdns
        ) 2>/dev/null
        if require_cmd massdns; then
            log INFO "MassDNS installed."
        else
            log WARN "MassDNS installation failed."
        fi
    fi

    # --- Check/Install Go Tools ---
    local -A go_tools=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["amass"]="github.com/owasp-amass/amass/v4/...@master"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["puredns"]="github.com/d3mondev/puredns/v2@latest"
        ["alterx"]="github.com/projectdiscovery/alterx/cmd/alterx@latest"
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["anew"]="github.com/tomnomnom/anew@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
    )

    for tool in "${!go_tools[@]}"; do
        if ! require_cmd "$tool"; then
            log INFO "Installing ${tool}..."
            go install -v "${go_tools[$tool]}" 2>/dev/null
            if require_cmd "$tool"; then
                log INFO "${tool} installed."
            else
                log WARN "Failed to install ${tool}."
            fi
        fi
    done

    # --- Wordlist ---
    if [[ ! -f "$WORDLIST" ]]; then
        log INFO "Downloading subdomain wordlist..."
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" -O "$WORDLIST"
    fi

    # --- Resolvers ---
    if [[ ! -f "$RESOLVERS" ]]; then
        log INFO "Downloading resolvers..."
        wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -O "$RESOLVERS"
    fi

    # --- Python deps ---
    if ! python3 -c "import requests" 2>/dev/null; then
        log INFO "Installing Python requests..."
        pip3 install -q requests
    fi
    if ! python3 -c "import bs4" 2>/dev/null; then
        log INFO "Installing Python beautifulsoup4..."
        pip3 install -q beautifulsoup4
    fi

    # --- Nuclei templates (refresh if missing or older than 7 days) ---
    if require_cmd nuclei; then
        local templates_dir="$HOME/nuclei-templates"
        local needs_update=false
        if [[ ! -d "$templates_dir" ]]; then
            needs_update=true
        else
            # Check mtime of the templates directory itself
            local age_days
            age_days=$(( ( $(date +%s) - $(stat -c %Y "$templates_dir" 2>/dev/null || echo 0) ) / 86400 ))
            if [[ "$age_days" -ge 7 ]]; then
                log INFO "Nuclei templates are ${age_days} days old. Refreshing..."
                needs_update=true
            fi
        fi
        if [[ "$needs_update" == true ]]; then
            log INFO "Updating nuclei templates..."
            nuclei -update-templates -silent 2>/dev/null || log WARN "Nuclei template update failed."
        else
            log INFO "Nuclei templates up-to-date (${age_days:-0} days old)."
        fi
    fi

    # --- Directory bruteforce wordlist ---
    if [[ ! -f "$DIRLIST" ]]; then
        log INFO "Downloading directory bruteforce wordlist..."
        wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories-lowercase.txt" \
            -O "$DIRLIST" || log WARN "Could not download DIRLIST; ffuf step will be skipped."
    fi

    phase_end 0 "OK"
}

# ============================================================================
# PHASE 1: ROOT DOMAIN INTELLIGENCE
# ============================================================================

phase1_root_domain() {
    if should_skip 1; then
        log INFO "Skipping Phase 1"
        return 0
    fi

    phase_start 1 "Root Domain Intelligence"
    local dir="${OUTDIR}/phase1_rootdomain"

    # WHOIS lookup
    log INFO "Running WHOIS lookup..."
    if require_cmd whois; then
        whois "$DOMAIN" > "${dir}/whois.txt" 2>/dev/null &
        local whois_pid=$!
    fi

    # ASN enumeration via Python helper
    log INFO "Running ASN enumeration..."
    python3 "${HELPERS_DIR}/asn_enum.py" "$DOMAIN" -o "${dir}" > "${dir}/asn_subdomains.txt" 2>"${dir}/asn_enum.log" &
    local asn_pid=$!

    # Wait for background jobs
    if [[ -n "${whois_pid:-}" ]]; then
        wait "$whois_pid" 2>/dev/null
        log INFO "WHOIS: $(count_lines "${dir}/whois.txt") lines"
    fi

    wait "$asn_pid" 2>/dev/null
    log INFO "ASN subdomains: $(count_lines "${dir}/asn_subdomains.txt")"

    if [[ -f "${dir}/ip_ranges.txt" ]]; then
        log INFO "IP ranges discovered: $(count_lines "${dir}/ip_ranges.txt")"
    fi

    phase_end 1 "OK"
}

# ============================================================================
# PHASE 2: PASSIVE SUBDOMAIN ENUMERATION
# ============================================================================

phase2_passive() {
    if should_skip 2; then
        log INFO "Skipping Phase 2"
        return 0
    fi

    phase_start 2 "Passive Subdomain Enumeration"
    local dir="${OUTDIR}/phase2_passive"
    local pids=()

    # 1. Subfinder
    log INFO "Starting subfinder..."
    subfinder -d "$DOMAIN" -all -silent -o "${dir}/subfinder.txt" 2>/dev/null &
    pids+=($!)

    # 2. Amass (passive only, with timeout)
    if require_cmd amass; then
        log INFO "Starting amass passive..."
        timeout 300 amass enum -passive -d "$DOMAIN" -o "${dir}/amass.txt" 2>/dev/null &
        pids+=($!)
    else
        log WARN "amass not found, skipping."
    fi

    # 3. crt.sh via Python helper
    log INFO "Starting crt.sh lookup..."
    python3 "${HELPERS_DIR}/crtsh_enum.py" "$DOMAIN" -o "${dir}/crtsh.txt" 2>"${dir}/crtsh.log" &
    pids+=($!)

    # 4. Wayback Machine via Python helper
    log INFO "Starting Wayback Machine lookup..."
    python3 "${HELPERS_DIR}/webarchive_enum.py" "$DOMAIN" -o "${dir}/wayback.txt" 2>"${dir}/wayback.log" &
    pids+=($!)

    # 5. Passive APIs (RapidDNS, AlienVault, HackerTarget, URLScan)
    log INFO "Starting passive API queries..."
    python3 "${HELPERS_DIR}/passive_enum.py" "$DOMAIN" -o "${dir}/passive_apis.txt" 2>"${dir}/passive_apis.log" &
    pids+=($!)

    # 6. GitHub dorking (if token provided)
    if [[ -n "$GITHUB_TOKEN" ]]; then
        log INFO "Starting GitHub dorking..."
        python3 "${HELPERS_DIR}/github_dorking.py" "$DOMAIN" --token "$GITHUB_TOKEN" -o "${dir}/github.txt" 2>"${dir}/github.log" &
        pids+=($!)
    else
        log INFO "No GitHub token provided, skipping GitHub dorking."
    fi

    # Wait for all passive sources
    log INFO "Waiting for ${#pids[@]} passive sources to complete..."
    local failed=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            ((failed++))
        fi
    done

    if [[ $failed -gt 0 ]]; then
        log WARN "${failed} passive source(s) had issues."
    fi

    # Report per-source counts
    for src_file in "${dir}"/*.txt; do
        local src_name
        src_name=$(basename "$src_file" .txt)
        log INFO "  ${src_name}: $(count_lines "$src_file") subdomains"
    done

    # Include ASN subdomains from Phase 1
    local asn_subs="${OUTDIR}/phase1_rootdomain/asn_subdomains.txt"

    # Merge all passive sources
    merge_files "${dir}/merged_passive.txt" \
        "${dir}/subfinder.txt" \
        "${dir}/amass.txt" \
        "${dir}/crtsh.txt" \
        "${dir}/wayback.txt" \
        "${dir}/passive_apis.txt" \
        "${dir}/github.txt" \
        "$asn_subs"

    local total
    total=$(count_lines "${dir}/merged_passive.txt")
    log INFO "Total unique passive subdomains: ${BOLD}${total}${NC}"

    phase_end 2 "OK"
}

# ============================================================================
# PHASE 3: DNS RESOLUTION & FILTERING
# ============================================================================

phase3_dns() {
    if should_skip 3; then
        log INFO "Skipping Phase 3"
        return 0
    fi

    phase_start 3 "DNS Resolution & Filtering"
    local dir="${OUTDIR}/phase3_dns"
    local passive_merged="${OUTDIR}/phase2_passive/merged_passive.txt"

    if [[ ! -s "$passive_merged" ]]; then
        log WARN "No passive subdomains to resolve."
        touch "${dir}/resolved.txt"
        phase_end 3 "FAIL"
        return 1
    fi

    # Resolve with puredns
    log INFO "Resolving $(count_lines "$passive_merged") subdomains with puredns..."
    puredns resolve "$passive_merged" \
        -r "$RESOLVERS" \
        --write "${dir}/resolved.txt" \
        --write-wildcards "${dir}/wildcards.txt" \
        --rate-limit "$RATE_LIMIT" \
        2>"${dir}/puredns_resolve.log" || true

    log INFO "Resolved: $(count_lines "${dir}/resolved.txt") alive subdomains"
    log INFO "Wildcards: $(count_lines "${dir}/wildcards.txt")"

    # DNSX for detailed records (two separate runs: text + JSON)
    if require_cmd dnsx && [[ -s "${dir}/resolved.txt" ]]; then
        log INFO "Collecting DNS records with dnsx..."
        dnsx -l "${dir}/resolved.txt" \
            -a -aaaa -cname -mx -ns -txt \
            -resp -silent \
            -threads "$THREADS" \
            -o "${dir}/dns_records.txt" \
            2>/dev/null || true

        dnsx -l "${dir}/resolved.txt" \
            -a -aaaa -cname -mx -ns -txt \
            -resp -silent -json \
            -threads "$THREADS" \
            -o "${dir}/dns_records.json" \
            2>/dev/null || true

        # Extract CNAMEs for potential takeover
        if [[ -s "${dir}/dns_records.txt" ]]; then
            grep "CNAME" "${dir}/dns_records.txt" > "${dir}/cnames.txt" 2>/dev/null || true
            log INFO "CNAME records: $(count_lines "${dir}/cnames.txt")"
        fi
    fi

    phase_end 3 "OK"
}

# ============================================================================
# PHASE 4: ACTIVE DISCOVERY (Bruteforce + Permutations)
# ============================================================================

phase4_active() {
    if should_skip 4; then
        log INFO "Skipping Phase 4"
        return 0
    fi

    if [[ "$ONLY_PASSIVE" == true ]]; then
        log INFO "Skipping Phase 4 (--only-passive)"
        return 0
    fi

    phase_start 4 "Active Discovery (Bruteforce + Permutations)"
    local dir="${OUTDIR}/phase4_active"

    # Bruteforce
    log INFO "Bruteforcing subdomains with puredns..."
    puredns bruteforce "$WORDLIST" "$DOMAIN" \
        -r "$RESOLVERS" \
        --write "${dir}/bruteforce.txt" \
        --rate-limit "$RATE_LIMIT" \
        2>"${dir}/bruteforce.log" || true

    log INFO "Bruteforce found: $(count_lines "${dir}/bruteforce.txt") subdomains"

    # Merge known alive for permutation input
    local resolved="${OUTDIR}/phase3_dns/resolved.txt"
    local known_alive
    known_alive=$(mktemp)

    merge_files "$known_alive" "$resolved" "${dir}/bruteforce.txt"

    # Permutations with alterx
    if require_cmd alterx && [[ -s "$known_alive" ]]; then
        log INFO "Generating permutations with alterx..."
        local permutation_candidates
        permutation_candidates=$(mktemp)

        alterx -l "$known_alive" -silent > "$permutation_candidates" 2>/dev/null

        if [[ -s "$permutation_candidates" ]]; then
            local perm_count
            perm_count=$(count_lines "$permutation_candidates")
            log INFO "Resolving ${perm_count} permutation candidates..."
            puredns resolve "$permutation_candidates" \
                -r "$RESOLVERS" \
                --write "${dir}/permutations.txt" \
                --rate-limit "$RATE_LIMIT" \
                2>"${dir}/permutations.log" || true

            log INFO "Permutations resolved: $(count_lines "${dir}/permutations.txt")"
        else
            touch "${dir}/permutations.txt"
        fi
        rm -f "$permutation_candidates"
    else
        touch "${dir}/permutations.txt"
    fi

    rm -f "$known_alive"

    phase_end 4 "OK"
}

# ============================================================================
# MASTER SUBDOMAIN MERGE (between Phase 4 and 5)
# ============================================================================

merge_master() {
    log PHASE "Merging Master Subdomain List"

    local master="${OUTDIR}/master_subdomains.txt"

    merge_files "$master" \
        "${OUTDIR}/phase3_dns/resolved.txt" \
        "${OUTDIR}/phase4_active/bruteforce.txt" \
        "${OUTDIR}/phase4_active/permutations.txt"

    local total
    total=$(count_lines "$master")
    log INFO "Master subdomain list: ${BOLD}${total}${NC} unique live subdomains"
}

# ============================================================================
# PHASE 5: PORT SCANNING
# ============================================================================

phase5_ports() {
    if should_skip 5; then
        log INFO "Skipping Phase 5"
        return 0
    fi

    if [[ "$ONLY_PASSIVE" == true ]]; then
        log INFO "Skipping Phase 5 (--only-passive)"
        return 0
    fi

    phase_start 5 "Port Scanning"
    local dir="${OUTDIR}/phase5_ports"
    local master="${OUTDIR}/master_subdomains.txt"

    if [[ ! -s "$master" ]]; then
        log WARN "No subdomains to port scan."
        phase_end 5 "FAIL"
        return 1
    fi

    if ! require_cmd naabu; then
        log WARN "naabu not found. Skipping port scanning."
        phase_end 5 "FAIL"
        return 1
    fi

    local sub_count
    sub_count=$(count_lines "$master")
    log INFO "Scanning ports on ${sub_count} hosts with naabu..."

    naabu -list "$master" \
        -top-ports 1000 \
        -rate "$RATE_LIMIT" \
        -silent \
        -o "${dir}/naabu_scan.txt" \
        2>"${dir}/naabu.log" || true

    log INFO "Open ports found: $(count_lines "${dir}/naabu_scan.txt") host:port entries"

    # Extract unique hosts with open ports
    if [[ -s "${dir}/naabu_scan.txt" ]]; then
        cut -d':' -f1 "${dir}/naabu_scan.txt" | sort -u > "${dir}/hosts_with_ports.txt"
        log INFO "Hosts with open ports: $(count_lines "${dir}/hosts_with_ports.txt")"
    fi

    phase_end 5 "OK"
}

# ============================================================================
# PHASE 6: WEB PROBING
# ============================================================================

phase6_web() {
    if should_skip 6; then
        log INFO "Skipping Phase 6"
        return 0
    fi

    if [[ "$ONLY_PASSIVE" == true ]]; then
        log INFO "Skipping Phase 6 (--only-passive)"
        return 0
    fi

    phase_start 6 "Web Probing"
    local dir="${OUTDIR}/phase6_web"
    local master="${OUTDIR}/master_subdomains.txt"

    if [[ ! -s "$master" ]]; then
        log WARN "No subdomains to probe."
        phase_end 6 "FAIL"
        return 1
    fi

    if ! require_cmd httpx; then
        log WARN "httpx not found. Skipping web probing."
        phase_end 6 "FAIL"
        return 1
    fi

    # Build input: if we have port scan data, use host:port pairs
    local probe_input="$master"
    local naabu_scan="${OUTDIR}/phase5_ports/naabu_scan.txt"
    if [[ -s "$naabu_scan" ]]; then
        # Combine master list (default ports) with specific port discoveries
        local combined
        combined=$(mktemp)
        cat "$master" "$naabu_scan" | sort -u > "$combined"
        probe_input="$combined"
    fi

    local probe_count
    probe_count=$(count_lines "$probe_input")
    log INFO "Probing ${probe_count} targets with httpx..."

    # HTTPX JSON run (primary output - all data)
    httpx -l "$probe_input" \
        -title -status-code -ip -cname -tech-detect -web-server \
        -content-length -content-type \
        -favicon -jarm \
        -cdn \
        -follow-redirects \
        -random-agent \
        -threads "$THREADS" \
        -silent \
        -json \
        -o "${dir}/httpx_output.json" \
        2>"${dir}/httpx.log" || true

    # Clean up temp file
    if [[ -n "${combined:-}" ]]; then
        rm -f "$combined"
    fi

    # Check for empty output and log the httpx error log for debugging
    if [[ ! -s "${dir}/httpx_output.json" ]]; then
        log WARN "httpx produced no JSON output. Check ${dir}/httpx.log for details:"
        if [[ -s "${dir}/httpx.log" ]]; then
            head -20 "${dir}/httpx.log" | while IFS= read -r line; do
                log WARN "  [httpx] ${line}"
            done
        fi
        phase_end 6 "FAIL"
        return 1
    fi

    # Parse JSON output via helper: derives text summary, live_urls.txt,
    # and per-status-code files in by_status/
    python3 "${HELPERS_DIR}/httpx_parse.py" "${dir}/httpx_output.json" \
        --text-out   "${dir}/httpx_output.txt" \
        --urls-out   "${dir}/live_urls.txt" \
        --status-dir "${dir}/by_status" \
        2>"${dir}/httpx_parse.log" || true

    local web_count
    web_count=$(count_lines "${dir}/httpx_output.txt")
    log INFO "Web assets found: ${web_count}"

    if [[ "$web_count" -gt 0 ]]; then
        log INFO "  200 OK:        $(count_lines "${dir}/by_status/200.txt")"
        log INFO "  301 Redirect:  $(count_lines "${dir}/by_status/301.txt")"
        log INFO "  302 Redirect:  $(count_lines "${dir}/by_status/302.txt")"
        log INFO "  403 Forbidden: $(count_lines "${dir}/by_status/403.txt")"
        log INFO "  500 Error:     $(count_lines "${dir}/by_status/500.txt")"
    fi

    phase_end 6 "OK"
}

# ============================================================================
# PHASE 7: CONTENT DISCOVERY
# ============================================================================

phase7_content() {
    if should_skip 7; then
        log INFO "Skipping Phase 7"
        return 0
    fi

    if [[ "$ONLY_PASSIVE" == true ]]; then
        log INFO "Skipping Phase 7 (--only-passive)"
        return 0
    fi

    phase_start 7 "Content Discovery"
    local dir="${OUTDIR}/phase7_content"
    local live_urls="${OUTDIR}/phase6_web/live_urls.txt"

    if [[ ! -s "$live_urls" ]]; then
        log WARN "No live URLs for content discovery."
        phase_end 7 "FAIL"
        return 1
    fi

    local pids=()

    # 1. Katana spider/crawl
    if require_cmd katana; then
        log INFO "Starting katana crawl..."
        katana -list "$live_urls" \
            -depth 3 \
            -js-crawl \
            -known-files all \
            -silent \
            -concurrency "$THREADS" \
            -o "${dir}/katana_urls.txt" \
            2>"${dir}/katana.log" &
        pids+=($!)
    else
        log WARN "katana not found, skipping crawl."
    fi

    # 2. GAU historical URLs
    if require_cmd gau; then
        log INFO "Starting gau historical URL fetch..."
        echo "$DOMAIN" | gau --threads "$THREADS" --o "${dir}/gau_urls.txt" 2>"${dir}/gau.log" &
        pids+=($!)
    else
        log WARN "gau not found, skipping historical URLs."
    fi

    # Wait for content discovery tools
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    log INFO "Katana URLs: $(count_lines "${dir}/katana_urls.txt")"
    log INFO "GAU URLs: $(count_lines "${dir}/gau_urls.txt")"

    # 3. FFUF directory bruteforce on live 200/403 targets
    local live_200="${OUTDIR}/phase6_web/by_status/200.txt"
    local live_403="${OUTDIR}/phase6_web/by_status/403.txt"
    if require_cmd ffuf && [[ -f "$DIRLIST" && -s "$DIRLIST" ]]; then
        # Collect unique base URLs (scheme://host) from 200 and 403 responses
        local ffuf_targets
        ffuf_targets=$(mktemp)
        python3 - "$live_200" "$live_403" <<'PYEOF' 2>/dev/null | head -20 > "$ffuf_targets"
import sys
from urllib.parse import urlparse
seen = set()
for path in sys.argv[1:]:
    try:
        with open(path) as fh:
            for line in fh:
                url = line.strip()
                if not url:
                    continue
                p = urlparse(url)
                if p.scheme and p.netloc:
                    base = f"{p.scheme}://{p.netloc}"
                    if base not in seen:
                        seen.add(base)
                        print(base)
    except OSError:
        pass
PYEOF

        local ffuf_target_count
        ffuf_target_count=$(count_lines "$ffuf_targets")

        if [[ "$ffuf_target_count" -gt 0 ]]; then
            mkdir -p "${dir}/ffuf"
            log INFO "Running ffuf on ${ffuf_target_count} base URLs (directory bruteforce)..."

            while IFS= read -r base_url; do
                local safe_name
                safe_name=$(echo "$base_url" | sed 's|https\?://||; s|[/:]|_|g')
                ffuf -u "${base_url}/FUZZ" \
                    -w "$DIRLIST" \
                    -mc 200,301,302,403,500 \
                    -t 30 \
                    -rate 100 \
                    -of json \
                    -o "${dir}/ffuf/${safe_name}.json" \
                    -s \
                    2>/dev/null || true
            done < "$ffuf_targets"

            # Parse all ffuf JSON files into a single results file
            if ls "${dir}/ffuf/"*.json &>/dev/null; then
                python3 "${HELPERS_DIR}/ffuf_parse.py" "${dir}/ffuf" \
                    --output "${dir}/ffuf_results.txt" \
                    2>/dev/null || true
                log INFO "FFUF directory findings: $(count_lines "${dir}/ffuf_results.txt")"
            else
                log WARN "FFUF produced no output files."
            fi
        else
            log INFO "No 200/403 targets found for ffuf; skipping directory bruteforce."
        fi
        rm -f "$ffuf_targets"
    else
        if ! require_cmd ffuf; then
            log WARN "ffuf not found; skipping directory bruteforce."
        else
            log WARN "DIRLIST not found (${DIRLIST}); skipping directory bruteforce."
        fi
    fi

    # Merge all discovered URLs (katana + gau)
    merge_files "${dir}/all_urls.txt" \
        "${dir}/katana_urls.txt" \
        "${dir}/gau_urls.txt"

    log INFO "Total unique URLs: $(count_lines "${dir}/all_urls.txt")"

    # Extract JS file URLs
    if [[ -s "${dir}/all_urls.txt" ]]; then
        grep -iE '\.js(\?|$)' "${dir}/all_urls.txt" | sort -u > "${dir}/js_files.txt" 2>/dev/null || true
        log INFO "JavaScript files: $(count_lines "${dir}/js_files.txt")"
    fi

    # Run JSAnalyzer on discovered JS files
    if [[ -s "${dir}/js_files.txt" ]]; then
        local js_count
        js_count=$(count_lines "${dir}/js_files.txt")
        log INFO "Analyzing ${js_count} JavaScript files for endpoints, secrets, and URLs..."

        # Run jsanalyzer.py and capture output
        if [[ -f "${SCRIPT_DIR}/jsanalyzer.py" ]]; then
            python3 "${SCRIPT_DIR}/jsanalyzer.py" "${dir}/js_files.txt" > "${dir}/js_analysis.txt" 2>/dev/null || true

            if [[ -s "${dir}/js_analysis.txt" ]]; then
                # Extract structured findings for easier analysis
                grep -i "^\[ENDPOINT\]" "${dir}/js_analysis.txt" | cut -d']' -f2- | sed 's/^ *//' | sort -u > "${dir}/js_endpoints.txt" 2>/dev/null || true
                grep -i "^\[URL\]" "${dir}/js_analysis.txt" | cut -d']' -f2- | sed 's/^ *//' | sort -u > "${dir}/js_urls.txt" 2>/dev/null || true
                grep -i "^\[SECRET\]" "${dir}/js_analysis.txt" | cut -d']' -f2- | sed 's/^ *//' | sort -u > "${dir}/js_secrets.txt" 2>/dev/null || true
                grep -i "^\[EMAIL\]" "${dir}/js_analysis.txt" | cut -d']' -f2- | sed 's/^ *//' | sort -u > "${dir}/js_emails.txt" 2>/dev/null || true
                grep -i "^\[FILE\]" "${dir}/js_analysis.txt" | cut -d']' -f2- | sed 's/^ *//' | sort -u > "${dir}/js_files_found.txt" 2>/dev/null || true

                log INFO "  Endpoints: $(count_lines "${dir}/js_endpoints.txt")"
                log INFO "  URLs: $(count_lines "${dir}/js_urls.txt")"
                log INFO "  Secrets: $(count_lines "${dir}/js_secrets.txt")"
                log INFO "  Emails: $(count_lines "${dir}/js_emails.txt")"
                log INFO "  Files: $(count_lines "${dir}/js_files_found.txt")"
            else
                log WARN "JS analysis produced no output"
            fi
        else
            log WARN "jsanalyzer.py not found at ${SCRIPT_DIR}/jsanalyzer.py. Skipping JS analysis."
        fi
    else
        log INFO "No JavaScript files to analyze"
    fi

    phase_end 7 "OK"
}

# ============================================================================
# PHASE 8: VULNERABILITY SCANNING
# ============================================================================

phase8_vulns() {
    if should_skip 8; then
        log INFO "Skipping Phase 8"
        return 0
    fi

    if [[ "$ONLY_PASSIVE" == true ]]; then
        log INFO "Skipping Phase 8 (--only-passive)"
        return 0
    fi

    phase_start 8 "Vulnerability Scanning"
    local dir="${OUTDIR}/phase8_vulns"
    local live_urls="${OUTDIR}/phase6_web/live_urls.txt"

    if ! require_cmd nuclei; then
        log WARN "nuclei not found. Skipping vulnerability scanning."
        phase_end 8 "FAIL"
        return 1
    fi

    if [[ ! -s "$live_urls" ]]; then
        log WARN "No live URLs for vulnerability scanning."
        phase_end 8 "FAIL"
        return 1
    fi

    local url_count
    url_count=$(count_lines "$live_urls")
    log INFO "Running nuclei on ${url_count} live URLs..."

    # Run nuclei with all severities, JSON output
    nuclei -l "$live_urls" \
        -severity info,low,medium,high,critical \
        -silent \
        -concurrency "$THREADS" \
        -json \
        -o "${dir}/nuclei_all.json" \
        2>"${dir}/nuclei.log" || true

    # Parse JSON output: derive text summary + per-severity JSON files
    if [[ -s "${dir}/nuclei_all.json" ]]; then
        python3 "${HELPERS_DIR}/nuclei_parse.py" "${dir}/nuclei_all.json" \
            --text-out    "${dir}/nuclei_all.txt" \
            --severity-dir "${dir}" \
            2>"${dir}/nuclei_parse.log" || true
    fi

    log INFO "Total findings: $(count_lines "${dir}/nuclei_all.txt")"

    for severity in critical high medium low info; do
        local sev_count
        sev_count=$(count_lines "${dir}/nuclei_${severity}.json")
        if [[ "$sev_count" -gt 0 ]]; then
            log INFO "  ${severity^^}: ${sev_count} findings"
        fi
    done

    phase_end 8 "OK"
}

# ============================================================================
# PHASE 9: CERTSTREAM MONITOR (Standalone Daemon)
# ============================================================================

phase9_certstream() {
    if should_skip 9; then
        log INFO "Skipping Phase 9"
        return 0
    fi

    phase_start 9 "Certstream Monitor (Background)"

    # Check for websocket-client
    if ! python3 -c "import websocket" 2>/dev/null; then
        log WARN "websocket-client not installed. Installing..."
        pip3 install -q websocket-client 2>/dev/null
        if ! python3 -c "import websocket" 2>/dev/null; then
            log WARN "Could not install websocket-client. Skipping certstream."
            phase_end 9 "FAIL"
            return 1
        fi
    fi

    local certstream_out="${OUTDIR}/phase2_passive/certstream.txt"
    local certstream_pid_file="${OUTDIR}/certstream.pid"

    log INFO "Starting certstream monitor in background (60s sample)..."
    python3 "${HELPERS_DIR}/certstream_monitor.py" \
        --domains "$DOMAIN" \
        -o "$certstream_out" \
        --duration 60 \
        2>"${OUTDIR}/certstream.log" &
    local cs_pid=$!
    CERTSTREAM_PID="$cs_pid"          # global so cleanup_exit can kill it
    echo "$cs_pid" > "$certstream_pid_file"
    log INFO "Certstream PID: ${cs_pid} (output: ${certstream_out})"
    log INFO "To run indefinitely later: python3 ${HELPERS_DIR}/certstream_monitor.py --domains ${DOMAIN} -o certs.txt"

    # Don't wait - let it run in background during other phases.
    # It auto-stops after --duration seconds; cleanup_exit handles early termination.

    phase_end 9 "OK"
}

# ============================================================================
# PHASE 10: REPORTING
# ============================================================================

phase10_reporting() {
    phase_start 10 "Reporting & Summary"
    local report_dir="${OUTDIR}/report"
    local master="${OUTDIR}/master_subdomains.txt"

    # Wait for certstream (started in phase 9) to finish before reporting
    local certstream_pid_file="${OUTDIR}/certstream.pid"
    if [[ -n "$CERTSTREAM_PID" ]] && kill -0 "$CERTSTREAM_PID" 2>/dev/null; then
        log INFO "Waiting for certstream monitor to finish (max 90s)..."
        local waited=0
        while kill -0 "$CERTSTREAM_PID" 2>/dev/null && [[ $waited -lt 90 ]]; do
            sleep 1
            waited=$((waited + 1))
        done
        if kill -0 "$CERTSTREAM_PID" 2>/dev/null; then
            log WARN "Certstream still running after 90s; letting cleanup_exit handle it."
        fi
        CERTSTREAM_PID=""
    fi
    rm -f "$certstream_pid_file"

    # Merge certstream findings into master
    local cs_out="${OUTDIR}/phase2_passive/certstream.txt"
    if [[ -s "$cs_out" && -s "$master" ]]; then
        cat "$cs_out" >> "$master"
        sort -u "$master" -o "$master"
    fi

    # Mark Phase 10 status before generating the summary table
    PHASE_STATUS[10]="OK"

    # Build summary
    local summary="${report_dir}/summary.txt"
    {
        echo "=============================================="
        echo "  BEAST MODE RECON - SUMMARY REPORT"
        echo "=============================================="
        echo ""
        echo "Program:    ${PROGRAM}"
        echo "Target:     ${DOMAIN}"
        echo "Date:       $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Output Dir: ${OUTDIR}"
        echo ""
        echo "----------------------------------------------"
        echo "  SUBDOMAIN COUNTS"
        echo "----------------------------------------------"
        echo "Passive sources:"
        for src in subfinder amass crtsh wayback passive_apis github certstream; do
            local f="${OUTDIR}/phase2_passive/${src}.txt"
            if [[ -f "$f" ]]; then
                printf "  %-20s %s\n" "${src}:" "$(count_lines "$f")"
            fi
        done
        echo ""
        echo "Merged passive:      $(count_lines "${OUTDIR}/phase2_passive/merged_passive.txt" 2>/dev/null)"
        echo "Resolved (alive):    $(count_lines "${OUTDIR}/phase3_dns/resolved.txt" 2>/dev/null)"
        echo "Bruteforce:          $(count_lines "${OUTDIR}/phase4_active/bruteforce.txt" 2>/dev/null)"
        echo "Permutations:        $(count_lines "${OUTDIR}/phase4_active/permutations.txt" 2>/dev/null)"
        echo "MASTER TOTAL:        $(count_lines "$master" 2>/dev/null)"
        echo ""
        echo "----------------------------------------------"
        echo "  INFRASTRUCTURE"
        echo "----------------------------------------------"
        echo "IP ranges (ASN):     $(count_lines "${OUTDIR}/phase1_rootdomain/ip_ranges.txt" 2>/dev/null)"
        echo "Open ports (naabu):  $(count_lines "${OUTDIR}/phase5_ports/naabu_scan.txt" 2>/dev/null)"
        echo "Web assets (httpx):  $(count_lines "${OUTDIR}/phase6_web/httpx_output.txt" 2>/dev/null)"
        echo ""
        echo "----------------------------------------------"
        echo "  CONTENT & VULNS"
        echo "----------------------------------------------"
        echo "URLs discovered:     $(count_lines "${OUTDIR}/phase7_content/all_urls.txt" 2>/dev/null)"
        echo "JS files:            $(count_lines "${OUTDIR}/phase7_content/js_files.txt" 2>/dev/null)"
        echo "FFUF dir findings:   $(count_lines "${OUTDIR}/phase7_content/ffuf_results.txt" 2>/dev/null)"
        echo "Nuclei findings:     $(count_lines "${OUTDIR}/phase8_vulns/nuclei_all.txt" 2>/dev/null)"
        for sev in critical high medium low info; do
            local sev_file="${OUTDIR}/phase8_vulns/nuclei_${sev}.json"
            if [[ -f "$sev_file" && -s "$sev_file" ]]; then
                printf "  %-20s %s\n" "${sev^^}:" "$(count_lines "$sev_file")"
            fi
        done
        echo ""
        echo "----------------------------------------------"
        echo "  PHASE STATUS"
        echo "----------------------------------------------"
        for phase_num in 0 1 2 3 4 5 6 7 8 9 10; do
            local status="${PHASE_STATUS[$phase_num]:-SKIPPED}"
            printf "  Phase %-2s: %s\n" "$phase_num" "$status"
        done
        echo ""
        echo "=============================================="
    } > "$summary"

    # Display summary
    cat "$summary"

    # Save a JSON stats file via helper
    python3 "${HELPERS_DIR}/stats_gen.py" \
        --program "${PROGRAM}" \
        --domain  "${DOMAIN}" \
        --outdir  "${OUTDIR}" \
        --output  "${report_dir}/stats.json" \
        2>/dev/null || true

    # Generate consolidated domain report
    generate_consolidated_report

    phase_end 10 "OK"
}

# ============================================================================
# CONSOLIDATED DOMAIN REPORT
# ============================================================================

generate_consolidated_report() {
    log INFO "Generating consolidated domain report..."
    local consolidated="${OUTDIR}/${DOMAIN}_consolidated_report.txt"

    {
        echo "╔══════════════════════════════════════════════════════════════════════════╗"
        echo "║                    CONSOLIDATED RECONNAISSANCE REPORT                     ║"
        echo "╚══════════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  BASIC INFORMATION"
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "Program:          ${PROGRAM}"
        echo "Target Domain:    ${DOMAIN}"
        echo "Scan Date:        $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Output Directory: ${OUTDIR}"
        echo ""

        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  DISCOVERY SUMMARY"
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "Total Subdomains:     $(count_lines "${OUTDIR}/master_subdomains.txt" 2>/dev/null)"
        echo "Live Web Assets:      $(count_lines "${OUTDIR}/phase6_web/live_urls.txt" 2>/dev/null)"
        echo "Open Ports:           $(count_lines "${OUTDIR}/phase5_ports/naabu_scan.txt" 2>/dev/null)"
        echo "URLs Discovered:      $(count_lines "${OUTDIR}/phase7_content/all_urls.txt" 2>/dev/null)"
        echo "JS Files Analyzed:    $(count_lines "${OUTDIR}/phase7_content/js_files.txt" 2>/dev/null)"
        echo "FFUF Dir Findings:    $(count_lines "${OUTDIR}/phase7_content/ffuf_results.txt" 2>/dev/null)"
        echo "Vulnerabilities:      $(count_lines "${OUTDIR}/phase8_vulns/nuclei_all.txt" 2>/dev/null)"
        echo ""

        # ASN Information
        if [[ -f "${OUTDIR}/phase1_rootdomain/asn_info.json" ]]; then
            echo "═══════════════════════════════════════════════════════════════════════════"
            echo "  ASN INFORMATION"
            echo "═══════════════════════════════════════════════════════════════════════════"
            python3 - "${OUTDIR}/phase1_rootdomain/asn_info.json" <<'PYEOF' 2>/dev/null || echo "ASN information not available"
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    asns     = data.get('asns', [])
    prefixes = data.get('prefixes', [])
    print('Domain IP:        {}'.format(data.get('ip', 'N/A')))
    if asns:
        for entry in asns:
            print('ASN Number:       {}'.format(entry.get('asn', 'N/A')))
            print('ASN Org:          {}'.format(entry.get('org', 'N/A')))
    else:
        print('ASN Number:       N/A')
        print('ASN Org:          N/A')
    print('IP Ranges:        {} CIDR blocks'.format(len(prefixes)))
except Exception as e:
    print('ASN information not available ({})'.format(e))
PYEOF
            echo ""
        fi

        # All Discovered Subdomains
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  ALL DISCOVERED SUBDOMAINS ($(count_lines "${OUTDIR}/master_subdomains.txt" 2>/dev/null))"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/master_subdomains.txt" ]]; then
            head -100 "${OUTDIR}/master_subdomains.txt" 2>/dev/null || echo "No subdomains found"
            local total_subs
            total_subs=$(count_lines "${OUTDIR}/master_subdomains.txt" 2>/dev/null)
            if [[ $total_subs -gt 100 ]]; then
                echo ""
                echo "... and $((total_subs - 100)) more subdomains"
                echo "(See master_subdomains.txt for full list)"
            fi
        else
            echo "No subdomains discovered"
        fi
        echo ""

        # Live Web URLs
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  LIVE WEB URLS ($(count_lines "${OUTDIR}/phase6_web/live_urls.txt" 2>/dev/null))"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase6_web/live_urls.txt" && -s "${OUTDIR}/phase6_web/live_urls.txt" ]]; then
            head -50 "${OUTDIR}/phase6_web/live_urls.txt" 2>/dev/null || echo "No live URLs found"
            local total_urls
            total_urls=$(count_lines "${OUTDIR}/phase6_web/live_urls.txt" 2>/dev/null)
            if [[ $total_urls -gt 50 ]]; then
                echo ""
                echo "... and $((total_urls - 50)) more URLs"
                echo "(See phase6_web/live_urls.txt for full list)"
            fi
        else
            echo "No live URLs found"
        fi
        echo ""

        # Status Code Breakdown
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  STATUS CODE BREAKDOWN"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -d "${OUTDIR}/phase6_web/by_status" ]]; then
            for status_file in "${OUTDIR}/phase6_web/by_status"/*.txt; do
                if [[ -f "$status_file" && -s "$status_file" ]]; then
                    local status_code
                    status_code=$(basename "$status_file" .txt)
                    printf "  Status %-4s: %s URLs\n" "$status_code" "$(count_lines "$status_file")"
                fi
            done
        else
            echo "No status code data available"
        fi
        echo ""

        # Open Ports Summary
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  OPEN PORTS (Top 20)"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase5_ports/naabu_scan.txt" && -s "${OUTDIR}/phase5_ports/naabu_scan.txt" ]]; then
            head -20 "${OUTDIR}/phase5_ports/naabu_scan.txt" 2>/dev/null
            local total_ports
            total_ports=$(count_lines "${OUTDIR}/phase5_ports/naabu_scan.txt" 2>/dev/null)
            if [[ $total_ports -gt 20 ]]; then
                echo "... and $((total_ports - 20)) more open ports"
                echo "(See phase5_ports/naabu_scan.txt for full list)"
            fi
        else
            echo "No open ports found"
        fi
        echo ""

        # JavaScript Analysis - Endpoints
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  JAVASCRIPT ANALYSIS - API ENDPOINTS"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase7_content/js_endpoints.txt" && -s "${OUTDIR}/phase7_content/js_endpoints.txt" ]]; then
            echo "Total Endpoints: $(count_lines "${OUTDIR}/phase7_content/js_endpoints.txt")"
            echo ""
            head -30 "${OUTDIR}/phase7_content/js_endpoints.txt" 2>/dev/null
            local total_endpoints
            total_endpoints=$(count_lines "${OUTDIR}/phase7_content/js_endpoints.txt" 2>/dev/null)
            if [[ $total_endpoints -gt 30 ]]; then
                echo "... and $((total_endpoints - 30)) more endpoints"
                echo "(See phase7_content/js_endpoints.txt for full list)"
            fi
        else
            echo "No endpoints found in JavaScript files"
        fi
        echo ""

        # JavaScript Analysis - URLs
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  JAVASCRIPT ANALYSIS - URLS"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase7_content/js_urls.txt" && -s "${OUTDIR}/phase7_content/js_urls.txt" ]]; then
            echo "Total URLs: $(count_lines "${OUTDIR}/phase7_content/js_urls.txt")"
            echo ""
            head -20 "${OUTDIR}/phase7_content/js_urls.txt" 2>/dev/null
            local total_js_urls
            total_js_urls=$(count_lines "${OUTDIR}/phase7_content/js_urls.txt" 2>/dev/null)
            if [[ $total_js_urls -gt 20 ]]; then
                echo "... and $((total_js_urls - 20)) more URLs"
                echo "(See phase7_content/js_urls.txt for full list)"
            fi
        else
            echo "No URLs found in JavaScript files"
        fi
        echo ""

        # JavaScript Analysis - Secrets
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  JAVASCRIPT ANALYSIS - SECRETS & API KEYS (*** HIGH PRIORITY ***)"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase7_content/js_secrets.txt" && -s "${OUTDIR}/phase7_content/js_secrets.txt" ]]; then
            echo "⚠️  TOTAL SECRETS FOUND: $(count_lines "${OUTDIR}/phase7_content/js_secrets.txt")"
            echo ""
            cat "${OUTDIR}/phase7_content/js_secrets.txt" 2>/dev/null
        else
            echo "✓ No secrets found in JavaScript files"
        fi
        echo ""

        # JavaScript Analysis - Emails
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  JAVASCRIPT ANALYSIS - EMAIL ADDRESSES"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase7_content/js_emails.txt" && -s "${OUTDIR}/phase7_content/js_emails.txt" ]]; then
            echo "Total Emails: $(count_lines "${OUTDIR}/phase7_content/js_emails.txt")"
            echo ""
            head -20 "${OUTDIR}/phase7_content/js_emails.txt" 2>/dev/null
            local total_emails
            total_emails=$(count_lines "${OUTDIR}/phase7_content/js_emails.txt" 2>/dev/null)
            if [[ $total_emails -gt 20 ]]; then
                echo "... and $((total_emails - 20)) more emails"
                echo "(See phase7_content/js_emails.txt for full list)"
            fi
        else
            echo "No email addresses found"
        fi
        echo ""

        # JavaScript Analysis - Interesting Files
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  JAVASCRIPT ANALYSIS - INTERESTING FILES"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase7_content/js_files_found.txt" && -s "${OUTDIR}/phase7_content/js_files_found.txt" ]]; then
            echo "Total Files: $(count_lines "${OUTDIR}/phase7_content/js_files_found.txt")"
            echo ""
            cat "${OUTDIR}/phase7_content/js_files_found.txt" 2>/dev/null
        else
            echo "No interesting file paths found"
        fi
        echo ""

        # CNAME Records (Subdomain Takeover Candidates)
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  CNAME RECORDS (Potential Subdomain Takeover)"
        echo "═══════════════════════════════════════════════════════════════════════════"
        if [[ -f "${OUTDIR}/phase3_dns/cnames.txt" && -s "${OUTDIR}/phase3_dns/cnames.txt" ]]; then
            echo "Total CNAMEs: $(count_lines "${OUTDIR}/phase3_dns/cnames.txt")"
            echo ""
            head -30 "${OUTDIR}/phase3_dns/cnames.txt" 2>/dev/null
            local total_cnames
            total_cnames=$(count_lines "${OUTDIR}/phase3_dns/cnames.txt" 2>/dev/null)
            if [[ $total_cnames -gt 30 ]]; then
                echo "... and $((total_cnames - 30)) more CNAMEs"
                echo "(See phase3_dns/cnames.txt for full list)"
            fi
        else
            echo "No CNAME records found"
        fi
        echo ""

        # Vulnerabilities - Critical
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  CRITICAL VULNERABILITIES (*** IMMEDIATE ACTION REQUIRED ***)"
        echo "═══════════════════════════════════════════════════════════════════════════"
        local crit_file="${OUTDIR}/phase8_vulns/nuclei_critical.json"
        if [[ -f "$crit_file" && -s "$crit_file" ]]; then
            echo "CRITICAL FINDINGS: $(count_lines "$crit_file")"
            echo ""
            python3 - "$crit_file" <<'PYEOF' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1]) as f:
        for line in f:
            try:
                obj = json.loads(line)
                tid     = obj.get('template-id', 'unknown')
                name    = obj.get('info', {}).get('name', 'Unknown')
                matched = obj.get('matched-at', 'N/A')
                print(f'[{tid}] {name}')
                print(f'  -> {matched}')
                print()
            except Exception:
                pass
except Exception:
    print('No critical vulnerabilities')
PYEOF
        else
            echo "No critical vulnerabilities found"
        fi
        echo ""

        # Vulnerabilities - High
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  HIGH SEVERITY VULNERABILITIES"
        echo "═══════════════════════════════════════════════════════════════════════════"
        local high_file="${OUTDIR}/phase8_vulns/nuclei_high.json"
        if [[ -f "$high_file" && -s "$high_file" ]]; then
            echo "HIGH SEVERITY FINDINGS: $(count_lines "$high_file")"
            echo ""
            python3 - "$high_file" <<'PYEOF' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1]) as f:
        for line in f:
            try:
                obj = json.loads(line)
                tid     = obj.get('template-id', 'unknown')
                name    = obj.get('info', {}).get('name', 'Unknown')
                matched = obj.get('matched-at', 'N/A')
                print(f'[{tid}] {name}')
                print(f'  -> {matched}')
                print()
            except Exception:
                pass
except Exception:
    print('No high severity vulnerabilities')
PYEOF
        else
            echo "No high severity vulnerabilities found"
        fi
        echo ""

        # Vulnerability Summary
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  VULNERABILITY SUMMARY (All Severities)"
        echo "═══════════════════════════════════════════════════════════════════════════"
        for sev in critical high medium low info; do
            local sev_file="${OUTDIR}/phase8_vulns/nuclei_${sev}.json"
            if [[ -f "$sev_file" ]]; then
                printf "  %-10s: %s findings\n" "${sev^^}" "$(count_lines "$sev_file" 2>/dev/null)"
            fi
        done
        echo ""
        echo "See phase8_vulns/ for detailed vulnerability reports"
        echo ""

        # Next Steps
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  RECOMMENDED NEXT STEPS"
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "1. Review and validate all CRITICAL and HIGH severity vulnerabilities"
        echo "2. Check for exposed secrets in phase7_content/js_secrets.txt"
        echo "3. Test CNAME records for subdomain takeover vulnerabilities"
        echo "4. Manually verify interesting API endpoints from JavaScript analysis"
        echo "5. Review open ports for unnecessary services"
        echo "6. Investigate FFUF directory findings in phase7_content/ffuf_results.txt"
        echo "7. Test discovered admin/debug/internal endpoints"
        echo "8. Analyze URLs for potential injection points"
        echo "9. Check for outdated software versions in httpx output"
        echo ""

        # File Locations
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "  DETAILED OUTPUT LOCATIONS"
        echo "═══════════════════════════════════════════════════════════════════════════"
        echo "Master Subdomains:    master_subdomains.txt"
        echo "Live URLs:            phase6_web/live_urls.txt"
        echo "Open Ports:           phase5_ports/naabu_scan.txt"
        echo "JS Endpoints:         phase7_content/js_endpoints.txt"
        echo "JS Secrets:           phase7_content/js_secrets.txt"
        echo "FFUF Dir Results:     phase7_content/ffuf_results.txt"
        echo "Critical Vulns:       phase8_vulns/nuclei_critical.json"
        echo "High Vulns:           phase8_vulns/nuclei_high.json"
        echo "Full Summary:         report/summary.txt"
        echo "Statistics (JSON):    report/stats.json"
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════════════╗"
        echo "║                         END OF CONSOLIDATED REPORT                        ║"
        echo "╚══════════════════════════════════════════════════════════════════════════╝"
    } > "$consolidated"

    log INFO "Consolidated report saved: ${BOLD}${DOMAIN}_consolidated_report.txt${NC}"
    log INFO "Full path: ${consolidated}"
}

# ============================================================================
# MAIN PIPELINE
# ============================================================================

# Run the full recon pipeline for a single domain
run_recon_pipeline() {
    # Reset OUTDIR for each domain run
    OUTDIR=""

    # Reset phase tracking for each domain
    unset PHASE_START
    unset PHASE_STATUS
    declare -gA PHASE_START
    declare -gA PHASE_STATUS

    # Phase 0: Setup
    phase0_setup || { log ERROR "Setup failed for ${DOMAIN}. Skipping."; return 1; }

    # Phase 1: Root Domain Intelligence
    phase1_root_domain || true

    # Phase 2: Passive Subdomain Enum
    phase2_passive || true

    # Phase 3: DNS Resolution
    phase3_dns || true

    # If only-passive, stop after Phase 3
    if [[ "$ONLY_PASSIVE" == true ]]; then
        # Still merge and report
        merge_master
        phase10_reporting
        log INFO "Passive-only mode complete for ${DOMAIN}."
        return 0
    fi

    # Phase 4: Active Discovery
    phase4_active || true

    # Merge master list
    merge_master

    # Phase 5: Port Scanning
    phase5_ports || true

    # Phase 6: Web Probing
    phase6_web || true

    # Phase 7: Content Discovery
    phase7_content || true

    # Phase 8: Vulnerability Scanning
    phase8_vulns || true

    # Phase 9: Certstream (background daemon)
    phase9_certstream || true

    # Phase 10: Reporting
    phase10_reporting

    echo ""
    log INFO "All phases complete for ${DOMAIN}. Results in: ${BOLD}${OUTDIR}${NC}"
}

main() {
    parse_args "$@"
    banner

    log INFO "Program: ${BOLD}${PROGRAM}${NC}"

    if [[ -n "$DOMAINS_FILE" ]]; then
        # Multi-domain mode: read domains from file
        local domain_count
        domain_count=$(grep -cve '^\s*$' "$DOMAINS_FILE" 2>/dev/null || echo "0")
        log INFO "Processing ${domain_count} domains from: ${DOMAINS_FILE}"
        echo ""

        local current=0
        while IFS= read -r line <&3 || [[ -n "$line" ]]; do
            # Skip empty lines and comments
            line=$(echo "$line" | sed 's/#.*//' | xargs)
            [[ -z "$line" ]] && continue

            ((current++))
            DOMAIN="$line"

            echo ""
            log PHASE "Domain ${current}/${domain_count}: ${DOMAIN}"
            echo ""

            run_recon_pipeline

        done 3< "$DOMAINS_FILE"

        echo ""
        log INFO "All domains processed. Results in: ${BOLD}${SCRIPT_DIR}/${PROGRAM}/${NC}"
    else
        # Single domain mode
        run_recon_pipeline
    fi
}

main "$@"
