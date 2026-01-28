#!/bin/bash

# 1. Check for Go, install if missing
if command -v go >/dev/null; then
    echo "Go is already installed: $(go version)"
else
    echo "Go not installed. Installing Go 1.24.12..."
    
    # Download Go 1.24.12 specifically
    # We use -f to fail silently on server errors so tar doesn't try to unzip an error page
    if curl -fsSL https://go.dev/dl/go1.24.12.linux-amd64.tar.gz -o go.tar.gz; then
        # Remove old installation if it exists
        sudo rm -rf /usr/local/go
        
        # Extract to /usr/local
        sudo tar -C /usr/local -xzf go.tar.gz
        rm go.tar.gz
        
        # Setup Path for CURRENT session so the rest of the script works
        export PATH=$PATH:/usr/local/go/bin
        
        # Setup Path for FUTURE sessions (persist to bashrc)
        if ! grep -q '/usr/local/go/bin' ~/.bashrc; then
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        fi
        
        echo "Go $(go version) installed successfully"
    else
        echo "Failed to download Go! Check your internet connection or the version number."
        exit 1
    fi
fi

#Installing recon tools
echo "Checking / installing core recon tools..."

# Define tools list

# 3. Check/Download Wordlist
#if [ ! -f "$WORDLIST" ]; then
#    echo "[+] Downloading wordlist ($WORDLIST)..."
#    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" -O "$WORDLIST"
#fi

# 4. Check/Download Resolvers
#if [ ! -f "$RESOLVERS" ]; then
#    echo "[+] Downloading resolvers..."
#    wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O resolvers.txt
#fi

#Installing MASSDNS
if ! command -v massdns &> /dev/null; then
    echo "[+] MassDNS not found. Installing..."
    if [ -d "massdns" ]; then rm -rf massdns; fi
    git clone https://github.com/blechschmidt/massdns.git
    cd massdns
    make
    sudo make install
    cd ..
    rm -rf massdns
    echo "[+] MassDNS installed."
fi

for tool in \
    "subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
    "httpx     github.com/projectdiscovery/httpx/cmd/httpx@latest" \
    "nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
    "ffuf      github.com/ffuf/ffuf/v2@latest" \
    "puredns github.com/d3mondev/puredns/v2@latest" \
    "alterx github.com/projectdiscovery/alterx/cmd/alterx@latest" \
    "anew github.com/tomnomnom/anew@latest"; do

    name=$(echo $tool | awk '{print $1}')
    repo=$(echo $tool | awk '{print $2}')

    # Check if tool exists
    if command -v "$name" >/dev/null 2>&1; then
        echo "→ $name already installed"
        # Try standard version flags, suppress massive help output if they fail
        $name -version 2>/dev/null || $name -V 2>/dev/null || echo "    (Version check skipped to avoid spam)"
    else
        echo "→ Installing $name ..."
        # Run go install
        if go install -v "$repo"; then
            echo "    → $name installed successfully"
            # Add GOPATH/bin to PATH for this session just in case
            export PATH=$PATH:$(go env GOPATH)/bin
        else
            echo "    → Installation failed!"
        fi
    fi
done

# 3. Update nuclei templates if installed
if command -v nuclei >/dev/null; then
    echo "Updating Nuclei templates..."
    nuclei -update-templates 2>/dev/null
fi
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc



# Target scanning
if [[ -z "$1" ]]; then
  echo "No subdomain provided. Exiting"
  exit 1
fi


#!/bin/bash

# Usage: ./recon.sh example.com
DOMAIN=$1
WORDLIST="subdomains-top1million-110000.txt"
RESOLVERS="resolvers.txt"

if [ -z "$DOMAIN" ]; then
    echo "Usage: ./recon.sh <domain>"
    exit 1
fi

# 0. setup
if [ ! -f "$RESOLVERS" ]; then
    echo "[+] Downloading resolvers..."
    wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O resolvers.txt
fi

echo "=========================================="
echo " RUNNING RECON ON: $DOMAIN"
echo "=========================================="

# --- Phase 1: Passive Recon ---
echo "[+] 1. Starting Passive Discovery (Subfinder)..."
subfinder -d "$DOMAIN" -all -silent -o "${DOMAIN}_passive.txt"

# --- Phase 2: Filter Alive (Resolution) ---
echo "[+] 2. Filtering alive subdomains (PureDNS)..."
puredns resolve "${DOMAIN}_passive.txt" -r "$RESOLVERS" --write "${DOMAIN}_passive_resolved.txt" --quiet

# --- Phase 3a: Bruteforce ---
echo "[+] 3a. Bruteforcing hidden subdomains..."
puredns bruteforce "$WORDLIST" "$DOMAIN" -r "$RESOLVERS" --write "${DOMAIN}_bruteforce.txt" --quiet

# --- Phase 3b: Permutations (Alterx) ---
echo "[+] 3b. Generating Permutations..."
# Combine results so far to feed Alterx
cat "${DOMAIN}_passive_resolved.txt" "${DOMAIN}_bruteforce.txt" | sort -u > "${DOMAIN}_known_alive.txt"
# Run Alterx and resolve immediately
cat "${DOMAIN}_known_alive.txt" | alterx -silent | puredns resolve -r "$RESOLVERS" --write "${DOMAIN}_permutations.txt" --quiet

# --- Merge All Subdomains ---
echo "[+] Merging all subdomain lists..."
cat "${DOMAIN}_passive_resolved.txt" "${DOMAIN}_bruteforce.txt" "${DOMAIN}_permutations.txt" | sort -u > "${DOMAIN}_final_all.txt"
COUNT=$(wc -l < "${DOMAIN}_final_all.txt")
echo "    -> Found $COUNT live subdomains."

# --- Phase 5: Public Exposure Probing (HTTPX) ---
echo "[+] 5. Probing for Web Servers (HTTPX)..."
# We use -random-agent to avoid blocking and -follow-redirects to see final destinations
httpx -l "${DOMAIN}_final_all.txt" \
      -title -status-code -ip -cname -tech-detect -web-server \
      -random-agent \
      -follow-redirects \
      -threads 50 \
      -o "${DOMAIN}_web_assets.txt"

echo "    -> HTTP assets saved to: ${DOMAIN}_web_assets.txt"

# --- Phase 5b: Port Scanning (Optional but recommended) ---
# Note: Nmap on a large list is slow. 
# If you have 'naabu' installed, uncomment the lines below for faster scanning:
# echo "[+] Scanning for non-web ports..."
# naabu -list "${DOMAIN}_final_all.txt" -top-ports 1000 -exclude-ports 80,443 -o "${DOMAIN}_open_ports.txt"

echo "=========================================="
echo " RECON FINISHED."
echo " Data saved to ${DOMAIN}_web_assets.txt"
echo "=========================================="
