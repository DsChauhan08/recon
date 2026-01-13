#!/bin/bash
set -euo pipefail
if ! command -v whiptail &>/dev/null; then
  sudo dnf install -y newt dialog 2>/dev/null || true
fi
if ! command -v go &>/dev/null; then
  sudo dnf install -y golang 2>/dev/null || true
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi
export PATH=$PATH:$HOME/go/bin

# tools
declare -A TOOLS=(
  ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  ["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
  ["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  ["naabu"]="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  ["dnsx"]="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  ["gau"]="go install github.com/lc/gau/v2/cmd/gau@latest"
  ["waybackurls"]="go install github.com/tomnomnom/waybackurls@latest"
  ["ffuf"]="go install github.com/ffuf/ffuf/v2@latest"
  ["nmap"]="sudo dnf install -y nmap"
  ["masscan"]="sudo dnf install -y masscan"
)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

install_tool() {
  local name=$1
  local cmd=${TOOLS[$name]}

  if ! command -v "$name" &>/dev/null; then
    log "Installing $name..."
    if eval "$cmd" 2>&1 | tee -a install.log; then
      success "$name installed"
    else
      warn "Failed to install $name (check install.log)"
    fi
  else
    success "$name already installed"
  fi
}

show_menu() {
  while true; do
    CHOICE=$(whiptail --title "Recon TUI" --menu "Choose action:" 20 70 10 \
      "1" "Quick Recon (Core tools)" \
      "2" "Full Scan (All tools)" \
      "3" "Install/Update Tools" \
      "4" "View Results" \
      "5" "Configure Targets" \
      "Q" "Quit" 3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ $exitstatus != 0 ]; then
      break
    fi

    case $CHOICE in
    1) quick_scan ;;
    2) full_scan ;;
    3) install_all ;;
    4) show_results ;;
    5) config_targets ;;
    Q | q) break ;;
    esac
  done
}

install_all() {
  (
    echo "0"
    sleep 1
    for tool in "${!TOOLS[@]}"; do
      install_tool "$tool"
      echo "50"
    done
    echo "100"
  ) | whiptail --gauge "Installing tools..." 8 60 0

  if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>&1 | tee -a install.log
  fi

  whiptail --msgbox "Tools installation complete!\nCheck install.log for details" 10 60
}

# quickie
quick_scan() {
  TARGET=$(whiptail --inputbox "Enter target domain:" 10 60 "example.com" --title "Quick Scan" 3>&1 1>&2 2>&3)

  exitstatus=$?
  if [ $exitstatus != 0 ] || [ -z "$TARGET" ]; then
    return
  fi

  OUTPUT_DIR="recon_$(date +%Y%m%d_%H%M%S)_${TARGET//[^a-zA-Z0-9]/_}"
  mkdir -p "$OUTPUT_DIR"
  cd "$OUTPUT_DIR"

  (
    echo "10"
    echo "# Finding subdomains..."
    if command -v subfinder &>/dev/null; then
      subfinder -d "$TARGET" -silent -o subs.txt 2>&1 || touch subs.txt
    else
      echo "$TARGET" >subs.txt
    fi

    echo "40"
    echo "# Checking alive hosts..."
    if command -v httpx &>/dev/null && [ -s subs.txt ]; then
      cat subs.txt | httpx -silent -o alive.txt 2>&1 || touch alive.txt
    else
      cp subs.txt alive.txt 2>/dev/null || touch alive.txt
    fi

    echo "70"
    echo "# Scanning for vulnerabilities..."
    if command -v nuclei &>/dev/null && [ -s alive.txt ]; then
      cat alive.txt | nuclei -silent -severity critical,high -o vulns.txt 2>&1 || touch vulns.txt
    else
      touch vulns.txt
    fi

    echo "100"
    echo "# Generating report..."
    generate_report "$TARGET" "quick"

  ) | whiptail --gauge "Scanning $TARGET..." 8 60 0

  cd - >/dev/null

  whiptail --title "Scan Complete" --msgbox "Quick scan finished!\n\nResults in: $OUTPUT_DIR\n\nSubdomains: $(wc -l <"$OUTPUT_DIR/subs.txt" 2>/dev/null || echo 0)\nAlive: $(wc -l <"$OUTPUT_DIR/alive.txt" 2>/dev/null || echo 0)\nVulns: $(wc -l <"$OUTPUT_DIR/vulns.txt" 2>/dev/null || echo 0)" 14 60
}

# Full
full_scan() {
  TARGET=$(whiptail --inputbox "Enter target domain:" 10 60 "example.com" --title "Full Scan" 3>&1 1>&2 2>&3)

  exitstatus=$?
  if [ $exitstatus != 0 ] || [ -z "$TARGET" ]; then
    return
  fi

  OUTPUT_DIR="recon_full_$(date +%Y%m%d_%H%M%S)_${TARGET//[^a-zA-Z0-9]/_}"
  mkdir -p "$OUTPUT_DIR"
  cd "$OUTPUT_DIR"

  (
    echo "5"
    echo "# Phase 1: Subdomain enumeration..."
    if command -v subfinder &>/dev/null; then
      subfinder -d "$TARGET" -silent -o subs_subfinder.txt 2>&1 &
    fi
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null |
      grep -Po '"name_value":"\K[^"]*' | sort -u >subs_crtsh.txt &

    wait
    cat subs_*.txt 2>/dev/null | sort -u | grep -E "^[a-zA-Z0-9.-]+\.$TARGET$" >all_subs.txt || touch all_subs.txt

    echo "30"
    echo "# Phase 2: Checking alive hosts..."
    if command -v httpx &>/dev/null && [ -s all_subs.txt ]; then
      cat all_subs.txt | httpx -silent -title -tech-detect -o alive.txt 2>&1
    fi

    echo "50"
    echo "# Phase 3: Port scanning..."
    if command -v naabu &>/dev/null && [ -s all_subs.txt ]; then
      cat all_subs.txt | naabu -top-ports 100 -silent -o ports.txt 2>&1 &
    fi

    echo "70"
    echo "# Phase 4: Vulnerability scanning..."
    if command -v nuclei &>/dev/null && [ -s alive.txt ]; then
      cat alive.txt | nuclei -silent -severity critical,high -o critical_vulns.txt 2>&1
    fi

    echo "90"
    echo "# Phase 5: Content discovery..."
    if command -v waybackurls &>/dev/null; then
      echo "$TARGET" | waybackurls >wayback.txt 2>&1 &
    fi
    if command -v gau &>/dev/null; then
      echo "$TARGET" | gau --subs >gau.txt 2>&1 &
    fi
    wait

    echo "100"
    echo "# Generating report..."
    generate_report "$TARGET" "full"

  ) | whiptail --gauge "Full scan in progress..." 8 60 0

  cd - >/dev/null

  whiptail --title "Scan Complete" --msgbox "Full scan finished!\n\nResults: $OUTPUT_DIR\n\nSubdomains: $(wc -l <"$OUTPUT_DIR/all_subs.txt" 2>/dev/null || echo 0)\nAlive: $(wc -l <"$OUTPUT_DIR/alive.txt" 2>/dev/null || echo 0)\nPorts: $(wc -l <"$OUTPUT_DIR/ports.txt" 2>/dev/null || echo 0)\nVulns: $(wc -l <"$OUTPUT_DIR/critical_vulns.txt" 2>/dev/null || echo 0)" 16 60
}

#HTML
generate_report() {
  local target=$1
  local type=${2:-quick}

  local subs_count=$(wc -l <all_subs.txt 2>/dev/null || wc -l <subs.txt 2>/dev/null || echo 0)
  local alive_count=$(wc -l <alive.txt 2>/dev/null || echo 0)
  local vulns_count=$(wc -l <critical_vulns.txt 2>/dev/null || wc -l <vulns.txt 2>/dev/null || echo 0)

  cat >"summary.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Recon Report: $target</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a1a; color: #0f0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #0f0; border-bottom: 2px solid #0f0; padding-bottom: 10px; }
        .metric { background: #2a2a2a; padding: 20px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #0f0; }
        .metric h2 { margin-top: 0; color: #ff0; }
        .metric .value { font-size: 2em; font-weight: bold; }
        .file-list { background: #333; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .file-list ul { list-style: none; padding: 0; }
        .file-list li { padding: 5px 0; }
        .timestamp { color: #888; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Recon Report: $target</h1>
        <p class="timestamp">Generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
        <p>Scan Type: <strong>$type</strong></p>
        
        <div class="metric">
            <h2>Subdomains</h2>
            <div class="value">$subs_count</div>
        </div>
        
        <div class="metric">
            <h2>Live Hosts</h2>
            <div class="value" style="color: #ff0;">$alive_count</div>
        </div>
        
        <div class="metric">
            <h2>Vulnerabilities</h2>
            <div class="value" style="color: #f00;">$vulns_count</div>
        </div>
        
        <div class="file-list">
            <h3>Output Files:</h3>
            <ul>
$(for file in *.txt; do [ -f "$file" ] && echo "                <li>$file ($(wc -l <"$file") lines)</li>"; done)
            </ul>
        </div>
    </div>
</body>
</html>
EOF
}

# old result
show_results() {
  if ! ls -d recon_* &>/dev/null; then
    whiptail --msgbox "No scan results found.\nRun a scan first!" 10 50
    return
  fi

  RESULTS_DIR=$(ls -dt recon_* 2>/dev/null | head -1)

  if [ -f "$RESULTS_DIR/summary.html" ]; then
    if command -v firefox &>/dev/null; then
      firefox "$RESULTS_DIR/summary.html" 2>/dev/null &
    elif command -v xdg-open &>/dev/null; then
      xdg-open "$RESULTS_DIR/summary.html" 2>/dev/null &
    else
      whiptail --msgbox "Results location:\n$RESULTS_DIR\n\nOpen summary.html in a browser" 12 60
    fi
  else
    whiptail --msgbox "Latest results:\n$RESULTS_DIR\n\nNo HTML report found" 10 60
  fi
}

# automations
config_targets() {
  if [ ! -f "targets.txt" ]; then
    echo "# Add target domains, one per line" >targets.txt
    echo "example.com" >>targets.txt
  fi

  whiptail --title "Target Configuration" --msgbox "Edit targets.txt file\nOne domain per line\n\nPress OK to continue" 12 60

  if command -v nano &>/dev/null; then
    nano targets.txt
  elif command -v vim &>/dev/null; then
    vim targets.txt
  else
    whiptail --msgbox "No text editor found.\nEdit targets.txt manually" 10 50
  fi
}

# fully running
clear
echo -e "${PURPLE}
╔═══════════════════════════════════════════════╗
║     RECON TUI - Blue Team Edition             ║
║     Fedora Compatible                         ║
╚═══════════════════════════════════════════════╝
${NC}"
show_menu

clear
echo "Recon TUI closed. Results saved in recon_* directories."
