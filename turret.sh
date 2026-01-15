#!/bin/bash

set -euo pipefail

if ! command -v whiptail &>/dev/null; then
  sudo dnf install -y newt dialog jq curl 2>/dev/null || true
fi

if ! command -v go &>/dev/null; then
  sudo dnf install -y golang 2>/dev/null || true
fi

export PATH=$PATH:$HOME/go/bin

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }
vuln() { echo -e "${PURPLE}[VULN]${NC} $1"; }

BASE_DIR="$(pwd)/vuln_scans_$(date +%Y%m%d)"
DASHBOARD="$BASE_DIR/dashboard"
FINDINGS="$DASHBOARD/findings.json"
mkdir -p "$DASHBOARD" "$BASE_DIR/scans"

if [ ! -f "$FINDINGS" ]; then
  echo "[]" >"$FINDINGS"
fi

install_scanner() {
  log "Installing vulnerability scanning tools..."

  (
    echo "10"
    echo "# Installing nuclei..."
    if ! command -v nuclei &>/dev/null; then
      go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>&1 | tee -a install.log
    fi

    echo "30"
    echo "# Installing httpx..."
    if ! command -v httpx &>/dev/null; then
      go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>&1 | tee -a install.log
    fi

    echo "50"
    echo "# Installing system tools..."
    sudo dnf install -y nmap jq sqlite 2>&1 | tee -a install.log

    echo "70"
    echo "# Updating nuclei templates..."
    if command -v nuclei &>/dev/null; then
      nuclei -update-templates 2>&1 | tee -a install.log
    fi

    echo "100"
    echo "# Setup complete"

  ) | whiptail --gauge "Installing tools..." 8 60 0

  mkdir -p "$BASE_DIR/templates"
  create_custom_templates

  success "Tools installed successfully"
}

create_custom_templates() {

  cat >"$BASE_DIR/templates/exposed-git.yaml" <<'EOF'
id: exposed-git-config
info:
  name: Exposed Git Config
  severity: high
  tags: misconfig,git

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.git/HEAD"
    
    matchers:
      - type: word
        words:
          - "[core]"
          - "repositoryformatversion"
EOF

  cat >"$BASE_DIR/templates/aws-keys.yaml" <<'EOF'
id: exposed-aws-keys
info:
  name: Exposed AWS Keys
  severity: critical
  tags: exposure,keys

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    matchers:
      - type: regex
        regex:
          - "AKIA[0-9A-Z]{16}"
EOF

  success "Custom templates created"
}

add_finding() {
  local url=$1
  local vuln_type=$2
  local evidence=$3
  local severity=$4
  local proof=${5:-"N/A"}

  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  local finding_id=$(date +%s)

  local temp_file=$(mktemp)

  jq --arg id "$finding_id" \
    --arg url "$url" \
    --arg type "$vuln_type" \
    --arg evidence "$evidence" \
    --arg sev "$severity" \
    --arg proof "$proof" \
    --arg time "$timestamp" \
    '. += [{id: $id, url: $url, type: $type, evidence: $evidence, severity: $sev, proof: $proof, timestamp: $time}]' \
    "$FINDINGS" >"$temp_file" && mv "$temp_file" "$FINDINGS"

  vuln "Finding #$finding_id: $url - $vuln_type [$severity]"
}
update_dashboard() {
  local count=$(jq 'length' "$FINDINGS" 2>/dev/null || echo 0)
  local critical=$(jq '[.[] | select(.severity=="critical")] | length' "$FINDINGS" 2>/dev/null || echo 0)
  local high=$(jq '[.[] | select(.severity=="high")] | length' "$FINDINGS" 2>/dev/null || echo 0)
  local scan_count=$(ls -1 "$BASE_DIR"/scans/ 2>/dev/null | wc -l)

  cat >"$DASHBOARD/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Dashboard - $(date)</title>
    <meta http-equiv="refresh" content="60">
    <style>
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #0f0; margin: 0; padding: 20px; }
        .header { background: linear-gradient(90deg, #1a1a1a, #2a2a2a); padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-box { background: #1a1a1a; border: 2px solid #0f0; border-radius: 8px; padding: 20px; text-align: center; }
        .stat-box.critical { border-color: #f00; }
        .stat-box.high { border-color: #ff8800; }
        .stat-value { font-size: 3em; font-weight: bold; }
        .finding { background: #1a1a1a; border-left: 4px solid #0f0; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .finding.critical { border-left-color: #f00; background: rgba(255,0,0,0.1); }
        .finding.high { border-left-color: #ff8800; background: rgba(255,136,0,0.1); }
        .severity-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; font-size: 0.9em; }
        .severity-badge.critical { background: #f00; color: #000; }
        .severity-badge.high { background: #ff8800; color: #000; }
        .severity-badge.medium { background: #ff0; color: #000; }
        .timestamp { color: #888; font-size: 0.85em; }
        details { margin-top: 10px; cursor: pointer; }
        summary { color: #0ff; }
        pre { background: #000; padding: 10px; overflow-x: auto; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Vulnerability Assessment Dashboard</h1>
        <p class="timestamp">Last updated: $(date '+%Y-%m-%d %H:%M:%S')</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <div>Total Findings</div>
            <div class="stat-value">$count</div>
        </div>
        <div class="stat-box critical">
            <div>Critical</div>
            <div class="stat-value">$critical</div>
        </div>
        <div class="stat-box high">
            <div>High</div>
            <div class="stat-value">$high</div>
        </div>
        <div class="stat-box">
            <div>Scans Run</div>
            <div class="stat-value">$scan_count</div>
        </div>
    </div>
    
    <h2>Findings</h2>
    <div class="findings">
EOF

  if [ "$count" -gt 0 ]; then
    jq -r '.[] | 
            "<div class=\"finding \(.severity)\">
                <span class=\"severity-badge \(.severity)\">\(.severity | ascii_upcase)</span>
                <h3>\(.type)</h3>
                <p><strong>URL:</strong> \(.url)</p>
                <p><strong>Evidence:</strong> \(.evidence)</p>
                <p class=\"timestamp\">Found: \(.timestamp)</p>
                <details>
                    <summary>Proof of Concept</summary>
                    <pre>\(.proof)</pre>
                </details>
            </div>"' "$FINDINGS" >>"$DASHBOARD/index.html"
  else
    echo "<p>No findings yet. Run a scan to populate this dashboard.</p>" >>"$DASHBOARD/index.html"
  fi

  cat >>"$DASHBOARD/index.html" <<'EOF'
    </div>
</body>
</html>
EOF

  success "Dashboard updated: $DASHBOARD/index.html"
}

scan_target() {
  local target=$1
  local scan_dir="$BASE_DIR/scans/$(date +%Y%m%d_%H%M%S)_${target//[^a-zA-Z0-9]/_}"
  mkdir -p "$scan_dir"
  cd "$scan_dir"

  log "Scanning $target..."

  (
    echo "10"
    echo "# Discovering subdomains..."
    if command -v subfinder &>/dev/null; then
      subfinder -d "$target" -silent -o subs.txt 2>&1 || echo "$target" >subs.txt
    else
      echo "$target" >subs.txt
    fi

    echo "30"
    echo "# Checking alive hosts..."
    if command -v httpx &>/dev/null; then
      cat subs.txt | httpx -silent -o alive.txt 2>&1 || cp subs.txt alive.txt
    else
      cp subs.txt alive.txt
    fi

    echo "60"
    echo "# Running vulnerability scans..."
    if command -v nuclei &>/dev/null && [ -s alive.txt ]; then
      cat alive.txt | nuclei -silent -severity critical,high -templates "$BASE_DIR/templates" -o nuclei_results.txt 2>&1 || true

      if [ -f nuclei_results.txt ]; then
        while IFS= read -r line; do
          if [[ "$line" =~ \[([a-z]+)\].*\[([^\]]+)\].*(https?://[^\s]+) ]]; then
            severity="${BASH_REMATCH[1]}"
            vuln_type="${BASH_REMATCH[2]}"
            url="${BASH_REMATCH[3]}"
            add_finding "$url" "$vuln_type" "$line" "$severity" "$(echo "$line" | tail -c 200)"
          fi
        done <nuclei_results.txt
      fi
    fi

    echo "90"
    echo "# Checking common misconfigurations..."
    while read -r url; do
      if curl -sf "$url/.git/config" -m 5 | grep -q "repository"; then
        add_finding "$url" "Exposed Git Config" ".git/config accessible" "high" "$(curl -s $url/.git/config | head -20)"
      fi

      if curl -sf "$url/.env" -m 5 | grep -qi "api_key\|password\|secret"; then
        add_finding "$url" "Exposed Environment File" ".env file accessible" "critical" "$(curl -s $url/.env | head -20)"
      fi
    done <alive.txt

    echo "100"
    echo "# Scan complete"

  ) | whiptail --gauge "Scanning $target..." 10 60 0

  cd - >/dev/null
  update_dashboard
}

view_dashboard() {
  if [ ! -f "$DASHBOARD/index.html" ]; then
    update_dashboard
  fi
  if ! pgrep -f "python3.*8080.*$DASHBOARD" >/dev/null; then
    (cd "$DASHBOARD" && python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1) &
    sleep 2
  fi

  if command -v firefox &>/dev/null; then
    firefox "http://localhost:8080/index.html" 2>/dev/null &
  elif command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:8080/index.html" 2>/dev/null &
  else
    whiptail --msgbox "Dashboard ready at:\nhttp://localhost:8080/index.html\n\nOpen in your browser" 12 60
  fi
}
export_findings() {
  if [ ! -f "$FINDINGS" ]; then
    whiptail --msgbox "No findings to export" 10 50
    return
  fi

  local export_file="findings_export_$(date +%Y%m%d_%H%M%S).csv"

  echo "ID,URL,Type,Severity,Timestamp" >"$export_file"
  jq -r '.[] | [.id, .url, .type, .severity, .timestamp] | @csv' "$FINDINGS" >>"$export_file"

  whiptail --msgbox "Findings exported to:\n$export_file" 10 60
}

# TUI Menu
show_menu() {
  while true; do
    CHOICE=$(whiptail --title "Vulnerability Scanner" --menu "Choose action:" 20 70 10 \
      "1" "Scan Target" \
      "2" "View Dashboard" \
      "3" "Install/Setup Tools" \
      "4" "Export Findings" \
      "5" "Configure Targets" \
      "6" "Clear Findings" \
      "Q" "Quit" 3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ $exitstatus != 0 ]; then
      break
    fi

    case $CHOICE in
    1)
      TARGET=$(whiptail --inputbox "Enter target domain:" 10 60 "example.com" 3>&1 1>&2 2>&3)
      if [ $? -eq 0 ] && [ -n "$TARGET" ]; then
        scan_target "$TARGET"
        whiptail --msgbox "Scan complete!\nCheck dashboard for results" 10 50
      fi
      ;;
    2) view_dashboard ;;
    3)
      install_scanner
      whiptail --msgbox "Setup complete!" 10 50
      ;;
    4) export_findings ;;
    5)
      touch targets.txt
      nano targets.txt 2>/dev/null || vim targets.txt 2>/dev/null ||
        whiptail --msgbox "Edit targets.txt manually" 10 50
      ;;
    6)
      if whiptail --yesno "Clear all findings?" 10 50; then
        echo "[]" >"$FINDINGS"
        update_dashboard
        whiptail --msgbox "Findings cleared" 10 50
      fi
      ;;
    Q | q) break ;;
    esac
  done
}
clear
echo -e "${PURPLE}
╔═══════════════════════════════════════════════╗
║   VULNERABILITY SCANNER - Blue Team Edition   ║
║   For Authorized Security Assessments Only    ║
╚═══════════════════════════════════════════════╝
${NC}"

whiptail --title "AUTHORIZATION REQUIRED" --yesno "This tool is for AUTHORIZED security assessments only.\n\nDo you have written permission to scan the target(s)?" 12 60

if [ $? -ne 0 ]; then
  echo "Authorization required. Exiting."
  exit 1
fi

show_menu

clear
echo "Scanner closed. Dashboard available at: $DASHBOARD/index.html"
