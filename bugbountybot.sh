#!/bin/bash
set -euo pipefail

VERSION="1.0.0"
NAME="BugBountyBot"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

log() { echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
critical() { echo -e "${RED}[CRITICAL]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_SCRIPT="$SCRIPT_DIR/vul.sh"
VULN_SCRIPT="$SCRIPT_DIR/turret.sh"
OUTPUT_DIR="$HOME/.local/share/bugbountybot"
DATA_DIR="$OUTPUT_DIR/data"
REPORTS_DIR="$OUTPUT_DIR/reports"
TEMP_DIR="$OUTPUT_DIR/temp"
LOG_FILE="$OUTPUT_DIR/logs/bugbountybot.log"
CONFIG_FILE="$HOME/.config/bugbountybot/config.yaml"
DATABASE="$DATA_DIR/programs.db"

mkdir -p "$OUTPUT_DIR" "$DATA_DIR" "$REPORTS_DIR" "$TEMP_DIR" "$(dirname "$LOG_FILE")" "$(dirname "$CONFIG_FILE")" 2>/dev/null

init_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" << 'EOF'
# BugBountyBot Configuration v1.0
# Automated HackerOne Program Scanner

general:
  mode: "passive"  # passive, active, hybrid
  scan_interval: 3600  # seconds between scans
  max_concurrent_scans: 3
  ratelimit_delay: 1
  timeout_per_target: 1800

recon:
  subdomain_enumeration: true
  port_scanning: false
  web_technology_fingerprinting: true
  wayback_history: true
  github_dorking: true
  dns_enumeration: true

vuln:
  nuclei_scan: true
  nuclei_severity: "critical,high,medium"
  tls_scanning: true
  secret_detection: true
  cors_check: true
  subdomain_takeover: true

filters:
  exclude_private: true
  exclude_archived: true
  min_bounty: 0
  max_reports_resolved: 1000

notifications:
  slack_webhook: ""
  discord_webhook: ""
  email: ""
  desktop: false

reporting:
  format: ["html", "json"]
  severity_threshold: "medium"
  include_evidence: true
  auto_upload_h1: false

api:
  hackerone_username: ""
  hackerone_api_key: ""
  shodan_api_key: ""
  censys_api_id: ""
  censys_api_secret: ""
  virustotal_api_key: ""
EOF
        success "Created config: $CONFIG_FILE"
    fi
}

load_config() {
    if command -v yq &>/dev/null; then
        eval "$(yq eval -o=shell "$CONFIG_FILE" 2>/dev/null || echo 'true')"
    fi
    
    MAX_CONCURRENT=${scan_max_concurrent_scans:-3}
    SCAN_INTERVAL=${general_scan_interval:-3600}
    MODE="${general_mode:-passive}"
}

load_db() {
    if [ ! -f "$DATABASE" ]; then
        sqlite3 "$DATABASE" << 'EOF'
CREATE TABLE programs (
    id INTEGER PRIMARY KEY,
    handle TEXT UNIQUE,
    name TEXT,
    url TEXT,
    reward_range TEXT,
    min_bounty INTEGER,
    max_bounty INTEGER,
    in_scope TEXT,
    out_of_scope TEXT,
    last_scanned TIMESTAMP,
    status TEXT,
    resolved_count INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE targets (
    id INTEGER PRIMARY KEY,
    program_handle TEXT,
    type TEXT,
    value TEXT,
    status TEXT,
    last_found TIMESTAMP,
    last_scanned TIMESTAMP,
    vuln_count INTEGER DEFAULT 0,
    FOREIGN KEY (program_handle) REFERENCES programs(handle)
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    program_handle TEXT,
    target TEXT,
    vulnerability TEXT,
    severity TEXT,
    status TEXT,
    evidence TEXT,
    reported_at TIMESTAMP,
    resolved_at TIMESTAMP,
    bounty TEXT,
    FOREIGN KEY (program_handle) REFERENCES programs(handle)
);

CREATE INDEX idx_targets_program ON targets(program_handle);
CREATE INDEX idx_targets_value ON targets(value);
CREATE INDEX idx_findings_program ON findings(program_handle);
CREATE INDEX idx_findings_severity ON findings(severity);
EOF
        success "Initialized database: $DATABASE"
    fi
}

h1_api_request() {
    local endpoint="$1"
    local method="${2:-GET}"
    local data="${3:-}"
    
    if [ -z "${api_hackerone_username:-}" ] || [ -z "${api_hackerone_api_key:-}" ]; then
        warn "HackerOne API credentials not configured"
        return 1
    fi
    
    local auth=$(echo -n "${api_hackerone_username}:${api_hackerone_api_key}" | base64)
    
    curl -s -X "$method" \
        -H "Authorization: Basic $auth" \
        -H "Content-Type: application/json" \
        "https://api.hackerone.com/v1$endpoint" \
        $data
}

fetch_h1_programs() {
    log "Fetching HackerOne bug bounty programs..."
    
    local programs_json
    programs_json=$(h1_api_request "/programs" "GET")
    
    if [ -z "$programs_json" ] || [ "$programs_json" = "null" ]; then
        warn "Could not fetch programs via API, using public data..."
        fetch_programs_public
        return
    fi
    
    echo "$programs_json" | jq -r '.data[] | {handle: .attributes.handle, name: .attributes.name, url: .attributes.url, bounty: .attributes.reward_range}' 2>/dev/null
}

fetch_programs_public() {
    log "Fetching programs from public sources..."
    
    local temp_programs=$(mktemp)
    
    curl -s "https://hackerone.com/directory?sort=published" 2>/dev/null | \
        grep -oP '"handle":"[^"]+"|"name":"[^"]+"|"reward_range":"[^"]+"|"state":"[^"]+"' 2>/dev/null | \
        sed 's/"//g' | sed 's/:/:/' > "$temp_programs"
    
    cat "$temp_programs"
    rm -f "$temp_programs"
}

get_program_scope() {
    local handle="$1"
    
    local scope_json
    scope_json=$(h1_api_request "/programs/$handle/scopes" "GET")
    
    if [ -z "$scope_json" ] || [ "$scope_json" = "null" ]; then
        log "Fetching scope for $handle from public data..."
        fetch_scope_public "$handle"
        return
    fi
    
    echo "$scope_json" | jq -r '.data[] | select(.attributes.eligible_for_submission==true) | .attributes.asset_identifier' 2>/dev/null
}

fetch_scope_public() {
    local handle="$1"
    local url="https://hackerone.com/$handle"
    
    curl -s "$url" 2>/dev/null | \
        grep -oP 'data-test="scope-[^"]*"[^>]*>[^<]*' 2>/dev/null | \
        sed 's/.*>//' | grep -E '\*?\.?[^ ]+' | head -50
}

add_program() {
    local handle="$1"
    local name="$2"
    local url="$3"
    local bounty="$4"
    
    local min_bounty=0 max_bounty=0
    if [ -n "$bounty" ] && [ "$bounty" != "null" ]; then
        min_bounty=$(echo "$bounty" | grep -oP '\$[0-9]+' | head -1 | sed 's/\$//' | sed 's/,//')
        max_bounty=$(echo "$bounty" | grep -oP '\$[0-9]+' | tail -1 | sed 's/\$//' | sed 's/,//')
    fi
    
    sqlite3 "$DATABASE" << EOF
INSERT OR REPLACE INTO programs (handle, name, url, reward_range, min_bounty, max_bounty, status, updated_at)
VALUES ('$handle', '${name:-"$handle"}', '$url', '$bounty', $min_bounty, $max_bounty, 'active', datetime('now'))
ON CONFLICT(handle) DO UPDATE SET
    name='${name:-"$handle"}',
    url='$url',
    reward_range='$bounty',
    min_bounty=$min_bounty,
    max_bounty=$max_bounty,
    updated_at=datetime('now');
EOF
}

add_target() {
    local program="$1"
    local type="$2"
    local value="$3"
    
    sqlite3 "$DATABASE" << EOF
INSERT OR IGNORE INTO targets (program_handle, type, value, status, last_found)
VALUES ('$program', '$type', '$value', 'active', datetime('now'));
EOF
}

get_active_targets() {
    sqlite3 "$DATABASE" "SELECT program_handle, type, value FROM targets WHERE status='active';" 2>/dev/null
}

get_targets_for_program() {
    local program="$1"
    sqlite3 "$DATABASE" "SELECT type, value FROM targets WHERE program_handle='$program' AND status='active';" 2>/dev/null
}

update_target_scan() {
    local program="$1"
    local value="$2"
    
    sqlite3 "$DATABASE" "UPDATE targets SET last_scanned=datetime('now') WHERE program_handle='$program' AND value='$value';" 2>/dev/null
}

add_finding() {
    local program="$1"
    local target="$2"
    local vuln="$3"
    local severity="$4"
    local evidence="$5"
    
    sqlite3 "$DATABASE" << EOF
INSERT INTO findings (program_handle, target, vulnerability, severity, status, evidence, reported_at)
VALUES ('$program', '$target', '$vuln', '$severity', 'new', '$evidence', datetime('now'));
EOF
    
    local id=$(sqlite3 "$DATABASE" "SELECT last_insert_rowid();")
    echo "$id"
}

get_resolved_count() {
    local program="$1"
    sqlite3 "$DATABASE" "SELECT COUNT(*) FROM programs WHERE handle='$program' AND status='resolved';" 2>/dev/null
}

sync_all_programs() {
    log "Syncing all programs..."
    
    local temp_file=$(mktemp)
    fetch_h1_programs > "$temp_file" 2>/dev/null
    
    while IFS= read -r line; do
        if [[ "$line" =~ handle:(.*) ]]; then
            local handle="${BASH_REMATCH[1]}"
            add_program "$handle" "" "" ""
            get_program_scope "$handle" | while read -r scope; do
                add_target "$handle" "domain" "$scope"
            done
        fi
    done < "$temp_file"
    
    rm -f "$temp_file"
    success "Synced all programs"
}

recon_target() {
    local program="$1"
    local target="$2"
    local output_dir="$3"
    
    log "Running recon on: $target"
    
    local target_dir="$output_dir/$(echo "$target" | tr '/.' '_')"
    mkdir -p "$target_dir"
    
    if [ "${recon_subdomain_enumeration:-true}" = "true" ] && command -v subfinder &>/dev/null; then
        info "Enumerating subdomains for $target..."
        subfinder -d "$target" -silent -o "$target_dir/subs.txt" 2>/dev/null &
    fi
    
    if [ "${recon_web_technology_fingerprinting:-true}" = "true" ] && command -v whatweb &>/dev/null; then
        info "Fingerprinting $target..."
        whatweb -a 3 "$target" --log-brief="$target_dir/tech.txt" 2>/dev/null &
    fi
    
    if [ "${recon_wayback_history:-true}" = "true" ] && command -v waybackurls &>/dev/null; then
        info "Fetching wayback history for $target..."
        echo "$target" | waybackurls > "$target_dir/wayback.txt" 2>/dev/null &
    fi
    
    if [ "${recon_dns_enumeration:-true}" = "true" ] && command -v dnsrecon &>/dev/null; then
        info "Running DNS enumeration on $target..."
        dnsrecon -d "$target" -j "$target_dir/dns.json" 2>/dev/null &
    fi
    
    wait
}

vuln_scan_target() {
    local program="$1"
    local target="$2"
    local output_dir="$3"
    
    log "Running vulnerability scan on: $target"
    
    local target_dir="$output_dir/$(echo "$target" | tr '/.' '_')"
    mkdir -p "$target_dir"
    
    if [ "${vuln_nuclei_scan:-true}" = "true" ] && command -v nuclei &>/dev/null; then
        info "Running nuclei on $target..."
        nuclei -u "$target" \
            -severity "${vuln_nuclei_severity:-critical,high,medium}" \
            -silent \
            -o "$target_dir/nuclei.txt" 2>/dev/null &
    fi
    
    if [ "${vuln_tls_scanning:-true}" = "true" ] && command -v testssl &>/dev/null; then
        info "Running TLS scan on $target..."
        testssl --jsonfile="$target_dir/tls.json" "$target" 2>/dev/null &
    fi
    
    if [ "${vuln_secret_detection:-true}" = "true" ] && command -v trufflehog &>/dev/null; then
        info "Running secret detection on $target..."
        trufflehog url "$target" --output="$target_dir/secrets.txt" 2>/dev/null &
    fi
    
    wait
}

process_target() {
    local program="$1"
    local type="$2"
    local target="$3"
    local scan_type="$4"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="$REPORTS_DIR/$program/$timestamp"
    mkdir -p "$output_dir"
    
    log "Processing target: $program -> $target"
    
    local start_time=$(date +%s)
    
    case "$scan_type" in
        recon)
            recon_target "$program" "$target" "$output_dir"
            ;;
        vuln)
            vuln_scan_target "$program" "$target" "$output_dir"
            ;;
        full)
            recon_target "$program" "$target" "$output_dir"
            sleep 5
            vuln_scan_target "$program" "$target" "$output_dir"
            ;;
        *)
            recon_target "$program" "$target" "$output_dir"
            vuln_scan_target "$program" "$target" "$output_dir"
            ;;
    esac
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    update_target_scan "$program" "$target"
    
    parse_results "$program" "$target" "$output_dir"
    
    success "Completed $target in ${duration}s"
}

parse_results() {
    local program="$1"
    local target="$2"
    local output_dir="$3"
    
    if [ -f "$output_dir/nuclei.txt" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                local severity=$(echo "$line" | grep -oE '\[(critical|high|medium|low|info)\]' | sed 's/\[//;s/\]//')
                local vuln_name=$(echo "$line" | grep -oE '\[.*\]' | tail -n +2 | head -1 | sed 's/\[//;s/\]//')
                if [ -n "$severity" ]; then
                    add_finding "$program" "$target" "$vuln_name" "$severity" "$line"
                fi
            fi
        done < "$output_dir/nuclei.txt"
    fi
}

scan_program() {
    local program="$1"
    local scan_type="${2:-full}"
    
    log "Scanning program: $program"
    
    local targets=$(get_targets_for_program "$program")
    
    if [ -z "$targets" ]; then
        warn "No targets found for $program"
        return 1
    fi
    
    local count=0
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            local type=$(echo "$line" | cut -d'|' -f1)
            local target=$(echo "$line" | cut -d'|' -f2)
            
            if [ $count -ge $MAX_CONCURRENT ]; then
                wait
                count=0
            fi
            
            process_target "$program" "$type" "$target" "$scan_type" &
            count=$((count + 1))
        fi
    done <<< "$targets"
    
    wait
    success "Completed scan for $program"
}

run_continuous_scan() {
    log "Starting continuous bug bounty scanning..."
    log "Mode: $MODE | Interval: ${SCAN_INTERVAL}s | Max concurrent: $MAX_CONCURRENT"
    
    while true; do
        log "=== Scan cycle started at $(date) ==="
        
        local programs=$(sqlite3 "$DATABASE" "SELECT handle FROM programs WHERE status='active';" 2>/dev/null)
        
        for program in $programs; do
            local resolved=$(sqlite3 "$DATABASE" "SELECT resolved_count FROM programs WHERE handle='$program';" 2>/dev/null || echo 0)
            local min_bounty=${filters_min_bounty:-0}
            local max_reports=${filters_max_reports_resolved:-1000}
            
            if [ "$resolved" -gt "$max_reports" ]; then
                warn "Skipping $program - too many resolved reports"
                continue
            fi
            
            scan_program "$program" "$MODE"
        done
        
        log "=== Scan cycle completed ==="
        log "Sleeping for ${SCAN_INTERVAL}s..."
        
        sleep "$SCAN_INTERVAL"
    done
}

scan_single_program() {
    local program="$1"
    local scan_type="${2:-full}"
    
    if [ -z "$program" ]; then
        error "Program handle required"
        return 1
    fi
    
    scan_program "$program" "$scan_type"
}

scan_single_target() {
    local program="$1"
    local target="$2"
    local scan_type="${3:-full}"
    
    if [ -z "$program" ] || [ -z "$target" ]; then
        error "Program and target required"
        return 1
    fi
    
    process_target "$program" "domain" "$target" "$scan_type"
}

list_programs() {
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         BUG BOUNTY PROGRAMS                   ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    sqlite3 -header -column "$DATABASE" "SELECT handle, name, reward_range, last_scanned, resolved_count FROM programs ORDER BY resolved_count DESC LIMIT 20;" 2>/dev/null
}

list_targets() {
    local program="${1:-}"
    
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         TARGETS                               ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    if [ -n "$program" ]; then
        sqlite3 -header -column "$DATABASE" "SELECT program_handle, type, value, last_scanned, vuln_count FROM targets WHERE program_handle='$program' ORDER BY last_found DESC LIMIT 50;" 2>/dev/null
    else
        sqlite3 -header -column "$DATABASE" "SELECT program_handle, type, value, last_scanned, vuln_count FROM targets ORDER BY last_found DESC LIMIT 50;" 2>/dev/null
    fi
}

list_findings() {
    local program="${1:-}"
    local severity="${2:-}"
    
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         FINDINGS                              ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    local query="SELECT program_handle, target, vulnerability, severity, reported_at FROM findings WHERE status='new'"
    
    if [ -n "$program" ]; then
        query="$query AND program_handle='$program'"
    fi
    
    if [ -n "$severity" ]; then
        query="$query AND severity='$severity'"
    fi
    
    query="$query ORDER BY severity DESC, reported_at DESC LIMIT 100;"
    
    sqlite3 -header -column "$DATABASE" "$query" 2>/dev/null
}

generate_report() {
    local program="${1:-all}"
    local format="${2:-html}"
    
    local output_file="$REPORTS_DIR/report_$(date +%Y%m%d_%H%M%S).$format"
    
    log "Generating $format report for $program..."
    
    local critical=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='critical';" 2>/dev/null || echo 0)
    local high=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='high';" 2>/dev/null || echo 0)
    local medium=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='medium';" 2>/dev/null || echo 0)
    local total=$((critical + high + medium))
    
    case "$format" in
        html)
            cat > "$output_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>BugBountyBot Report - $program</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0d0d0d; color: #00ff00; margin: 0; padding: 20px; }
        .header { background: linear-gradient(135deg, #1a1a1a, #2a2a2a); padding: 30px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #00ff00; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-box { background: #1a1a1a; border: 1px solid #00ff00; border-radius: 8px; padding: 20px; text-align: center; }
        .stat-box.critical { border-color: #ff0000; background: rgba(255,0,0,0.1); }
        .stat-box.high { border-color: #ff8800; background: rgba(255,136,0,0.1); }
        .stat-value { font-size: 2.5em; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; }
        th { background: #1a1a1a; color: #00ff00; }
        .critical { color: #ff0000; }
        .high { color: #ff8800; }
        .medium { color: #ffff00; }
    </style>
</head>
<body>
    <div class="header">
        <h1>BugBountyBot Report</h1>
        <p>Program: $program</p>
        <p>Generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
        <p>Version: $VERSION</p>
    </div>
    
    <div class="stats">
        <div class="stat-box critical">
            <div>CRITICAL</div>
            <div class="stat-value">$critical</div>
        </div>
        <div class="stat-box high">
            <div>HIGH</div>
            <div class="stat-value">$high</div>
        </div>
        <div class="stat-box">
            <div>MEDIUM</div>
            <div class="stat-value">$medium</div>
        </div>
        <div class="stat-box">
            <div>TOTAL</div>
            <div class="stat-value">$total</div>
        </div>
    </div>
    
    <h2>Findings</h2>
    <table>
        <tr><th>Program</th><th>Target</th><th>Vulnerability</th><th>Severity</th><th>Date</th></tr>
        $(sqlite3 "$DATABASE" "SELECT program_handle, target, vulnerability, severity, reported_at FROM findings WHERE status='new' AND program_handle='$program' ORDER BY severity DESC, reported_at DESC LIMIT 100;" 2>/dev/null | sed 's/|/<\/td><td>/g' | sed 's/^/<tr><td>/' | sed 's/$/<\/td><\/tr>/')
    </table>
</body>
</html>
EOF
            ;;
        json)
            sqlite3 "$DATABASE" "SELECT json_object('program', program_handle, 'target', target, 'vulnerability', vulnerability, 'severity', severity, 'date', reported_at, 'evidence', evidence) FROM findings WHERE status='new' AND program_handle='$program' ORDER BY severity DESC;" 2>/dev/null > "$output_file"
            ;;
    esac
    
    success "Report generated: $output_file"
    echo "$output_file"
}

export_findings() {
    local program="${1:-all}"
    local format="${2:-csv}"
    
    local output_file="$REPORTS_DIR/findings_$(date +%Y%m%d_%H%M%S).$format"
    
    case "$format" in
        csv)
            echo "Program,Target,Vulnerability,Severity,Date,Evidence" > "$output_file"
            sqlite3 "$DATABASE" "SELECT program_handle, target, vulnerability, severity, reported_at, evidence FROM findings WHERE status='new' AND program_handle='$program';" 2>/dev/null | sed 's/|/,/g' >> "$output_file"
            ;;
        json)
            sqlite3 "$DATABASE" "SELECT json_group_array(json_object('program', program_handle, 'target', target, 'vulnerability', vulnerability, 'severity', severity, 'date', reported_at, 'evidence', evidence)) FROM findings WHERE status='new' AND program_handle='$program';" 2>/dev/null > "$output_file"
            ;;
    esac
    
    success "Exported: $output_file"
}

clear_findings() {
    local program="${1:-}"
    
    if [ -n "$program" ]; then
        sqlite3 "$DATABASE" "DELETE FROM findings WHERE program_handle='$program' AND status='new';" 2>/dev/null
        success "Cleared findings for $program"
    else
        sqlite3 "$DATABASE" "DELETE FROM findings WHERE status='new';" 2>/dev/null
        success "Cleared all findings"
    fi
}

status_check() {
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         BugBountyBot Status                   ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    local programs=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM programs;" 2>/dev/null || echo 0)
    local targets=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM targets;" 2>/dev/null || echo 0)
    local findings=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new';" 2>/dev/null || echo 0)
    local critical=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='critical';" 2>/dev/null || echo 0)
    local high=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='high';" 2>/dev/null || echo 0)
    
    echo "Programs:    $programs"
    echo "Targets:     $targets"
    echo "Findings:    $findings"
    echo "  - Critical: $critical"
    echo "  - High:     $high"
    echo ""
    echo "Mode:        $MODE"
    echo "Scan Interval: ${SCAN_INTERVAL}s"
    echo "Max Concurrent: $MAX_CONCURRENT"
    echo ""
    
    local last_scan=$(sqlite3 "$DATABASE" "SELECT MAX(last_scanned) FROM targets;" 2>/dev/null || echo "Never")
    echo "Last Scan:   $last_scan"
}

show_help() {
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         BugBountyBot v$VERSION                  ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "COMMANDS:"
    echo "  sync                Sync all HackerOne programs"
    echo "  scan <program>      Scan a specific program"
    echo "  scan-target <p> <t> Scan a specific target"
    echo "  list                List all programs"
    echo "  targets [program]   List targets"
    echo "  findings [prog]     List findings"
    echo "  report [prog] [fmt] Generate report (html/json)"
    echo "  export [prog] [fmt] Export findings (csv/json)"
    echo "  clear [program]     Clear findings"
    echo "  status              Show status"
    echo "  continuous          Run continuous scanning"
    echo "  help                Show this help"
    echo ""
    echo "OPTIONS:"
    echo "  --mode passive|active|hybrid  Scan mode"
    echo "  --interval SECONDS            Scan interval"
    echo ""
    echo "EXAMPLES:"
    echo "  bugbountybot sync"
    echo "  bugbountybot scan google"
    echo "  bugbountybot scan twitter --mode active"
    echo "  bugbountybot continuous"
    echo ""
}

main() {
    load_config
    load_db
    
    local command="${1:-help}"
    local arg1="${2:-}"
    local arg2="${3:-}"
    
    case "$command" in
        sync)
            sync_all_programs
            ;;
        scan)
            scan_single_program "$arg1" "${arg2:-full}"
            ;;
        scan-target)
            scan_single_target "$arg1" "$arg2" "${3:-full}"
            ;;
        list)
            list_programs
            ;;
        targets)
            list_targets "$arg1"
            ;;
        findings)
            list_findings "$arg1" "$arg2"
            ;;
        report)
            generate_report "$arg1" "${arg2:-html}"
            ;;
        export)
            export_findings "$arg1" "${arg2:-csv}"
            ;;
        clear)
            clear_findings "$arg1"
            ;;
        status)
            status_check
            ;;
        continuous)
            run_continuous_scan
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
