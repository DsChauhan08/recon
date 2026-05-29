#!/bin/bash
# Unified configuration loader

init_config() {
    local config_dir
    config_dir="$(dirname "$CONFIG_FILE")"
    mkdir -p "$config_dir" 2>/dev/null || true

    if [ ! -f "$CONFIG_FILE" ] && [ -w "$config_dir" ] 2>/dev/null; then
        cat > "$CONFIG_FILE" << 'EOF'
# Recon Platform Configuration v2.0

general:
  mode: "passive"
  scan_interval: 3600
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

hunt:
  max_rate: 10000
  default_ports: "22,23,80,443,8080,554,3389,21,445,139"
  exclude_file: ""
  require_authorized: true

cve:
  sync_days: 7
  watch_interval: 3600
  nvd_api_key: ""

msf:
  msfconsole_path: ""
  msfvenom_path: ""
  default_lhost: ""
  default_lport: 4444

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
  github_token: ""
  shodan_api_key: ""
  censys_api_id: ""
  censys_api_secret: ""
  virustotal_api_key: ""
EOF
        success "Created config: $CONFIG_FILE"
    fi

    # Migrate legacy bugbountybot config if recon config was just created empty
    local legacy_config="$HOME/.config/bugbountybot/config.yaml"
    if [ -f "$legacy_config" ] && [ ! -s "$CONFIG_FILE" ] 2>/dev/null; then
        cp "$legacy_config" "$CONFIG_FILE"
    fi
}

load_config() {
    init_config

    if command -v yq &>/dev/null; then
        eval "$(yq eval -o=shell "$CONFIG_FILE" 2>/dev/null || echo 'true')"
    fi

    MAX_CONCURRENT=${general_max_concurrent_scans:-3}
    SCAN_INTERVAL=${general_scan_interval:-3600}
    MODE="${general_mode:-passive}"

    if ! is_positive_int "$MAX_CONCURRENT"; then
        MAX_CONCURRENT=3
    fi

    if ! is_positive_int "$SCAN_INTERVAL"; then
        SCAN_INTERVAL=3600
    fi
}

init_paths() {
    if [ -z "${RECON_ROOT:-}" ]; then
        RECON_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi
    SCRIPT_DIR="$RECON_ROOT"
    OUTPUT_DIR="${RECON_OUTPUT_DIR:-$HOME/.local/share/recon}"
    DATA_DIR="$OUTPUT_DIR/data"
    REPORTS_DIR="$OUTPUT_DIR/reports"
    TEMP_DIR="$OUTPUT_DIR/temp"
    LOG_FILE="$OUTPUT_DIR/logs/recon.log"
    CONFIG_FILE="${RECON_CONFIG:-$HOME/.config/recon/config.yaml}"
    DATABASE="$DATA_DIR/recon.db"
    LEGACY_DATABASE="$HOME/.local/share/bugbountybot/data/programs.db"

    mkdir -p "$OUTPUT_DIR" "$DATA_DIR" "$REPORTS_DIR" "$TEMP_DIR" \
        "$(dirname "$LOG_FILE")" "$(dirname "$CONFIG_FILE")" 2>/dev/null
}
