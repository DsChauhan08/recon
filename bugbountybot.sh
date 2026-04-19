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

sql_escape() {
    local value="${1:-}"
    value="${value//\'/\'\'}"
    printf "%s" "$value"
}

is_positive_int() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]
}

resolve_scan_type() {
    local mode="${1:-full}"

    case "$mode" in
        passive|recon)
            echo "recon"
            ;;
        active|vuln)
            echo "vuln"
            ;;
        hybrid|full)
            echo "full"
            ;;
        *)
            warn "Unknown scan mode '$mode', defaulting to full" >&2
            echo "full"
            ;;
    esac
}

build_program_filter_clause() {
    local program="${1:-all}"

    if [ -n "$program" ] && [ "$program" != "all" ]; then
        printf " AND program_handle='%s'" "$(sql_escape "$program")"
    fi
}

json_escape() {
    local value="${1:-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf "%s" "$value"
}

hash_string() {
    local input="${1:-}"

    if command -v sha256sum &>/dev/null; then
        printf "%s" "$input" | sha256sum | cut -d' ' -f1
    elif command -v shasum &>/dev/null; then
        printf "%s" "$input" | shasum -a 256 | cut -d' ' -f1
    else
        printf "%s" "$input" | cksum | cut -d' ' -f1
    fi
}

declare -a RECON_PLUGIN_ORDER=()
declare -a VULN_PLUGIN_ORDER=()
declare -A PLUGIN_RUNNER=()
declare -A PLUGIN_COMMAND=()
declare -A PLUGIN_ENABLED_KEY=()
declare -A PLUGIN_CATEGORY=()
declare -A PLUGIN_CONFIDENCE=()
declare -A PLUGIN_RESULT_PARSER=()

register_plugin() {
    local phase="$1"
    local name="$2"
    local runner="$3"
    local command_name="$4"
    local enabled_key="${5:-}"
    local category="${6:-misc}"
    local confidence="${7:-medium}"
    local parser="${8:-}"

    if [ -z "$phase" ] || [ -z "$name" ] || [ -z "$runner" ] || [ -z "$command_name" ]; then
        warn "Invalid plugin definition: phase/name/runner/command required"
        return 1
    fi

    if [ "$phase" = "recon" ]; then
        RECON_PLUGIN_ORDER+=("$name")
    elif [ "$phase" = "vuln" ]; then
        VULN_PLUGIN_ORDER+=("$name")
    else
        warn "Unknown plugin phase while registering '$name': $phase"
        return 1
    fi

    PLUGIN_RUNNER["$name"]="$runner"
    PLUGIN_COMMAND["$name"]="$command_name"
    PLUGIN_ENABLED_KEY["$name"]="$enabled_key"
    PLUGIN_CATEGORY["$name"]="$category"
    PLUGIN_CONFIDENCE["$name"]="$confidence"
    PLUGIN_RESULT_PARSER["$name"]="$parser"
}

load_plugins() {
    RECON_PLUGIN_ORDER=()
    VULN_PLUGIN_ORDER=()
    PLUGIN_RUNNER=()
    PLUGIN_COMMAND=()
    PLUGIN_ENABLED_KEY=()
    PLUGIN_CATEGORY=()
    PLUGIN_CONFIDENCE=()
    PLUGIN_RESULT_PARSER=()

    local plugin_file

    for plugin_file in "$SCRIPT_DIR/plugins/recon/"*.sh; do
        [ -f "$plugin_file" ] || continue
        # shellcheck source=/dev/null
        source "$plugin_file"
    done

    for plugin_file in "$SCRIPT_DIR/plugins/vuln/"*.sh; do
        [ -f "$plugin_file" ] || continue
        # shellcheck source=/dev/null
        source "$plugin_file"
    done

    if [ "${#RECON_PLUGIN_ORDER[@]}" -eq 0 ] && [ "${#VULN_PLUGIN_ORDER[@]}" -eq 0 ]; then
        warn "No plugins loaded from $SCRIPT_DIR/plugins"
    fi
}

plugin_enabled() {
    local plugin="$1"
    local key="${PLUGIN_ENABLED_KEY[$plugin]:-}"

    if [ -z "$key" ]; then
        return 0
    fi

    local value="${!key:-true}"
    [ "$value" = "true" ]
}

plugin_available() {
    local plugin="$1"
    local command_name="${PLUGIN_COMMAND[$plugin]:-}"
    [ -n "$command_name" ] && command -v "$command_name" &>/dev/null
}

run_plugins() {
    local phase="$1"
    local target="$2"
    local output_dir="$3"
    local -a plugin_list=()

    case "$phase" in
        recon)
            plugin_list=("${RECON_PLUGIN_ORDER[@]}")
            ;;
        vuln)
            plugin_list=("${VULN_PLUGIN_ORDER[@]}")
            ;;
        *)
            warn "Unknown plugin phase: $phase"
            return 1
            ;;
    esac

    local plugin
    for plugin in "${plugin_list[@]}"; do
        if ! plugin_enabled "$plugin"; then
            continue
        fi

        if ! plugin_available "$plugin"; then
            continue
        fi

        local runner="${PLUGIN_RUNNER[$plugin]:-}"
        if [ -n "$runner" ] && declare -F "$runner" >/dev/null; then
            "$runner" "$target" "$output_dir" &
        fi
    done

    wait
}

parse_plugin_results() {
    local program="$1"
    local target="$2"
    local output_dir="$3"

    local plugin parser
    for plugin in "${VULN_PLUGIN_ORDER[@]}"; do
        parser="${PLUGIN_RESULT_PARSER[$plugin]:-}"
        if [ -n "$parser" ] && declare -F "$parser" >/dev/null; then
            "$parser" "$program" "$target" "$output_dir"
        fi
    done
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

CREATE TABLE normalized_findings (
    id INTEGER PRIMARY KEY,
    finding_hash TEXT UNIQUE,
    program_handle TEXT,
    target TEXT,
    plugin TEXT,
    title TEXT,
    category TEXT,
    severity TEXT,
    confidence TEXT,
    status TEXT,
    raw_file TEXT,
    raw_line INTEGER,
    raw_payload TEXT,
    normalized_json TEXT,
    asset TEXT,
    vector TEXT,
    correlation_key TEXT,
    seen_delta_seconds INTEGER DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE finding_correlations (
    id INTEGER PRIMARY KEY,
    correlation_key TEXT,
    finding_hash TEXT,
    program_handle TEXT,
    target TEXT,
    asset TEXT,
    plugin TEXT,
    vector TEXT,
    severity TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(correlation_key, finding_hash)
);

CREATE INDEX idx_targets_program ON targets(program_handle);
CREATE INDEX idx_targets_value ON targets(value);
CREATE INDEX idx_findings_program ON findings(program_handle);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_nf_program ON normalized_findings(program_handle);
CREATE INDEX idx_nf_target ON normalized_findings(target);
CREATE INDEX idx_nf_plugin ON normalized_findings(plugin);
CREATE INDEX idx_nf_severity ON normalized_findings(severity);
CREATE INDEX idx_nf_asset ON normalized_findings(asset);
CREATE INDEX idx_nf_vector ON normalized_findings(vector);
CREATE INDEX idx_nf_corr ON normalized_findings(correlation_key);
CREATE INDEX idx_fc_corr ON finding_correlations(correlation_key);
CREATE INDEX idx_fc_hash ON finding_correlations(finding_hash);
EOF
        success "Initialized database: $DATABASE"
    fi

    if ! sqlite3 "$DATABASE" "PRAGMA table_info(programs);" 2>/dev/null | grep -q '|updated_at|'; then
        sqlite3 "$DATABASE" "ALTER TABLE programs ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;" 2>/dev/null || true
    fi

    sqlite3 "$DATABASE" << 'EOF' 2>/dev/null
CREATE TABLE IF NOT EXISTS normalized_findings (
    id INTEGER PRIMARY KEY,
    finding_hash TEXT UNIQUE,
    program_handle TEXT,
    target TEXT,
    plugin TEXT,
    title TEXT,
    category TEXT,
    severity TEXT,
    confidence TEXT,
    status TEXT,
    raw_file TEXT,
    raw_line INTEGER,
    raw_payload TEXT,
    normalized_json TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS finding_correlations (
    id INTEGER PRIMARY KEY,
    correlation_key TEXT,
    finding_hash TEXT,
    program_handle TEXT,
    target TEXT,
    asset TEXT,
    plugin TEXT,
    vector TEXT,
    severity TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(correlation_key, finding_hash)
);
EOF

    sqlite3 "$DATABASE" "ALTER TABLE normalized_findings ADD COLUMN asset TEXT;" 2>/dev/null || true
    sqlite3 "$DATABASE" "ALTER TABLE normalized_findings ADD COLUMN vector TEXT;" 2>/dev/null || true
    sqlite3 "$DATABASE" "ALTER TABLE normalized_findings ADD COLUMN correlation_key TEXT;" 2>/dev/null || true
    sqlite3 "$DATABASE" "ALTER TABLE normalized_findings ADD COLUMN seen_delta_seconds INTEGER DEFAULT 0;" 2>/dev/null || true

    sqlite3 "$DATABASE" "CREATE INDEX IF NOT EXISTS idx_nf_program ON normalized_findings(program_handle);" 2>/dev/null || true
    sqlite3 "$DATABASE" "CREATE INDEX IF NOT EXISTS idx_nf_target ON normalized_findings(target);" 2>/dev/null || true
    sqlite3 "$DATABASE" "CREATE INDEX IF NOT EXISTS idx_nf_plugin ON normalized_findings(plugin);" 2>/dev/null || true
    sqlite3 "$DATABASE" "CREATE INDEX IF NOT EXISTS idx_nf_severity ON normalized_findings(severity);" 2>/dev/null || true
    sqlite3 "$DATABASE" "CREATE INDEX IF NOT EXISTS idx_nf_asset ON normalized_findings(asset);" 2>/dev/null || true
    sqlite3 "$DATABASE" "CREATE INDEX IF NOT EXISTS idx_nf_vector ON normalized_findings(vector);" 2>/dev/null || true
    sqlite3 "$DATABASE" "CREATE INDEX IF NOT EXISTS idx_nf_corr ON normalized_findings(correlation_key);" 2>/dev/null || true
    sqlite3 "$DATABASE" "CREATE INDEX IF NOT EXISTS idx_fc_corr ON finding_correlations(correlation_key);" 2>/dev/null || true
    sqlite3 "$DATABASE" "CREATE INDEX IF NOT EXISTS idx_fc_hash ON finding_correlations(finding_hash);" 2>/dev/null || true
    sqlite3 "$DATABASE" "CREATE UNIQUE INDEX IF NOT EXISTS idx_fc_unique ON finding_correlations(correlation_key, finding_hash);" 2>/dev/null || true
}

run_smoke_tests() {
    local failures=0
    local smoke_status=0

    if ! command -v sqlite3 &>/dev/null; then
        warn "sqlite3 not found; skipping smoke tests"
        return 0
    fi

    local test_dir
    test_dir=$(mktemp -d)
    local test_db="$test_dir/programs.db"
    local test_reports_dir="$test_dir/reports"
    mkdir -p "$test_reports_dir"

    local original_database="$DATABASE"
    local original_reports_dir="$REPORTS_DIR"
    local original_script_dir="$SCRIPT_DIR"
    DATABASE="$test_db"
    REPORTS_DIR="$test_reports_dir"
    SCRIPT_DIR="/home/regulus/Programs/Recon"

    if ! load_db >/dev/null 2>&1; then
        error "Smoke test failed: unable to initialize database"
        failures=$((failures + 1))
    fi

    load_plugins >/dev/null 2>&1 || true

    if ! add_program "acme'corp" "ACME's Program" "https://example.com" "\$100-\$500" >/dev/null 2>&1; then
        error "Smoke test failed: add_program with quotes"
        failures=$((failures + 1))
    fi

    if ! add_target "acme'corp" "domain" "api.example.com" >/dev/null 2>&1; then
        error "Smoke test failed: add_target"
        failures=$((failures + 1))
    fi

    if ! add_finding "acme'corp" "api.example.com" "test vuln" "high" "example evidence" >/dev/null 2>&1; then
        error "Smoke test failed: add_finding"
        failures=$((failures + 1))
    fi

    local targets_count
    targets_count=$(get_targets_for_program "acme'corp" | wc -l | tr -d ' ')
    if [ "${targets_count:-0}" -lt 1 ]; then
        error "Smoke test failed: query targets"
        failures=$((failures + 1))
    fi

    generate_report "acme'corp" "json" >/dev/null 2>&1 || true
    local report_exists=0
    for report_candidate in "$REPORTS_DIR"/report_*.json; do
        if [ -f "$report_candidate" ]; then
            report_exists=1
            break
        fi
    done

    if [ "$report_exists" -ne 1 ]; then
        error "Smoke test failed: generate_report"
        failures=$((failures + 1))
    fi

    local normalized_table_exists
    normalized_table_exists=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='normalized_findings';" 2>/dev/null || echo 0)
    if [ "$normalized_table_exists" != "1" ]; then
        error "Smoke test failed: normalized_findings table missing"
        failures=$((failures + 1))
    fi

    local correlation_table_exists
    correlation_table_exists=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='finding_correlations';" 2>/dev/null || echo 0)
    if [ "$correlation_table_exists" != "1" ]; then
        error "Smoke test failed: finding_correlations table missing"
        failures=$((failures + 1))
    fi

    local normalized_count
    normalized_count=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM normalized_findings;" 2>/dev/null || echo 0)
    if ! [[ "$normalized_count" =~ ^[0-9]+$ ]]; then
        normalized_count=0
    fi

    if [ "$normalized_count" -lt 1 ]; then
        add_normalized_finding "acme'corp" "api.example.com" "nuclei" "phase2-smoke" "web" "high" "high" "smoke" 1 "payload"
        normalized_count=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM normalized_findings;" 2>/dev/null || echo 0)
    fi

    if ! [[ "$normalized_count" =~ ^[0-9]+$ ]] || [ "$normalized_count" -lt 1 ]; then
        error "Smoke test failed: normalized findings insert"
        failures=$((failures + 1))
    fi

    local correlation_count
    correlation_count=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM finding_correlations;" 2>/dev/null || echo 0)
    if ! [[ "$correlation_count" =~ ^[0-9]+$ ]] || [ "$correlation_count" -lt 1 ]; then
        error "Smoke test failed: correlation insert"
        failures=$((failures + 1))
    fi

    DATABASE="$original_database"
    REPORTS_DIR="$original_reports_dir"
    SCRIPT_DIR="$original_script_dir"
    rm -rf "$test_dir"

    if [ "$failures" -gt 0 ]; then
        error "Smoke tests failed: $failures"
        smoke_status=1
    else
        success "Smoke tests passed"
    fi

    return "$smoke_status"
}

run_unit_tests() {
    local failures=0

    local parsed
    parsed="$(resolve_scan_type "passive")"
    [ "$parsed" = "recon" ] || failures=$((failures + 1))

    parsed="$(resolve_scan_type "active")"
    [ "$parsed" = "vuln" ] || failures=$((failures + 1))

    parsed="$(resolve_scan_type "hybrid")"
    [ "$parsed" = "full" ] || failures=$((failures + 1))

    local escaped
    escaped="$(sql_escape "a'b")"
    [ "$escaped" = "a''b" ] || failures=$((failures + 1))

    local clause
    clause="$(build_program_filter_clause "all")"
    [ -z "$clause" ] || failures=$((failures + 1))

    clause="$(build_program_filter_clause "acme")"
    [ "$clause" = " AND program_handle='acme'" ] || failures=$((failures + 1))

    local plugin_runner
    plugin_runner="${PLUGIN_RUNNER[nuclei]:-}"
    [ -n "$plugin_runner" ] || failures=$((failures + 1))
    if [ -n "$plugin_runner" ]; then
        declare -F "$plugin_runner" >/dev/null || failures=$((failures + 1))
    fi

    local parser
    parser="${PLUGIN_RESULT_PARSER[nuclei]:-}"
    [ -n "$parser" ] || failures=$((failures + 1))
    if [ -n "$parser" ]; then
        declare -F "$parser" >/dev/null || failures=$((failures + 1))
    fi

    local testssl_parser
    testssl_parser="${PLUGIN_RESULT_PARSER[testssl]:-}"
    [ "$testssl_parser" = "parse_testssl_results" ] || failures=$((failures + 1))

    local trufflehog_parser
    trufflehog_parser="${PLUGIN_RESULT_PARSER[trufflehog]:-}"
    [ "$trufflehog_parser" = "parse_trufflehog_results" ] || failures=$((failures + 1))

    local corr_hash
    corr_hash="$(hash_string "program|asset|vector")"
    [ -n "$corr_hash" ] || failures=$((failures + 1))

    local escaped_json
    escaped_json="$(json_escape $'a\n"b' )"
    [ "$escaped_json" = 'a\n\"b' ] || failures=$((failures + 1))

    if [ "$failures" -gt 0 ]; then
        error "Unit tests failed: $failures"
        return 1
    fi

    success "Unit tests passed"
    return 0
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
    
    if [ -n "$data" ]; then
        curl -s -X "$method" \
            -H "Authorization: Basic $auth" \
            -H "Content-Type: application/json" \
            --data "$data" \
            "https://api.hackerone.com/v1$endpoint"
    else
        curl -s -X "$method" \
            -H "Authorization: Basic $auth" \
            -H "Content-Type: application/json" \
            "https://api.hackerone.com/v1$endpoint"
    fi
}

fetch_h1_programs() {
    log "Fetching HackerOne bug bounty programs..."

    if ! command -v jq &>/dev/null; then
        warn "jq not installed, using public program feed"
        fetch_programs_public
        return
    fi
    
    local programs_json
    programs_json=$(h1_api_request "/programs" "GET" || true)
    
    if [ -z "$programs_json" ] || [ "$programs_json" = "null" ]; then
        warn "Could not fetch programs via API, using public data..."
        fetch_programs_public
        return
    fi
    
    echo "$programs_json" | jq -r '.data[] | [(.attributes.handle // ""), (.attributes.name // ""), (.attributes.url // ""), (.attributes.reward_range // "")] | @tsv' 2>/dev/null
}

fetch_programs_public() {
    log "Fetching programs from public sources..."

    local handles
    handles=$(
        curl -s "https://hackerone.com/directory?sort=published" 2>/dev/null | \
            grep -oP '"handle":"[^"]+"' 2>/dev/null | \
            sed -E 's/"handle":"([^"]+)"/\1/' | \
            sort -u || true
    )

    while IFS= read -r handle; do
        [ -n "$handle" ] || continue
        printf "%s\t%s\t%s\t%s\n" "$handle" "" "https://hackerone.com/$handle" ""
    done <<< "$handles"
}

get_program_scope() {
    local handle="$1"

    if ! command -v jq &>/dev/null; then
        fetch_scope_public "$handle"
        return
    fi
    
    local scope_json
    scope_json=$(h1_api_request "/programs/$handle/scopes" "GET" || true)
    
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
    
    local safe_handle safe_name safe_url safe_bounty
    safe_handle="$(sql_escape "$handle")"
    safe_name="$(sql_escape "${name:-$handle}")"
    safe_url="$(sql_escape "$url")"
    safe_bounty="$(sql_escape "$bounty")"

    local min_bounty=0 max_bounty=0
    if [ -n "$bounty" ] && [ "$bounty" != "null" ]; then
        min_bounty=$(echo "$bounty" | grep -oP '\$[0-9]+' | head -1 | sed 's/\$//' | sed 's/,//' || true)
        max_bounty=$(echo "$bounty" | grep -oP '\$[0-9]+' | tail -1 | sed 's/\$//' | sed 's/,//' || true)

        if ! [[ "$min_bounty" =~ ^[0-9]+$ ]]; then
            min_bounty=0
        fi

        if ! [[ "$max_bounty" =~ ^[0-9]+$ ]]; then
            max_bounty=$min_bounty
        fi
    fi
    
    sqlite3 "$DATABASE" << EOF
INSERT OR REPLACE INTO programs (handle, name, url, reward_range, min_bounty, max_bounty, status, updated_at)
VALUES ('$safe_handle', '$safe_name', '$safe_url', '$safe_bounty', $min_bounty, $max_bounty, 'active', datetime('now'))
ON CONFLICT(handle) DO UPDATE SET
    name='$safe_name',
    url='$safe_url',
    reward_range='$safe_bounty',
    min_bounty=$min_bounty,
    max_bounty=$max_bounty,
    updated_at=datetime('now');
EOF
}

add_target() {
    local program="$1"
    local type="$2"
    local value="$3"

    local safe_program safe_type safe_value
    safe_program="$(sql_escape "$program")"
    safe_type="$(sql_escape "$type")"
    safe_value="$(sql_escape "$value")"
    
    sqlite3 "$DATABASE" << EOF
INSERT OR IGNORE INTO targets (program_handle, type, value, status, last_found)
VALUES ('$safe_program', '$safe_type', '$safe_value', 'active', datetime('now'));
EOF
}

get_active_targets() {
    sqlite3 "$DATABASE" "SELECT program_handle, type, value FROM targets WHERE status='active';" 2>/dev/null
}

get_targets_for_program() {
    local program="$1"
    local safe_program
    safe_program="$(sql_escape "$program")"

    sqlite3 "$DATABASE" "SELECT type, value FROM targets WHERE program_handle='$safe_program' AND status='active';" 2>/dev/null
}

update_target_scan() {
    local program="$1"
    local value="$2"

    local safe_program safe_value
    safe_program="$(sql_escape "$program")"
    safe_value="$(sql_escape "$value")"
    
    sqlite3 "$DATABASE" "UPDATE targets SET last_scanned=datetime('now') WHERE program_handle='$safe_program' AND value='$safe_value';" 2>/dev/null
}

add_finding() {
    local program="$1"
    local target="$2"
    local vuln="$3"
    local severity="$4"
    local evidence="$5"
    
    local safe_program safe_target safe_vuln safe_severity safe_evidence
    safe_program="$(sql_escape "$program")"
    safe_target="$(sql_escape "$target")"
    safe_vuln="$(sql_escape "$vuln")"
    safe_severity="$(sql_escape "$severity")"
    safe_evidence="$(sql_escape "$evidence")"

    sqlite3 "$DATABASE" << EOF
INSERT INTO findings (program_handle, target, vulnerability, severity, status, evidence, reported_at)
VALUES ('$safe_program', '$safe_target', '$safe_vuln', '$safe_severity', 'new', '$safe_evidence', datetime('now'));
EOF
    
    local id=$(sqlite3 "$DATABASE" "SELECT last_insert_rowid();")
    echo "$id"
}

add_normalized_finding() {
    local program="$1"
    local target="$2"
    local plugin="$3"
    local title="$4"
    local category="$5"
    local severity="$6"
    local confidence="$7"
    local raw_file="$8"
    local raw_line="$9"
    shift 9
    local raw_payload="${1:-}"
    local vector_hint="${2:-}"

    local fingerprint_source
    fingerprint_source="$program|$target|$plugin|$title|$category|$severity|$raw_payload"
    local finding_hash
    finding_hash="$(hash_string "$fingerprint_source")"

    local asset vector
    asset="$(extract_asset_from_target "$target")"
    if [ -n "$vector_hint" ]; then
        vector="$(normalize_vector "$vector_hint")"
    else
        vector="$(normalize_vector "$category")"
    fi

    local correlation_key_source
    correlation_key_source="$program|$asset|$vector"
    local correlation_key
    correlation_key="$(hash_string "$correlation_key_source")"

    local normalized_json
    normalized_json=$(printf '{"program":"%s","target":"%s","plugin":"%s","title":"%s","category":"%s","severity":"%s","confidence":"%s","asset":"%s","vector":"%s","correlation_key":"%s"}' \
        "$(json_escape "$program")" \
        "$(json_escape "$target")" \
        "$(json_escape "$plugin")" \
        "$(json_escape "$title")" \
        "$(json_escape "$category")" \
        "$(json_escape "$severity")" \
        "$(json_escape "$confidence")" \
        "$(json_escape "$asset")" \
        "$(json_escape "$vector")" \
        "$(json_escape "$correlation_key")")

    local safe_hash safe_program safe_target safe_plugin safe_title safe_category
    local safe_severity safe_confidence safe_raw_file safe_raw_payload safe_json safe_asset safe_vector safe_correlation
    local safe_line
    safe_hash="$(sql_escape "$finding_hash")"
    safe_program="$(sql_escape "$program")"
    safe_target="$(sql_escape "$target")"
    safe_plugin="$(sql_escape "$plugin")"
    safe_title="$(sql_escape "$title")"
    safe_category="$(sql_escape "$category")"
    safe_severity="$(sql_escape "$severity")"
    safe_confidence="$(sql_escape "$confidence")"
    safe_raw_file="$(sql_escape "$raw_file")"
    safe_raw_payload="$(sql_escape "$raw_payload")"
    safe_json="$(sql_escape "$normalized_json")"
    safe_asset="$(sql_escape "$asset")"
    safe_vector="$(sql_escape "$vector")"
    safe_correlation="$(sql_escape "$correlation_key")"

    safe_line="$raw_line"
    if ! [[ "$safe_line" =~ ^[0-9]+$ ]]; then
        safe_line=0
    fi

    sqlite3 "$DATABASE" << EOF
INSERT INTO normalized_findings (
    finding_hash,
    program_handle,
    target,
    plugin,
    title,
    category,
    severity,
    confidence,
    status,
    raw_file,
    raw_line,
    raw_payload,
    normalized_json,
    asset,
    vector,
    correlation_key,
    seen_delta_seconds,
    first_seen,
    last_seen
) VALUES (
    '$safe_hash',
    '$safe_program',
    '$safe_target',
    '$safe_plugin',
    '$safe_title',
    '$safe_category',
    '$safe_severity',
    '$safe_confidence',
    'new',
    '$safe_raw_file',
    $safe_line,
    '$safe_raw_payload',
    '$safe_json',
    '$safe_asset',
    '$safe_vector',
    '$safe_correlation',
    0,
    datetime('now'),
    datetime('now')
)
ON CONFLICT(finding_hash) DO UPDATE SET
    last_seen=datetime('now'),
    raw_payload=excluded.raw_payload,
    normalized_json=excluded.normalized_json,
    asset=excluded.asset,
    vector=excluded.vector,
    correlation_key=excluded.correlation_key,
    severity=excluded.severity,
    confidence=excluded.confidence;
EOF

    record_finding_correlation "$finding_hash" "$program" "$target" "$plugin" "$vector" "$severity"
    update_correlation_summary "$finding_hash"
}

extract_asset_from_target() {
    local target="${1:-}"
    target="${target#http://}"
    target="${target#https://}"
    target="${target%%/*}"
    target="${target%%:*}"
    printf "%s" "$target"
}

normalize_vector() {
    local value="${1:-}"
    value="$(printf "%s" "$value" | tr '[:upper:]' '[:lower:]')"
    value="${value// /-}"
    printf "%s" "$value"
}

record_finding_correlation() {
    local finding_hash="$1"
    local program="$2"
    local target="$3"
    local plugin="$4"
    local vector="$5"
    local severity="$6"

    local asset
    asset="$(extract_asset_from_target "$target")"
    local normalized_vector
    normalized_vector="$(normalize_vector "$vector")"

    local key_source
    key_source="$program|$asset|$normalized_vector"
    local correlation_key
    correlation_key="$(hash_string "$key_source")"

    local safe_corr safe_hash safe_program safe_target safe_asset safe_plugin safe_vector safe_severity
    safe_corr="$(sql_escape "$correlation_key")"
    safe_hash="$(sql_escape "$finding_hash")"
    safe_program="$(sql_escape "$program")"
    safe_target="$(sql_escape "$target")"
    safe_asset="$(sql_escape "$asset")"
    safe_plugin="$(sql_escape "$plugin")"
    safe_vector="$(sql_escape "$normalized_vector")"
    safe_severity="$(sql_escape "$severity")"

    sqlite3 "$DATABASE" << EOF
INSERT INTO finding_correlations (
    correlation_key,
    finding_hash,
    program_handle,
    target,
    asset,
    plugin,
    vector,
    severity,
    first_seen,
    last_seen
) VALUES (
    '$safe_corr',
    '$safe_hash',
    '$safe_program',
    '$safe_target',
    '$safe_asset',
    '$safe_plugin',
    '$safe_vector',
    '$safe_severity',
    datetime('now'),
    datetime('now')
)
ON CONFLICT(correlation_key, finding_hash) DO UPDATE SET
    last_seen=datetime('now'),
    severity=excluded.severity;
EOF
}

update_correlation_summary() {
    local finding_hash="$1"

    local safe_hash
    safe_hash="$(sql_escape "$finding_hash")"

    local correlation_key
    correlation_key=$(sqlite3 "$DATABASE" "SELECT correlation_key FROM normalized_findings WHERE finding_hash='$safe_hash' LIMIT 1;" 2>/dev/null || echo "")
    if [ -z "$correlation_key" ] || [ "$correlation_key" = "null" ]; then
        return 0
    fi

    local safe_corr
    safe_corr="$(sql_escape "$correlation_key")"

    local first_seen
    first_seen=$(sqlite3 "$DATABASE" "SELECT MIN(first_seen) FROM finding_correlations WHERE correlation_key='$safe_corr';" 2>/dev/null || echo "")
    local last_seen
    last_seen=$(sqlite3 "$DATABASE" "SELECT MAX(last_seen) FROM finding_correlations WHERE correlation_key='$safe_corr';" 2>/dev/null || echo "")

    local delta_seconds=0
    if [ -n "$first_seen" ] && [ -n "$last_seen" ] && [ "$first_seen" != "null" ] && [ "$last_seen" != "null" ]; then
        delta_seconds=$(sqlite3 "$DATABASE" "SELECT CAST(strftime('%s','$last_seen') - strftime('%s','$first_seen') AS INTEGER);" 2>/dev/null || echo 0)
        if ! [[ "$delta_seconds" =~ ^-?[0-9]+$ ]]; then
            delta_seconds=0
        fi
    fi

    if ! [[ "$delta_seconds" =~ ^[0-9]+$ ]]; then
        delta_seconds=0
    fi

    sqlite3 "$DATABASE" "UPDATE normalized_findings SET first_seen=COALESCE('$first_seen', first_seen), last_seen=COALESCE('$last_seen', last_seen), seen_delta_seconds=$delta_seconds WHERE correlation_key='$safe_corr';" 2>/dev/null
}

get_resolved_count() {
    local program="$1"
    local safe_program
    safe_program="$(sql_escape "$program")"

    sqlite3 "$DATABASE" "SELECT COUNT(*) FROM programs WHERE handle='$safe_program' AND status='resolved';" 2>/dev/null
}

sync_all_programs() {
    log "Syncing all programs..."
    
    local temp_file=$(mktemp)
    fetch_h1_programs > "$temp_file" 2>/dev/null
    
    while IFS=$'\t' read -r handle name url bounty; do
        [ -n "$handle" ] || continue
        add_program "$handle" "$name" "$url" "$bounty"
        while IFS= read -r scope; do
            [ -n "$scope" ] || continue
            add_target "$handle" "domain" "$scope"
        done < <(get_program_scope "$handle")
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
    
    run_plugins "recon" "$target" "$target_dir"
}

vuln_scan_target() {
    local program="$1"
    local target="$2"
    local output_dir="$3"
    
    log "Running vulnerability scan on: $target"
    
    local target_dir="$output_dir/$(echo "$target" | tr '/.' '_')"
    mkdir -p "$target_dir"
    
    run_plugins "vuln" "$target" "$target_dir"
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

    parse_plugin_results "$program" "$target" "$output_dir"
}

parse_nuclei_results() {
    local program="$1"
    local target="$2"
    local output_dir="$3"

    local nuclei_file="$output_dir/$(echo "$target" | tr '/.' '_')/nuclei.txt"
    [ -f "$nuclei_file" ] || return 0

    local line_no=0
    while IFS= read -r line; do
        line_no=$((line_no + 1))
        [ -n "$line" ] || continue

        local severity
        severity=$(echo "$line" | grep -oE '\[(critical|high|medium|low|info)\]' | head -1 | tr -d '[]' || true)
        [ -n "$severity" ] || severity="info"

        local vuln_name
        vuln_name=$(echo "$line" | sed -n 's/^\[[^]]*\]\[[^]]*\]\s*\([^ ]*\).*/\1/p')
        [ -n "$vuln_name" ] || vuln_name="nuclei-finding"

        local category confidence vector_hint
        category="${PLUGIN_CATEGORY[nuclei]:-web}"
        confidence="${PLUGIN_CONFIDENCE[nuclei]:-high}"
        vector_hint="${line%%]*]}"
        vector_hint="${vector_hint#[}"
        [ -n "$vector_hint" ] || vector_hint="$vuln_name"

        add_finding "$program" "$target" "$vuln_name" "$severity" "$line" >/dev/null
        add_normalized_finding "$program" "$target" "nuclei" "$vuln_name" "$category" "$severity" "$confidence" "$nuclei_file" "$line_no" "$line" "$vector_hint"
    done < "$nuclei_file"
}

parse_testssl_results() {
    local program="$1"
    local target="$2"
    local output_dir="$3"

    local tls_file="$output_dir/$(echo "$target" | tr '/.' '_')/tls.json"
    [ -f "$tls_file" ] || return 0

    local line_no=0
    while IFS= read -r line; do
        line_no=$((line_no + 1))
        [ -n "$line" ] || continue

        local severity="medium"
        local title="tls-misconfiguration"
        local vector_hint="tls"

        if echo "$line" | grep -qiE 'critical|high|vulnerable|weak|insecure|failed'; then
            severity="high"
            title="tls-critical-issue"
        elif echo "$line" | grep -qiE 'medium|warning|deprecated'; then
            severity="medium"
            title="tls-warning"
        elif echo "$line" | grep -qiE 'info|ok|pass'; then
            severity="info"
            title="tls-info"
        fi

        if echo "$line" | grep -qi 'heartbleed'; then
            title="tls-heartbleed"
            vector_hint="heartbleed"
        elif echo "$line" | grep -qi 'renegotiation'; then
            title="tls-renegotiation"
            vector_hint="renegotiation"
        elif echo "$line" | grep -qi 'cipher'; then
            title="tls-weak-cipher"
            vector_hint="cipher"
        fi

        add_normalized_finding "$program" "$target" "testssl" "$title" "${PLUGIN_CATEGORY[testssl]:-tls}" "$severity" "${PLUGIN_CONFIDENCE[testssl]:-medium}" "$tls_file" "$line_no" "$line" "$vector_hint"
    done < "$tls_file"
}

parse_trufflehog_results() {
    local program="$1"
    local target="$2"
    local output_dir="$3"

    local secrets_file="$output_dir/$(echo "$target" | tr '/.' '_')/secrets.txt"
    [ -f "$secrets_file" ] || return 0

    local line_no=0
    while IFS= read -r line; do
        line_no=$((line_no + 1))
        [ -n "$line" ] || continue

        local title="secret-detected"
        local vector_hint="generic-secret"
        local severity="high"

        if echo "$line" | grep -qi 'aws'; then
            title="aws-secret"
            vector_hint="aws-key"
            severity="critical"
        elif echo "$line" | grep -qi 'github'; then
            title="github-token"
            vector_hint="github-token"
            severity="high"
        elif echo "$line" | grep -qi 'slack'; then
            title="slack-token"
            vector_hint="slack-token"
            severity="high"
        elif echo "$line" | grep -qi 'password'; then
            title="password-leak"
            vector_hint="password"
            severity="high"
        fi

        add_normalized_finding "$program" "$target" "trufflehog" "$title" "${PLUGIN_CATEGORY[trufflehog]:-secrets}" "$severity" "${PLUGIN_CONFIDENCE[trufflehog]:-medium}" "$secrets_file" "$line_no" "$line" "$vector_hint"
    done < "$secrets_file"
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
    
    local normalized_scan_type
    normalized_scan_type="$(resolve_scan_type "$scan_type")"

    local count=0
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            local type=$(echo "$line" | cut -d'|' -f1)
            local target=$(echo "$line" | cut -d'|' -f2)
            
            if [ $count -ge $MAX_CONCURRENT ]; then
                wait
                count=0
            fi
            
            process_target "$program" "$type" "$target" "$normalized_scan_type" &
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
            local safe_program
            safe_program="$(sql_escape "$program")"
            local resolved=$(sqlite3 "$DATABASE" "SELECT COALESCE(resolved_count,0) FROM programs WHERE handle='$safe_program';" 2>/dev/null || echo 0)
            local min_bounty=${filters_min_bounty:-0}
            local max_reports=${filters_max_reports_resolved:-1000}

            if ! [[ "$resolved" =~ ^[0-9]+$ ]]; then
                resolved=0
            fi

            if ! [[ "$max_reports" =~ ^[0-9]+$ ]]; then
                max_reports=1000
            fi
            
            if [ "$resolved" -gt "$max_reports" ]; then
                warn "Skipping $program - too many resolved reports"
                continue
            fi

            if [[ "$min_bounty" =~ ^[0-9]+$ ]]; then
                local safe_program_for_bounty
                safe_program_for_bounty="$(sql_escape "$program")"
                local program_max_bounty
                program_max_bounty=$(sqlite3 "$DATABASE" "SELECT COALESCE(max_bounty,0) FROM programs WHERE handle='$safe_program_for_bounty';" 2>/dev/null || echo 0)
                if ! [[ "$program_max_bounty" =~ ^[0-9]+$ ]]; then
                    program_max_bounty=0
                fi

                if [ "$program_max_bounty" -lt "$min_bounty" ]; then
                    warn "Skipping $program - bounty below minimum filter"
                    continue
                fi
            fi
            
            scan_program "$program" "$(resolve_scan_type "$MODE")"
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
    
    process_target "$program" "domain" "$target" "$(resolve_scan_type "$scan_type")"
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
        local safe_program
        safe_program="$(sql_escape "$program")"
        sqlite3 -header -column "$DATABASE" "SELECT program_handle, type, value, last_scanned, vuln_count FROM targets WHERE program_handle='$safe_program' ORDER BY last_found DESC LIMIT 50;" 2>/dev/null
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
        query="$query AND program_handle='$(sql_escape "$program")'"
    fi
    
    if [ -n "$severity" ]; then
        query="$query AND severity='$(sql_escape "$severity")'"
    fi
    
    query="$query ORDER BY severity DESC, reported_at DESC LIMIT 100;"
    
    sqlite3 -header -column "$DATABASE" "$query" 2>/dev/null
}

list_normalized_findings() {
    local program="${1:-}"
    local severity="${2:-}"

    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║      NORMALIZED FINDINGS                      ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""

    local query="SELECT program_handle, asset, vector, target, plugin, title, category, severity, confidence, seen_delta_seconds, first_seen, last_seen FROM normalized_findings WHERE status='new'"

    if [ -n "$program" ]; then
        query="$query AND program_handle='$(sql_escape "$program")'"
    fi

    if [ -n "$severity" ]; then
        query="$query AND severity='$(sql_escape "$severity")'"
    fi

    query="$query ORDER BY severity DESC, last_seen DESC LIMIT 100;"
    sqlite3 -header -column "$DATABASE" "$query" 2>/dev/null
}

generate_report() {
    local program="${1:-all}"
    local format="${2:-html}"
    
    local output_file="$REPORTS_DIR/report_$(date +%Y%m%d_%H%M%S).$format"
    local where_program
    where_program="$(build_program_filter_clause "$program")"
    
    log "Generating $format report for $program..."
    
    local critical=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='critical'$where_program;" 2>/dev/null || echo 0)
    local high=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='high'$where_program;" 2>/dev/null || echo 0)
    local medium=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='medium'$where_program;" 2>/dev/null || echo 0)
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
        $(sqlite3 "$DATABASE" "SELECT program_handle, target, vulnerability, severity, reported_at FROM findings WHERE status='new'$where_program ORDER BY severity DESC, reported_at DESC LIMIT 100;" 2>/dev/null | sed 's/|/<\/td><td>/g' | sed 's/^/<tr><td>/' | sed 's/$/<\/td><\/tr>/')
    </table>
</body>
</html>
EOF
            ;;
        json)
            sqlite3 "$DATABASE" "SELECT json_object('program', program_handle, 'target', target, 'vulnerability', vulnerability, 'severity', severity, 'date', reported_at, 'evidence', evidence) FROM findings WHERE status='new'$where_program ORDER BY severity DESC;" 2>/dev/null > "$output_file"
            ;;
    esac
    
    success "Report generated: $output_file"
    echo "$output_file"
}

export_findings() {
    local program="${1:-all}"
    local format="${2:-csv}"
    
    local output_file="$REPORTS_DIR/findings_$(date +%Y%m%d_%H%M%S).$format"
    
    local where_program
    where_program="$(build_program_filter_clause "$program")"

    case "$format" in
        csv)
            echo "Program,Target,Vulnerability,Severity,Date,Evidence" > "$output_file"
            sqlite3 "$DATABASE" "SELECT program_handle, target, vulnerability, severity, reported_at, evidence FROM findings WHERE status='new'$where_program;" 2>/dev/null | sed 's/|/,/g' >> "$output_file"
            ;;
        json)
            sqlite3 "$DATABASE" "SELECT json_group_array(json_object('program', program_handle, 'target', target, 'vulnerability', vulnerability, 'severity', severity, 'date', reported_at, 'evidence', evidence)) FROM findings WHERE status='new'$where_program;" 2>/dev/null > "$output_file"
            ;;
    esac
    
    success "Exported: $output_file"
}

clear_findings() {
    local program="${1:-}"
    
    if [ -n "$program" ]; then
        sqlite3 "$DATABASE" "DELETE FROM findings WHERE program_handle='$(sql_escape "$program")' AND status='new';" 2>/dev/null
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
    echo "  normalized [prog]   List normalized findings"
    echo "  report [prog] [fmt] Generate report (html/json)"
    echo "  export [prog] [fmt] Export findings (csv/json)"
    echo "  clear [program]     Clear findings"
    echo "  status              Show status"
    echo "  continuous          Run continuous scanning"
    echo "  test                Run internal tests"
    echo "  help                Show this help"
    echo ""
    echo "OPTIONS:"
    echo "  --mode passive|active|hybrid  Scan mode"
    echo "  --interval SECONDS            Scan interval"
    echo "  --test                        Run tests before command"
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
    load_plugins
    
    local command="${1:-help}"
    shift || true

    local mode_override=""
    local interval_override=""
    local run_tests=false
    local positional=()

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --test)
                run_tests=true
                ;;
            --mode)
                shift || true
                if [ "$#" -eq 0 ]; then
                    error "--mode requires a value"
                    exit 1
                fi
                mode_override="$1"
                ;;
            --interval)
                shift || true
                if [ "$#" -eq 0 ]; then
                    error "--interval requires a value"
                    exit 1
                fi
                interval_override="$1"
                ;;
            *)
                positional+=("$1")
                ;;
        esac
        shift || true
    done

    local arg1="${positional[0]:-}"
    local arg2="${positional[1]:-}"
    local arg3="${positional[2]:-}"

    if [ -n "$mode_override" ]; then
        MODE="$mode_override"
    fi

    if [ -n "$interval_override" ]; then
        if is_positive_int "$interval_override"; then
            SCAN_INTERVAL="$interval_override"
        else
            error "--interval must be a positive integer"
            exit 1
        fi
    fi

    MODE="$(resolve_scan_type "$MODE")"

    if [ "$run_tests" = true ]; then
        run_unit_tests || exit 1
        run_smoke_tests || exit 1
    fi
    
    case "$command" in
        sync)
            sync_all_programs
            ;;
        scan)
            scan_single_program "$arg1" "${arg2:-$MODE}"
            ;;
        scan-target)
            scan_single_target "$arg1" "$arg2" "${arg3:-$MODE}"
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
        normalized)
            list_normalized_findings "$arg1" "$arg2"
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
        test)
            run_unit_tests && run_smoke_tests
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
