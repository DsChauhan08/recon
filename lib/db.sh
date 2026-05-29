#!/bin/bash
# SQLite database schema and CRUD operations

migrate_legacy_database() {
    if [ -f "$LEGACY_DATABASE" ] && [ ! -f "$DATABASE" ]; then
        cp "$LEGACY_DATABASE" "$DATABASE"
        success "Migrated legacy database to $DATABASE"
    fi
}

load_db() {
    migrate_legacy_database

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

CREATE TABLE devices (
    id INTEGER PRIMARY KEY,
    ip TEXT,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    banner TEXT,
    fingerprint_json TEXT,
    risk_score INTEGER DEFAULT 0,
    compromise_indicators TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip, port, protocol)
);

CREATE TABLE scan_jobs (
    id INTEGER PRIMARY KEY,
    mode TEXT,
    status TEXT,
    config_json TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP
);

CREATE TABLE cves (
    id TEXT PRIMARY KEY,
    published_at TEXT,
    severity TEXT,
    cvss REAL,
    description TEXT,
    kev INTEGER DEFAULT 0,
    exploit_available INTEGER DEFAULT 0,
    affected_products TEXT,
    raw_json TEXT,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cve_device_matches (
    cve_id TEXT,
    device_id INTEGER,
    confidence TEXT,
    matched_on TEXT,
    PRIMARY KEY (cve_id, device_id)
);

CREATE TABLE msf_sessions (
    id INTEGER PRIMARY KEY,
    target TEXT,
    module TEXT,
    session_id TEXT,
    status TEXT,
    opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP
);

CREATE TABLE blocklist (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
CREATE INDEX idx_devices_ip ON devices(ip);
CREATE INDEX idx_devices_risk ON devices(risk_score);
CREATE INDEX idx_cves_severity ON cves(severity);
CREATE INDEX idx_scan_jobs_mode ON scan_jobs(mode);
EOF
        success "Initialized database: $DATABASE"
    fi

    sqlite3 "$DATABASE" << 'EOF' 2>/dev/null
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    ip TEXT, port INTEGER, protocol TEXT,
    service TEXT, banner TEXT, fingerprint_json TEXT,
    risk_score INTEGER DEFAULT 0, compromise_indicators TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip, port, protocol)
);
CREATE TABLE IF NOT EXISTS scan_jobs (
    id INTEGER PRIMARY KEY, mode TEXT, status TEXT, config_json TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, finished_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cves (
    id TEXT PRIMARY KEY, published_at TEXT, severity TEXT, cvss REAL,
    description TEXT, kev INTEGER DEFAULT 0, exploit_available INTEGER DEFAULT 0,
    affected_products TEXT, raw_json TEXT, synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cve_device_matches (
    cve_id TEXT, device_id INTEGER, confidence TEXT, matched_on TEXT,
    PRIMARY KEY (cve_id, device_id)
);
CREATE TABLE IF NOT EXISTS msf_sessions (
    id INTEGER PRIMARY KEY, target TEXT, module TEXT, session_id TEXT,
    status TEXT, opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, closed_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS blocklist (
    ip TEXT PRIMARY KEY, reason TEXT, added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_risk ON devices(risk_score);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
EOF

    if ! sqlite3 "$DATABASE" "PRAGMA table_info(programs);" 2>/dev/null | grep -q '|updated_at|'; then
        sqlite3 "$DATABASE" "ALTER TABLE programs ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;" 2>/dev/null || true
    fi

    for col in asset vector correlation_key seen_delta_seconds; do
        sqlite3 "$DATABASE" "ALTER TABLE normalized_findings ADD COLUMN $col TEXT;" 2>/dev/null || true
    done
    sqlite3 "$DATABASE" "ALTER TABLE normalized_findings ADD COLUMN seen_delta_seconds INTEGER DEFAULT 0;" 2>/dev/null || true
}

# --- Program / target CRUD ---

add_program() {
    local handle="$1" name="$2" url="$3" bounty="$4"
    local safe_handle safe_name safe_url safe_bounty
    safe_handle="$(sql_escape "$handle")"
    safe_name="$(sql_escape "${name:-$handle}")"
    safe_url="$(sql_escape "$url")"
    safe_bounty="$(sql_escape "$bounty")"

    local min_bounty=0 max_bounty=0
    if [ -n "$bounty" ] && [ "$bounty" != "null" ]; then
        min_bounty=$(echo "$bounty" | grep -oP '\$[0-9]+' | head -1 | sed 's/\$//' | sed 's/,//' || true)
        max_bounty=$(echo "$bounty" | grep -oP '\$[0-9]+' | tail -1 | sed 's/\$//' | sed 's/,//' || true)
        [[ "$min_bounty" =~ ^[0-9]+$ ]] || min_bounty=0
        [[ "$max_bounty" =~ ^[0-9]+$ ]] || max_bounty=$min_bounty
    fi

    sqlite3 "$DATABASE" << EOF
INSERT OR REPLACE INTO programs (handle, name, url, reward_range, min_bounty, max_bounty, status, updated_at)
VALUES ('$safe_handle', '$safe_name', '$safe_url', '$safe_bounty', $min_bounty, $max_bounty, 'active', datetime('now'))
ON CONFLICT(handle) DO UPDATE SET
    name='$safe_name', url='$safe_url', reward_range='$safe_bounty',
    min_bounty=$min_bounty, max_bounty=$max_bounty, updated_at=datetime('now');
EOF
}

add_target() {
    local program="$1" type="$2" value="$3"
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
    sqlite3 "$DATABASE" "SELECT type, value FROM targets WHERE program_handle='$(sql_escape "$program")' AND status='active';" 2>/dev/null
}

update_target_scan() {
    local program="$1" value="$2"
    sqlite3 "$DATABASE" "UPDATE targets SET last_scanned=datetime('now') WHERE program_handle='$(sql_escape "$program")' AND value='$(sql_escape "$value")';" 2>/dev/null
}

add_finding() {
    local program="$1" target="$2" vuln="$3" severity="$4" evidence="$5"
    sqlite3 "$DATABASE" << EOF
INSERT INTO findings (program_handle, target, vulnerability, severity, status, evidence, reported_at)
VALUES ('$(sql_escape "$program")', '$(sql_escape "$target")', '$(sql_escape "$vuln")',
        '$(sql_escape "$severity")', 'new', '$(sql_escape "$evidence")', datetime('now'));
EOF
    sqlite3 "$DATABASE" "SELECT last_insert_rowid();"
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
    local finding_hash="$1" program="$2" target="$3" plugin="$4" vector="$5" severity="$6"
    local asset normalized_vector correlation_key
    asset="$(extract_asset_from_target "$target")"
    normalized_vector="$(normalize_vector "$vector")"
    correlation_key="$(hash_string "$program|$asset|$normalized_vector")"

    sqlite3 "$DATABASE" << EOF
INSERT INTO finding_correlations (correlation_key, finding_hash, program_handle, target, asset, plugin, vector, severity, first_seen, last_seen)
VALUES ('$(sql_escape "$correlation_key")', '$(sql_escape "$finding_hash")', '$(sql_escape "$program")',
        '$(sql_escape "$target")', '$(sql_escape "$asset")', '$(sql_escape "$plugin")',
        '$(sql_escape "$normalized_vector")', '$(sql_escape "$severity")', datetime('now'), datetime('now'))
ON CONFLICT(correlation_key, finding_hash) DO UPDATE SET last_seen=datetime('now'), severity=excluded.severity;
EOF
}

update_correlation_summary() {
    local finding_hash="$1"
    local safe_hash correlation_key first_seen last_seen delta_seconds=0
    safe_hash="$(sql_escape "$finding_hash")"
    correlation_key=$(sqlite3 "$DATABASE" "SELECT correlation_key FROM normalized_findings WHERE finding_hash='$safe_hash' LIMIT 1;" 2>/dev/null || echo "")
    [ -n "$correlation_key" ] && [ "$correlation_key" != "null" ] || return 0

    first_seen=$(sqlite3 "$DATABASE" "SELECT MIN(first_seen) FROM finding_correlations WHERE correlation_key='$(sql_escape "$correlation_key")';" 2>/dev/null || echo "")
    last_seen=$(sqlite3 "$DATABASE" "SELECT MAX(last_seen) FROM finding_correlations WHERE correlation_key='$(sql_escape "$correlation_key")';" 2>/dev/null || echo "")

    if [ -n "$first_seen" ] && [ -n "$last_seen" ] && [ "$first_seen" != "null" ] && [ "$last_seen" != "null" ]; then
        delta_seconds=$(sqlite3 "$DATABASE" "SELECT CAST(strftime('%s','$last_seen') - strftime('%s','$first_seen') AS INTEGER);" 2>/dev/null || echo 0)
        [[ "$delta_seconds" =~ ^[0-9]+$ ]] || delta_seconds=0
    fi

    sqlite3 "$DATABASE" "UPDATE normalized_findings SET first_seen=COALESCE('$first_seen', first_seen), last_seen=COALESCE('$last_seen', last_seen), seen_delta_seconds=$delta_seconds WHERE correlation_key='$(sql_escape "$correlation_key")';" 2>/dev/null
}

add_normalized_finding() {
    local program="$1" target="$2" plugin="$3" title="$4" category="$5"
    local severity="$6" confidence="$7" raw_file="$8" raw_line="$9"
    shift 9
    local raw_payload="${1:-}" vector_hint="${2:-}"

    local finding_hash asset vector correlation_key normalized_json
    finding_hash="$(hash_string "$program|$target|$plugin|$title|$category|$severity|$raw_payload")"
    asset="$(extract_asset_from_target "$target")"
    if [ -n "$vector_hint" ]; then vector="$(normalize_vector "$vector_hint")"; else vector="$(normalize_vector "$category")"; fi
    correlation_key="$(hash_string "$program|$asset|$vector")"

    normalized_json=$(printf '{"program":"%s","target":"%s","plugin":"%s","title":"%s","category":"%s","severity":"%s","confidence":"%s","asset":"%s","vector":"%s","correlation_key":"%s"}' \
        "$(json_escape "$program")" "$(json_escape "$target")" "$(json_escape "$plugin")" \
        "$(json_escape "$title")" "$(json_escape "$category")" "$(json_escape "$severity")" \
        "$(json_escape "$confidence")" "$(json_escape "$asset")" "$(json_escape "$vector")" \
        "$(json_escape "$correlation_key")")

    [[ "$raw_line" =~ ^[0-9]+$ ]] || raw_line=0

    sqlite3 "$DATABASE" << EOF
INSERT INTO normalized_findings (finding_hash, program_handle, target, plugin, title, category, severity, confidence, status, raw_file, raw_line, raw_payload, normalized_json, asset, vector, correlation_key, seen_delta_seconds, first_seen, last_seen)
VALUES ('$(sql_escape "$finding_hash")', '$(sql_escape "$program")', '$(sql_escape "$target")', '$(sql_escape "$plugin")',
        '$(sql_escape "$title")', '$(sql_escape "$category")', '$(sql_escape "$severity")', '$(sql_escape "$confidence")',
        'new', '$(sql_escape "$raw_file")', $raw_line, '$(sql_escape "$raw_payload")', '$(sql_escape "$normalized_json")',
        '$(sql_escape "$asset")', '$(sql_escape "$vector")', '$(sql_escape "$correlation_key")', 0, datetime('now'), datetime('now'))
ON CONFLICT(finding_hash) DO UPDATE SET last_seen=datetime('now'), raw_payload=excluded.raw_payload,
    normalized_json=excluded.normalized_json, asset=excluded.asset, vector=excluded.vector,
    correlation_key=excluded.correlation_key, severity=excluded.severity, confidence=excluded.confidence;
EOF
    record_finding_correlation "$finding_hash" "$program" "$target" "$plugin" "$vector" "$severity"
    update_correlation_summary "$finding_hash"
}

# --- Device / hunt CRUD ---

upsert_device() {
    local ip="$1" port="$2" protocol="$3" service="$4" banner="$5"
    local fingerprint_json="${6:-{}}" risk_score="${7:-0}" indicators="${8:-}"
    sqlite3 "$DATABASE" << EOF
INSERT INTO devices (ip, port, protocol, service, banner, fingerprint_json, risk_score, compromise_indicators, first_seen, last_seen)
VALUES ('$(sql_escape "$ip")', $port, '$(sql_escape "$protocol")', '$(sql_escape "$service")',
        '$(sql_escape "$banner")', '$(sql_escape "$fingerprint_json")', $risk_score,
        '$(sql_escape "$indicators")', datetime('now'), datetime('now'))
ON CONFLICT(ip, port, protocol) DO UPDATE SET
    service=excluded.service, banner=excluded.banner, fingerprint_json=excluded.fingerprint_json,
    risk_score=excluded.risk_score, compromise_indicators=excluded.compromise_indicators, last_seen=datetime('now');
EOF
}

create_scan_job() {
    local mode="$1" config_json="$2"
    sqlite3 "$DATABASE" << EOF
INSERT INTO scan_jobs (mode, status, config_json) VALUES ('$(sql_escape "$mode")', 'running', '$(sql_escape "$config_json")');
SELECT last_insert_rowid();
EOF
}

finish_scan_job() {
    local job_id="$1" status="${2:-done}"
    sqlite3 "$DATABASE" "UPDATE scan_jobs SET status='$(sql_escape "$status")', finished_at=datetime('now') WHERE id=$job_id;" 2>/dev/null
}

is_blocklisted() {
    local ip="$1"
    local count
    count=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM blocklist WHERE ip='$(sql_escape "$ip")';" 2>/dev/null || echo 0)
    [ "${count:-0}" -gt 0 ]
}

# --- CVE CRUD ---

upsert_cve() {
    local id="$1" published_at="$2" severity="$3" cvss="$4" description="$5"
    local kev="${6:-0}" exploit="${7:-0}" products="${8:-}" raw_json="${9:-}"
    [[ "$cvss" =~ ^[0-9.]+$ ]] || cvss=0
    sqlite3 "$DATABASE" << EOF
INSERT INTO cves (id, published_at, severity, cvss, description, kev, exploit_available, affected_products, raw_json, synced_at)
VALUES ('$(sql_escape "$id")', '$(sql_escape "$published_at")', '$(sql_escape "$severity")', $cvss,
        '$(sql_escape "$description")', $kev, $exploit, '$(sql_escape "$products")', '$(sql_escape "$raw_json")', datetime('now'))
ON CONFLICT(id) DO UPDATE SET published_at=excluded.published_at, severity=excluded.severity, cvss=excluded.cvss,
    description=excluded.description, kev=excluded.kev, exploit_available=excluded.exploit_available,
    affected_products=excluded.affected_products, raw_json=excluded.raw_json, synced_at=datetime('now');
EOF
}

add_cve_device_match() {
    local cve_id="$1" device_id="$2" confidence="$3" matched_on="$4"
    sqlite3 "$DATABASE" << EOF
INSERT OR IGNORE INTO cve_device_matches (cve_id, device_id, confidence, matched_on)
VALUES ('$(sql_escape "$cve_id")', $device_id, '$(sql_escape "$confidence")', '$(sql_escape "$matched_on")');
EOF
}

# --- MSF session CRUD ---

add_msf_session() {
    local target="$1" module="$2" session_id="$3" status="${4:-open}"
    sqlite3 "$DATABASE" << EOF
INSERT INTO msf_sessions (target, module, session_id, status) VALUES ('$(sql_escape "$target")', '$(sql_escape "$module")', '$(sql_escape "$session_id")', '$(sql_escape "$status")');
SELECT last_insert_rowid();
EOF
}

close_msf_session() {
    local session_id="$1"
    sqlite3 "$DATABASE" "UPDATE msf_sessions SET status='closed', closed_at=datetime('now') WHERE session_id='$(sql_escape "$session_id")';" 2>/dev/null
}
