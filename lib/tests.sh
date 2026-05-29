#!/bin/bash
# Unit and smoke tests

run_unit_tests() {
    local failures=0

    local parsed
    parsed="$(resolve_scan_type "passive")"
    [ "$parsed" = "recon" ] || failures=$((failures + 1))
    parsed="$(resolve_scan_type "active")"
    [ "$parsed" = "vuln" ] || failures=$((failures + 1))
    parsed="$(resolve_scan_type "hybrid")"
    [ "$parsed" = "full" ] || failures=$((failures + 1))

    [ "$(sql_escape "a'b")" = "a''b" ] || failures=$((failures + 1))
    [ -z "$(build_program_filter_clause "all")" ] || failures=$((failures + 1))
    [ "$(build_program_filter_clause "acme")" = " AND program_handle='acme'" ] || failures=$((failures + 1))

    local plugin_runner="${PLUGIN_RUNNER[nuclei]:-}"
    [ -n "$plugin_runner" ] || failures=$((failures + 1))
    [ -n "$plugin_runner" ] && declare -F "$plugin_runner" >/dev/null || failures=$((failures + 1))

    [ -n "${PLUGIN_RESULT_PARSER[nuclei]:-}" ] || failures=$((failures + 1))
    [ "$(json_escape $'a\n"b')" = 'a\n\"b' ] || failures=$((failures + 1))

    if [ "$failures" -gt 0 ]; then
        error "Unit tests failed: $failures"
        return 1
    fi
    success "Unit tests passed"
}

run_smoke_tests() {
    local failures=0

    if ! command -v sqlite3 &>/dev/null; then
        warn "sqlite3 not found; skipping smoke tests"
        return 0
    fi

    local test_dir test_db test_reports original_database original_reports
    test_dir=$(mktemp -d)
    test_db="$test_dir/recon.db"
    test_reports="$test_dir/reports"
    mkdir -p "$test_reports"

    original_database="$DATABASE"
    original_reports="$REPORTS_DIR"
    DATABASE="$test_db"
    REPORTS_DIR="$test_reports"

    load_db >/dev/null 2>&1 || failures=$((failures + 1))
    load_plugins >/dev/null 2>&1 || true

    add_program "acme'corp" "ACME's Program" "https://example.com" "\$100-\$500" >/dev/null 2>&1 || failures=$((failures + 1))
    add_target "acme'corp" "domain" "api.example.com" >/dev/null 2>&1 || failures=$((failures + 1))
    add_finding "acme'corp" "api.example.com" "test vuln" "high" "example evidence" >/dev/null 2>&1 || failures=$((failures + 1))

    local targets_count
    targets_count=$(get_targets_for_program "acme'corp" | wc -l | tr -d ' ')
    [ "${targets_count:-0}" -ge 1 ] || failures=$((failures + 1))

    generate_bounty_report "acme'corp" "json" >/dev/null 2>&1 || true
    local report_exists=0
    for f in "$REPORTS_DIR"/bounty/report_*.json; do
        [ -f "$f" ] && report_exists=1 && break
    done
    [ "$report_exists" -eq 1 ] || failures=$((failures + 1))

    upsert_device "127.0.0.1" 80 "tcp" "http" "test" "{}" 10 "test" || failures=$((failures + 1))
    upsert_cve "CVE-2024-0001" "2024-01-01" "HIGH" 7.5 "test cve" 0 0 "http" "{}" || failures=$((failures + 1))

    local device_tables
    device_tables=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('devices','cves','scan_jobs','msf_sessions');" 2>/dev/null || echo 0)
    [ "${device_tables:-0}" -ge 4 ] || failures=$((failures + 1))

    DATABASE="$original_database"
    REPORTS_DIR="$original_reports"
    rm -rf "$test_dir"

    if [ "$failures" -gt 0 ]; then
        error "Smoke tests failed: $failures"
        return 1
    fi
    success "Smoke tests passed"
}
