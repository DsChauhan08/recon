#!/bin/bash
# Bug bounty (HackerOne) mode

h1_api_request() {
    local endpoint="$1"
    local method="${2:-GET}"
    local data="${3:-}"

    if [ -z "${api_hackerone_username:-}" ] || [ -z "${api_hackerone_api_key:-}" ]; then
        warn "HackerOne API credentials not configured"
        return 1
    fi

    local auth
    auth=$(echo -n "${api_hackerone_username}:${api_hackerone_api_key}" | base64)

    if [ -n "$data" ]; then
        curl -s -X "$method" -H "Authorization: Basic $auth" -H "Content-Type: application/json" \
            --data "$data" "https://api.hackerone.com/v1$endpoint"
    else
        curl -s -X "$method" -H "Authorization: Basic $auth" -H "Content-Type: application/json" \
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
    handles=$(curl -s "https://hackerone.com/directory?sort=published" 2>/dev/null | \
        grep -oP '"handle":"[^"]+"' 2>/dev/null | sed -E 's/"handle":"([^"]+)"/\1/' | sort -u || true)
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
        fetch_scope_public "$handle"
        return
    fi

    echo "$scope_json" | jq -r '.data[] | select(.attributes.eligible_for_submission==true) | .attributes.asset_identifier' 2>/dev/null
}

fetch_scope_public() {
    local handle="$1"
    curl -s "https://hackerone.com/$handle" 2>/dev/null | \
        grep -oP 'data-test="scope-[^"]*"[^>]*>[^<]*' 2>/dev/null | \
        sed 's/.*>//' | grep -E '\*?\.?[^ ]+' | head -50
}

sync_all_programs() {
    log "Syncing all programs..."
    local temp_file
    temp_file=$(mktemp)
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
    local program="$1" target="$2" output_dir="$3"
    log "Running recon on: $target"
    local target_dir
    target_dir="$(target_output_dir "$output_dir" "$target")"
    mkdir -p "$target_dir"
    run_plugins "recon" "$target" "$target_dir"
}

vuln_scan_target() {
    local program="$1" target="$2" output_dir="$3"
    log "Running vulnerability scan on: $target"
    local target_dir
    target_dir="$(target_output_dir "$output_dir" "$target")"
    mkdir -p "$target_dir"
    run_plugins "vuln" "$target" "$target_dir"
}

process_target() {
    local program="$1" type="$2" target="$3" scan_type="$4"
    local timestamp output_dir start_time end_time duration
    timestamp=$(date +%Y%m%d_%H%M%S)
    output_dir="$REPORTS_DIR/bounty/$program/$timestamp"
    mkdir -p "$output_dir"

    log "Processing target: $program -> $target"
    start_time=$(date +%s)

    case "$scan_type" in
        recon) recon_target "$program" "$target" "$output_dir" ;;
        vuln) vuln_scan_target "$program" "$target" "$output_dir" ;;
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

    end_time=$(date +%s)
    duration=$((end_time - start_time))
    update_target_scan "$program" "$target"
    parse_plugin_results "$program" "$target" "$output_dir"
    success "Completed $target in ${duration}s"
}

scan_program() {
    local program="$1" scan_type="${2:-full}"
    log "Scanning program: $program"

    local targets
    targets=$(get_targets_for_program "$program")
    if [ -z "$targets" ]; then
        warn "No targets found for $program"
        return 1
    fi

    local normalized_scan_type count=0
    normalized_scan_type="$(resolve_scan_type "$scan_type")"

    while IFS='|' read -r type target; do
        [ -n "$target" ] || continue
        if [ $count -ge "$MAX_CONCURRENT" ]; then
            wait
            count=0
        fi
        process_target "$program" "$type" "$target" "$normalized_scan_type" &
        count=$((count + 1))
    done <<< "$targets"

    wait
    success "Completed scan for $program"
}

run_continuous_scan() {
    log "Starting continuous bug bounty scanning..."
    log "Mode: $MODE | Interval: ${SCAN_INTERVAL}s | Max concurrent: $MAX_CONCURRENT"

    while true; do
        log "=== Scan cycle started at $(date) ==="
        local programs
        programs=$(sqlite3 "$DATABASE" "SELECT handle FROM programs WHERE status='active';" 2>/dev/null)

        for program in $programs; do
            local resolved min_bounty max_reports program_max_bounty
            resolved=$(sqlite3 "$DATABASE" "SELECT COALESCE(resolved_count,0) FROM programs WHERE handle='$(sql_escape "$program")';" 2>/dev/null || echo 0)
            min_bounty=${filters_min_bounty:-0}
            max_reports=${filters_max_reports_resolved:-1000}
            [[ "$resolved" =~ ^[0-9]+$ ]] || resolved=0
            [[ "$max_reports" =~ ^[0-9]+$ ]] || max_reports=1000

            if [ "$resolved" -gt "$max_reports" ]; then
                warn "Skipping $program - too many resolved reports"
                continue
            fi

            if [[ "$min_bounty" =~ ^[0-9]+$ ]]; then
                program_max_bounty=$(sqlite3 "$DATABASE" "SELECT COALESCE(max_bounty,0) FROM programs WHERE handle='$(sql_escape "$program")';" 2>/dev/null || echo 0)
                [[ "$program_max_bounty" =~ ^[0-9]+$ ]] || program_max_bounty=0
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
    local program="$1" scan_type="${2:-full}"
    [ -n "$program" ] || { error "Program handle required"; return 1; }
    scan_program "$program" "$scan_type"
}

scan_single_target() {
    local program="$1" target="$2" scan_type="${3:-full}"
    [ -n "$program" ] && [ -n "$target" ] || { error "Program and target required"; return 1; }
    process_target "$program" "domain" "$target" "$(resolve_scan_type "$scan_type")"
}

list_programs() {
    echo -e "${MAGENTA}BUG BOUNTY PROGRAMS${NC}\n"
    sqlite3 -header -column "$DATABASE" \
        "SELECT handle, name, reward_range, last_scanned, resolved_count FROM programs ORDER BY resolved_count DESC LIMIT 20;" 2>/dev/null
}

list_targets() {
    local program="${1:-}"
    echo -e "${MAGENTA}TARGETS${NC}\n"
    if [ -n "$program" ]; then
        sqlite3 -header -column "$DATABASE" \
            "SELECT program_handle, type, value, last_scanned, vuln_count FROM targets WHERE program_handle='$(sql_escape "$program")' ORDER BY last_found DESC LIMIT 50;" 2>/dev/null
    else
        sqlite3 -header -column "$DATABASE" \
            "SELECT program_handle, type, value, last_scanned, vuln_count FROM targets ORDER BY last_found DESC LIMIT 50;" 2>/dev/null
    fi
}

list_findings() {
    local program="${1:-}" severity="${2:-}"
    echo -e "${RED}FINDINGS${NC}\n"
    local query="SELECT program_handle, target, vulnerability, severity, reported_at FROM findings WHERE status='new'"
    [ -n "$program" ] && query="$query AND program_handle='$(sql_escape "$program")'"
    [ -n "$severity" ] && query="$query AND severity='$(sql_escape "$severity")'"
    query="$query ORDER BY severity DESC, reported_at DESC LIMIT 100;"
    sqlite3 -header -column "$DATABASE" "$query" 2>/dev/null
}

list_normalized_findings() {
    local program="${1:-}" severity="${2:-}"
    echo -e "${CYAN}NORMALIZED FINDINGS${NC}\n"
    local query="SELECT program_handle, asset, vector, target, plugin, title, category, severity, confidence, seen_delta_seconds, first_seen, last_seen FROM normalized_findings WHERE status='new'"
    [ -n "$program" ] && query="$query AND program_handle='$(sql_escape "$program")'"
    [ -n "$severity" ] && query="$query AND severity='$(sql_escape "$severity")'"
    query="$query ORDER BY severity DESC, last_seen DESC LIMIT 100;"
    sqlite3 -header -column "$DATABASE" "$query" 2>/dev/null
}

generate_bounty_report() {
    local program="${1:-all}" format="${2:-html}"
    local output_file where_program critical high medium total
    mkdir -p "$REPORTS_DIR/bounty"
    output_file="$REPORTS_DIR/bounty/report_$(date +%Y%m%d_%H%M%S).$format"
    where_program="$(build_program_filter_clause "$program")"

    log "Generating $format report for $program..."
    critical=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='critical'$where_program;" 2>/dev/null || echo 0)
    high=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='high'$where_program;" 2>/dev/null || echo 0)
    medium=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='medium'$where_program;" 2>/dev/null || echo 0)
    total=$((critical + high + medium))

    case "$format" in
        html)
            cat > "$output_file" << EOF
<!DOCTYPE html><html><head><title>Recon Bounty Report - $program</title>
<style>body{font-family:monospace;background:#0d0d0d;color:#0f0;padding:20px}
table{width:100%;border-collapse:collapse}th,td{border:1px solid #333;padding:8px}</style></head><body>
<h1>Recon Bounty Report</h1><p>Program: $program | Generated: $(date)</p>
<p>Critical: $critical | High: $high | Medium: $medium | Total: $total</p>
<table><tr><th>Program</th><th>Target</th><th>Vuln</th><th>Severity</th><th>Date</th></tr>
$(sqlite3 "$DATABASE" "SELECT program_handle, target, vulnerability, severity, reported_at FROM findings WHERE status='new'$where_program ORDER BY severity DESC LIMIT 100;" 2>/dev/null | sed 's/|/<\/td><td>/g;s/^/<tr><td>/;s/$/<\/td><\/tr>/')
</table></body></html>
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
    local program="${1:-all}" format="${2:-csv}"
    local output_file="$REPORTS_DIR/bounty/findings_$(date +%Y%m%d_%H%M%S).$format"
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

bounty_status() {
    echo -e "${MAGENTA}Bounty Mode Status${NC}\n"
    local programs targets findings critical high
    programs=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM programs;" 2>/dev/null || echo 0)
    targets=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM targets;" 2>/dev/null || echo 0)
    findings=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new';" 2>/dev/null || echo 0)
    critical=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='critical';" 2>/dev/null || echo 0)
    high=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM findings WHERE status='new' AND severity='high';" 2>/dev/null || echo 0)
    echo "Programs: $programs | Targets: $targets | Findings: $findings (Critical: $critical, High: $high)"
    echo "Mode: $MODE | Interval: ${SCAN_INTERVAL}s | Max concurrent: $MAX_CONCURRENT"
}

bounty_mode_main() {
    local subcmd="${1:-help}"
    shift || true

    case "$subcmd" in
        sync) sync_all_programs ;;
        scan) scan_single_program "${1:-}" "${2:-$MODE}" ;;
        scan-target) scan_single_target "${1:-}" "${2:-}" "${3:-$MODE}" ;;
        list) list_programs ;;
        targets) list_targets "${1:-}" ;;
        findings) list_findings "${1:-}" "${2:-}" ;;
        normalized) list_normalized_findings "${1:-}" "${2:-}" ;;
        report) generate_bounty_report "${1:-all}" "${2:-html}" ;;
        export) export_findings "${1:-all}" "${2:-csv}" ;;
        clear) clear_findings "${1:-}" ;;
        status) bounty_status ;;
        continuous) run_continuous_scan ;;
        help|--help|-h)
            echo "Usage: recon bounty <command>"
            echo "  sync, scan <program>, scan-target <p> <t>, list, targets, findings,"
            echo "  normalized, report, export, clear, status, continuous"
            ;;
        *)
            error "Unknown bounty command: $subcmd"
            return 1
            ;;
    esac
}
