#!/bin/bash
# CVE feed monitoring and correlation mode

cve_sync_nvd() {
    local days="${cve_sync_days:-7}"
    local api_key="${cve_nvd_api_key:-}"
    local start_date end_date url response

    end_date=$(date -u +"%Y-%m-%dT%H:%M:%S.000")
    start_date=$(date -u -d "-${days} days" +"%Y-%m-%dT%H:%M:%S.000" 2>/dev/null || \
        date -u -v-"${days}d" +"%Y-%m-%dT%H:%M:%S.000" 2>/dev/null || echo "")

    if [ -z "$start_date" ]; then
        start_date=$(date -u +"%Y-%m-%dT%H:%M:%S.000")
    fi

    log "Syncing CVEs from NVD (last ${days} days)..."

    url="https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${start_date}&pubEndDate=${end_date}&resultsPerPage=2000"
    if [ -n "$api_key" ]; then
        response=$(curl -s -H "apiKey: $api_key" "$url" 2>/dev/null)
    else
        response=$(curl -s "$url" 2>/dev/null)
        sleep 6
    fi

    if [ -z "$response" ] || ! echo "$response" | grep -q '"vulnerabilities"'; then
        warn "NVD sync failed, trying CIRCL fallback..."
        cve_sync_circl "$days"
        return
    fi

    if ! command -v jq &>/dev/null; then
        error "jq required for CVE sync"
        return 1
    fi

    local count=0
    while IFS= read -r cve_line; do
        [ -n "$cve_line" ] || continue
        local cve_id published severity cvss description products kev exploit raw
        cve_id=$(echo "$cve_line" | jq -r '.cve.id // empty')
        [ -n "$cve_id" ] || continue
        published=$(echo "$cve_line" | jq -r '.cve.published // ""')
        description=$(echo "$cve_line" | jq -r '.cve.descriptions[]? | select(.lang=="en") | .value' | head -1)
        cvss=$(echo "$cve_line" | jq -r '.cve.metrics.cvssMetricV31[0].cvssData.baseScore // .cve.metrics.cvssMetricV30[0].cvssData.baseScore // 0')
        severity=$(echo "$cve_line" | jq -r '.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV30[0].cvssData.baseSeverity // "UNKNOWN"')
        products=$(echo "$cve_line" | jq -r '[.cve.configurations[]?.nodes[]?.cpeMatch[]?.criteria // empty] | join(", ")' 2>/dev/null)
        kev=0
        exploit=0
        raw=$(echo "$cve_line" | jq -c '.' 2>/dev/null)

        if command -v cvemap &>/dev/null; then
            local enrich
            enrich=$(cvemap id "$cve_id" -json -silent 2>/dev/null || true)
            if echo "$enrich" | grep -qi 'kev\|known exploited'; then kev=1; fi
            if echo "$enrich" | grep -qi 'poc\|exploit'; then exploit=1; fi
        fi

        if command -v searchsploit &>/dev/null; then
            searchsploit "$cve_id" 2>/dev/null | grep -q "$cve_id" && exploit=1
        fi

        upsert_cve "$cve_id" "$published" "$severity" "$cvss" "$description" "$kev" "$exploit" "$products" "$raw"
        count=$((count + 1))
    done < <(echo "$response" | jq -c '.vulnerabilities[]?' 2>/dev/null)

    success "Synced $count CVEs from NVD"
    correlate_device_cves
}

cve_sync_circl() {
    local days="${1:-7}"
    log "Syncing CVEs from CIRCL (last ${days} days)..."
    local response
    response=$(curl -s "https://cve.circl.lu/api/last/${days}" 2>/dev/null) || return 1

    if ! command -v jq &>/dev/null; then
        error "jq required for CVE sync"
        return 1
    fi

    local count=0
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        local cve_id summary cvss
        cve_id=$(echo "$entry" | jq -r '.id // empty')
        [ -n "$cve_id" ] || continue
        summary=$(echo "$entry" | jq -r '.summary // ""')
        cvss=$(echo "$entry" | jq -r '.cvss // 0')
        upsert_cve "$cve_id" "" "UNKNOWN" "$cvss" "$summary" 0 0 "" "$entry"
        count=$((count + 1))
    done < <(echo "$response" | jq -c '.[]?' 2>/dev/null)

    success "Synced $count CVEs from CIRCL"
    correlate_device_cves
}

cve_list() {
    local since_filter="" kev_only=false exploit_only=false
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --since) shift; since_filter="$1" ;;
            --kev) kev_only=true ;;
            --exploit) exploit_only=true ;;
        esac
        shift || true
    done

    local query="SELECT id, published_at, severity, cvss, kev, exploit_available, substr(description,1,80) FROM cves WHERE 1=1"
    if [ "$kev_only" = true ]; then query="$query AND kev=1"; fi
    if [ "$exploit_only" = true ]; then query="$query AND exploit_available=1"; fi
    if [ -n "$since_filter" ]; then
        case "$since_filter" in
            *h) query="$query AND synced_at >= datetime('now', '-${since_filter%h} hours')" ;;
            *d) query="$query AND synced_at >= datetime('now', '-${since_filter%d} days')" ;;
        esac
    fi
    query="$query ORDER BY cvss DESC, synced_at DESC LIMIT 100;"

    echo -e "${MAGENTA}CVE Feed${NC}\n"
    sqlite3 -header -column "$DATABASE" "$query" 2>/dev/null
}

cve_show() {
    local cve_id="$1"
    [ -n "$cve_id" ] || { error "CVE ID required"; return 1; }

    sqlite3 "$DATABASE" "SELECT id, published_at, severity, cvss, kev, exploit_available, description, affected_products FROM cves WHERE id='$(sql_escape "$cve_id")';" 2>/dev/null

    info "Related devices:"
    sqlite3 -header -column "$DATABASE" "
SELECT d.ip, d.port, d.service, m.confidence, m.matched_on
FROM cve_device_matches m JOIN devices d ON d.id=m.device_id
WHERE m.cve_id='$(sql_escape "$cve_id")';" 2>/dev/null

    if command -v msfconsole &>/dev/null || msf_find_binary msfconsole &>/dev/null; then
        info "Metasploit modules:"
        msf_search_cve "$cve_id" 2>/dev/null | head -20
    fi
}

cve_watch() {
    local interval="${cve_watch_interval:-3600}"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --interval) shift; interval="$1" ;;
        esac
        shift || true
    done

    log "CVE watch started (interval: ${interval}s)"
    while true; do
        local before after
        before=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM cves;" 2>/dev/null || echo 0)
        cve_sync_nvd
        after=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM cves;" 2>/dev/null || echo 0)
        local new_count=$((after - before))

        if [ "$new_count" -gt 0 ]; then
            local msg="CVE watch: $new_count new CVEs synced"
            success "$msg"
            send_notification "CVE Watch" "$msg"

            local critical_cves
            critical_cves=$(sqlite3 "$DATABASE" "SELECT id FROM cves WHERE severity='CRITICAL' AND synced_at >= datetime('now', '-1 hour') LIMIT 5;" 2>/dev/null)
            if [ -n "$critical_cves" ]; then
                send_notification "Critical CVEs" "$critical_cves"
            fi
        fi

        sleep "$interval"
    done
}

cve_match() {
    log "Running CVE-to-device correlation..."
    correlate_device_cves
    local count
    count=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM cve_device_matches;" 2>/dev/null || echo 0)
    success "Total CVE-device matches: $count"
    sqlite3 -header -column "$DATABASE" "
SELECT c.id, c.severity, c.cvss, d.ip, d.port, d.service, m.confidence
FROM cve_device_matches m
JOIN cves c ON c.id=m.cve_id JOIN devices d ON d.id=m.device_id
ORDER BY c.cvss DESC LIMIT 50;" 2>/dev/null
}

cve_mode_main() {
    local subcmd="${1:-help}"
    shift || true

    case "$subcmd" in
        sync) cve_sync_nvd ;;
        list) cve_list "$@" ;;
        show) cve_show "${1:-}" ;;
        watch) cve_watch "$@" ;;
        match) cve_match ;;
        help|--help|-h)
            echo "Usage: recon cve <sync|list|show|watch|match>"
            echo "  sync              Pull recent CVEs from NVD"
            echo "  list [--kev] [--exploit] [--since 24h]"
            echo "  show CVE-YYYY-NNNN"
            echo "  watch [--interval SEC]"
            echo "  match             Correlate CVEs with discovered devices"
            ;;
        *)
            error "Unknown cve command: $subcmd"
            return 1
            ;;
    esac
}
