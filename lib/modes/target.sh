#!/bin/bash
# Single-device targeted engagement mode

target_port_scan() {
    local target="$1" output_dir="$2" deep="${3:-false}"
    local ports_file="$output_dir/ports.txt"
    : > "$ports_file"

    info "Port scanning: $target"

    if command -v naabu &>/dev/null; then
        if [ "$deep" = true ]; then
            naabu -host "$target" -p - -silent -o "$output_dir/ports_naabu.txt" 2>/dev/null || true
        else
            naabu -host "$target" -top-ports 1000 -silent -o "$output_dir/ports_naabu.txt" 2>/dev/null || true
        fi
        cat "$output_dir/ports_naabu.txt" 2>/dev/null >> "$ports_file"
    fi

    if [ "$deep" = true ] && command -v masscan &>/dev/null; then
        local rate="${hunt_max_rate:-1000}"
        masscan "$target" -p1-65535 --rate="$rate" -oG "$output_dir/ports_masscan.txt" 2>/dev/null || true
        grep -oP 'Ports: \K[0-9]+' "$output_dir/ports_masscan.txt" 2>/dev/null >> "$ports_file" || true
    fi

    sort -un "$ports_file" -o "$ports_file"
    success "Found $(wc -l < "$ports_file" | tr -d ' ') open ports"
}

target_fingerprint() {
    local target="$1" output_dir="$2"
    local ports_file="$output_dir/ports.txt"
    local services_file="$output_dir/services.txt"
    : > "$services_file"

    info "Service fingerprinting: $target"

    if command -v nmap &>/dev/null && [ -s "$ports_file" ]; then
        local port_list
        port_list=$(paste -sd, "$ports_file")
        nmap -sV -sC -p "$port_list" "$target" -oN "$output_dir/nmap.txt" 2>/dev/null || true
        grep -E '^[0-9]+/' "$output_dir/nmap.txt" 2>/dev/null >> "$services_file" || true
    fi

    if command -v httpx &>/dev/null; then
        httpx -u "http://$target" -u "https://$target" -silent -tech-detect -o "$output_dir/httpx.txt" 2>/dev/null || true
    fi

    if command -v whatweb &>/dev/null; then
        whatweb -a 1 "http://$target" "https://$target" 2>/dev/null | tee "$output_dir/whatweb.txt" || true
    fi

    success "Fingerprinting complete"
}

target_vuln_scan() {
    local target="$1" output_dir="$2"
    info "Vulnerability scanning: $target"
    mkdir -p "$output_dir/scan"
    run_plugins "vuln" "$target" "$output_dir/scan"
}

target_cve_check() {
    local target="$1" output_dir="$2"
    info "CVE correlation: $target"

    if command -v cvemap &>/dev/null; then
        cvemap search "$target" -silent -json -o "$output_dir/cvemap.json" 2>/dev/null || \
            echo "$target" | cvemap -silent -output "$output_dir/cvemap.json" 2>/dev/null || true
    fi

    if command -v osv-scanner &>/dev/null && [ -d "$output_dir" ]; then
        osv-scanner --recursive "$output_dir" --format json --output "$output_dir/osv.json" 2>/dev/null || true
    fi

    correlate_target_services "$target" "$output_dir/services.txt"
}

target_tls_scan() {
    local target="$1" output_dir="$2"
    if command -v testssl &>/dev/null; then
        testssl --jsonfile "$output_dir/tls.json" "$target" 2>/dev/null || true
    elif command -v testssl.sh &>/dev/null; then
        testssl.sh --jsonfile "$output_dir/tls.json" "$target" 2>/dev/null || true
    fi
}

target_generate_report() {
    local target="$1" output_dir="$2"
    local report_file="$output_dir/report.html"
    local port_count service_count cve_count

    port_count=$(wc -l < "$output_dir/ports.txt" 2>/dev/null | tr -d ' ' || echo 0)
    service_count=$(wc -l < "$output_dir/services.txt" 2>/dev/null | tr -d ' ' || echo 0)
    cve_count=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM cve_device_matches m JOIN devices d ON d.id=m.device_id WHERE d.ip='$(sql_escape "$(extract_asset_from_target "$target")")';" 2>/dev/null || echo 0)

    cat > "$report_file" << EOF
<!DOCTYPE html><html><head><title>Target Report: $target</title>
<style>body{font-family:monospace;background:#0a0a0a;color:#0f0;padding:20px}
.section{margin:20px 0;padding:15px;border:1px solid #333}pre{background:#111;padding:10px;overflow:auto}</style></head><body>
<h1>Target Report: $target</h1>
<p>Generated: $(date) | Ports: $port_count | Services: $service_count | CVE matches: $cve_count</p>
<div class="section"><h2>Open Ports</h2><pre>$(cat "$output_dir/ports.txt" 2>/dev/null || echo "none")</pre></div>
<div class="section"><h2>Services</h2><pre>$(cat "$output_dir/services.txt" 2>/dev/null || echo "none")</pre></div>
<div class="section"><h2>CVE Matches</h2><pre>$(list_cve_matches_for_device "$(extract_asset_from_target "$target")" 2>/dev/null || echo "none")</pre></div>
<div class="section"><h2>Exploit Suggestions</h2><pre>$(cat "$output_dir/exploit_suggestions.json" 2>/dev/null || echo "Run with --exploit")</pre></div>
</body></html>
EOF
    success "Report: $report_file"
}

run_target_scan() {
    local target="" deep=false exploit=false output_base=""

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --deep) deep=true ;;
            --exploit) exploit=true ;;
            --output) shift; output_base="${1:-}" ;;
            --*) ;;
            *) target="$1" ;;
        esac
        shift || true
    done

    [ -n "$target" ] || { error "Target required"; return 1; }

    local timestamp output_dir
    timestamp=$(date +%Y%m%d_%H%M%S)
    if [ -n "$output_base" ]; then
        output_dir="$output_base"
    else
        output_dir="$REPORTS_DIR/target/${timestamp}_$(sanitize_filename "$target")"
    fi
    mkdir -p "$output_dir"

    log "Target engagement: $target (deep=$deep, exploit=$exploit)"
    local job_id
    job_id=$(create_scan_job "target" "{\"target\":\"$target\",\"deep\":$deep}")

    target_port_scan "$target" "$output_dir" "$deep"
    target_fingerprint "$target" "$output_dir"
    target_vuln_scan "$target" "$output_dir"
    target_tls_scan "$target" "$output_dir"
    target_cve_check "$target" "$output_dir"

    if [ "$exploit" = true ]; then
        msf_build_suggestions "$target" "$output_dir/services.txt" "$output_dir/exploit_suggestions.json"
        info "Exploit suggestions written to $output_dir/exploit_suggestions.json"
    fi

    target_generate_report "$target" "$output_dir"
    finish_scan_job "$job_id" "done"
    success "Target scan complete: $output_dir"
    echo "$output_dir"
}

target_mode_main() {
    local args=()
    while [ "$#" -gt 0 ]; do
        args+=("$1")
        shift || true
    done

    if [ "${#args[@]}" -eq 0 ]; then
        echo "Usage: recon target <ip/host> [--deep] [--exploit] [--output DIR]"
        return 1
    fi

    run_target_scan "${args[@]}"
}
