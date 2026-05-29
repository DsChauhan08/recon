#!/bin/bash
# Internet-wide active device hunt mode

HUNT_DEFAULT_EXCLUDES="$SCRIPT_DIR/data/banners/default_excludes.txt"

init_hunt_excludes() {
    if [ ! -f "$HUNT_DEFAULT_EXCLUDES" ]; then
        cat > "$HUNT_DEFAULT_EXCLUDES" << 'EOF'
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
169.254.0.0/16
224.0.0.0/4
240.0.0.0/4
0.0.0.0/8
255.255.255.255/32
EOF
    fi
}

hunt_build_exclude_args() {
    local exclude_file="${hunt_exclude_file:-}"
    local args=""

    if [ -n "$exclude_file" ] && [ -f "$exclude_file" ]; then
        args="--exclude-file=$exclude_file"
    elif [ -f "$HUNT_DEFAULT_EXCLUDES" ]; then
        args="--exclude-file=$HUNT_DEFAULT_EXCLUDES"
    fi

    echo "$args"
}

hunt_filter_blocklist() {
    local input_file="$1" output_file="$2"
    : > "$output_file"
    while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        is_blocklisted "$ip" && continue
        echo "$ip" >> "$output_file"
    done < "$input_file"
}

hunt_zmap_sweep() {
    local input_file="$1" ports="$2" rate="$3" output_file="$4"
    local exclude_args
    exclude_args=$(hunt_build_exclude_args)

    if command -v zmap &>/dev/null; then
        info "Running zmap on ports $ports (rate: $rate)"
        # shellcheck disable=SC2086
        zmap -p "$ports" -r "$rate" $exclude_args -w "$input_file" -o "$output_file" 2>/dev/null || true
        return 0
    fi
    return 1
}

hunt_masscan_sweep() {
    local input_file="$1" ports="$2" rate="$3" output_file="$4"

    if ! command -v masscan &>/dev/null; then
        return 1
    fi

    info "Running masscan on ports $ports (rate: $rate)"
    local targets
    targets=$(paste -sd, "$input_file")

    masscan "$targets" -p"$ports" --rate="$rate" -oG "$output_file.masscan" 2>/dev/null || true
    grep -oP '\d+\.\d+\.\d+\.\d+' "$output_file.masscan" 2>/dev/null | sort -u > "$output_file" || true
}

hunt_fingerprint_host() {
    local ip="$1" ports="$2" output_dir="$3"

    local port_list="${ports// /,}"
    if command -v nmap &>/dev/null; then
        nmap -sV -p "$port_list" "$ip" -oN "$output_dir/nmap_${ip}.txt" 2>/dev/null || true
    fi

    if command -v httpx &>/dev/null; then
        httpx -u "http://$ip" -u "https://$ip" -silent -tech-detect -o "$output_dir/httpx_${ip}.txt" 2>/dev/null || true
    fi
}

hunt_score_device() {
    local ip="$1" port="$2" service="$3" banner="$4" nuclei_hits="${5:-}"
    local score=0 indicators=""

    case "$port" in
        23|2323) score=$((score + 30)); indicators+="telnet_open," ;;
        21) score=$((score + 15)); indicators+="ftp_open," ;;
        445|139) score=$((score + 25)); indicators+="smb_open," ;;
        3389) score=$((score + 20)); indicators+="rdp_open," ;;
        554) score=$((score + 15)); indicators+="rtsp_open," ;;
    esac

    if echo "$banner" | grep -qiE 'default|admin:admin|root:root|password'; then
        score=$((score + 25))
        indicators+="default_creds_banner,"
    fi

    if [ -n "$nuclei_hits" ]; then
        score=$((score + 20))
        indicators+="nuclei_hits,"
    fi

    local banner_file
    for banner_file in "$SCRIPT_DIR/data/banners/"*.txt; do
        [ -f "$banner_file" ] || continue
        while IFS= read -r pattern; do
            [ -n "$pattern" ] || continue
            [[ "$pattern" =~ ^# ]] && continue
            if echo "$banner" | grep -qiE "$pattern"; then
                score=$((score + 15))
                indicators+="banner:$(basename "$banner_file" .txt),"
            fi
        done < "$banner_file"
    done

    [ "$score" -gt 100 ] && score=100
    indicators="${indicators%,}"
    echo "$score|$indicators"
}

hunt_compromise_check() {
    local ip="$1" output_dir="$2"
    local hits=""

    if command -v nuclei &>/dev/null; then
        nuclei -u "http://$ip" -tags iot,default-login,misconfig,exposure -silent \
            -o "$output_dir/nuclei_${ip}.txt" 2>/dev/null || true
        hits=$(wc -l < "$output_dir/nuclei_${ip}.txt" 2>/dev/null | tr -d ' ')
    fi

    echo "${hits:-0}"
}

hunt_process_hosts() {
    local hosts_file="$1" ports="$2" output_dir="$3"
    local filtered_hosts="$output_dir/hosts_filtered.txt"
    hunt_filter_blocklist "$hosts_file" "$filtered_hosts"

    local ip
    while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        info "Processing host: $ip"

        hunt_fingerprint_host "$ip" "$ports" "$output_dir"

        local service banner port
        if [ -f "$output_dir/nmap_${ip}.txt" ]; then
            while IFS= read -r line; do
                echo "$line" | grep -qE '^[0-9]+/' || continue
                port=$(echo "$line" | cut -d/ -f1)
                service=$(echo "$line" | awk '{print $3}')
                banner=$(echo "$line" | cut -d' ' -f4-)
                [[ "$port" =~ ^[0-9]+$ ]] || continue

                local nuclei_hits compromise_result score indicators
                nuclei_hits=$(hunt_compromise_check "$ip" "$output_dir")
                compromise_result=$(hunt_score_device "$ip" "$port" "$service" "$banner" "$nuclei_hits")
                score="${compromise_result%%|*}"
                indicators="${compromise_result#*|}"

                upsert_device "$ip" "$port" "tcp" "${service:-unknown}" "${banner:-}" "{}" "$score" "$indicators"
            done < "$output_dir/nmap_${ip}.txt"
        else
            IFS=',' read -ra port_arr <<< "${ports// /,}"
            for port in "${port_arr[@]}"; do
                [[ "$port" =~ ^[0-9]+$ ]] || continue
                local nuclei_hits compromise_result score indicators
                nuclei_hits=$(hunt_compromise_check "$ip" "$output_dir")
                compromise_result=$(hunt_score_device "$ip" "$port" "unknown" "" "$nuclei_hits")
                score="${compromise_result%%|*}"
                indicators="${compromise_result#*|}"
                upsert_device "$ip" "$port" "tcp" "unknown" "" "{}" "$score" "$indicators"
            done
        fi
    done < "$filtered_hosts"

    correlate_device_cves
}

hunt_start() {
    local input_file="" ports="${hunt_default_ports:-22,23,80,443,8080,554,3389}" rate="${hunt_max_rate:-10000}"
    local authorized=false

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --input) shift; input_file="$1" ;;
            --ports) shift; ports="$1" ;;
            --rate) shift; rate="$1" ;;
            --authorized) authorized=true ;;
        esac
        shift || true
    done

    if [ "$authorized" != true ] && [ "${hunt_require_authorized:-true}" = "true" ]; then
        error "Active scanning requires --authorized flag. Only scan networks you have permission to test."
        return 1
    fi

    [ -n "$input_file" ] && [ -f "$input_file" ] || { error "Input file required: --input ranges.txt"; return 1; }

    init_hunt_excludes
    local timestamp output_dir hosts_file job_id
    timestamp=$(date +%Y%m%d_%H%M%S)
    output_dir="$REPORTS_DIR/hunt/${timestamp}"
    mkdir -p "$output_dir"
    hosts_file="$output_dir/discovered_hosts.txt"

    job_id=$(create_scan_job "hunt" "{\"input\":\"$input_file\",\"ports\":\"$ports\",\"rate\":$rate}")

    if ! hunt_zmap_sweep "$input_file" "$ports" "$rate" "$hosts_file"; then
        warn "zmap unavailable, falling back to masscan"
        hunt_masscan_sweep "$input_file" "$ports" "$rate" "$hosts_file"
    fi

    if [ ! -s "$hosts_file" ]; then
        warn "No hosts discovered"
        finish_scan_job "$job_id" "done"
        return 0
    fi

    success "Discovered $(wc -l < "$hosts_file" | tr -d ' ') hosts"
    hunt_process_hosts "$hosts_file" "$ports" "$output_dir"

    local high_risk
    high_risk=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM devices WHERE risk_score >= 70;" 2>/dev/null || echo 0)
    if [ "${high_risk:-0}" -gt 0 ]; then
        send_notification "Hunt Complete" "Found $high_risk high-risk devices (score >= 70)"
    fi

    finish_scan_job "$job_id" "done"
    success "Hunt complete. Results in DB and $output_dir"
}

hunt_continuous() {
    local interval=86400 input_file=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --interval) shift; interval="$1" ;;
            --input) shift; input_file="$1" ;;
        esac
        shift || true
    done

    [ -n "$input_file" ] || { error "--input required for continuous hunt"; return 1; }

    while true; do
        hunt_start --input "$input_file" --authorized
        log "Sleeping ${interval}s until next hunt cycle..."
        sleep "$interval"
    done
}

hunt_results() {
    local min_risk=0 service_filter=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --min-risk) shift; min_risk="$1" ;;
            --service) shift; service_filter="$1" ;;
        esac
        shift || true
    done

    local query="SELECT ip, port, service, risk_score, compromise_indicators, last_seen FROM devices WHERE risk_score >= $min_risk"
    [ -n "$service_filter" ] && query="$query AND service LIKE '%$(sql_escape "$service_filter")%'"
    query="$query ORDER BY risk_score DESC LIMIT 100;"

    echo -e "${MAGENTA}Hunt Results${NC}\n"
    sqlite3 -header -column "$DATABASE" "$query" 2>/dev/null
}

hunt_export() {
    local format="${1:-csv}"
    local output_file="$REPORTS_DIR/hunt/export_$(date +%Y%m%d_%H%M%S).$format"

    case "$format" in
        csv)
            echo "ip,port,protocol,service,banner,risk_score,indicators,last_seen" > "$output_file"
            sqlite3 "$DATABASE" "SELECT ip, port, protocol, service, banner, risk_score, compromise_indicators, last_seen FROM devices ORDER BY risk_score DESC;" 2>/dev/null | sed 's/|/,/g' >> "$output_file"
            ;;
        json)
            sqlite3 "$DATABASE" "SELECT json_group_array(json_object('ip',ip,'port',port,'service',service,'risk_score',risk_score,'indicators',compromise_indicators)) FROM devices;" 2>/dev/null > "$output_file"
            ;;
    esac
    success "Exported: $output_file"
}

hunt_status() {
    echo -e "${MAGENTA}Hunt Status${NC}\n"
    local devices high_risk last_job
    devices=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM devices;" 2>/dev/null || echo 0)
    high_risk=$(sqlite3 "$DATABASE" "SELECT COUNT(*) FROM devices WHERE risk_score >= 70;" 2>/dev/null || echo 0)
    last_job=$(sqlite3 "$DATABASE" "SELECT mode, status, started_at FROM scan_jobs WHERE mode='hunt' ORDER BY id DESC LIMIT 1;" 2>/dev/null || echo "none")
    echo "Devices tracked: $devices | High risk (>=70): $high_risk"
    echo "Last hunt job: $last_job"
}

hunt_mode_main() {
    local subcmd="${1:-help}"
    shift || true

    case "$subcmd" in
        start) hunt_start "$@" ;;
        continuous) hunt_continuous "$@" ;;
        results) hunt_results "$@" ;;
        export) hunt_export "${1:-csv}" ;;
        status) hunt_status ;;
        help|--help|-h)
            echo "Usage: recon hunt <start|continuous|results|export|status>"
            echo "  start --input FILE --ports PORTS --rate RATE --authorized"
            echo "  continuous --input FILE --interval SEC"
            echo "  results [--min-risk N] [--service NAME]"
            echo "  export csv|json"
            ;;
        *)
            error "Unknown hunt command: $subcmd"
            return 1
            ;;
    esac
}
