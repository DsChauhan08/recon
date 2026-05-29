#!/bin/bash
# CVE-to-device correlation engine

correlate_device_cves() {
    local device_id="${1:-}"
    local where_clause=""

    if [ -n "$device_id" ]; then
        where_clause="WHERE d.id=$device_id"
    fi

    local devices
    devices=$(sqlite3 "$DATABASE" "SELECT id, ip, service, banner FROM devices $where_clause;" 2>/dev/null) || return 0
    [ -n "$devices" ] || return 0

    while IFS='|' read -r dev_id ip service banner; do
        [ -n "$dev_id" ] || continue
        local search_terms="${service:-} ${banner:-}"
        [ -n "$search_terms" ] || continue

        local cves
        cves=$(sqlite3 "$DATABASE" "SELECT id, affected_products, description FROM cves;" 2>/dev/null) || continue

        while IFS='|' read -r cve_id products description; do
            [ -n "$cve_id" ] || continue
            local confidence="" matched_on=""

            if [ -n "$service" ] && echo "${products:-} $description" | grep -qi "$service"; then
                confidence="medium"
                matched_on="service:$service"
            fi

            if [ -n "$banner" ]; then
                local word
                for word in $banner; do
                    [ "${#word}" -lt 4 ] && continue
                    if echo "${products:-} $description" | grep -qi "$word"; then
                        confidence="high"
                        matched_on="banner:$word"
                        break
                    fi
                done
            fi

            if [ -n "$confidence" ]; then
                add_cve_device_match "$cve_id" "$dev_id" "$confidence" "$matched_on"
            fi
        done <<< "$cves"
    done <<< "$devices"
}

correlate_target_services() {
    local target="$1" services_file="$2"
    [ -f "$services_file" ] || return 0

    local ip
    ip=$(extract_asset_from_target "$target")

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        local port service banner
        port=$(echo "$line" | awk '{print $1}' | cut -d/ -f1)
        service=$(echo "$line" | awk '{print $3}')
        banner=$(echo "$line" | cut -d' ' -f4-)
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        upsert_device "$ip" "$port" "tcp" "${service:-unknown}" "${banner:-}" "{}" 0 ""
        local device_id
        device_id=$(sqlite3 "$DATABASE" "SELECT id FROM devices WHERE ip='$(sql_escape "$ip")' AND port=$port AND protocol='tcp';" 2>/dev/null)
        [ -n "$device_id" ] && correlate_device_cves "$device_id"
    done < "$services_file"
}

list_cve_matches_for_device() {
    local ip="$1"
    sqlite3 -header -column "$DATABASE" "
SELECT c.id, c.severity, c.cvss, c.kev, c.exploit_available, m.confidence, m.matched_on
FROM cve_device_matches m
JOIN cves c ON c.id = m.cve_id
JOIN devices d ON d.id = m.device_id
WHERE d.ip='$(sql_escape "$ip")'
ORDER BY c.cvss DESC;" 2>/dev/null
}
