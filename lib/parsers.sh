#!/bin/bash
# Result parsers for vulnerability plugins

parse_nuclei_results() {
    local program="$1" target="$2" output_dir="$3"
    local nuclei_file
    nuclei_file="$(target_output_dir "$output_dir" "$target")/nuclei.txt"
    [ -f "$nuclei_file" ] || return 0

    local line_no=0 line severity vuln_name category confidence vector_hint
    while IFS= read -r line; do
        line_no=$((line_no + 1))
        [ -n "$line" ] || continue
        severity=$(echo "$line" | grep -oE '\[(critical|high|medium|low|info)\]' | head -1 | tr -d '[]' || true)
        [ -n "$severity" ] || severity="info"
        vuln_name=$(echo "$line" | sed -n 's/^\[[^]]*\]\[[^]]*\]\s*\([^ ]*\).*/\1/p')
        [ -n "$vuln_name" ] || vuln_name="nuclei-finding"
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
    local program="$1" target="$2" output_dir="$3"
    local tls_file
    tls_file="$(target_output_dir "$output_dir" "$target")/tls.json"
    [ -f "$tls_file" ] || return 0

    local line_no=0 line severity title vector_hint
    while IFS= read -r line; do
        line_no=$((line_no + 1))
        [ -n "$line" ] || continue
        severity="medium"; title="tls-misconfiguration"; vector_hint="tls"
        if echo "$line" | grep -qiE 'critical|high|vulnerable|weak|insecure|failed'; then
            severity="high"; title="tls-critical-issue"
        elif echo "$line" | grep -qiE 'medium|warning|deprecated'; then
            severity="medium"; title="tls-warning"
        elif echo "$line" | grep -qiE 'info|ok|pass'; then
            severity="info"; title="tls-info"
        fi
        if echo "$line" | grep -qi 'heartbleed'; then title="tls-heartbleed"; vector_hint="heartbleed"
        elif echo "$line" | grep -qi 'renegotiation'; then title="tls-renegotiation"; vector_hint="renegotiation"
        elif echo "$line" | grep -qi 'cipher'; then title="tls-weak-cipher"; vector_hint="cipher"; fi
        add_normalized_finding "$program" "$target" "testssl" "$title" "${PLUGIN_CATEGORY[testssl]:-tls}" "$severity" "${PLUGIN_CONFIDENCE[testssl]:-medium}" "$tls_file" "$line_no" "$line" "$vector_hint"
    done < "$tls_file"
}

parse_trufflehog_results() {
    local program="$1" target="$2" output_dir="$3"
    local secrets_file
    secrets_file="$(target_output_dir "$output_dir" "$target")/secrets.txt"
    [ -f "$secrets_file" ] || return 0

    local line_no=0 line title vector_hint severity
    while IFS= read -r line; do
        line_no=$((line_no + 1))
        [ -n "$line" ] || continue
        title="secret-detected"; vector_hint="generic-secret"; severity="high"
        if echo "$line" | grep -qi 'aws'; then title="aws-secret"; vector_hint="aws-key"; severity="critical"
        elif echo "$line" | grep -qi 'github'; then title="github-token"; vector_hint="github-token"
        elif echo "$line" | grep -qi 'slack'; then title="slack-token"; vector_hint="slack-token"
        elif echo "$line" | grep -qi 'password'; then title="password-leak"; vector_hint="password"; fi
        add_normalized_finding "$program" "$target" "trufflehog" "$title" "${PLUGIN_CATEGORY[trufflehog]:-secrets}" "$severity" "${PLUGIN_CONFIDENCE[trufflehog]:-medium}" "$secrets_file" "$line_no" "$line" "$vector_hint"
    done < "$secrets_file"
}

parse_cors_results() {
    local program="$1" target="$2" output_dir="$3"
    local cors_file
    cors_file="$(target_output_dir "$output_dir" "$target")/cors.txt"
    [ -f "$cors_file" ] || return 0

    local line_no=0 line
    while IFS= read -r line; do
        line_no=$((line_no + 1))
        [ -n "$line" ] || continue
        add_normalized_finding "$program" "$target" "cors" "cors-misconfiguration" "web" "medium" "high" "$cors_file" "$line_no" "$line" "cors"
    done < "$cors_file"
}

parse_subtakeover_results() {
    local program="$1" target="$2" output_dir="$3"
    local sub_file
    sub_file="$(target_output_dir "$output_dir" "$target")/subtakeover.txt"
    [ -f "$sub_file" ] || return 0

    local line_no=0 line
    while IFS= read -r line; do
        line_no=$((line_no + 1))
        [ -n "$line" ] || continue
        add_normalized_finding "$program" "$target" "subtakeover" "subdomain-takeover" "dns" "high" "high" "$sub_file" "$line_no" "$line" "takeover"
    done < "$sub_file"
}
