register_plugin "vuln" "subtakeover" "plugin_vuln_subtakeover" "subzy" "vuln_subdomain_takeover" "dns" "high" "parse_subtakeover_results"

plugin_vuln_subtakeover() {
    local target="$1"
    local output_dir="$2"
    subzy run --targets "$target" --hide_fails --concurrency 10 2>/dev/null | tee "$output_dir/subtakeover.txt" || true
}
