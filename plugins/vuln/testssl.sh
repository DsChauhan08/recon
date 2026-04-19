register_plugin "vuln" "testssl" "plugin_vuln_testssl" "testssl" "vuln_tls_scanning" "tls" "medium" "parse_testssl_results"

plugin_vuln_testssl() {
    local target="$1"
    local output_dir="$2"
    testssl --jsonfile="$output_dir/tls.json" "$target" 2>/dev/null
}
