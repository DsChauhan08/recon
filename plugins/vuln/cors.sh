register_plugin "vuln" "cors" "plugin_vuln_cors" "nuclei" "vuln_cors_check" "web" "high" "parse_cors_results"

plugin_vuln_cors() {
    local target="$1"
    local output_dir="$2"
    local url="http://$target"
    [[ "$target" == http* ]] && url="$target"
    nuclei -u "$url" -tags cors -silent -o "$output_dir/cors.txt" 2>/dev/null || true
}
