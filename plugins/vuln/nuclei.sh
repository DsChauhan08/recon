register_plugin "vuln" "nuclei" "plugin_vuln_nuclei" "nuclei" "vuln_nuclei_scan" "web" "high" "parse_nuclei_results"

plugin_vuln_nuclei() {
    local target="$1"
    local output_dir="$2"
    nuclei -u "$target" -severity "${vuln_nuclei_severity:-critical,high,medium}" -silent -o "$output_dir/nuclei.txt" 2>/dev/null
}
