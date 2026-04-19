register_plugin "vuln" "trufflehog" "plugin_vuln_trufflehog" "trufflehog" "vuln_secret_detection" "secrets" "medium" "parse_trufflehog_results"

plugin_vuln_trufflehog() {
    local target="$1"
    local output_dir="$2"
    trufflehog url "$target" --output="$output_dir/secrets.txt" 2>/dev/null
}
