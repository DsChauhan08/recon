register_plugin "recon" "whatweb" "plugin_recon_whatweb" "whatweb" "recon_web_technology_fingerprinting" "recon" "medium"

plugin_recon_whatweb() {
    local target="$1"
    local output_dir="$2"
    whatweb -a 3 "$target" --log-brief="$output_dir/tech.txt" 2>/dev/null
}
