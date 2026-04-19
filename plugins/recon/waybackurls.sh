register_plugin "recon" "waybackurls" "plugin_recon_waybackurls" "waybackurls" "recon_wayback_history" "recon" "low"

plugin_recon_waybackurls() {
    local target="$1"
    local output_dir="$2"
    echo "$target" | waybackurls > "$output_dir/wayback.txt" 2>/dev/null
}
