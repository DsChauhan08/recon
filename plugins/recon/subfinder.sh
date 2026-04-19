register_plugin "recon" "subfinder" "plugin_recon_subfinder" "subfinder" "recon_subdomain_enumeration" "recon" "medium"

plugin_recon_subfinder() {
    local target="$1"
    local output_dir="$2"
    subfinder -d "$target" -silent -o "$output_dir/subs.txt" 2>/dev/null
}
