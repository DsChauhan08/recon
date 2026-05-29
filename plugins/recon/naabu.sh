register_plugin "recon" "naabu" "plugin_recon_naabu" "naabu" "recon_port_scanning" "port" "medium"

plugin_recon_naabu() {
    local target="$1"
    local output_dir="$2"
    naabu -host "$target" -top-ports 100 -silent -o "$output_dir/ports_naabu.txt" 2>/dev/null || true
}
