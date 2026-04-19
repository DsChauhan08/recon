register_plugin "recon" "dnsrecon" "plugin_recon_dnsrecon" "dnsrecon" "recon_dns_enumeration" "recon" "medium"

plugin_recon_dnsrecon() {
    local target="$1"
    local output_dir="$2"
    dnsrecon -d "$target" -j "$output_dir/dns.json" 2>/dev/null
}
