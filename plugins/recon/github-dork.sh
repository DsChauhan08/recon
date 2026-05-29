register_plugin "recon" "github-dork" "plugin_recon_github_dork" "curl" "recon_github_dorking" "osint" "low"

plugin_recon_github_dork() {
    local target="$1"
    local output_dir="$2"
    local token="${api_github_token:-}"

    [ -n "$token" ] || return 0

    curl -s -H "Authorization: token $token" \
        "https://api.github.com/search/code?q=${target}+password" \
        -o "$output_dir/github_dork.json" 2>/dev/null || true
}
