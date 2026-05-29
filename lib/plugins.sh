#!/bin/bash
# Plugin registration and execution

declare -a RECON_PLUGIN_ORDER=()
declare -a VULN_PLUGIN_ORDER=()
declare -a HUNT_PLUGIN_ORDER=()
declare -A PLUGIN_RUNNER=()
declare -A PLUGIN_COMMAND=()
declare -A PLUGIN_ENABLED_KEY=()
declare -A PLUGIN_CATEGORY=()
declare -A PLUGIN_CONFIDENCE=()
declare -A PLUGIN_RESULT_PARSER=()
declare -A PLUGIN_PHASE=()

register_plugin() {
    local phase="$1"
    local name="$2"
    local runner="$3"
    local command_name="$4"
    local enabled_key="${5:-}"
    local category="${6:-misc}"
    local confidence="${7:-medium}"
    local parser="${8:-}"

    if [ -z "$phase" ] || [ -z "$name" ] || [ -z "$runner" ] || [ -z "$command_name" ]; then
        warn "Invalid plugin definition: phase/name/runner/command required"
        return 1
    fi

    case "$phase" in
        recon) RECON_PLUGIN_ORDER+=("$name") ;;
        vuln) VULN_PLUGIN_ORDER+=("$name") ;;
        hunt) HUNT_PLUGIN_ORDER+=("$name") ;;
        *)
            warn "Unknown plugin phase while registering '$name': $phase"
            return 1
            ;;
    esac

    PLUGIN_RUNNER["$name"]="$runner"
    PLUGIN_COMMAND["$name"]="$command_name"
    PLUGIN_ENABLED_KEY["$name"]="$enabled_key"
    PLUGIN_CATEGORY["$name"]="$category"
    PLUGIN_CONFIDENCE["$name"]="$confidence"
    PLUGIN_RESULT_PARSER["$name"]="$parser"
    PLUGIN_PHASE["$name"]="$phase"
}

load_plugins() {
    RECON_PLUGIN_ORDER=()
    VULN_PLUGIN_ORDER=()
    HUNT_PLUGIN_ORDER=()
    PLUGIN_RUNNER=()
    PLUGIN_COMMAND=()
    PLUGIN_ENABLED_KEY=()
    PLUGIN_CATEGORY=()
    PLUGIN_CONFIDENCE=()
    PLUGIN_RESULT_PARSER=()
    PLUGIN_PHASE=()

    local plugin_dir plugin_file
    for plugin_dir in "$SCRIPT_DIR/plugins/recon" "$SCRIPT_DIR/plugins/vuln" "$SCRIPT_DIR/plugins/hunt"; do
        [ -d "$plugin_dir" ] || continue
        for plugin_file in "$plugin_dir"/*.sh; do
            [ -f "$plugin_file" ] || continue
            # shellcheck source=/dev/null
            source "$plugin_file"
        done
    done

    if [ "${#RECON_PLUGIN_ORDER[@]}" -eq 0 ] && \
       [ "${#VULN_PLUGIN_ORDER[@]}" -eq 0 ] && \
       [ "${#HUNT_PLUGIN_ORDER[@]}" -eq 0 ]; then
        warn "No plugins loaded from $SCRIPT_DIR/plugins"
    fi
}

plugin_enabled() {
    local plugin="$1"
    local key="${PLUGIN_ENABLED_KEY[$plugin]:-}"

    if [ -z "$key" ]; then
        return 0
    fi

    local value="${!key:-true}"
    [ "$value" = "true" ]
}

plugin_available() {
    local plugin="$1"
    local command_name="${PLUGIN_COMMAND[$plugin]:-}"
    [ -n "$command_name" ] && command -v "$command_name" &>/dev/null
}

run_plugins() {
    local phase="$1"
    local target="$2"
    local output_dir="$3"
    local -a plugin_list=()

    case "$phase" in
        recon) plugin_list=("${RECON_PLUGIN_ORDER[@]}") ;;
        vuln) plugin_list=("${VULN_PLUGIN_ORDER[@]}") ;;
        hunt) plugin_list=("${HUNT_PLUGIN_ORDER[@]}") ;;
        *)
            warn "Unknown plugin phase: $phase"
            return 1
            ;;
    esac

    local plugin
    for plugin in "${plugin_list[@]}"; do
        if ! plugin_enabled "$plugin"; then
            continue
        fi
        if ! plugin_available "$plugin"; then
            continue
        fi
        local runner="${PLUGIN_RUNNER[$plugin]:-}"
        if [ -n "$runner" ] && declare -F "$runner" >/dev/null; then
            "$runner" "$target" "$output_dir" &
        fi
    done

    wait
}

parse_plugin_results() {
    local program="$1"
    local target="$2"
    local output_dir="$3"

    local plugin parser
    for plugin in "${VULN_PLUGIN_ORDER[@]}"; do
        parser="${PLUGIN_RESULT_PARSER[$plugin]:-}"
        if [ -n "$parser" ] && declare -F "$parser" >/dev/null; then
            "$parser" "$program" "$target" "$output_dir"
        fi
    done
}
