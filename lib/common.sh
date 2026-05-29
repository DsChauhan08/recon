#!/bin/bash
# Shared utilities for recon platform

VERSION="2.0.0"
NAME="Recon"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

log() { echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
critical() { echo -e "${RED}[CRITICAL]${NC} $1"; }

sql_escape() {
    local value="${1:-}"
    value="${value//\'/\'\'}"
    printf "%s" "$value"
}

json_escape() {
    local value="${1:-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf "%s" "$value"
}

hash_string() {
    local input="${1:-}"
    if command -v sha256sum &>/dev/null; then
        printf "%s" "$input" | sha256sum | cut -d' ' -f1
    elif command -v shasum &>/dev/null; then
        printf "%s" "$input" | shasum -a 256 | cut -d' ' -f1
    else
        printf "%s" "$input" | cksum | cut -d' ' -f1
    fi
}

is_positive_int() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]
}

resolve_scan_type() {
    local mode="${1:-full}"
    case "$mode" in
        passive|recon) echo "recon" ;;
        active|vuln) echo "vuln" ;;
        hybrid|full) echo "full" ;;
        *)
            warn "Unknown scan mode '$mode', defaulting to full" >&2
            echo "full"
            ;;
    esac
}

build_program_filter_clause() {
    local program="${1:-all}"
    if [ -n "$program" ] && [ "$program" != "all" ]; then
        printf " AND program_handle='%s'" "$(sql_escape "$program")"
    fi
}

sanitize_filename() {
    local value="${1:-unknown}"
    echo "$value" | tr '/.' '_'
}

target_output_dir() {
    local output_dir="$1"
    local target="$2"
    echo "$output_dir/$(sanitize_filename "$target")"
}

send_notification() {
    local title="${1:-Recon Alert}"
    local message="${2:-}"
    local payload

    if [ -n "${notifications_slack_webhook:-}" ]; then
        payload=$(printf '{"text":"%s: %s"}' "$(json_escape "$title")" "$(json_escape "$message")")
        curl -s -X POST -H 'Content-Type: application/json' --data "$payload" \
            "$notifications_slack_webhook" >/dev/null 2>&1 || true
    fi

    if [ -n "${notifications_discord_webhook:-}" ]; then
        payload=$(printf '{"content":"**%s**: %s"}' "$(json_escape "$title")" "$(json_escape "$message")")
        curl -s -X POST -H 'Content-Type: application/json' --data "$payload" \
            "$notifications_discord_webhook" >/dev/null 2>&1 || true
    fi
}
