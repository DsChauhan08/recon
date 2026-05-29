#!/bin/bash
# Metasploit CLI mode

msf_mode_main() {
    local subcmd="${1:-help}"
    shift || true

    case "$subcmd" in
        doctor) msf_doctor ;;
        search)
            if [ "${1:-}" = "--cve" ]; then
                shift; msf_search_cve "${1:-}"
            else
                msf_search "$@"
            fi
            ;;
        info) msf_info "${1:-}" ;;
        run) msf_run_module "$@" ;;
        payload) msf_generate_payload "$@" ;;
        sessions)
            local action="${1:-list}"
            case "$action" in
                list) msf_list_sessions ;;
                kill)
                    shift
                    close_msf_session "${1:-}"
                    success "Session marked closed: ${1:-}"
                    ;;
                *)
                    error "Usage: recon msf sessions list|kill <id>"
                    return 1
                    ;;
            esac
            ;;
        suggest)
            if [ "${1:-}" = "--target" ]; then
                shift
                msf_suggest_from_target "${1:-}"
            else
                msf_suggest_from_target "${1:-}"
            fi
            ;;
        help|--help|-h)
            echo "Usage: recon msf <command>"
            echo "  doctor                         Check msf installation"
            echo "  search <query>                 Search modules"
            echo "  search --cve CVE-YYYY-NNNN     Search by CVE"
            echo "  info <module>                  Module details"
            echo "  run <module> --rhost IP [--lhost IP] [--lport N]"
            echo "  payload <type> [--lhost IP] [--lport N] [--format elf]"
            echo "  sessions list|kill <id>"
            echo "  suggest --target IP            From target scan results"
            ;;
        *)
            error "Unknown msf command: $subcmd"
            return 1
            ;;
    esac
}
