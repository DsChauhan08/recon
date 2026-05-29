#!/bin/bash
# Legacy TUI launcher

tui_mode_main() {
    local which="${1:-}"
    shift || true

    case "$which" in
        recon|vul)
            if [ -x "$SCRIPT_DIR/vul.sh" ]; then
                exec "$SCRIPT_DIR/vul.sh" "$@"
            else
                error "vul.sh not found"
                return 1
            fi
            ;;
        vuln|turret)
            if [ -x "$SCRIPT_DIR/turret.sh" ]; then
                exec "$SCRIPT_DIR/turret.sh" "$@"
            else
                error "turret.sh not found"
                return 1
            fi
            ;;
        *)
            echo "Usage: recon tui <recon|vuln>"
            echo "  recon  Launch legacy recon TUI (vul.sh)"
            echo "  vuln   Launch legacy vuln TUI (turret.sh)"
            return 1
            ;;
    esac
}
