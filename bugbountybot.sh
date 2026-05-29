#!/bin/bash
# bugbountybot.sh - deprecated wrapper for recon bounty mode
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/recon" bounty "$@"
