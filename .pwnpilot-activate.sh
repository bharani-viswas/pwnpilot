#!/bin/bash
# PwnPilot activation helper
# Source this file to activate the PwnPilot environment:
#   source .pwnpilot-activate.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.venv/bin/activate"
echo "✓ PwnPilot environment activated"
