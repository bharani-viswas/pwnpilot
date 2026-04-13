#!/bin/bash
# install.sh - Quick installation script for PwnPilot
# Usage: bash install.sh [OPTIONS]
#
# Options:
#   --dev              Install with development dependencies (pytest, mypy, ruff)
#   --system-deps      Install system dependencies (requires sudo)
#   --python CMD       Use specific Python binary (default: python3)
#   --help             Show this help message

set -e

DEV=false
INSTALL_DEPS=false
PYTHON_CMD="python3"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev) DEV=true; shift ;;
        --system-deps) INSTALL_DEPS=true; shift ;;
        --python) PYTHON_CMD="$2"; shift 2 ;;
        --help|-h) cat << 'EOF'
PwnPilot Installation Script

Usage: bash install.sh [OPTIONS]

Options:
  --dev              Install with development dependencies (pytest, mypy, ruff)
  --system-deps      Install system dependencies (requires sudo)
  --python CMD       Use specific Python binary (default: python3)
  --help, -h         Show this help message

Examples:
  bash install.sh                    # Basic installation
  bash install.sh --system-deps      # With system dependencies
  bash install.sh --dev --system-deps  # Full development setup
  bash install.sh --python python3.11  # Use specific Python version

See INSTALLATION.md for more details.
EOF
            exit 0 ;;
        *) echo "Unknown option: $1"; echo "Use --help for usage information"; exit 1 ;;
    esac
done

echo "================================================"
echo "  PwnPilot Installation Script"
echo "================================================"

# Install system dependencies if requested
if [ "$INSTALL_DEPS" = true ]; then
    echo ""
    echo "[*] Installing system dependencies..."
    sudo apt-get update
    sudo apt-get install -y \
        python3.10 python3.11 python3-pip python3-venv \
        build-essential python3-dev \
        nmap nikto \
        git curl wget
    echo "✓ System dependencies installed"
fi

# Check Python version
echo ""
echo "[*] Checking Python version..."
$PYTHON_CMD --version
PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.10"
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"; then
    echo "✗ Python 3.10+ is required"
    exit 1
fi
echo "✓ Python version OK: $PYTHON_VERSION"

# Create virtual environment
echo ""
echo "[*] Creating virtual environment..."
if [ ! -d ".venv" ]; then
    $PYTHON_CMD -m venv .venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip
echo ""
echo "[*] Upgrading pip, setuptools, and wheel..."
pip install --upgrade pip setuptools wheel

# Install dependencies
echo ""
echo "[*] Installing PwnPilot dependencies..."
pip install -e .

if [ "$DEV" = true ]; then
    echo "[*] Installing development dependencies..."
    pip install -e ".[dev]"
fi

# Database setup
echo ""
echo "[*] Setting up database..."
mkdir -p ~/.pwnpilot
alembic upgrade head

# Generate signing keys
echo ""
echo "[*] Generating operator signing keys..."
pwnpilot keys --generate

# Verify installation
echo ""
echo "[*] Verifying installation..."
pwnpilot check 2>/dev/null || echo "Note: Some checks may fail if security tools aren't installed yet"

# Copy example config if not present
echo ""
echo "[*] Setting up configuration..."
if [ ! -f ~/.pwnpilot/config.yaml ]; then
    cp examples/config.example.yaml ~/.pwnpilot/config.yaml
    chmod 600 ~/.pwnpilot/config.yaml
    echo "✓ Created config at ~/.pwnpilot/config.yaml"
    echo "  Edit this file to add your LLM API keys"
else
    echo "✓ Config file already exists at ~/.pwnpilot/config.yaml"
fi

# Create activation helper script
cat > .pwnpilot-activate.sh << 'EOF'
#!/bin/bash
# PwnPilot activation helper
# Source this file to activate the PwnPilot environment:
#   source .pwnpilot-activate.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.venv/bin/activate"
echo "✓ PwnPilot environment activated"
EOF
chmod +x .pwnpilot-activate.sh

# Installation complete
echo ""
echo "================================================"
echo "  ✓ Installation Complete!"
echo "================================================"
echo ""
echo "⚠️  IMPORTANT: Activate the virtual environment"
echo ""
echo "Run one of these commands to activate PwnPilot:"
echo ""
echo "  Option 1 (recommended - easy to remember):"
echo "    source .pwnpilot-activate.sh"
echo ""
echo "  Option 2 (standard venv activation):"
echo "    source .venv/bin/activate"
echo ""
echo "After activation, verify with:"
echo "    pwnpilot --version"
echo ""
echo "================================================"
echo ""
echo "Next steps:"
echo "  1. Activate the virtual environment (see above)"
echo "  2. Configure LLM (default: Ollama)"
echo "     Make sure Ollama is running: ollama serve"
echo ""
echo "  3. Install required security tools:"
echo "     sudo bash scripts/install_security_tools.sh"
echo "     bash scripts/verify_toolchain.sh"
echo ""
echo "  4. Start an engagement:"
echo "     pwnpilot start --help"
echo ""
echo "  5. View dashboard:"
echo "     pwnpilot tui"
echo ""
echo "================================================"
echo ""
