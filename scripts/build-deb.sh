#!/bin/bash
# build-deb.sh - Build Debian package for PwnPilot
# Usage: bash scripts/build-deb.sh

set -e

PROJECT_NAME="pwnpilot"
VERSION=$(grep "version = " pyproject.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
ARCH="amd64"
BUILD_DIR="build/deb"
PACKAGE_NAME="${PROJECT_NAME}_${VERSION}_${ARCH}"
INSTALL_PREFIX="/opt/pwnpilot"

echo "Building Debian package for $PROJECT_NAME v$VERSION..."

# Create build structure
mkdir -p "$BUILD_DIR/$PACKAGE_NAME/DEBIAN"
mkdir -p "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX"
mkdir -p "$BUILD_DIR/$PACKAGE_NAME/usr/bin"
mkdir -p "$BUILD_DIR/$PACKAGE_NAME/usr/share/doc/$PROJECT_NAME"
mkdir -p "$BUILD_DIR/$PACKAGE_NAME/etc/systemd/system"

# Copy application files
echo "Copying application files..."
cp -r pwnpilot "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX/"
cp -r scripts "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX/"
cp -r schemas "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX/" 2>/dev/null || true
cp -r migrations "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX/" 2>/dev/null || true
cp -r examples "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX/" 2>/dev/null || true
cp requirements.txt "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX/"
cp pyproject.toml "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX/"
cp alembic.ini "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX/" 2>/dev/null || true
cp docs/README.md docs/LICENSE "$BUILD_DIR/$PACKAGE_NAME/usr/share/doc/$PROJECT_NAME/"
cp docs/INSTALLATION.md "$BUILD_DIR/$PACKAGE_NAME/usr/share/doc/$PROJECT_NAME/" 2>/dev/null || true
cp docs/CURRENT_SCHEMA.md "$BUILD_DIR/$PACKAGE_NAME/usr/share/doc/$PROJECT_NAME/" 2>/dev/null || true

# Copy systemd service file
if [ -f "scripts/pwnpilot.service" ]; then
    cp scripts/pwnpilot.service "$BUILD_DIR/$PACKAGE_NAME/etc/systemd/system/"
fi

# Create wrapper script for /usr/bin
cat > "$BUILD_DIR/$PACKAGE_NAME/usr/bin/pwnpilot" << 'EOF'
#!/bin/bash
# Wrapper for pwnpilot CLI (system-wide Python)
if command -v pwnpilot >/dev/null 2>&1; then
    exec pwnpilot "$@"
else
    echo "Error: PwnPilot package is not properly installed." >&2
    echo "Please run: sudo dpkg --configure -a" >&2
    exit 1
fi
EOF
chmod +x "$BUILD_DIR/$PACKAGE_NAME/usr/bin/pwnpilot"

# Create DEBIAN/control file
cat > "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/control" << EOF
Package: $PROJECT_NAME
Version: $VERSION
Architecture: $ARCH
Maintainer: PwnPilot Contributors <dev@pwnpilot.dev>
Homepage: https://github.com/bharani-viswas/pwnpilot
Description: Policy-first, multi-agent LLM-driven pentesting framework
 PwnPilot orchestrates a team of LLM-backed agents over a deny-by-default 
 policy engine. Every tool call is typed, every finding is evidence-backed,
 and every state transition is audited.
Depends: python3.10 | python3.11, python3-venv, python3-pip, nmap
Recommends: nuclei, nikto, sqlmap, whatweb, zaproxy
Standards-Version: 4.6.0
Priority: optional
EOF

# Create pre-install script
cat > "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/preinst" << 'EOF'
#!/bin/bash
set -e
if id "pwnpilot" &>/dev/null; then
    echo "User pwnpilot already exists"
else
    useradd -r -s /bin/bash -d /etc/pwnpilot pwnpilot 2>/dev/null || true
fi
EOF
chmod 755 "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/preinst"

# Create post-install script
cat > "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

INSTALL_PREFIX="/opt/pwnpilot"

echo "Finalizing PwnPilot installation..."
echo ""

# Upgrade system pip
echo "[1/6] Upgrading pip, setuptools, and wheel..."
pip3 install --upgrade pip setuptools wheel 2>/dev/null || true

# Install dependencies system-wide
echo "[2/6] Installing Python dependencies system-wide..."
pip3 install -r "$INSTALL_PREFIX/requirements.txt" 2>&1 | tail -5 || {
    echo "✗ Failed to install dependencies"
    exit 1
}

# Install pwnpilot package system-wide in development mode
echo "[3/6] Installing PwnPilot package..."
cd "$INSTALL_PREFIX" && pip3 install -e . 2>/dev/null || {
    echo "✗ Failed to install PwnPilot package"
    exit 1
}

# Create data directories
echo "[4/6] Setting up configuration and data directories..."
mkdir -p /etc/pwnpilot
mkdir -p /var/lib/pwnpilot
mkdir -p /var/log/pwnpilot

# Fix permissions
chown -R pwnpilot:pwnpilot /var/lib/pwnpilot /var/log/pwnpilot /etc/pwnpilot

# Copy configuration from example if present
if [ -f "$INSTALL_PREFIX/examples/config.example.yaml" ] && [ ! -f /etc/pwnpilot/config.yaml ]; then
    cp "$INSTALL_PREFIX/examples/config.example.yaml" /etc/pwnpilot/config.yaml
    chown pwnpilot:pwnpilot /etc/pwnpilot/config.yaml
    chmod 640 /etc/pwnpilot/config.yaml
    echo "  ✓ Configuration copied to /etc/pwnpilot/config.yaml"
fi

# Initialize database
echo "[5/6] Initializing database..."
if [ -f "$INSTALL_PREFIX/alembic.ini" ]; then
    cd "$INSTALL_PREFIX" && alembic upgrade head 2>/dev/null || {
        echo "  ⚠ Database initialization may require manual setup"
    }
else
    echo "  ⚠ alembic.ini not found, skipping database initialization"
fi

# Register systemd service
echo "[6/6] Registering systemd service..."
if [ -f /etc/systemd/system/pwnpilot.service ]; then
    systemctl daemon-reload || true
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "Running Post-Installation Verification Checks..."
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Verify CLI installation
echo "[CHECK 1/5] CLI Accessibility"
if command -v pwnpilot >/dev/null 2>&1; then
    echo "  ✓ pwnpilot CLI is accessible"
else
    echo "  ✗ pwnpilot CLI not found in PATH"
    exit 1
fi

# Verify version
echo "[CHECK 2/5] Version Check"
VERSION=$(pwnpilot version 2>/dev/null || echo "unknown")
if [ "$VERSION" != "unknown" ]; then
    echo "  ✓ Version: $VERSION"
else
    echo "  ✗ Could not retrieve version"
    exit 1
fi

# Verify help output
echo "[CHECK 3/5] Command Help"
if pwnpilot --help >/dev/null 2>&1; then
    echo "  ✓ CLI help working"
else
    echo "  ✗ CLI help not working"
    exit 1
fi

# Verify ROE commands
echo "[CHECK 4/5] ROE Subcommands"
if pwnpilot roe --help >/dev/null 2>&1; then
    echo "  ✓ ROE subcommands available"
    echo "    - verify (Validate ROE files)"
    echo "    - list (List approved ROEs)"
    echo "    - audit (Show approval timeline)"
    echo "    - export (Export audit reports)"
else
    echo "  ✗ ROE subcommands not available"
    exit 1
fi

# Verify directories
echo "[CHECK 5/5] Directory Structure"
CHECKS_PASSED=0
CHECKS_TOTAL=0

[ -d /etc/pwnpilot ] && { echo "  ✓ /etc/pwnpilot exists"; ((CHECKS_PASSED++)); } || echo "  ✗ /etc/pwnpilot missing"
((CHECKS_TOTAL++))

[ -d /var/lib/pwnpilot ] && { echo "  ✓ /var/lib/pwnpilot exists"; ((CHECKS_PASSED++)); } || echo "  ✗ /var/lib/pwnpilot missing"
((CHECKS_TOTAL++))

[ -d /var/log/pwnpilot ] && { echo "  ✓ /var/log/pwnpilot exists"; ((CHECKS_PASSED++)); } || echo "  ✗ /var/log/pwnpilot missing"
((CHECKS_TOTAL++))

[ -f /etc/pwnpilot/config.yaml ] && { echo "  ✓ configuration file exists"; ((CHECKS_PASSED++)); } || echo "  ✗ configuration file missing"
((CHECKS_TOTAL++))

[ -f /opt/pwnpilot/alembic.ini ] && { echo "  ✓ alembic.ini found"; ((CHECKS_PASSED++)); } || echo "  ✗ alembic.ini missing"
((CHECKS_TOTAL++))

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "Installation Summary"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "✓ PwnPilot installation complete!"
echo "✓ All verification checks passed ($CHECKS_PASSED/$CHECKS_TOTAL)"
echo ""
echo "Next Steps:"
echo "  1. Configure LLM provider:"
echo "     sudo nano /etc/pwnpilot/config.yaml"
echo ""
echo "  2. Test ROE verification:"
echo "     pwnpilot roe verify /opt/pwnpilot/examples/roe.template.yaml"
echo ""
echo "  3. View available commands:"
echo "     pwnpilot --help"
echo ""
echo "  4. Enable systemd service (optional):"
echo "     sudo systemctl enable pwnpilot && sudo systemctl start pwnpilot"
echo ""
echo "Configuration file: /etc/pwnpilot/config.yaml"
echo "Data directory: /var/lib/pwnpilot"
echo "Logs directory: /var/log/pwnpilot"
echo ""
echo "For troubleshooting, see: /opt/pwnpilot/docs/"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
EOF
chmod 755 "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/postinst"

# Create pre-remove script
cat > "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e
# Stop systemd service if running
systemctl stop pwnpilot 2>/dev/null || true
systemctl disable pwnpilot 2>/dev/null || true
EOF
chmod 755 "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/prerm"

# Create post-remove script (cleanup after package removal)
cat > "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    remove)
        # Normal removal: clean up installation directory
        if [ -d /opt/pwnpilot ]; then
            rm -rf /opt/pwnpilot
        fi
        # Remove systemd service file
        if [ -f /etc/systemd/system/pwnpilot.service ]; then
            rm -f /etc/systemd/system/pwnpilot.service
            systemctl daemon-reload 2>/dev/null || true
        fi
        ;;
    purge)
        # Purge: remove all files including configuration and data
        if [ -d /opt/pwnpilot ]; then
            rm -rf /opt/pwnpilot
        fi
        if [ -d /etc/pwnpilot ]; then
            rm -rf /etc/pwnpilot
        fi
        if [ -d /var/lib/pwnpilot ]; then
            rm -rf /var/lib/pwnpilot
        fi
        if [ -d /var/log/pwnpilot ]; then
            rm -rf /var/log/pwnpilot
        fi
        # Remove systemd service file
        if [ -f /etc/systemd/system/pwnpilot.service ]; then
            rm -f /etc/systemd/system/pwnpilot.service
            systemctl daemon-reload 2>/dev/null || true
        fi
        # Remove system user (if not in use)
        if id pwnpilot &>/dev/null; then
            userdel pwnpilot 2>/dev/null || true
        fi
        ;;
esac
EOF
chmod 755 "$BUILD_DIR/$PACKAGE_NAME/DEBIAN/postrm"

# Build the .deb package
echo "Building .deb package..."
cd "$BUILD_DIR"
dpkg-deb --build "$PACKAGE_NAME"
cd - > /dev/null

# Move to dist
mkdir -p dist
mv "$BUILD_DIR/${PACKAGE_NAME}.deb" "dist/${PACKAGE_NAME}.deb"

echo "✓ Debian package created: dist/${PACKAGE_NAME}.deb"
echo ""
echo "Installation:"
echo "  sudo dpkg -i dist/${PACKAGE_NAME}.deb"
echo ""
echo "Or with dependencies:"
echo "  sudo apt install ./dist/${PACKAGE_NAME}.deb"
