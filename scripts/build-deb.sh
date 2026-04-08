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
cp requirements.txt "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX/"
cp pyproject.toml "$BUILD_DIR/$PACKAGE_NAME$INSTALL_PREFIX/"
cp README.md LICENSE "$BUILD_DIR/$PACKAGE_NAME/usr/share/doc/$PROJECT_NAME/"
cp INSTALLATION.md "$BUILD_DIR/$PACKAGE_NAME/usr/share/doc/$PROJECT_NAME/" 2>/dev/null || true

# Copy systemd service file
if [ -f "scripts/pwnpilot.service" ]; then
    cp scripts/pwnpilot.service "$BUILD_DIR/$PACKAGE_NAME/etc/systemd/system/"
fi

# Create wrapper script for /usr/bin
cat > "$BUILD_DIR/$PACKAGE_NAME/usr/bin/pwnpilot" << 'EOF'
#!/bin/bash
exec /opt/pwnpilot/.venv/bin/pwnpilot "$@"
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

# Create Python virtual environment
if [ ! -d "$INSTALL_PREFIX/.venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "$INSTALL_PREFIX/.venv" || python3.11 -m venv "$INSTALL_PREFIX/.venv" || python3.10 -m venv "$INSTALL_PREFIX/.venv"
fi

# Upgrade pip and install dependencies
echo "Installing Python dependencies..."
"$INSTALL_PREFIX/.venv/bin/pip" install --upgrade pip setuptools wheel
"$INSTALL_PREFIX/.venv/bin/pip" install -r "$INSTALL_PREFIX/requirements.txt"

# Create data directories
mkdir -p /etc/pwnpilot
mkdir -p /var/lib/pwnpilot
mkdir -p /var/log/pwnpilot

# Fix permissions
chown -R pwnpilot:pwnpilot /var/lib/pwnpilot /var/log/pwnpilot /etc/pwnpilot

# Create default config
if [ ! -f /etc/pwnpilot/config.yaml ]; then
    cat > /etc/pwnpilot/config.yaml << 'CONFIG'
# PwnPilot Configuration
# See README for detailed configuration options

llm:
  provider: ollama
  base_url: http://localhost:11434
  planner_model: llama3
  validator_model: mistral
  executor_model: llama3
  reporter_model: llama3

database:
  type: sqlite
  sqlite_path: /var/lib/pwnpilot/pwnpilot.db

tools:
  nmap:
    enabled: true
  nuclei:
    enabled: true
  nikto:
    enabled: true
  sqlmap:
    enabled: true
  whatweb:
    enabled: true
  zap:
    enabled: true
    port: 8080

policy:
  deny_by_default: true
  approval_required: true
CONFIG
    chown pwnpilot:pwnpilot /etc/pwnpilot/config.yaml
fi

# Initialize database
echo "Initializing database..."
cd "$INSTALL_PREFIX"
"$INSTALL_PREFIX/.venv/bin/alembic" upgrade head || true

# Generate keys if not present
echo "Generating signing keys..."
"$INSTALL_PREFIX/.venv/bin/pwnpilot" keys --generate --output /etc/pwnpilot || true

# Enable systemd service
if [ -f /etc/systemd/system/pwnpilot.service ]; then
    systemctl daemon-reload || true
    echo "To enable pwnpilot service, run: sudo systemctl enable pwnpilot"
fi

echo "✓ PwnPilot installation complete!"
echo "Run 'pwnpilot --help' to get started"
echo "Configuration file: /etc/pwnpilot/config.yaml"
echo "Data directory: /var/lib/pwnpilot"
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
