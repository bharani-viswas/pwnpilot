# PwnPilot Installation Guide

This guide covers all installation methods for PwnPilot across different platforms and use cases.

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
  - [Method 1: One-Command Installation](#method-1-one-command-installation)
  - [Method 2: Debian/Ubuntu Package (.deb)](#method-2-debian-ubuntu-package-deb)
  - [Method 3: Manual Installation](#method-3-manual-installation)
  - [Method 4: Development Setup](#method-4-development-setup)
- [Supported Platforms](#supported-platforms)
- [Troubleshooting](#troubleshooting)
- [Post-Installation](#post-installation)

## System Requirements

### Hardware
- **CPU**: 2+ cores recommended
- **RAM**: 4GB minimum, 8GB+ recommended
- **Storage**: 5GB for installation, 10GB+ for data/logs

### Software
- **OS**: Ubuntu 20.04 LTS+, Debian 11+, Kali Linux 2022+
- **Python**: 3.10+ (3.11+ recommended)
- **Package Manager**: apt (Debian/Ubuntu based)

### Network
- Internet access for downloading dependencies
- Local LLM server access (Ollama/vLLM on localhost:11434)
- Or cloud API access if using OpenAI/Anthropic

## Quick Start

### For Developers (5 minutes)
```bash
git clone https://github.com/bharani-viswas/pwnpilot.git
cd pwnpilot
bash scripts/install.sh --system-deps
```

### For Production (Ubuntu/Debian/Kali)
```bash
git clone https://github.com/bharani-viswas/pwnpilot.git
cd pwnpilot
make deb && sudo apt install ./dist/pwnpilot_*.deb
```

### For Cloud Deployment
See [Systemd Deployment](#systemd-deployment) section in main README.

## Installation Methods

### Method 1: One-Command Installation

**Fastest way to get started on a fresh system:**

```bash
git clone https://github.com/bharani-viswas/pwnpilot.git
cd pwnpilot
bash scripts/install.sh --system-deps --dev
```

**What this does:**
1. Installs Python 3.10+, pip, venv, and build tools
2. Creates a Python virtual environment
3. Installs all PwnPilot dependencies
4. Initializes the database
5. Generates operator signing keys
6. Verifies the installation

**Supported on:**
- Ubuntu 20.04 LTS+
- Debian 11+
- Kali Linux 2022+

**Usage:**
```bash
bash scripts/install.sh [OPTIONS]

Options:
  --dev              Install development dependencies (pytest, mypy, ruff)
  --system-deps      Install system dependencies (requires sudo)
  --python PYTHON    Use specific Python binary (default: python3)
```

### Method 2: Debian/Ubuntu Package (.deb)

**Recommended for production environments.**

#### Step 1: Build the Package

```bash
git clone https://github.com/bharani-viswas/pwnpilot.git
cd pwnpilot
make deb
```

This creates a Debian package in `dist/pwnpilot_*.deb`.

#### Step 2: Install the Package

**Option A: With automatic dependency resolution (recommended)**
```bash
sudo apt install ./dist/pwnpilot_*.deb
```

**Option B: Using dpkg (manual dependency handling)**
```bash
sudo dpkg -i dist/pwnpilot_*.deb
```

#### Step 3: Complete Installation

The postinstall script automatically:
- Creates Python virtual environment at `/opt/pwnpilot/.venv`
- Installs all Python dependencies
- Creates system user `pwnpilot`
- Initializes database at `/var/lib/pwnpilot/pwnpilot.db`
- Creates config template at `/etc/pwnpilot/config.yaml`
- Sets up systemd service

**Verify installation:**
```bash
sudo systemctl status pwnpilot
pwnpilot --version
```

#### Package Contents
```
/opt/pwnpilot/                  # Application files
/etc/pwnpilot/                  # Configuration
/var/lib/pwnpilot/              # Data directory
/var/log/pwnpilot/              # Logs
/etc/systemd/system/pwnpilot.service
/usr/bin/pwnpilot               # CLI executable
```

### Method 3: Manual Installation

**For maximum control and customization:**

```bash
# 1. Clone repository
git clone https://github.com/bharani-viswas/pwnpilot.git
cd pwnpilot

# 2. Install system dependencies
sudo apt-get update
sudo apt-get install -y \
    python3.11 python3-pip python3-venv \
    build-essential python3-dev \
    nmap nikto git curl wget

# 3. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Upgrade core tools
pip install --upgrade pip setuptools wheel

# 5. Install PwnPilot
pip install -e .

# 6. Initialize database
alembic upgrade head

# 7. Generate signing keys
pwnpilot keys --generate

# 8. Verify installation
pwnpilot check
```

### Method 4: Development Setup

**For developers contributing to PwnPilot:**

```bash
# All of Method 3, plus:
pip install -e ".[dev]"

# Running tests
pytest tests/ -v

# Code quality
make lint      # ruff + mypy
make format    # auto-format with ruff
```

## Supported Platforms

### ✅ Tested & Supported
- **Ubuntu**: 20.04 LTS, 22.04 LTS, 24.04 LTS
- **Debian**: 11 (Bullseye), 12 (Bookworm)
- **Kali Linux**: 2022.x, 2023.x, 2024.x

### ⚠️ May Work But Not Tested
- **Fedora/RHEL**: May require adapter scripts for RPM
- **Arch Linux**: Requires AUR or manual build
- **macOS**: Requires Homebrew, UNIX paths adjustments
- **Windows**: Requires WSL2 or Docker

### Installation on macOS (Homebrew)
```bash
# Install dependencies via Homebrew
brew install python@3.11 nmap nikto

# Then proceed with Method 3 or use Docker
```

## Troubleshooting

### Python Version Issues

**Error**: `python: command not found` or `Python 3.10+ required`

**Solution:**
```bash
# Check installed Python versions
python3 --version
python3.11 --version

# If 3.11 is available, use it
python3.11 -m venv .venv
source .venv/bin/activate

# Or install Python 3.11
sudo apt-get install python3.11 python3.11-venv
```

### Virtual Environment Issues

**Error**: `ModuleNotFoundError: No module named 'pip'`

**Solution:**
```bash
# Recreate virtual environment
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
```

### Dependency Installation Failures

**Error**: `pip install` fails with build errors

**Solution:**
```bash
# Install build dependencies
sudo apt-get install -y build-essential python3-dev libffi-dev libssl-dev

# Try install again
pip install --upgrade pip
pip install -e .
```

### Database Initialization Fails

**Error**: `alembic upgrade head` fails

**Solution:**
```bash
# Check database path permissions
mkdir -p ~/.pwnpilot
ls -la ~/.pwnpilot

# Or specify custom config
export PWNPILOT_DB_PATH=/custom/path/pwnpilot.db
alembic upgrade head
```

### Signing Key Generation Fails

**Error**: `pwnpilot keys --generate` fails

**Solution:**
```bash
# Try with explicit output directory
mkdir -p ~/.pwnpilot/keys
pwnpilot keys --generate --output ~/.pwnpilot/keys
```

### Package Installation Fails

**Error**: `dpkg: error processing package pwnpilot`

**Solution:**
```bash
# Fix broken dependencies
sudo apt --fix-broken install

# Retry package installation
sudo apt install ./dist/pwnpilot_*.deb
```

### LLM Connection Issues

**Error**: `Connection to Ollama failed`

**Solution:**
1. Verify Ollama is running:
   ```bash
   ollama serve
   ```
   (In separate terminal)

2. Test connection:
   ```bash
   curl http://localhost:11434/api/tags
   ```

3. If not working, configure alt LLM:
   ```yaml
   # Edit /etc/pwnpilot/config.yaml
   llm:
     provider: openai  # or anthropic
     api_key: sk-...
   ```

## Post-Installation

### For Users (Installed via Package)

**Start the daemon:**
```bash
sudo systemctl start pwnpilot
sudo systemctl enable pwnpilot  # auto-start on boot
```

**Check installation:**
```bash
pwnpilot version
pwnpilot check
```

**First engagement:**
```bash
pwnpilot start --help
```

### For Developers (Development Installation)

**Activate development environment:**
```bash
source .venv/bin/activate
```

**Run tests:**
```bash
pytest tests/ -v --cov
```

**Start development server:**
```bash
pwnpilot tui
```

### Install Security Tools (Optional)

For full tool adapter support:

```bash
# Install all security tools
sudo bash scripts/install_security_tools.sh

# Verify installation
bash scripts/verify_toolchain.sh

# Individual tools
sudo apt-get install nmap nikto sqlmap whatweb nuclei zaproxy
```

### Configure LLM

**Local (Recommended):**
```bash
# Install and run Ollama
curl https://ollama.ai/install.sh | sh
ollama pull llama3
ollama serve
```

**Cloud (OpenAI):**
```yaml
# /etc/pwnpilot/config.yaml
llm:
  provider: openai
  api_key: sk-...
```

### Test Installation

```bash
# Quick verification
pwnpilot check

# Run unit tests (dev install)
pytest tests/unit/ -v

# List available tools
pwnpilot --version
```

## Getting Help

- **Documentation**: See [README.md](README.md)
- **Issues**: https://github.com/bharani-viswas/pwnpilot/issues
- **CLI Help**: `pwnpilot --help`
- **Development**: See DEVELOPMENT.md (if available)

## Next Steps

After successful installation:

1. **Configure LLM**: Set up local (Ollama) or cloud LLM
2. **Configure Policy**: Edit `/etc/pwnpilot/config.yaml` (package install)
3. **Install Tools**: Run `sudo bash scripts/install_security_tools.sh`
4. **Test Setup**: Run `pwnpilot check`
5. **Start First Test**: `pwnpilot start --target <target>`
