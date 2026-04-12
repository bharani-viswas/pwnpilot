# PwnPilot Installation Guide

Complete installation instructions for all platforms with troubleshooting and verification procedures.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
- [Pre-Installation Checklist](#pre-installation-checklist)
- [Installation Steps](#installation-steps)
- [Post-Installation Verification](#post-installation-verification)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

---

## System Requirements

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 4 GB | 8+ GB |
| **Storage** | 5 GB | 20 GB |
| **Network** | Internet access | Stable connection |

### Software

| Component | Requirement | Tested | Status |
|-----------|------------|--------|--------|
| **OS** | Ubuntu 20.04+, Debian 11+, Kali 2022+ | ✅ Yes | ✅ Supported |
| **Python** | 3.10+ | ✅ 3.10.12 | ✅ Available |
| **pip** | Latest | ✅ 26.0.1 | ✅ Available |
| **nmap** | Any version | ✅ Latest | ✅ Available |

### Supported Platforms

- ✅ **Ubuntu:** 20.04 LTS, 22.04 LTS, 24.04 LTS
- ✅ **Debian:** 11 (Bullseye), 12 (Bookworm)
- ✅ **Kali Linux:** 2022.0+

---

## Installation Methods

### Method 1: Standard Debian Package (Recommended)

```bash
sudo dpkg -i dist/pwnpilot_0.1.0_amd64.deb
```

### Method 2: Automated Dependency Installation

```bash
sudo apt install ./dist/pwnpilot_0.1.0_amd64.deb
```

### Method 3: Development Installation

```bash
bash scripts/install.sh --system-deps --dev
```

---

## Installation Steps

### Step 1: Prepare System

```bash
sudo apt update
sudo apt install -y python3.10 python3-pip nmap
python3 --version    # Must be 3.10+
pip3 --version
```

### Step 2: Install Package

Choose one method and run it:

```bash
sudo dpkg -i dist/pwnpilot_0.1.0_amd64.deb
```

Watch for the completion message showing all verification checks passed.

---

## Post-Installation Verification

After installation completes, verify everything works:

### Phase 1: CLI (30 seconds)
```bash
pwnpilot version              # Should show: pwnpilot v0.1.0
pwnpilot --help               # Should show all commands
pwnpilot roe --help           # Should show 4 ROE subcommands
```

### Phase 2: System Check (1 minute)
```bash
pwnpilot check                # All checks should pass
```

### Phase 3: ROE Validation (1 minute)
```bash
pwnpilot roe verify /opt/pwnpilot/examples/roe.template.yaml
pwnpilot roe list
```

### Phase 4: Directories (1 minute)
```bash
ls -la /etc/pwnpilot/         # Should have config.yaml
ls -la /var/lib/pwnpilot/     # Data directory
ls -la /var/log/pwnpilot/     # Logs directory
```

---

## Configuration

### Basic Setup

```bash
# Edit configuration
sudo nano /etc/pwnpilot/config.yaml

# Minimal example:
database:
  url: "sqlite:////var/lib/pwnpilot/pwnpilot.db"

llm:
  provider: "ollama"
  base_url: "http://localhost:11434"
  model: "mistral"
```

### LLM Options

**OpenAI:**
```yaml
llm:
  provider: "openai"
  api_key: "sk-..."
  model: "gpt-4o"
```

**Anthropic:**
```yaml
llm:
  provider: "anthropic"
  api_key: "sk-ant-..."
  model: "claude-3-sonnet"
```

**Local Ollama:**
```yaml
llm:
  provider: "ollama"
  base_url: "http://localhost:11434"
  model: "mistral"
```

### Enable Service (Optional)

```bash
sudo systemctl enable pwnpilot
sudo systemctl start pwnpilot
sudo systemctl status pwnpilot
```

---

## Troubleshooting

### "pwnpilot: command not found"

```bash
# Verify installation
pip3 list | grep pwnpilot

# Reinstall if needed
sudo dpkg --configure -a
sudo dpkg -i dist/pwnpilot_0.1.0_amd64.deb
```

### Database Initialization Failed

```bash
# Manual database initialization
cd /opt/pwnpilot
alembic upgrade head
```

### Permission Denied

```bash
# Fix permissions
sudo chown -R pwnpilot:pwnpilot /etc/pwnpilot
sudo chown -R pwnpilot:pwnpilot /var/lib/pwnpilot
sudo chown -R pwnpilot:pwnpilot /var/log/pwnpilot
sudo chmod 750 /etc/pwnpilot /var/lib/pwnpilot /var/log/pwnpilot
```

### Dependency Won't Install

```bash
# Upgrade pip
sudo pip3 install --upgrade pip setuptools wheel

# Reinstall package
pip3 install -r /opt/pwnpilot/requirements.txt
```

### ROE Validation Fails

Ensure your ROE file:
- ✓ Has valid YAML syntax
- ✓ Contains all required fields
- ✓ Description is 100+ characters

```bash
pwnpilot roe verify /path/to/roe.yaml
```

---

## Uninstallation

### Complete Removal

```bash
sudo dpkg -r pwnpilot
sudo rm -rf /etc/pwnpilot        # Optional: remove config
sudo rm -rf /var/lib/pwnpilot    # Optional: remove data
sudo rm -rf /var/log/pwnpilot    # Optional: remove logs
sudo userdel pwnpilot            # Optional: remove user
```

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| Installation Time | ~132 seconds |
| CLI Startup | ~100 ms |
| ROE Validation | <100 ms |
| Disk Usage | ~100 MB |

---

## Verification Checklist

✅ `pwnpilot version` works  
✅ `pwnpilot --help` shows commands  
✅ `pwnpilot roe --help` shows 4 subcommands  
✅ `pwnpilot check` passes all checks  
✅ Configuration file exists  
✅ Data directory exists  
✅ Logs directory exists  
✅ All CLI commands accessible  
✅ ROE verification working

---

**Last Updated:** April 12, 2026  
**Version:** 1.0
