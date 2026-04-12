# PwnPilot Post-Installation Guide

## Installation Overview

This guide helps troubleshoot and complete PwnPilot installation on Ubuntu 20.04+, Debian 11+, or Kali Linux 2022+.

## Installation Steps

### Step 1: Install Debian Package

```bash
# Copy package to target system if needed
scp dist/pwnpilot_0.1.0_amd64.deb user@target:/tmp/

# Install with dpkg
sudo dpkg -i /tmp/pwnpilot_0.1.0_amd64.deb

# Or install with auto-dependency resolution
sudo apt install /tmp/pwnpilot_0.1.0_amd64.deb
```

### Step 2: Verify Installation

```bash
# Check CLI is accessible
pwnpilot version
# Expected output: pwnpilot v0.1.0

# Check ROE commands available
pwnpilot roe --help

# Run preflight checks
pwnpilot check
```

### Step 3: Configuration

```bash
# Edit configuration file (requires sudo)
sudo nano /etc/pwnpilot/config.yaml

# Example configuration:
# llm:
#   provider: openai
#   api_key: sk-...
# database:
#   url: sqlite:////var/lib/pwnpilot/pwnpilot.db
```

### Step 4: Initialize Database (Optional)

If database initialization was skipped during installation:

```bash
# Navigate to installation directory
cd /opt/pwnpilot

# Run migrations manually
/opt/pwnpilot/.venv/bin/alembic upgrade head

# Verify database exists
ls -la /var/lib/pwnpilot/
```

### Step 5: Generate Signing Keys (Optional)

If signing key generation was skipped:

```bash
# Generate keys
pwnpilot keys --generate

# Verify keys exist
ls -la /etc/pwnpilot/
```

### Step 6: Enable Systemd Service (Optional)

```bash
# Enable auto-start on boot
sudo systemctl enable pwnpilot

# Start service
sudo systemctl start pwnpilot

# Check status
sudo systemctl status pwnpilot

# View logs
sudo journalctl -u pwnpilot -f
```

## Troubleshooting

### Issue 1: "pwnpilot: command not found"

**Cause:** CLI wrapper not properly installed or venv not initialized.

**Solution:**

```bash
# Option A: Reinstall package
sudo dpkg --configure -a
sudo dpkg -i /tmp/pwnpilot_0.1.0_amd64.deb

# Option B: Manually fix installation
cd /opt/pwnpilot
./.venv/bin/pip install -e .
which pwnpilot  # Should show /usr/bin/pwnpilot
```

### Issue 2: Database Initialization Failed

**Error:** "FAILED: No 'script_location' key found in configuration"

**Cause:** Alembic configuration issue during installation.

**Solution:**

```bash
# Manually initialize database
cd /opt/pwnpilot
./.venv/bin/alembic upgrade head

# If above fails, check alembic.ini exists
[ -f /opt/pwnpilot/alembic.ini ] && echo "✓ alembic.ini found" || echo "✗ Missing alembic.ini"

# Verify migrations directory
ls -la /opt/pwnpilot/pwnpilot/migrations/
```

### Issue 3: Signing Keys Generation Failed

**Error:** "Signing key generation requires manual setup"

**Cause:** CLI not available during post-install phase.

**Solution:**

```bash
# Generate keys after successful installation
pwnpilot keys --generate --output /etc/pwnpilot

# Verify keys created
ls -la /etc/pwnpilot/keys/

# If issues persist, check file permissions
sudo chown pwnpilot:pwnpilot /etc/pwnpilot -R
sudo chmod 700 /etc/pwnpilot/keys
```

### Issue 4: Python Dependencies Failed to Install

**Error:** Pip dependency resolution failures.

**Cause:** Missing system dependencies or incompatible Python version.

**Solution:**

```bash
# Ensure system dependencies installed
sudo apt update
sudo apt install -y python3.10 python3-dev build-essential

# Check Python version
python3 --version  # Must be 3.10+

# Manually fix venv installation
cd /opt/pwnpilot
rm -rf .venv
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip setuptools wheel
./.venv/bin/pip install -r requirements.txt
```

### Issue 5: Permission Denied Errors

**Error:** "Permission denied" when accessing /etc/pwnpilot or /var/lib/pwnpilot

**Cause:** Improper file ownership or permissions.

**Solution:**

```bash
# Fix permissions
sudo chown -R pwnpilot:pwnpilot /var/lib/pwnpilot
sudo chown -R pwnpilot:pwnpilot /etc/pwnpilot
sudo chmod 750 /var/lib/pwnpilot
sudo chmod 750 /etc/pwnpilot

# Verify permissions
ls -la /etc/pwnpilot
ls -la /var/lib/pwnpilot
```

### Issue 6: Systemd Service Fails to Start

**Error:** "systemd[1]: pwnpilot.service: Main process exited"

**Solution:**

```bash
# Check service logs
sudo journalctl -u pwnpilot -n 50

# Verify configuration file
sudo cat /etc/pwnpilot/config.yaml

# Check database connectivity
ls -la /var/lib/pwnpilot/pwnpilot.db

# Try starting service manually (for debugging)
/usr/bin/pwnpilot check
```

## Post-Installation Verification

### CLI Functionality

```bash
# Test all main commands
pwnpilot version                    # Show version
pwnpilot --help                     # Show main help
pwnpilot roe --help                 # Show ROE subcommands
pwnpilot check                      # Run system checks

# Test ROE commands with example file
pwnpilot roe verify /opt/pwnpilot/examples/roe.template.yaml
pwnpilot roe list
```

### Database Verification

```bash
# Check database file exists
ls -lh /var/lib/pwnpilot/pwnpilot.db

# Check database tables (requires sqlite3)
sudo apt install -y sqlite3
sqlite3 /var/lib/pwnpilot/pwnpilot.db ".tables"
```

### File Structure Verification

```bash
# Verify installation directory
ls -la /opt/pwnpilot/
# Should contain: pwnpilot/, scripts/, schemas/, examples/, alembic.ini, requirements.txt

# Verify configuration
ls -la /etc/pwnpilot/
# Should contain: config.yaml and optionally keys/

# Verify data directory
ls -la /var/lib/pwnpilot/
# Should contain: pwnpilot.db (after first run)

# Verify logs directory
ls -la /var/log/pwnpilot/
```

## Performance Verification

### Installation Time Benchmarks

| Phase | Expected Time | Description |
|-------|-------|--|
| Package extraction | ~2 seconds | dpkg unpacking |
| Virtual environment creation | ~3 seconds | Python venv setup |
| Dependency installation | ~120 seconds | pip install all packages |
| Database initialization | ~2 seconds | Alembic migrations |
| Key generation | ~1 second | Ed25519 key creation |
| **Total** | **~128 seconds** | Full installation |

### Runtime Performance

| Operation | Expected Time | Notes |
|-----------|-------|-------|
| CLI startup | <1 second | Fast local tool |
| ROE validation | <100 ms | Schema checking |
| ROE listing | <200 ms | Database query |
| Database operations | <100 ms | SQLAlchemy ORM |

## Uninstallation

If you need to remove PwnPilot:

```bash
# Remove package
sudo dpkg -r pwnpilot

# Or more aggressive removal with apt
sudo apt remove --purge pwnpilot

# Clean configuration (optional)
sudo rm -rf /etc/pwnpilot
sudo rm -rf /var/lib/pwnpilot
sudo rm -rf /var/log/pwnpilot

# Remove user account (optional)
sudo userdel pwnpilot
```

## Getting Help

### Common Commands for Debugging

```bash
# Check installation status
pwnpilot check

# View detailed help
pwnpilot --help

# Check specific command help
pwnpilot roe verify --help

# Test ROE file
pwnpilot roe verify <path-to-roe-file>

# List current ROEs
pwnpilot roe list --json

# Export audit report
pwnpilot roe export --output report.json
```

### Log Locations

```bash
# Application logs
/var/log/pwnpilot/

# Systemd journal (if service enabled)
sudo journalctl -u pwnpilot

# Database logs (if enabled in config)
/var/log/pwnpilot/pwnpilot.log
```

## Next Steps

After successful installation:

1. **Create Rules of Engagement (ROE)**: See examples in `/opt/pwnpilot/examples/`
2. **Configure LLM Provider**: Edit `/etc/pwnpilot/config.yaml`
3. **Initialize Engagement**: Run `pwnpilot start` with your ROE
4. **Monitor Execution**: Use `pwnpilot tui` for live dashboard

## Configuration Reference

### LLM Providers

**OpenAI:**
```yaml
llm:
  provider: openai
  api_key: sk-...
  model: gpt-4o
```

**Anthropic Claude:**
```yaml
llm:
  provider: anthropic
  api_key: sk-ant-...
  model: claude-3-sonnet
```

**Local Ollama:**
```yaml
llm:
  provider: ollama
  base_url: http://localhost:11434
  model: mistral
```

## Security Best Practices

1. **Restrict Configuration Access:**
   ```bash
   sudo chmod 600 /etc/pwnpilot/config.yaml
   ```

2. **Use Strong API Keys:**
   - Never commit API keys to version control
   - Rotate keys regularly
   - Use environment variables: `export LITELLM_API_KEY=...`

3. **Monitor Access:**
   ```bash
   sudo tail -f /var/log/pwnpilot/pwnpilot.log
   ```

4. **Secure Database:**
   - Ensure `/var/lib/pwnpilot/` is only readable by pwnpilot user
   - Regular backups of engagement databases

## Version Information

- **Package Version:** 0.1.0
- **Python Requirements:** 3.10+
- **Supported OS:**
  - Ubuntu 20.04 LTS, 22.04 LTS, 24.04 LTS
  - Debian 11 (Bullseye), 12 (Bookworm)
  - Kali Linux 2022.0+
- **Architecture:** amd64 (Intel/AMD 64-bit)

---

**For more information:** See `/opt/pwnpilot/docs/` or visit the project repository.

**Installation Date:** $(date)
**Status:** ✅ Installation complete
