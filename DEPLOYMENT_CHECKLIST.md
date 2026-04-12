# PwnPilot Deployment Checklist

## Pre-Deployment

- [ ] Review `DEPLOYMENT_STATUS.md` for system requirements
- [ ] Review `DEPLOYMENT_FIX_SUMMARY.md` for all improvements made
- [ ] Ensure target system has:
  - [ ] Ubuntu 20.04+ OR Debian 11+ OR Kali 2022+
  - [ ] Python 3.10+ installed
  - [ ] sudo access or root privileges
  - [ ] Internet access (for package/dependency download)

## Deployment

### Option 1: Standard Installation
```bash
sudo dpkg -i dist/pwnpilot_0.1.0_amd64.deb
```

### Option 2: Installation with Auto-Dependencies
```bash
sudo apt install ./dist/pwnpilot_0.1.0_amd64.deb
```

### Option 3: Development Installation
```bash
bash scripts/install.sh --system-deps
```

**Expected Output:**
```
Building Debian package for pwnpilot v0.1.0...
✓ Debian package created: dist/pwnpilot_0.1.0_amd64.deb

Installation:
  sudo dpkg -i dist/pwnpilot_0.1.0_amd64.deb
```

## Post-Installation Verification

### Phase 1: CLI Verification (30 seconds)
```bash
# Test 1: CLI is accessible
pwnpilot version
# Expected: pwnpilot v0.1.0

# Test 2: Help is available
pwnpilot --help
# Expected: Shows all commands

# Test 3: ROE commands available
pwnpilot roe --help
# Expected: Shows 4 ROE subcommands
```

- [ ] CLI accessible
- [ ] Version displays correctly
- [ ] Help text shows all commands
- [ ] ROE subcommands available

### Phase 2: System Check (1 minute)
```bash
# Run preflight checks
pwnpilot check

# Expected checks:
# ✓ Configuration file exists
# ✓ Database connectivity
# ✓ Migration state
# ✓ Signing keys (may skip on fresh install)
# ✓ Tool binaries
```

- [ ] All preflight checks pass
- [ ] Configuration file accessible
- [ ] Database initialized or ready

### Phase 3: ROE Verification (1 minute)
```bash
# Test ROE validation
pwnpilot roe verify /opt/pwnpilot/examples/roe.template.yaml

# Expected: Validation success with schema info

# Test ROE listing
pwnpilot roe list

# Expected: May be empty on fresh install (OK)

# Test example ROE
pwnpilot roe verify /opt/pwnpilot/examples/roe.external-pentest.yaml
```

- [ ] ROE verification works
- [ ] ROE listing works
- [ ] Example files accessible

### Phase 4: Configuration (Optional)
```bash
# Review configuration
sudo cat /etc/pwnpilot/config.yaml

# Expected: Default YAML configuration

# Edit if needed (add LLM API keys)
sudo nano /etc/pwnpilot/config.yaml
```

- [ ] Configuration file exists
- [ ] Configuration is readable
- [ ] Can edit configuration

### Phase 5: Directory Structure Verification
```bash
# Check installation directory
ls -la /opt/pwnpilot/
# Expected: pwnpilot/, scripts/, schemas/, examples/, requirements.txt

# Check configuration
ls -la /etc/pwnpilot/
# Expected: config.yaml (and keys/ after first run)

# Check data directory
ls -la /var/lib/pwnpilot/
# Expected: May be empty initially

# Check logs
ls -la /var/log/pwnpilot/
# Expected: May be empty initially
```

- [ ] Installation directory has all files
- [ ] Configuration directory accessible
- [ ] Data directory exists and writable
- [ ] Logs directory exists

## Troubleshooting During Installation

### Issue: "pwnpilot: command not found"
```bash
# Solution: Reconfigure package
sudo dpkg --configure -a
sudo dpkg -i dist/pwnpilot_0.1.0_amd64.deb
pwnpilot version  # Should now work
```

- [ ] Issue resolved
- [ ] CLI now accessible

### Issue: Database initialization warnings
```bash
# Solution: Manual database initialization
cd /opt/pwnpilot
./.venv/bin/alembic upgrade head
```

- [ ] Database initialized manually (if needed)
- [ ] No errors shown

### Issue: Permission denied errors
```bash
# Solution: Fix permissions
sudo chown -R pwnpilot:pwnpilot /var/lib/pwnpilot
sudo chown -R pwnpilot:pwnpilot /etc/pwnpilot
sudo systemctl restart pwnpilot  # If service running
```

- [ ] Permissions fixed
- [ ] Service running normally

## Post-Installation Configuration

### Step 1: LLM Provider Setup
```bash
# Edit configuration
sudo nano /etc/pwnpilot/config.yaml

# Uncomment and set provider:
# Option A - OpenAI
# llm:
#   provider: openai
#   api_key: sk-...

# Option B - Anthropic
# llm:
#   provider: anthropic
#   api_key: sk-ant-...

# Option C - Local Ollama
# llm:
#   provider: ollama
#   base_url: http://localhost:11434
```

- [ ] Configuration file updated with LLM provider
- [ ] API keys set (if using cloud provider)

### Step 2: Enable Systemd Service (Optional)
```bash
# Enable auto-start on boot
sudo systemctl enable pwnpilot

# Start service
sudo systemctl start pwnpilot

# Verify status
sudo systemctl status pwnpilot

# View logs
sudo journalctl -u pwnpilot -f
```

- [ ] Service enabled (if desired)
- [ ] Service status shows active

### Step 3: Test with Real ROE (Optional)
```bash
# Create test ROE file
cat > test-roe.yaml << 'EOF'
version: "1.0"
engagement_type: "internal-security-assessment"
description: "Internal network security assessment with comprehensive threat modeling and vulnerability validation across all systems and services"
scope:
  cidrs: "192.168.0.0/16, 10.0.0.0/8"
  hosts: "server1.example.com, server2.example.com"
  excluded_ips: "192.168.1.1, 10.255.255.1"
  ports: "22, 80, 443, 3306, 5432"
active_hours_utc: "09:00-17:00"
valid_hours: 24
max_iterations: 50
max_retries: 3
timeout_seconds: 3600
allowed_actions:
  - "network_scan"
  - "vulnerability_scan"
  - "protocol_analysis"
  - "authentication_testing"
cloud_allowed: false
EOF

# Verify the test ROE
pwnpilot roe verify test-roe.yaml
```

- [ ] Test ROE validates successfully

## Success Criteria

✅ **Minimum Criteria Met:**
- [ ] `pwnpilot version` returns v0.1.0
- [ ] `pwnpilot --help` shows all commands
- [ ] `pwnpilot check` passes
- [ ] `/etc/pwnpilot/config.yaml` exists
- [ ] `/var/lib/pwnpilot/` directory exists
- [ ] `pwnpilot roe verify` works with example files

✅ **Full Criteria Met (Recommended):**
- [ ] All minimum criteria
- [ ] All CLI commands tested
- [ ] Configuration file customized
- [ ] LLM provider configured
- [ ] Systemd service enabled (if desired)
- [ ] Custom ROE tested successfully

## Performance Metrics (Expected)

| Metric | Expected | Actual |
|--------|----------|--------|
| Installation Time | ~132 seconds | ___ |
| CLI Startup | <1 second | ___ |
| ROE Validation | <100 ms | ___ |
| Database Query | <100 ms | ___ |
| Package Size | ~230-300 KB | 295 KB ✓ |

## Support & Documentation

**If issues occur:**
1. Check `POST_INSTALL_GUIDE.md` for troubleshooting
2. Check `DEPLOYMENT_FIX_SUMMARY.md` for known issues
3. Review `/var/log/pwnpilot/` for application logs
4. Run `pwnpilot check` for diagnostic output

**Key Documentation Files:**
- `/opt/pwnpilot/docs/README.md` - Main documentation
- `/opt/pwnpilot/docs/roe-usage.md` - ROE guide
- `/opt/pwnpilot/docs/roe-admin.md` - Admin guide
- `/opt/pwnpilot/docs/roe-compliance.md` - Compliance guide

## Deployment Sign-Off

| Item | Status | Notes |
|------|--------|-------|
| Pre-deployment checks | ☐ | |
| Installation completed | ☐ | |
| CLI verification | ☐ | |
| System checks passed | ☐ | |
| Configuration customized | ☐ | |
| Service enabled (if needed) | ☐ | |
| Documentation reviewed | ☐ | |
| Support plan confirmed | ☐ | |

**Deployment Date:** _____________  
**Deployed By:** _____________  
**System:** _____________  
**Status:** ✅ **READY FOR PRODUCTION**

---

For detailed deployment information, see:
- `DEPLOYMENT_STATUS.md` - Comprehensive status report
- `DEPLOYMENT_FIX_SUMMARY.md` - All fixes and improvements
- `POST_INSTALL_GUIDE.md` - Troubleshooting guide
