# PwnPilot Deployment Guide

Production deployment procedures, verification, and operations for PwnPilot.

## Table of Contents

- [Pre-Deployment](#pre-deployment)
- [Deployment Procedures](#deployment-procedures)
- [Post-Deployment Verification](#post-deployment-verification)
- [System Configuration](#system-configuration)
- [Monitoring & Troubleshooting](#monitoring--troubleshooting)
- [Operational Procedures](#operational-procedures)

## Document Scope

This guide focuses on installation, service setup, and day-1/day-2 operational checks.

For deep operational workflows, use these companion guides:
- [DB_OPERATIONS.md](DB_OPERATIONS.md): schema lifecycle, backup/restore, and advanced SQL procedures
- [LEGAL_HOLDS.md](LEGAL_HOLDS.md): legal-hold lifecycle and governance controls
- [PAYLOAD_TELEMETRY.md](PAYLOAD_TELEMETRY.md): telemetry extraction and interpretation
- [CONFIGURATION_REFERENCE.md](CONFIGURATION_REFERENCE.md): full config surface and precedence details

---

## Pre-Deployment

### Environment Preparation

Ensure target system meets requirements:

```bash
# Check OS version
lsb_release -a                    # Ubuntu/Debian
uname -a                          # Linux info

# Verify Python
python3 --version                 # Must be 3.10+
pip3 --version

# Check disk space
df /opt /var /etc                 # Each needs 5GB+

# Network connectivity
ping -c 1 8.8.8.8                 # Internet access
curl -I https://pypi.org          # PyPI accessible
```

### Pre-Deployment Checklist

- [ ] OS is Ubuntu 20.04+, Debian 11+, or Kali 2022+
- [ ] Python 3.10+ installed
- [ ] Sufficient disk space (20GB+ recommended)
- [ ] Internet connectivity confirmed
- [ ] sudo/root access available
- [ ] No port conflicts (check port 8000 if using service)
- [ ] Backup existing configurations (if upgrading)

---

## Deployment Procedures

### Option 1: Standard Deployment (Recommended)

**Best for:** Production systems, automated deployments

```bash
# Download package to deployment system
scp dist/pwnpilot_0.1.0_amd64.deb user@target:/tmp/

# On target system
sudo dpkg -i /tmp/pwnpilot_0.1.0_amd64.deb

# Monitor installation
# Watch for: "[1/6]" through "[6/6]" phases
# Watch for: "[CHECK 1/5]" through "[CHECK 5/5]" verification
# Final output: "✓ All verification checks passed (5/5)"
```

**Timing:**
- Total: ~132 seconds
- Dependencies: ~120 seconds of that

**Output Analysis:**
```
✓ Phase 1: Pip upgraded
✓ Phase 2: Dependencies installed
✓ Phase 3: PwnPilot installed
✓ Phase 4: Directories configured
✓ Phase 5: Database initialized
✓ Phase 6: Systemd registered

[CHECK 1/5] CLI Accessibility      ✓
[CHECK 2/5] Version Check          ✓
[CHECK 3/5] Command Help           ✓
[CHECK 4/5] ROE Subcommands        ✓
[CHECK 5/5] Directory Structure    ✓

✓ Installation complete!
✓ All verification checks passed (5/5)
```

### Option 2: Dependency-Aware Deployment

**Best for:** Systems with missing dependencies

```bash
# Install with automatic dependency resolution
sudo apt install ./pwnpilot_0.1.0_amd64.deb

# apt will:
# 1. Detect missing system packages
# 2. Install python3.10, nmap, etc
# 3. Proceed with PwnPilot installation
# 4. Run all verification checks
```

### Option 3: Development Deployment

**Best for:** Testing, CI/CD environments

```bash
bash scripts/install.sh --system-deps --dev

# Includes:
# - System dependencies
# - Development tools (pytest, mypy, etc)
# - Test suite
# - Debug utilities
```

---

## Post-Deployment Verification

### Immediate Verification (5 minutes)

#### Phase 1: CLI Accessibility (30 seconds)

```bash
# Test 1: Version
echo "Test 1: Version"
pwnpilot version
# Expected: pwnpilot v0.1.0

# Test 2: Help
echo "Test 2: Help System"
pwnpilot --help | head -20
# Expected: Shows all 13 commands

# Test 3: ROE Commands
echo "Test 3: ROE Subcommands"
pwnpilot roe --help
# Expected: Shows verify, list, audit, export
```

**Success Criteria:** All 3 commands work without errors

#### Phase 2: System Diagnostics (1 minute)

```bash
echo "Phase 2: System Diagnostics"
pwnpilot check

# Expected output:
# ✓ Configuration file found
# ✓ Database connectivity OK
# ✓ Migration state: Up to date
# ✓ Signing keys: Present
# ✓ Tool binaries: Available
```

**Success Criteria:** All 5 checks pass

#### Phase 3: ROE Validation (1 minute)

```bash
echo "Phase 3: ROE Functionality"
pwnpilot roe verify /opt/pwnpilot/examples/roe.template.yaml
# Expected: Validation success with schema info

pwnpilot roe verify /opt/pwnpilot/examples/roe.external-pentest.yaml
# Expected: Validation success

pwnpilot roe list
# Expected: Shows approved ROEs (empty ok on fresh install)
```

**Success Criteria:** All ROE commands work correctly

#### Phase 4: Directory Verification (1 minute)

```bash
echo "Phase 4: Directory Structure"
ls -ld /opt/pwnpilot /etc/pwnpilot /var/lib/pwnpilot /var/log/pwnpilot

# Expected:
# drwxrwxr-x ... /opt/pwnpilot
# drwxr-x--- ... /etc/pwnpilot
# drwxr-x--- ... /var/lib/pwnpilot
# drwxr-x--- ... /var/log/pwnpilot
```

**Success Criteria:** All directories exist with proper permissions

#### Phase 5: Configuration Check (1 minute)

```bash
echo "Phase 5: Configuration"
sudo cat /etc/pwnpilot/config.yaml | head -10
# Expected: Valid YAML configuration

[ -f /opt/pwnpilot/alembic.ini ] && echo "✓ alembic.ini found" || echo "✗ Missing"
[ -f /etc/pwnpilot/config.yaml ] && echo "✓ config.yaml found" || echo "✗ Missing"
[ -d /var/lib/pwnpilot ] && echo "✓ Database directory found" || echo "✗ Missing"
```

**Success Criteria:** All configuration files present

### Comprehensive Verification Script

```bash
#!/bin/bash
# Run all 5 verification phases

set -e

echo "════════════════════════════════════════════════════════"
echo "PwnPilot Post-Deployment Verification"
echo "════════════════════════════════════════════════════════"

PASSES=0
FAILS=0

# Phase 1: CLI
echo ""
echo "[Phase 1] CLI Accessibility"
if pwnpilot version >/dev/null 2>&1; then
    echo "  ✓ pwnpilot version works"
    ((PASSES++))
else
    echo "  ✗ pwnpilot version failed"
    ((FAILS++))
fi

# Phase 2: Checks
echo ""
echo "[Phase 2] System Diagnostics"
if pwnpilot check >/dev/null 2>&1; then
    echo "  ✓ pwnpilot check passed"
    ((PASSES++))
else
    echo "  ✗ pwnpilot check failed"
    ((FAILS++))
fi

# Phase 3: ROE
echo ""
echo "[Phase 3] ROE Functionality"
if pwnpilot roe --help >/dev/null 2>&1; then
    echo "  ✓ ROE commands available"
    ((PASSES++))
else
    echo "  ✗ ROE commands not found"
    ((FAILS++))
fi

# Phase 4: Directories
echo ""
echo "[Phase 4] Directory Structure"
for dir in /opt/pwnpilot /etc/pwnpilot /var/lib/pwnpilot /var/log/pwnpilot; do
    if [ -d "$dir" ]; then
        echo "  ✓ $dir exists"
        ((PASSES++))
    else
        echo "  ✗ $dir missing"
        ((FAILS++))
    fi
done

# Phase 5: Configuration
echo ""
echo "[Phase 5] Configuration"
if [ -f /etc/pwnpilot/config.yaml ]; then
    echo "  ✓ Configuration file present"
    ((PASSES++))
else
    echo "  ✗ Configuration file missing"
    ((FAILS++))
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "Results: $PASSES passed, $FAILS failed"
echo "════════════════════════════════════════════════════════"

[ $FAILS -eq 0 ] && echo "✓ Deployment verified successfully!" || echo "✗ Some checks failed"
```

Save as `/tmp/verify.sh` and run:
```bash
bash /tmp/verify.sh
```

---

## System Configuration

### Configuration Precedence and Safe Overrides

At runtime, configuration is resolved in this order:
1. `PWNPILOT_CONFIG`
2. `./config.yaml` in the current working directory
3. `~/.pwnpilot/config.yaml`
4. `/etc/pwnpilot/config.yaml`

If a config is loaded from the current working directory, pwnpilot emits a warning so operators can avoid accidental environment drift in production. For deterministic deployments, set `PWNPILOT_CONFIG` explicitly in your systemd environment file.

Example (`/etc/pwnpilot/pwnpilot.env`):

```bash
PWNPILOT_CONFIG=/etc/pwnpilot/config.yaml
```

### LLM Provider Setup

#### OpenAI Configuration

```bash
sudo tee /etc/pwnpilot/config.yaml > /dev/null << 'EOF'
llm:
  model_name: "gpt-4o"
  api_key: "sk-YOUR_API_KEY_HERE"
  api_base_url: ""
  fallback_model_name: "gpt-4o-mini"
  fallback_api_key: ""
  cloud_allowed: true
  timeout_seconds: 30

embedding:
  model_name: "text-embedding-3-small"
  api_key: "sk-YOUR_API_KEY_HERE"
  api_base_url: ""
  fallback_model_name: "text-embedding-3-small"
  fallback_api_key: ""
  cloud_allowed: true
  timeout_seconds: 30

database:
  url: "sqlite:////var/lib/pwnpilot/pwnpilot.db"
EOF

sudo chmod 640 /etc/pwnpilot/config.yaml
```

#### Anthropic Configuration

```bash
sudo tee /etc/pwnpilot/config.yaml > /dev/null << 'EOF'
llm:
  model_name: "claude-3-sonnet-20240229"
  api_key: "sk-ant-YOUR_API_KEY_HERE"
  api_base_url: ""
  fallback_model_name: "gpt-4o-mini"
  fallback_api_key: ""
  cloud_allowed: true
  timeout_seconds: 30

embedding:
  model_name: "text-embedding-3-small"
  api_key: "sk-YOUR_API_KEY_HERE"
  api_base_url: ""
  fallback_model_name: "text-embedding-3-small"
  fallback_api_key: ""
  cloud_allowed: true
  timeout_seconds: 30

database:
  url: "sqlite:////var/lib/pwnpilot/pwnpilot.db"
EOF

sudo chmod 640 /etc/pwnpilot/config.yaml
```

#### Local Ollama Configuration

```bash
sudo tee /etc/pwnpilot/config.yaml > /dev/null << 'EOF'
llm:
  model_name: "ollama/mistral"
  api_key: ""
  api_base_url: "http://localhost:11434"
  fallback_model_name: "gpt-4o-mini"
  fallback_api_key: ""
  cloud_allowed: false
  timeout_seconds: 30

embedding:
  model_name: "ollama/nomic-embed-text"
  api_key: ""
  api_base_url: "http://localhost:11434"
  fallback_model_name: "text-embedding-3-small"
  fallback_api_key: ""
  cloud_allowed: false
  timeout_seconds: 30

database:
  url: "sqlite:////var/lib/pwnpilot/pwnpilot.db"
EOF

sudo chmod 640 /etc/pwnpilot/config.yaml

# Start Ollama server
ollama serve &
```

### Service Management

```bash
# Enable auto-start
sudo systemctl enable pwnpilot

# Start service
sudo systemctl start pwnpilot

# Check status
sudo systemctl status pwnpilot

# View logs
sudo journalctl -u pwnpilot -f     # Follow logs
sudo journalctl -u pwnpilot -n 50  # Last 50 lines
```

### NVD API Key for CVE Enrichment

If `NVD_API_KEY` is not set, CVE enrichment still works but is rate-limited by the anonymous NVD quota and may run significantly slower.

```bash
# Recommended for production enrichment performance
echo 'NVD_API_KEY=<your-nvd-key>' | sudo tee -a /etc/pwnpilot/pwnpilot.env
sudo systemctl restart pwnpilot
```

Operational note: authenticated NVD usage typically allows a much higher request budget than anonymous usage.

### Tool Wordlist Overrides

`gobuster` wordlist path can be overridden in config:

```yaml
tools:
  gobuster:
    wordlist: "/usr/share/wordlists/dirb/common.txt"
```

Use a smaller list for faster scans or a larger list for deeper enumeration.

### Persistence Tables and Migrations

New persistence tables must be present in deployed environments:
- `rate_limit_records`
- `legal_holds`

Apply and verify migration state:

```bash
cd /opt/pwnpilot
alembic upgrade head
alembic current
alembic history
```

If these tables are missing, rate-limit restart durability and legal-hold persistence will not function.

For table-level schema details and migration rollback procedures, see [DB_OPERATIONS.md](DB_OPERATIONS.md).

### Legal Hold Operations in Production

Before scheduled retention cleanup windows:
1. Verify active holds.
2. Confirm expected protected engagements.
3. Proceed with retention job only after validation.

Example inspection query:

```bash
sqlite3 /var/lib/pwnpilot/pwnpilot.db \
  "SELECT engagement_id, holder, placed_at FROM legal_holds WHERE released_at IS NULL;"
```

For hold placement/release runbooks and compliance workflows, see [LEGAL_HOLDS.md](LEGAL_HOLDS.md).

---

## Monitoring & Troubleshooting

### Payload Telemetry Monitoring

Postmortem artifacts include payload telemetry to diagnose payload effectiveness and policy friction:
- `total_generations`
- `preflight_rejected`
- `tools_used`
- `techniques_attempted`
- `mutation_rounds`
- `semantic_outcomes`

Quick extraction:

```bash
jq '.payload_telemetry' reports/postmortem_<engagement-id>.json
```

Common interpretation:
- High `preflight_rejected`: ROE patterns may be too restrictive.
- High `mutation_rounds`: target defenses or payload strategy mismatch.
- Limited `tools_used`: planner routing or capability discovery gap.

For complete metric definitions and tuning strategies, see [PAYLOAD_TELEMETRY.md](PAYLOAD_TELEMETRY.md).

### Health Check Commands

```bash
# Quick health check
pwnpilot check

# Detailed diagnostics
sudo journalctl -u pwnpilot -n 100 --no-pager

# Check disk usage
du -sh /opt/pwnpilot /var/lib/pwnpilot /var/log/pwnpilot

# Check process
ps aux | grep pwnpilot

# Check ports (if service running)
sudo lsof -i :8000
sudo ss -tulpn | grep 8000
```

### Common Issues

#### Issue: Service Won't Start

```bash
# Check logs
sudo journalctl -u pwnpilot -n 50 --no-pager

# Check configuration
sudo cat /etc/pwnpilot/config.yaml

# Check permissions
ls -la /etc/pwnpilot /var/lib/pwnpilot

# Try manual start
/usr/local/bin/pwnpilot version
```

#### Issue: Database Connection Failed

```bash
# Check database
ls -la /var/lib/pwnpilot/

# Reinitialize database
cd /opt/pwnpilot
alembic upgrade head

# Verify
pwnpilot check
```

#### Issue: Rate Limits Not Surviving Restart

```bash
# Confirm migration level and table presence
alembic current
sqlite3 /var/lib/pwnpilot/pwnpilot.db \
  ".tables" | grep rate_limit_records
```

If missing, run `alembic upgrade head` and restart service.

For persistent rate-limit internals and cleanup semantics, see [DB_OPERATIONS.md](DB_OPERATIONS.md).

#### Issue: Evidence Expected but Missing from Reports

Zero-byte evidence artifacts are excluded from report aggregation by design. Check evidence metadata first:

```bash
sqlite3 /var/lib/pwnpilot/pwnpilot.db \
  "SELECT file_path, size_bytes FROM evidence_index WHERE engagement_id='<engagement-id>' ORDER BY timestamp DESC LIMIT 20;"
```

#### Issue: Permission Denied

```bash
# Fix permissions
sudo chown -R pwnpilot:pwnpilot /etc/pwnpilot
sudo chown -R pwnpilot:pwnpilot /var/lib/pwnpilot
sudo chown -R pwnpilot:pwnpilot /var/log/pwnpilot

# Set proper permissions
sudo chmod -R 750 /etc/pwnpilot
sudo chmod -R 750 /var/lib/pwnpilot
sudo chmod -R 750 /var/log/pwnpilot

# Verify
ls -ld /etc/pwnpilot /var/lib/pwnpilot
```

---

## Operational Procedures

### Creating Your First ROE

```bash
# Create ROE file
cat > /opt/my-pentest.yaml << 'EOF'
version: "1.0"
engagement_type: "external-pentest"
description: "External network security assessment with comprehensive vulnerability analysis and penetration testing across all accessible systems and services"
scope:
  cidrs: "192.168.1.0/24, 10.0.0.0/16"
  hosts: "example.com, api.example.com"
  ports: "22, 80, 443, 3306, 5432"
active_hours_utc: "09:00-17:00"
valid_hours: 24
max_iterations: 100
max_retries: 3
allowed_actions:
  - "network_scan"
  - "vulnerability_scan"
  - "protocol_analysis"
cloud_allowed: false
EOF

# Validate ROE
pwnpilot roe verify /opt/my-pentest.yaml

# View in system
pwnpilot roe list
```

### Approving Actions

```bash
# List pending approvals
pwnpilot roe list

# Approve action
pwnpilot approve <ticket-id>

# Deny action
pwnpilot deny <ticket-id>

# View audit trail
pwnpilot roe audit
```

### Generating Reports

```bash
# Generate report for completed engagement
pwnpilot report <engagement-id>

# Export audit data
pwnpilot roe export --output report.json

# View report
cat report.json
```

---

## Performance & Capacity

### Expected Performance

| Operation | Time |
|-----------|------|
| CLI startup | ~100 ms |
| ROE validation | <100 ms |
| Database query | <100 ms |
| Installation | ~132 seconds |

### Disk Usage

| Directory | Size |
|-----------|------|
| /opt/pwnpilot | ~100 MB |
| /etc/pwnpilot | ~1 MB |
| /var/lib/pwnpilot | Grows with engagements |
| /var/log/pwnpilot | ~1 MB per 1000 actions |

### Capacity Planning

- Single system: Supports ~1000 ROEs, ~10000 audit events
- Load testing: Handles ~100 concurrent approvals
- Database scaling: Consider PostgreSQL for >1M events

---

## Deployment Checklist

### Pre-Deployment
- [ ] System meets requirements
- [ ] Disk space verified (20GB+)
- [ ] Python 3.10+ available
- [ ] Internet connectivity confirmed
- [ ] Backup existing configs (if upgrading)
- [ ] Port 8000 available (if using service)

### During Deployment
- [ ] Installation command executed
- [ ] Monitor installation progress (6 phases)
- [ ] Watch verification checks (5 phases)
- [ ] No error messages shown
- [ ] "Installation complete" message displayed
- [ ] "All checks passed" confirmation shown

### Post-Deployment
- [ ] All 5 verification phases pass
- [ ] CLI commands work (version, --help, roe)
- [ ] System check passes (pwnpilot check)
- [ ] Directories all exist
- [ ] Configuration file present
- [ ] Documentation accessible
- [ ] Service enabled (if desired)

### Production Handoff
- [ ] LLM provider configured
- [ ] Test ROE validated
- [ ] Logging monitored
- [ ] Monitoring setup complete
- [ ] Backup procedures defined
- [ ] Escalation contacts documented
- [ ] Runbooks prepared

---

**Last Updated:** April 19, 2026  
**Version:** 1.1  
**Status:** Current with PwnPilot v0.1.0
