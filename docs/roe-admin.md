# PwnPilot ROE Administrator Guide

**Version**: 1.0  
**Last Updated**: April 12, 2026  
**Audience**: System administrators, DevOps engineers, security operations teams

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation & Setup](#installation--setup)
3. [Configuration](#configuration)
4. [Database Setup](#database-setup)
5. [Sudo Integration](#sudo-integration)
6. [CLI Commands Reference](#cli-commands-reference)
7. [Audit Log Management](#audit-log-management)
8. [Troubleshooting](#troubleshooting)
9. [Security Hardening](#security-hardening)

---

## Introduction

This guide covers the deployment, configuration, and operational management of PwnPilot's ROE (Rules of Engagement) system for system administrators and operations teams.

### Key Responsibilities

- **Installation**: Deploy PwnPilot with ROE support
- **Configuration**: Set up database, sudo integration, and operator profiles
- **Maintenance**: Monitor audit trails, manage ROE approvals, archive reports
- **Security**: Enforce password policies, manage sudo access, audit operator actions
- **Compliance**: Maintain immutable audit logs, generate compliance reports

---

## Installation & Setup

### Prerequisites

- Python 3.10+
- PostgreSQL 13+ (recommended for production) or SQLite (development)
- Linux/macOS (sudo PAM integration required)
- Git for version control

### Step 1: Install PwnPilot

```bash
# Clone repository
git clone https://github.com/your-org/pwnpilot.git
cd pwnpilot

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For development/testing

# Verify installation
pwnpilot version
```

### Step 2: Initialize Configuration

```bash
# Create config directory
mkdir -p ~/.pwnpilot

# Generate default config
pwnpilot config init

# Review and edit configuration
vim ~/.pwnpilot/config.yaml
```

### Step 3: Initialize Database

```bash
# Create database directory (for SQLite dev) or PostgreSQL database (production)
mkdir -p /var/lib/pwnpilot
chown pwnpilot:pwnpilot /var/lib/pwnpilot
chmod 700 /var/lib/pwnpilot

# Run database migrations
pwnpilot migrate

# Verify database
pwnpilot check  # Should show all checks passing
```

### Step 4: Create Operator Accounts

```bash
# Create operator account on system
sudo useradd -m -s /bin/bash -G pwnpilot operator1
sudo usermod -aG sudo operator1

# Set password policy
sudo passwd operator1
# Choose strong password (16+ chars, mix of upper/lower/number/special)
```

---

## Configuration

### config.yaml Structure

```yaml
# ~/.pwnpilot/config.yaml

app:
  name: "PwnPilot"
  version: "0.1.0"
  environment: "production"  # or "development"
  debug: false
  log_level: "INFO"

database:
  type: "postgresql"  # or "sqlite"
  # PostgreSQL
  host: "localhost"
  port: 5432
  name: "pwnpilot_prod"
  user: "pwnpilot_user"
  password: "${DB_PASSWORD}"  # Use environment variable
  # SQLite (dev)
  # path: "/var/lib/pwnpilot/db.sqlite"
  
  # Connection settings
  pool_size: 10
  max_overflow: 20
  connect_timeout: 5
  echo: false  # Set true for SQL debugging

auth:
  sudo_timeout_seconds: 15    # Sudo verification timeout
  session_timeout_seconds: 900 # 15 minutes session timeout
  max_failed_attempts: 5       # Lockout after attempts
  max_failed_window_seconds: 300

roe:
  validation_enabled: true
  confidence_threshold: 0.85  # Min confidence for AI extraction
  max_scope_cidrs: 10
  max_description_length: 5000
  allow_cloud_llm: false      # Restrict to local LLMs
  
audit:
  enabled: true
  log_path: "/var/log/pwnpilot/audit.log"
  retention_days: 1825        # ~5 years
  encryption_enabled: true    # Encrypt audit logs

llm:
  provider: "bedrock"         # bedrock, openai, huggingface
  model_id: "claude-3-haiku"
  temperature: 0.0            # Deterministic (0.0)
  max_tokens: 4096
  timeout_seconds: 30

logging:
  level: "INFO"
  format: "json"
  outputs:
    - type: "console"
    - type: "file"
      path: "/var/log/pwnpilot/app.log"
      max_size_mb: 100
      backup_count: 10
```

### Environment Variables

```bash
# Database credentials
export DB_USER="pwnpilot_user"
export DB_PASSWORD="strong_secure_password"
export DB_HOST="db.internal.company.com"

# AWS Bedrock (if using)
export AWS_REGION="us-east-1"
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."

# Logging
export LOG_LEVEL="DEBUG"
export LOG_PATH="/var/log/pwnpilot"
```

---

## Database Setup

### PostgreSQL (Production)

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE USER pwnpilot_user WITH PASSWORD 'strong_password';
CREATE DATABASE pwnpilot_prod OWNER pwnpilot_user;
GRANT ALL PRIVILEGES ON DATABASE pwnpilot_prod TO pwnpilot_user;
EOF

# Initialize schema
export PWNPILOT_DB_URL="postgresql://pwnpilot_user:password@localhost/pwnpilot_prod"
pwnpilot migrate upgrade head

# Verify
pwnpilot migrate current  # Should show latest migration revision
```

### SQLite (Development)

```bash
# SQLite database created automatically at config path
# Default: /var/lib/pwnpilot/db.sqlite

pwnpilot migrate upgrade head
```

### Database Backups

```bash
# PostgreSQL backup
pg_dump -U pwnpilot_user pwnpilot_prod | gzip > backup_$(date +%Y%m%d).sql.gz

# Schedule daily backups in crontab
0 2 * * * cd /backups && pg_dump -U pwnpilot_user pwnpilot_prod | gzip > backup_$(date +\%Y\%m\%d).sql.gz

# Keep 30 days of backups
find /backups -name "*.sql.gz" -mtime +30 -delete
```

### Database Verification

```bash
# Check connection
pwnpilot db-test

# List tables
pwnpilot db-tables

# Show schema version
pwnpilot migrate current
```

---

## Sudo Integration

PwnPilot uses sudo for operator authorization. This ensures engagement approvals require OS-level authentication.

### Setup Sudo Integration

#### 1. Configure Sudoers

```bash
# Edit sudoers to allow pwnpilot commands
sudo visudo << 'EOF'
# PwnPilot ROE approval requires sudo verification
Cmnd_Alias PWNPILOT_CMDS = /usr/bin/sudo -S -v
%pwnpilot_operators ALL=(ALL) NOPASSWD: PWNPILOT_CMDS
EOF
```

#### 2. Create Operator Group

```bash
# Create pwnpilot group
sudo groupadd pwnpilot

# Add users to group
sudo usermod -aG pwnpilot operator1
sudo usermod -aG pwnpilot operator2

# Verify group membership
id operator1  # Should show "groups=...pwnpilot..."
```

#### 3. Verify Sudo Access

```bash
# Test from operator account
su - operator1
sudo -S -v <<< "operator_password"
# Should return 0 (success)
echo $?
```

### Sudo Monitoring

```bash
# Monitor sudo usage in real-time
tail -f /var/log/auth.log | grep sudo

# Audit all sudo commands
sudo grep "pwnpilot\|COMMAND=" /var/log/auth.log | tail -100

# Generate daily sudo report
sudo cat /var/log/auth.log | grep COMMAND | mail -s "Daily Sudo Report" admin@company.com
```

### Troubleshooting Sudo

```bash
# Test sudo password verification (should prompt for password)
sudo -S -v
# Enter password when prompted

# Check if operator can use sudo without password prompt
sudo -n echo "works"
# Should fail: "sudo: a password is required"

# Verify PAM is configured correctly
sudo cat /etc/pam.d/sudo | grep -i "pam_"
```

---

## CLI Commands Reference

### ROE Management Commands

#### Verify ROE File

```bash
# Validate ROE against schema
pwnpilot roe verify path/to/roe.yaml

# Output:
# ✓ ROE file is valid: path/to/roe.yaml
#   Schema version: v1
#   Scope targets: 5
#   Allowed actions: 2
```

#### List Approved ROEs

```bash
# Show all approved ROE files
pwnpilot roe list

# Filter by engagement
pwnpilot roe list --engagement a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Include inactive ROEs
pwnpilot roe list --all

# Output:
# ┌─────────────────┬──────────────────────┬──────────────────┬──────────┬────────────────┐
# │ ROE ID          │ Filename             │ Uploaded By      │ Status   │ Uploaded At    │
# ├─────────────────┼──────────────────────┼──────────────────┼──────────┼────────────────┤
# │ roe-001         │ roe.prod-app.yaml    │ security@co.com  │ approved │ 2026-04-12 ... │
# └─────────────────┴──────────────────────┴──────────────────┴──────────┴────────────────┘
```

#### View Audit Trail

```bash
# Show approval and audit trail for engagement
pwnpilot roe audit a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Output:
# Audit Trail for Engagement: a1b2c3d4...
# ┌──────────────────┬──────────────┬──────────────────┬──────────────────────┐
# │ Timestamp        │ User         │ Event            │ Details              │
# ├──────────────────┼──────────────┼──────────────────┼──────────────────────┤
# │ 2026-04-12 10:00 │ operator@... │ ROE_APPROVED     │ Password verified    │
# │ 2026-04-12 09:55 │ operator@... │ ROE_INTERPRETED  │ Confidence: 0.92     │
# └──────────────────┴──────────────┴──────────────────┴──────────────────────┘
```

#### Export Audit Report

```bash
# Export audit report with ROE, approvals, timeline
pwnpilot roe export a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Custom output location
pwnpilot roe export a1b2c3d4-e5f6-7890-abcd-ef1234567890 --output /archives/roe-report.json

# Output: JSON file with complete audit chain
# {
#   "engagement_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
#   "exported_at": "2026-04-12T15:30:00Z",
#   "roe_file": "...",
#   "approvals": [...],
#   "audit_trail": [...]
# }
```

### Engagement Commands

```bash
# Start new engagement with ROE
pwnpilot start --name "Q2 Pentest" --roe-file roe.prod.yaml

# Dry-run (validate only)
pwnpilot start --name "Test" --roe-file roe.yaml --roe-dry-run

# Skip approval (admin override - use cautiously!)
pwnpilot start --name "Test" --roe-file roe.yaml --roe-skip-approval

# Resume from checkpoint
pwnpilot resume a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Approve high-risk action
pwnpilot approve abc-123-def-456 --reason "Approved by CISO"

# Deny high-risk action
pwnpilot deny abc-123-def-456 --reason "Scope violation"
```

---

## Audit Log Management

### Accessing Audit Logs

```bash
# View live audit logs
tail -f /var/log/pwnpilot/audit.log

# Search for specific user
grep "operator@company.com" /var/log/pwnpilot/audit.log

# Search for approval events
grep "ROE_APPROVED" /var/log/pwnpilot/audit.log

# Export to CSV for analysis
pwnpilot audit-export --format csv --output audit-report.csv
```

### Audit Log Immutability

Audit logs are cryptographically hashed to ensure immutability:

```bash
# Verify audit log integrity
pwnpilot audit-verify /var/log/pwnpilot/audit.log

# Output:
# ✓ Audit trail integrity verified
# ✓ 1,247 events with unbroken hash chain
# ✓ No tampering detected
```

### Retention Policy

```bash
# Archive old logs (5+ years)
find /var/log/pwnpilot -name "*.log" -mtime +1825 -exec gzip {} \;
move /var/log/pwnpilot/audit.log.*.gz /archive/pwnpilot/

# Delete after legal hold period
find /archive/pwnpilot -name "*.gz" -mtime +2555 -delete  # 7 years
```

---

## Troubleshooting

### Issue: "sudo: a password is required"

**Cause**: Operating out of scope for account

**Solution**:
```bash
# Check sudoers configuration
sudo visudo -c
# Output: "sudoers file syntax OK"

# Test sudo with password
sudo -S echo "success" <<< "password"
```

### Issue: Database Connection Error

**Cause**: PostgreSQL not running or connection invalid

**Solution**:
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Start PostgreSQL
sudo systemctl start postgresql

# Verify connection
psql -U pwnpilot_user -h localhost -d pwnpilot_prod -c "SELECT 1"

# Check config
pwnpilot db-test
```

### Issue: ROE Verification Fails

**Cause**: Schema validation error

**Solution**:
```bash
# Get detailed error message
pwnpilot roe verify roe.yaml

# Common issues:
# - Missing required fields (engagement.name)
# - Invalid email format
# - Description < 100 characters
# - Invalid CIDR notation
```

### Issue: Approval Timeout

**Cause**: Sudo password prompt timeout (15 seconds default)

**Solution**:
```bash
# Increase timeout in config.yaml
auth:
  sudo_timeout_seconds: 30  # was 15

# Restart application
systemctl restart pwnpilot
```

### Issue: Performance Degradation

**Cause**: Large audit logs causing slowdown

**Solution**:
```bash
# Archive and compress old audit logs
tar -czf audit-archive-2026-01.tar.gz /var/log/pwnpilot/audit.log.*
mv audit-archive-*.tar.gz /archive/pwnpilot/

# Create index on frequently queried fields
pwnpilot db-optimize
```

---

## Security Hardening

### 1. File Permissions

```bash
# Restrict config access
chmod 600 ~/.pwnpilot/config.yaml

# Restrict audit log access
chmod 600 /var/log/pwnpilot/audit.log

# Restrict database access
chmod 700 /var/lib/pwnpilot/

# Verify
ls -la ~/.pwnpilot/config.yaml  # Should show: -rw------- (600)
```

### 2. Database Security

```bash
# Use SSL for PostgreSQL connections
# In config.yaml:
database:
  sslmode: "require"
  sslcert: "/path/to/cert.pem"
  sslkey: "/path/to/key.pem"
  sslrootcert: "/path/to/ca.pem"

# Backup encryption
export BACKUP_ENCRYPTION_KEY="..."
pwnpilot backup --encrypt
```

### 3. Operator Access Control

```bash
# Grant least privilege
sudo usermod -G pwnpilot operator1  # Only pwnpilot group

# Remove sudo access if no longer needed
sudo usermod -G "" operator1

# Monitor sudo access
sudo lastlog -u operator1
```

### 4. Audit Log Protection

```bash
# Write audit logs to immutable storage
mount -o ro /mnt/audit-logs  # Read-only mount point

# Encrypt audit logs
gpg --symmetric audit.log
# Requires passphrase to read

# Set log rotation policy
mv /var/log/pwnpilot/audit.log audit-$(date +%Y%m%d).log
gzip audit-*.log
```

### 5. Network Security

```bash
# If using PostgreSQL remotely
# - Use VPN or encrypted tunnel
# - Restrict firewall to pwnpilot server only
# - Use SSL/TLS for connections

# Verify configuration
pwnpilot config validate
pwnpilot test-connectivity
```

### 6. Regular Security Updates

```bash
# Keep dependencies current
pip install --upgrade -r requirements.txt

# Check for vulnerabilities
pip install safety
safety check

# Regular patching schedule
# Week 1 of each month: Review patches
# Week 2: Test patches
# Week 3: Deploy patches
```

---

## Monitoring & Alerting

```bash
# Set up log monitoring
sudo apt-get install rsyslog logrotate

# Configure rsyslog for pwnpilot
cat > /etc/rsyslog.d/30-pwnpilot.conf << 'EOF'
:programname, isequal, "pwnpilot" /var/log/pwnpilot/syslog.log
& stop
EOF

sudo systemctl restart rsyslog

# Alert on approval failures
grep -i "failed\|denied\|error" /var/log/pwnpilot/audit.log | \
  tail -1 | mail -s "PwnPilot Alert" admin@company.com
```

---

## Maintenance Schedule

| Task | Frequency | Command |
|------|-----------|---------|
| Database backup | Daily | `pg_dump ... \| gzip` |
| Audit log review | Weekly | `grep "ROE\|ERROR" audit.log` |
| Dependency updates | Monthly | `pip check` |
| Security patches | Monthly | `safety check` |
| Integrity verification | Monthly | `pwnpilot audit-verify` |
| Compliance export | Quarterly | `pwnpilot roe-export-report` |
| Full archive | Yearly | Compress and store |

---

**Need Help?** Contact your security operations team or refer to [roe-compliance.md](roe-compliance.md) for compliance requirements.
