# PwnPilot Testing Guide - Demo Workflow

## Quick Start: Test Against Vulnerable Application

### Prerequisites
```bash
# Activate PwnPilot environment
source .pwnpilot-activate.sh

# Verify tools are installed
pwnpilot check
```

### Step 1: Create Rules of Engagement (ROE)

```bash
# Create ROE document
cat > roe.md << 'EOF'
# Rules of Engagement

## Scope
- Target: http://target.com
- Type: Web Application Security Assessment

## Authorized Activities
- Vulnerability scanning
- Penetration testing
- Exploitation (with approval)

## Restrictions
- No DoS attacks
- No permanent data destruction
- Authorization required for exploitation
EOF

# Generate SHA-256 hash
ROE_HASH=$(sha256sum roe.md | cut -d' ' -f1)
echo "ROE Hash: $ROE_HASH"
```

### Step 2: Configure PwnPilot

```bash
cat > config.yaml << 'EOF'
database:
  url: sqlite:////tmp/pwnpilot.db

llm:
  local_url: http://localhost:11434
  local_model: llama2
  cloud_allowed: false

policy:
  active_scan_rate_limit: 10
  require_approval_for_exploit: true

checkpoint:
  enabled: true
  dir: /tmp/pwnpilot_checkpoints

audit:
  enabled: true
  dir: /tmp/pwnpilot_audit
EOF
```

### Step 3: Start Engagement (Dry-Run First)

```bash
# Test with dry-run (policy simulation only)
pwnpilot start \
  --name "Test-Assessment" \
  --url "http://localhost:3000" \
  --roe-hash "$ROE_HASH" \
  --authoriser "SecurityTeam" \
  --config config.yaml \
  --dry-run \
  --max-iter 5
```

### Step 4: Generate Report

```bash
# Note the engagement ID from the output
ENGAGEMENT_ID="<from-output>"

# Generate report
pwnpilot report $ENGAGEMENT_ID -o ./results

# View report
cat results/report_${ENGAGEMENT_ID}.md
```

---

## Demo Test Performed

### Target: OWASP Juice Shop
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```

### Tools Executed

1. **Nmap** - Port Scanning
```bash
nmap -p 3000 localhost
# Result: Port 3000 open (service running)
```

2. **Nikto** - Web Server Scanning
```bash
nikto -h http://localhost:3000 -output nikto_report.txt
# Results:
# - ETag information disclosure
# - CORS misconfiguration (*)
# - Dangerous HTTP methods (PUT, PATCH, DELETE)
# - Exposed directories (/ftp/, /public/)
```

3. **WhatWeb** - Technology Fingerprinting
```bash
whatweb -v http://localhost:3000
# Results:
# - HTML5 application
# - Multiple security headers identified
# - CORS vulnerability highlighted
```

4. **SQLMap** - SQL Injection Testing
```bash
sqlmap -u "http://localhost:3000/api/users" --batch --risk=1
# Note: API requires authentication
```

---

## Running Real Engagements

### With Ollama (Local LLM)

```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve

# In another terminal, pull a model
ollama pull llama2

# Run engagement
pwnpilot start \
  --name "Full-Assessment" \
  --url "http://target.com" \
  --roe-hash "$ROE_HASH" \
  --authoriser "Team" \
  --config config.yaml \
  --max-iter 20
```

### With Cloud LLM (OpenAI)

```bash
# Set API key
export OPENAI_API_KEY="sk-..."

# Update config.yaml
cat > config.yaml << 'EOF'
llm:
  cloud_provider: openai
  cloud_model: gpt-4o-mini
  cloud_allowed: true
EOF

# Run with cloud fallback
pwnpilot start \
  --name "Cloud-Assessment" \
  --url "http://target.com" \
  --roe-hash "$ROE_HASH" \
  --authoriser "Team" \
  --config config.yaml
```

---

## Monitoring Engagement

### Check Engagement Status
```bash
# List engagements
pwnpilot db list-engagements

# View engagement details
pwnpilot db show-engagement $ENGAGEMENT_ID
```

### View Audit Trail
```bash
ls -lah /tmp/pwnpilot_audit/
```

### Resume Interrupted Engagement
```bash
pwnpilot resume --engagement $ENGAGEMENT_ID
```

---

## Handling Approvals

### View Pending Approvals
```bash
pwnpilot db list-approvals
```

### Approve High-Risk Action
```bash
pwnpilot approve <action-id> --reason "Proceed with exploitation"
```

### Deny Action
```bash
pwnpilot deny <action-id> --reason "Risk too high"
```

---

## Useful Environment Variables

```bash
# Override config location
export PWNPILOT_CONFIG="/path/to/config.yaml"

# Override database
export PWNPILOT_DATABASE__URL="postgresql://user:pass@localhost/pwnpilot"

# Override LLM settings
export PWNPILOT_LLM__LOCAL_MODEL="mistral"
export PWNPILOT_LLM__LOCAL_URL="http://ollama:11434"
```

---

## Troubleshooting

### LLM Connection Failed
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Try dry-run mode instead
pwnpilot start ... --dry-run
```

### Tools Not Found
```bash
# Verify toolchain
bash scripts/verify_toolchain.sh

# Install missing tools
sudo bash scripts/install_security_tools.sh
```

### Database Errors
```bash
# Reset database
rm ~/.pwnpilot/pwnpilot.db
alembic upgrade head
```

---

## Next Steps

1. **Set up local LLM**: Install Ollama and download a model
2. **Create ROE document**: Define scope and authorization
3. **Run dry-run**: Test policy simulation first
4. **Run real engagement**: Execute full security assessment
5. **Review results**: Analyze findings and recommendations

For more details, see README.md and ARCHITECTURE.md
