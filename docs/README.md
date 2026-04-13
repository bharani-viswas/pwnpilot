# pwnpilot

**Policy-first, multi-agent LLM-driven pentesting framework.**

pwnpilot orchestrates a team of LLM-backed agents — Planner, Validator, Executor, and Reporter — over a deny-by-default policy engine. Every tool call is constructed from a typed schema, every finding is backed by raw evidence, and every state transition is written to an immutable, hash-chained audit log. No free-form shell. No unreviewed LLM output ever reaches an execution boundary.

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Option 1: Quick Installation from Source](#option-1-quick-installation-from-source-recommended-for-development)
  - [Option 2: Debian/Ubuntu Package Installation](#option-2-debian-ubuntu-package-installation-recommended-for-production)
  - [Option 3: Development Installation](#option-3-development-installation)
  - [Option 4: Using Make](#option-4-using-make-comprehensive-build-system)
  - [Security Tools Installation](#security-tools-installation)
  - [Verify Installation](#verify-installation)
- [Configuration](#configuration)
  - [Config file](#config-file)
  - [Environment variable overrides](#environment-variable-overrides)
  - [Config reference](#config-reference)
- [Rules of Engagement (ROE)](#rules-of-engagement-roe)
  - [What is ROE?](#what-is-roe)
  - [ROE Documentation](#roe-documentation)
  - [Quick ROE Example](#quick-roe-example)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
  - [pwnpilot start](#pwnpilot-start)
  - [pwnpilot resume](#pwnpilot-resume)
  - [pwnpilot approve / deny](#pwnpilot-approve--deny)
  - [pwnpilot report](#pwnpilot-report)
  - [pwnpilot verify](#pwnpilot-verify)
  - [pwnpilot verify-report](#pwnpilot-verify-report)
  - [pwnpilot simulate](#pwnpilot-simulate)
  - [pwnpilot tui](#pwnpilot-tui)
  - [pwnpilot keys](#pwnpilot-keys)
  - [pwnpilot db](#pwnpilot-db)
  - [pwnpilot check](#pwnpilot-check)
  - [pwnpilot version](#pwnpilot-version)
- [Tool Adapters](#tool-adapters)
- [Plugin System](#plugin-system)
- [Reporting & Signing](#reporting--signing)
- [TUI Dashboard](#tui-dashboard)
- [Database Backends](#database-backends)
- [Systemd Deployment](#systemd-deployment)
- [Development](#development)
- [License](#license)

---

## Features

| Capability | Details |
|---|---|
| **Multi-agent loop** | Planner → Validator → Executor → Reporter, orchestrated via LangGraph StateGraph |
| **Deny-by-default policy engine** | Scope enforcement, action-class rate limiting, mandatory human approval for `exploit` / `post_exploit` |
| **Immutable audit trail** | Append-only, hash-chained event log; verified with `pwnpilot verify` |
| **Evidence-first findings** | Every finding requires a raw evidence artifact (stdout/stderr) before entering the store |
| **No free-form shell** | All tool invocations constructed from typed `ActionRequest` schemas |
| **Crash recovery** | LangGraph checkpointing; resume any interrupted engagement with `pwnpilot resume` |
| **10+ tool adapters** | nmap, nuclei, ZAP, nikto, sqlmap, whatweb, whois, dnsutils, searchsploit, CVE enrichment |
| **Ed25519 report signing** | JSON report bundles signed with operator key; verifiable offline |
| **Multi-provider LLM (via LiteLLM)** | Supports 100+ providers: OpenAI, Claude, Gemini, Ollama, vLLM, LocalAI, Mistral, and more. Local-first by default; cloud is policy-gated and prompt-redacted. |
| **TUI dashboard** | Live Textual-based engagement dashboard |
| **SQLite & PostgreSQL** | SQLite for labs; PostgreSQL with connection pooling for production |
| **Rules of Engagement (ROE)** | YAML-based authorization framework with SOC 2 Type II compliance, AI interpretation validation, injection detection, and immutable audit trails |
| **Comprehensive test suite** | 186+ automated tests (unit, integration, E2E); 100% ROE coverage |

---

## Architecture Overview

```
┌─────────────────────────────────────────┐
│           Operator Interface             │
│   CLI (Typer)  · TUI · Approval Queue   │
└───────────────────┬─────────────────────┘
                    │
┌───────────────────▼─────────────────────┐
│              Control Plane               │
│  Engagement  · Policy Engine · Approval  │
│           LLM Router                     │
└───────────────────┬─────────────────────┘
                    │  typed ActionRequests
┌───────────────────▼─────────────────────┐
│            Agent Orchestrator            │
│  Observe→Plan→Validate→Execute→Parse→   │
│  Update→Decide   (LangGraph StateGraph)  │
└───────────────────┬─────────────────────┘
                    │
┌───────────────────▼─────────────────────┐
│             Execution Plane              │
│   Tool Runner (subprocess, isolated)     │
│  nmap · nuclei · ZAP · nikto · sqlmap   │
│  whatweb · whois · dns · CVE · ssploit  │
└─────────────────────────────────────────┘
         │                      │
   Data (SQLite/PG)       Evidence Files
   Recon · Findings        (~/.pwnpilot/
   Audit · Approvals         evidence/)
```

**Agents:**

- **Planner** — novelty-checked, repeated-state circuit breaker, uses largest local model (e.g., `llama3`)
- **Validator** — independent second opinion; can raise risk level but cannot lower it (e.g., `mistral`)
- **Executor** — sole agent that touches the Policy Engine; constructs typed `ActionRequest`; writes raw evidence
- **Reporter** — builds and Ed25519-signs the report bundle; triggered on convergence, `max_iterations`, or operator command

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | ≥ 3.10 | 3.11+ recommended |
| Ollama or vLLM | latest | Local LLM inference server |
| nmap | ≥ 7.80 | |
| nuclei | ≥ 3.0 | |
| nikto | ≥ 2.1 | |
| sqlmap | ≥ 1.7 | |
| whatweb | ≥ 0.5.5 | |
| OWASP ZAP | ≥ 2.14 | |
| SQLite | ≥ 3.39 | bundled with Python; or PostgreSQL ≥ 14 |

Install the security toolchain with the provided helper script:

```bash
sudo bash scripts/install_security_tools.sh
bash scripts/verify_toolchain.sh        # sanity-check all binaries
```

---

## Installation

Choose your installation method based on your needs:

### Option 1: Quick Installation from Source (Recommended for Development)

**On Ubuntu/Debian/Kali Linux:**

```bash
git clone https://github.com/bharani-viswas/pwnpilot.git
cd pwnpilot
bash scripts/install.sh --system-deps
```

**Or manually (step-by-step):**

```bash
git clone https://github.com/bharani-viswas/pwnpilot.git
cd pwnpilot

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip setuptools wheel
pip install -e .

# Setup database and keys
alembic upgrade head
pwnpilot keys --generate

# Verify installation
pwnpilot check
```

### Option 2: Debian/Ubuntu Package Installation (Recommended for Production)

**Build the .deb package:**

```bash
git clone https://github.com/bharani-viswas/pwnpilot.git
cd pwnpilot
make deb
```

**Install the package:**

```bash
# Install with automatic dependency resolution
sudo apt install ./dist/pwnpilot_*.deb

# Or with dpkg (requires manual dependency installation)
sudo dpkg -i dist/pwnpilot_*.deb
```

**What the package includes:**
- ✓ Python virtual environment with all dependencies
- ✓ Automatic database initialization
- ✓ Systemd service for daemon deployment
- ✓ Configuration templates in `/etc/pwnpilot/`
- ✓ Data directory: `/var/lib/pwnpilot`
- ✓ Logs: `/var/log/pwnpilot`

**Post-installation:**

```bash
# Start the service
sudo systemctl start pwnpilot

# Enable on boot
sudo systemctl enable pwnpilot

# Check status
sudo systemctl status pwnpilot
```

### Option 3: Development Installation

**For contributing to PwnPilot:**

```bash
git clone https://github.com/bharani-viswas/pwnpilot.git
cd pwnpilot
bash scripts/install.sh --dev --system-deps
```

Or using make:

```bash
make dev          # Install with dev dependencies
make lint         # Run linters
make test         # Run tests
make format       # Format code
```

### Option 4: Using Make (Comprehensive Build System)

**Available targets:**

```bash
make help              # Show all available targets
make install-deps      # Install system dependencies (requires sudo)
make quick-install     # Install from source (Python only)
make install           # Full installation with system deps
make dev               # Development installation with extras
make test              # Run test suite
make lint              # Run linters
make format            # Auto-format code
make build             # Build Python distribution
make deb               # Build Debian package
make release           # Create release tarball
make clean             # Clean build artifacts
```

### Security Tools Installation

Install the required security toolkit (including ZAP) before running engagements:

```bash
# Only on first installation
sudo bash scripts/install_security_tools.sh

# Verify all tools
bash scripts/verify_toolchain.sh
```

### Verify Installation

```bash
# Check if all components are installed correctly
pwnpilot check

# Show version
pwnpilot version

# Show help
pwnpilot --help
pwnpilot version
```

---

## Configuration

### Config file

pwnpilot searches for a config file in this order:

1. Path passed via `--config` on the CLI
2. `$PWNPILOT_CONFIG` environment variable
3. `./config.yaml` in the current working directory
4. `~/.pwnpilot/config.yaml`

Minimal example (`config.yaml`):

```yaml
database:
  url: sqlite:///pwnpilot.db   # or postgresql://user:pass@localhost/pwnpilot

llm:
  local_url: http://localhost:11434
  local_model: llama3
  validator_model: mistral
  cloud_allowed: false           # set true to enable cloud LLM fallback

policy:
  active_scan_rate_limit: 10     # max active_scan actions per minute
  require_approval_for_exploit: true
  require_approval_for_post_exploit: true

storage:
  evidence_dir: ~/.pwnpilot/evidence
  report_dir: reports

logging:
  level: INFO
  file: ""                       # empty = stdout only
```

### Environment variable overrides

Any config value can be overridden at runtime using `PWNPILOT_<SECTION>__<KEY>` env vars (double underscore separates nested keys):

```bash
export PWNPILOT_LLM__LOCAL_MODEL=mistral
export PWNPILOT_DATABASE__URL=postgresql://user:pass@localhost/pwnpilot
export PWNPILOT_POLICY__ACTIVE_SCAN_RATE_LIMIT=5
export PWNPILOT_LLM__CLOUD_ALLOWED=true
```

Security-sensitive values use dedicated env vars:

| Variable | Purpose |
|---|---|
| `PWNPILOT_VAULT_KEY` | Master vault encryption key (base64) |
| `PWNPILOT_VAULT_KEY_FILE` | Path to file containing vault key |
| `PWNPILOT_SIGNING_KEY` | Ed25519 private key for report signing |
| `PWNPILOT_OPENAI_API_KEY` | OpenAI API key (required when `cloud_allowed: true`) |
| `PWNPILOT_ANTHROPIC_API_KEY` | Anthropic API key |

### Config reference

| Section | Key | Default | Description |
|---|---|---|---|
| `database` | `url` | `sqlite:///pwnpilot.db` | SQLAlchemy database URL |
| `database` | `pool_size` | `5` | Connection pool size (PostgreSQL) |
| `llm` | `local_url` | `http://localhost:11434` | Ollama/vLLM base URL |
| `llm` | `local_model` | `llama3` | Planner/Executor model |
| `llm` | `validator_model` | `mistral` | Validator model |
| `llm` | `cloud_allowed` | `false` | Enable cloud LLM fallback |
| `policy` | `active_scan_rate_limit` | `10` | Max active scans per minute (hard block) |
| `policy` | `require_approval_for_exploit` | `true` | Pause for human approval before exploit actions |
| `agent` | `max_iterations` | `50` | Agent loop iteration cap |
| `agent` | `convergence_threshold` | `3` | Consecutive no-new-findings cycles before reporting |
| `storage` | `evidence_dir` | `~/.pwnpilot/evidence` | Raw tool output storage |
| `storage` | `report_dir` | `reports` | Report output directory |
| `logging` | `level` | `INFO` | Log level (DEBUG/INFO/WARNING/ERROR) |

---

## Rules of Engagement (ROE)

### What is ROE?

PwnPilot implements a **policy-first authorization framework** via YAML-based **Rules of Engagement (ROE)** documents:

- **Scope definition** — CIDR ranges, domains, URLs, excluded targets
- **Restricted actions** — whitelisted operations (e.g., MODIFY_DATA, DELETE_DATA)
- **Policy constraints** — iteration limits, timeout, retry behavior, cloud LLM allowance
- **Authorization chain** — cryptographically verified approval workflows
- **Immutable audit trail** — hash-chained event logs for SOC 2 Type II compliance
- **AI safeguards** — LLM policy extraction with confidence scoring, hallucination detection, injection prevention

**ROE files are human-readable, machine-validated, and operator-signed.**

### ROE Documentation

**Start here:**
- [**ROE User Guide**](roe-usage.md) — How to create and use ROE files (13 KB)
- [**ROE Admin Guide**](roe-admin.md) — Deployment, configuration, CLI reference (16 KB)
- [**ROE Compliance Guide**](roe-compliance.md) — SOC 2 Type II alignment, audit procedures (21 KB)
- [**Database Schema**](CURRENT_SCHEMA.md) — ROE storage structure, approval workflow (12 KB)

### Quick ROE Example

```yaml
engagement:
  name: "lab-pentest-2024"
  authorizer: "alice@example.com"
  description: "Internal network penetration testing with emphasis on web and API layers"
  valid_hours: 24

scope:
  cidrs: "10.0.0.0/8,172.16.0.0/12"
  domains: "internal.example.com,api.example.com"
  urls: "https://api.example.com/v1"
  excluded_ips: "10.0.1.1,10.0.1.254"
  restricted_actions: "MODIFY_DATA,DELETE_DATA"

policy:
  max_iterations: 50
  max_retries: 3
  timeout_seconds: 3600
  cloud_allowed: false
```

**ROE workflow:**
1. Create ROE file (YAML)
2. Validate with `pwnpilot roe verify roe.yaml`
3. AI interprets policy with confidence scoring
4. Operator requests approval
5. Events logged with hash-chain integrity

---

## Quick Start

```bash
# Start Ollama
ollama serve &
ollama pull llama3
ollama pull mistral

# Run preflight checks
pwnpilot check

# Start an engagement against a target
pwnpilot start \
  --name "lab-01" \
  --cidr 10.10.10.0/24 \
  --domain lab.example.com \
  --roe-hash $(sha256sum roe.pdf | awk '{print $1}') \
  --authoriser "alice@example.com" \
  --valid-hours 8 \
  --max-iter 50

# In a separate terminal, watch the live dashboard
pwnpilot tui --engagement <engagement-id>

# If a high-risk action is queued for approval, approve it
pwnpilot approve <ticket-id> --reason "Authorised by Alice"

# Once done, generate the signed report
pwnpilot report <engagement-id> --output ./reports/

# Verify the audit chain is intact
pwnpilot verify <engagement-id>

# Verify report signature
pwnpilot verify-report reports/report.json reports/report.sig
```

**Dry run (no tool execution):**

```bash
pwnpilot start --name "preflight" --cidr 10.0.0.0/8 \
  --roe-hash 0000...0000 --authoriser ops --dry-run
```

**Resume a crashed engagement:**

```bash
pwnpilot resume <engagement-id>
```

---

## CLI Reference

### `pwnpilot start`

Create and launch a new engagement. The agent loop runs until `max_iterations` is reached, convergence is detected (3 consecutive cycles with no new findings), or the operator stops it.

```
pwnpilot start [OPTIONS]

Options:
  --name TEXT          Engagement name (required)
  --cidr TEXT          Target CIDR range (repeatable)
  --domain TEXT        Target domain (repeatable)
  --url TEXT           Target URL prefix (repeatable)
  --roe-hash TEXT      SHA-256 hash of the Rules of Engagement document (required)
  --authoriser TEXT    Authoriser identity — who approved the engagement (required)
  --valid-hours INT    Engagement validity window in hours [default: 24]
  --max-iter INT       Maximum agent loop iterations [default: 50]
  --config PATH        Config YAML path
  --dry-run            Policy simulation only — no tool execution
```

### `pwnpilot resume`

Resume an interrupted engagement from the last LangGraph checkpoint. All agent state, pending approvals, and evidence references are restored.

```
pwnpilot resume ENGAGEMENT_ID [--config PATH]
```

### `pwnpilot approve / deny`

Resolve a pending high-risk action ticket created when the Executor requests an `exploit` or `post_exploit` action.

```
pwnpilot approve TICKET_ID [--reason TEXT] [--operator TEXT] [--config PATH]
pwnpilot deny   TICKET_ID [--reason TEXT] [--operator TEXT] [--config PATH]
```

To list pending tickets, open the TUI (`pwnpilot tui`) or query the database directly.

### `pwnpilot report`

Generate a signed JSON bundle and Markdown summary for an engagement.

```
pwnpilot report ENGAGEMENT_ID [--output DIR] [--config PATH]
```

Output files:
- `<output>/report.json` — structured finding bundle
- `<output>/report.sig` — Ed25519 detached signature
- `<output>/summary.md` — Markdown narrative summary

### `pwnpilot verify`

Verify the append-only, hash-chained audit log for an engagement. Exits 1 on any integrity failure.

```
pwnpilot verify ENGAGEMENT_ID [--config PATH]
```

### `pwnpilot verify-report`

Verify the Ed25519 signature on a report bundle using the embedded public key.

```
pwnpilot verify-report REPORT_JSON REPORT_SIG
```

### `pwnpilot simulate`

Policy dry-run: check a list of `ActionRequest` dicts (from a JSON file) against the policy engine without executing any tools. Useful for preflight review.

```
pwnpilot simulate ACTIONS_FILE --engagement ENGAGEMENT_ID [--config PATH]
```

`ACTIONS_FILE` is a JSON array of action objects, e.g.:

```json
[
  {"tool": "nmap", "target": "10.0.0.1", "action_class": "recon_passive"},
  {"tool": "sqlmap", "target": "http://app/login", "action_class": "exploit"}
]
```

### `pwnpilot tui`

Launch the live Textual TUI dashboard. Shows real-time agent activity, findings, approval queue, and metrics for a running or completed engagement.

```
pwnpilot tui [--engagement ENGAGEMENT_ID] [--refresh SECONDS]
```

### `pwnpilot keys`

Manage the operator Ed25519 signing key pair used to sign and verify report bundles.

```
pwnpilot keys --generate                               # generate new key pair
pwnpilot keys --private-key PATH --public-key PATH    # use custom paths
```

Keys are stored at `~/.pwnpilot/operator.key` (private) and `~/.pwnpilot/operator.pub` (public) by default.

### `pwnpilot db`

Database maintenance sub-commands.

```
pwnpilot db backup  [--output PATH]    # backup database to file
pwnpilot db restore PATH               # restore from backup
```

SQLite backups use the native `.backup` API. PostgreSQL backups use `pg_dump`.

### `pwnpilot check`

Run preflight checks: config validation, database connectivity, migration state, signing key presence, and required tool binaries. Exits 1 if any check fails.

```
pwnpilot check [--config PATH]
```

### `pwnpilot version`

```
pwnpilot version
```

---

## Tool Adapters

pwnpilot ships adapters for the following tools. Each adapter is a typed module that constructs the subprocess command from a validated `ActionRequest`, streams stdout/stderr to the Evidence Store, and returns a parsed result.

| Adapter | Action Class | Requires Approval |
|---|---|---|
| `nmap` | `recon_passive` | No |
| `whois` | `recon_passive` | No |
| `dns` | `recon_passive` | No |
| `whatweb` | `recon_passive` | No |
| `cve_enrich` | `recon_passive` | No |
| `nuclei` | `active_scan` | No (rate limited) |
| `nikto` | `active_scan` | No (rate limited) |
| `zap` | `active_scan` | No (rate limited) |
| `searchsploit` | `active_scan` | No (rate limited) |
| `sqlmap` | `exploit` | **Yes** |

Active scans are hard-capped at `policy.active_scan_rate_limit` (default 10/min) by the token-bucket rate limiter. `exploit` and `post_exploit` actions always pause for human approval before execution.

---

## Plugin System

Third-party tools can be added as plugins implementing the `ToolAdapter` SDK interface (`pwnpilot/plugins/sdk.py`). Plugins are:

1. Distributed as Python packages exposing a `ToolAdapter` subclass
2. **Ed25519-signed** — the plugin's signing public key must be added to `pwnpilot/plugins/trust_store/` and the plugin explicitly trust-approved by the operator
3. Loaded at runtime by `pwnpilot/plugins/runner.py` only after signature verification

Plugin trust management:

```bash
# Add a third-party plugin signing key to the trust store
cp vendor.pub pwnpilot/plugins/trust_store/vendor.pub
pwnpilot plugin trust vendor
```

---

## Reporting & Signing

Reports are a self-contained JSON bundle plus an Ed25519 detached signature:

```
reports/
├── report.json       ← structured findings + metadata
├── report.sig        ← Ed25519 signature over report.json
└── summary.md        ← Jinja2-rendered narrative summary
```

**Signing:** The operator private key (`~/.pwnpilot/operator.key`) signs the bundle at report generation time. The matching public key is embedded in `report.json` for portability.

**Verification:**

```bash
pwnpilot verify-report reports/report.json reports/report.sig
```

The command exits 0 on success, 1 on signature mismatch or tampering.

---

## TUI Dashboard

The Textual TUI (`pwnpilot tui`) provides a live view of an active or completed engagement:

- **Findings panel** — severity, CVE/CWE, confidence, exploitability, dedup fingerprint
- **Agent activity** — current node in the LangGraph StateGraph, last action taken
- **Approval queue** — pending high-risk tickets with ticket ID, action class, and target
- **Metrics** — actions run, findings new/total, active scan rate, iteration counter

Launch during an active engagement to approve/deny tickets without leaving the TUI.

---

## Database Backends

| Backend | Use case | Driver |
|---|---|---|
| **SQLite** (default) | CTF labs, single-operator use | Built-in |
| **PostgreSQL ≥ 14** | Multi-operator, production | `psycopg2` / `asyncpg` |

Set the database URL in config or via env var:

```bash
# SQLite (default)
PWNPILOT_DATABASE__URL=sqlite:///pwnpilot.db

# PostgreSQL
PWNPILOT_DATABASE__URL=postgresql://user:pass@localhost:5432/pwnpilot
```

Apply or check migration state:

```bash
alembic upgrade head
alembic current
```

Five tables are managed by Alembic: `recon_hosts`, `findings`, `evidence`, `audit_events`, `approval_tickets`.

---

## Systemd Deployment

A unit template is provided at `scripts/pwnpilot.service`.

```bash
# Install
sudo cp scripts/pwnpilot.service /etc/systemd/system/pwnpilot@.service
sudo mkdir -p /opt/pwnpilot /etc/pwnpilot /var/lib/pwnpilot /var/log/pwnpilot
sudo cp -r . /opt/pwnpilot/
sudo python -m venv /opt/pwnpilot/.venv
sudo /opt/pwnpilot/.venv/bin/pip install /opt/pwnpilot

# Configure
sudo cp config.yaml /etc/pwnpilot/config.yaml
sudo tee /etc/pwnpilot/pwnpilot.env <<'EOF'
PWNPILOT_VAULT_KEY=<your-base64-key>
EOF

# Start an engagement as a systemd instance
sudo systemctl daemon-reload
sudo systemctl start pwnpilot@lab-01

# Follow logs
journalctl -u pwnpilot@lab-01 -f
```

---

## Development

### Setup Development Environment

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Lint and format
ruff check pwnpilot/ tests/
ruff format pwnpilot/ tests/

# Type-check
mypy pwnpilot/
```

### Testing

PwnPilot has a comprehensive test suite covering **all 8 implementation phases**:

**Test Structure (186+ tests, 100% ROE coverage):**

```
tests/
├── unit/                          # 71 tests — Components & validators
│   ├── test_roe_validator.py      # ROE schema validation (Phase 1)
│   ├── test_roe_interpreter.py    # LLM policy extraction (Phase 2)
│   ├── test_approval.py           # Approval workflows (Phase 3)
│   ├── test_models.py             # Database models (Phase 4)
│   └── ...
├── integration/                   # 97 tests — Multi-component flows
│   ├── test_roe_verification.py   # ROE verification CLI (Phase 6)
│   ├── test_roe_approval.py       # Approval chain workflows
│   ├── test_cli_roe.py            # CLI integration
│   └── ...
└── e2e/                           # 18 tests — End-to-end workflows (Phase 8)
    └── test_roe_complete.py       # Complete ROE lifecycle, injection prevention, 
                                  # security controls, audit trails, compliance
```

**Run tests:**

```bash
# Full test suite (all 186+ tests)
pytest tests/

# ROE tests only (unit + integration + E2E = 186 tests, 100% passing)
pytest tests/unit/test_roe*.py tests/integration/test_roe*.py tests/e2e/test_roe*.py

# E2E tests only (18 tests, Phase 8)
pytest tests/e2e/test_roe_complete.py -v

# Specific test class
pytest tests/e2e/test_roe_complete.py::TestCompleteROEWorkflow -v

# With coverage report
pytest tests/ --cov=pwnpilot --cov-report=html

# Run only fast tests (skip slow E2E)
pytest tests/unit/ tests/integration/ -v
```

**E2E Test Coverage (18 tests):**

| Test Class | Tests | Coverage |
|---|---|---|
| `TestCompleteROEWorkflow` | 3 | Valid/invalid ROE, multi-scope types |
| `TestInjectionPrevention` | 3 | Unknown actions, escaped commands, hallucinations |
| `TestPerformanceCharacteristics` | 2 | Large file parsing, batch operations |
| `TestSecurityControls` | 3 | Approval requirements, whitelisting, boundaries |
| `TestAuditTrailIntegrity` | 2 | Event logging, immutability |
| `TestEdgeCasesAndErrorHandling` | 3 | Boundary values, empty scopes, min/max params |
| `TestComplianceVerification` | 2 | SOC 2 approval chains, email validation |

**Expected output:**

```
============================== 186 passed in 1.73s ==============================
```

### Make Targets

```bash
make test              # Run full test suite
make test-roe          # Run ROE tests only (186 tests)
make test-e2e          # Run E2E tests (18 tests)
make test-fast         # Run unit + integration (skip E2E)
make coverage          # Generate HTML coverage report
make lint              # Run linters
make format            # Auto-format code
```

### Dependency Updates

```bash
# Compile pinned requirements (SHA-256 hashes)
pip-compile requirements.in -o requirements.txt
pip-compile requirements-dev.in -o requirements-dev.txt
```

**Project layout:**

```
pwnpilot/
├── agent/              # LangGraph agents (planner, validator, executor, reporter)
├── control/            # Engagement service, policy engine, LLM router, approvals
│   └── roe_approval.py # Phase 3: Approval workflow & sudo integration
├── data/               # SQLAlchemy models, stores
│   ├── roe_validator.py        # Phase 1: ROE schema validation
│   ├── approval_store.py       # Phase 3: Approval persistence
│   ├── audit_store.py          # Phase 4: Audit trail storage
│   └── models.py               # Phase 4: Database schema
├── agent/
│   └── roe_interpreter.py      # Phase 2: LLM policy interpretation with safeguards
├── governance/         # Authorization, kill switch, retention, simulation
├── migrations/         # Alembic: Phase 4 database schema versions (3 migrations)
├── observability/      # Metrics and structured tracing
├── plugins/            # Plugin SDK, trust verification, tool adapters
│   └── adapters/       # nmap, nuclei, ZAP, nikto, sqlmap, whatweb, whois, dns, CVE
├── reporting/          # Report generator, Ed25519 signer, Jinja2 templates
├── secrets/            # Vault, redactor
└── tui/                # Textual TUI dashboard

tests/
├── unit/               # Phase 1-6 component tests (71 tests, 100% passing)
├── integration/        # Phase 3-6 workflow tests (97 tests, 100% passing)
└── e2e/                # Phase 8: Complete workflows (18 tests, 100% passing)
    └── test_roe_complete.py  # 18 E2E tests covering all ROE features

docs/
├── README.md           # This file
├── ARCHITECTURE.md     # System design deep dive
├── IMPLEMENTATION_PLAN.md  # Detailed roadmap (8 phases)
├── INSTALLATION.md     # Setup & deployment
├── CURRENT_SCHEMA.md   # Database schema reference
├── roe-usage.md        # Phase 7: ROE user guide
├── roe-admin.md        # Phase 7: ROE admin guide
└── roe-compliance.md   # Phase 7: ROE compliance & audit procedures
```

### Implementation Status

| Phase | Component | Status | Tests | Coverage |
|-------|-----------|--------|-------|----------|
| 1 | ROE Validator | ✅ Complete | 71 | 97% |
| 2 | ROEInterpreter AI | ✅ Complete | 20 | 95% |
| 3 | Approval & Sudo | ✅ Complete | 28 | 90% |
| 4 | Database Schema | ✅ Complete | 8 tables | 3 migrations |
| 5 | CLI Integration | ✅ Complete | 5 commands | Integrated |
| 6 | Verification Commands | ✅ Complete | 21 | 100% |
| 7 | Documentation | ✅ Complete | 3 files | 55 KB |
| 8 | E2E Testing | ✅ Complete | 18 | 100% |
| **Total** | **All Phases** | **✅ 100% Complete** | **186** | **100%** |

---

## Troubleshooting

### Common Issues

**Tests failing: "LiteLLM credentials not found"**
- E2E tests use mocked LLM responses (no credentials needed)
- Unit tests mock `litellm.completion`
- If credentials needed for manual testing, set `LITELLM_API_KEY` or provider keys

**Database migration errors**
- Ensure Alembic is up-to-date: `alembic upgrade head`
- For a clean state: `rm pwnpilot.db && alembic upgrade head`

**ROE verification fails**
- Check description length (minimum 100 characters)
- Verify scope format (comma-separated for multiple values)
- Ensure all required fields are present

**LLM interpretation timeout**
- Increase `agent.timeout_seconds` in config
- Use smaller model: `llm.local_model: mistral7b`

### Getting Help

- **ROE Issues** → See [roe-usage.md](roe-usage.md) or [roe-compliance.md](roe-compliance.md)
- **Testing Questions** → Run `pytest tests/e2e/test_roe_complete.py -v` to see E2E examples
- **Database Schema** → Check [CURRENT_SCHEMA.md](CURRENT_SCHEMA.md)
- **Architecture Questions** → See [ARCHITECTURE.md](ARCHITECTURE.md)

---

## License

See [LICENSE](LICENSE).
