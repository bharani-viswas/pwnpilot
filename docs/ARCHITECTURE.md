# Architecture Plan: LLM-Driven Pentesting Framework

## 1. Overview

This document defines the complete architecture of the **pwnpilot** framework. It is derived from the Implementation Plan and governs every structural decision made during implementation.

The system is a single-machine, policy-first, **multi-agent** pentesting tool. The operator controls all high-risk decisions. A coordinated team of LLM-backed agents plans, validates, executes, and reports; the safety core governs every inter-agent and agent-to-tool boundary.

The multi-agent layer is built on **LangGraph** — a stateful, graph-based agent orchestration library that models the agent loop as an explicit directed graph with typed edges. LangGraph was chosen over alternatives (AutoGen, CrewAI) because its explicit state machine maps directly onto the existing `Observe→Plan→Validate→Execute→Parse→Update→Decide` loop and enforces deterministic node transitions, which is required for audit reproducibility. See ADR-013.

---

## 2. Architectural Principles

1. **Deny by default** — the policy engine is the first and last check before any execution.
2. **No free-form shell** — every tool invocation is constructed deterministically from typed schemas.
3. **Evidence first** — nothing enters the findings store without a raw artifact.
4. **Immutable audit** — all state transitions are recorded in an append-only, hash-chained event log.
5. **Pluggable by contract** — tools are adapters that satisfy a schema; the runtime has no knowledge of tool internals.
6. **Local first** — LLM inference is local by default; cloud is policy-gated and redacted.
7. **Agent isolation** — agents communicate only through typed message schemas; no agent can invoke a tool directly or access another agent's internal state.

---

## 3. Top-Level Component Map

```
┌──────────────────────────────────────────────────────────────────┐
│                         Operator Interface                        │
│          CLI (Typer)  ·  TUI Dashboard  ·  Approval Queue        │
└────────────────────────────┬─────────────────────────────────────┘
                             │ Commands / Approvals
┌────────────────────────────▼─────────────────────────────────────┐
│                        Control Plane                              │
│                                                                   │
│  ┌──────────────┐  ┌─────────────────┐  ┌──────────────────────┐ │
│  │  Engagement  │  │  Policy Engine  │  │   Approval Service   │ │
│  │   Service    │  │  (deny-default) │  │  (queue + lifecycle) │ │
│  └──────┬───────┘  └────────┬────────┘  └──────────┬───────────┘ │
│         │                   │                       │             │
│  ┌──────▼───────────────────▼───────────────────────▼───────────┐ │
│  │                   Agent Orchestrator                          │ │
│  │  Observe → Plan → Validate → Execute → Parse → Update → Decide│ │
│  └──────────────────────────┬────────────────────────────────────┘ │
│                             │                                     │
│  ┌──────────────────────────▼───────────────────┐                │
│  │                  LLM Router                   │                │
│  │  Local (Ollama/vLLM)  →  Cloud (policy-gated) │                │
│  └───────────────────────────────────────────────┘                │
└────────────────────────────┬─────────────────────────────────────┘
                             │ ActionRequests (typed, validated)
┌────────────────────────────▼─────────────────────────────────────┐
│                        Execution Plane                            │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                     Tool Runner                             │   │
│  │  (isolated subprocess / container, CPU/mem/time limits)    │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                   │
│   [nmap]   [nuclei]   [ZAP]   [nikto]   [sqlmap]   [CVE/enrich] │
│   [whatweb] [whois]  [dig]    [custom plugins ...]               │
└────────────────────────────┬─────────────────────────────────────┘
                             │ ToolExecutionResults + Evidence
┌────────────────────────────▼─────────────────────────────────────┐
│                          Data Plane                               │
│                                                                   │
│  ┌────────────┐  ┌──────────────┐  ┌────────────┐  ┌──────────┐ │
│  │ Recon      │  │ Findings     │  │ Evidence   │  │  Audit   │ │
│  │ Store      │  │ Store        │  │ Store      │  │  Store   │ │
│  │ (hosts,    │  │ (CVE/CWE,    │  │ (raw I/O,  │  │ (append- │ │
│  │  services) │  │  scores)     │  │  hashes)   │  │  only,   │ │
│  └────────────┘  └──────────────┘  └────────────┘  │  chained)│ │
│                                                      └──────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Repository / Package Structure

```
pwnpilot/
├── pwnpilot/                        # Main Python package
│   ├── __init__.py
│   ├── cli.py                       # Typer CLI entry point
│   │
│   ├── control/                     # Control plane
│   │   ├── engagement.py            # Engagement model + scope validator
│   │   ├── policy.py                # Policy engine (deny-default evaluator)
│   │   ├── approval.py              # Approval ticket model + lifecycle
│   │   └── llm_router.py            # Local-first LLM routing + redaction
│   │
│   ├── agent/                       # Agent layer (LangGraph)
│   │   ├── supervisor.py            # LangGraph graph definition + node wiring
│   │   ├── state.py                 # Shared AgentState TypedDict (LangGraph state)
│   │   ├── planner.py               # Planner agent node
│   │   ├── validator.py             # Validator agent node
│   │   ├── executor.py              # Executor agent node
│   │   ├── reporter.py              # Reporter agent node
│   │   ├── action_validator.py      # ActionRequest schema enforcer
│   │   └── action_envelope.py       # Structured LLM output parser
│   │
│   ├── plugins/                     # Plugin SDK + adapters
│   │   ├── sdk.py                   # Plugin manifest, base class, contracts
│   │   ├── runner.py                # Isolated subprocess/container runner
│   │   ├── trust.py                 # Checksum + signature verification
│   │   ├── adapters/
│   │   │   ├── nmap.py
│   │   │   ├── nuclei.py
│   │   │   ├── zap.py
│   │   │   ├── nikto.py
│   │   │   ├── sqlmap.py
│   │   │   ├── whatweb.py
│   │   │   ├── whois.py
│   │   │   ├── dns.py
│   │   │   └── cve_enrich.py
│   │   └── parsers/                 # Per-tool output parsers
│   │       ├── nmap_parser.py
│   │       ├── nuclei_parser.py
│   │       ├── zap_parser.py
│   │       └── ...
│   │
│   ├── data/                        # Data plane
│   │   ├── models.py                # Pydantic models: ActionRequest, Finding, AuditEvent, etc.
│   │   ├── schemas/                 # Versioned JSON/YAML schema definitions
│   │   │   └── v1/
│   │   │       ├── engagement.yaml
│   │   │       ├── action_request.yaml
│   │   │       ├── finding.yaml
│   │   │       └── audit_event.yaml
│   │   ├── migrations/              # Alembic migration scripts
│   │   │   ├── env.py
│   │   │   └── versions/
│   │   ├── recon_store.py           # Host/service/port graph storage
│   │   ├── finding_store.py         # Dedup, correlation, scoring
│   │   ├── evidence_store.py        # Raw artifact persistence + hash index
│   │   └── audit_store.py           # Append-only event stream + chain verifier
│   │
│   ├── reporting/
│   │   ├── generator.py             # JSON bundle + human summary
│   │   ├── signer.py                # Report and manifest signing
│   │   └── templates/
│   │       └── summary.md.jinja2
│   │
│   ├── secrets/                     # Secrets and credential handling
│   │   ├── vault.py                 # Encrypted-at-rest credential store
│   │   └── redactor.py              # Pattern-based secret scrubber
│   │
│   ├── governance/                  # Operational governance
│   │   ├── authorization.py         # Engagement authorization artifact model
│   │   ├── retention.py             # Retention TTL, legal hold, secure delete
│   │   ├── kill_switch.py           # Global halt + deterministic cleanup
│   │   └── simulation.py            # Policy simulation (no-execution dry run)
│   │
│   ├── observability/
│   │   ├── metrics.py               # Policy deny rate, latency, error taxonomy counters
│   │   └── tracing.py               # Structured trace spans
│   │
│   └── tui/                         # Operator terminal UI
│       ├── dashboard.py             # Live status panel
│       └── approval_view.py         # Approval queue display
│
├── tests/
│   ├── unit/                        # Per-module unit tests
│   ├── contract/                    # Adapter schema contract tests
│   ├── integration/                 # End-to-end with mocked tools
│   └── adversarial/                 # Prompt injection, scope bypass, parser fuzzing
│
├── schemas/                         # Machine-readable canonical schemas (JSON Schema)
├── scripts/
│   ├── install_security_tools.sh
│   ├── verify_toolchain.sh
│   └── pwnpilot.service             # systemd unit template
├── requirements.txt
├── pyproject.toml
├── IMPLEMENTATION_PLAN.md
├── ARCHITECTURE.md
└── README.md
```

---

## 5. Component Specifications

### 5.1 Engagement Service (`control/engagement.py`)

**Responsibility:** Define and validate the scope of a pentest engagement.

**Inputs:**
- CIDRs, domain names, URL prefixes, IoT device ranges
- Rule of engagement document hash + approver identity
- Validity window (start/end timestamps)

**Behaviour:**
- Parse and normalise scope targets.
- Validate authorisation metadata is present and not expired.
- Expose `is_in_scope(target: str) -> bool` used by every downstream component.
- Block instantiation if authorisation metadata is missing or expired.

**Key schema fields:**
```
engagement_id, scope_cidrs[], scope_domains[], scope_urls[],
roe_document_hash, authoriser_identity, valid_from, valid_until,
operator_id, time_window
```

---

### 5.2 Policy Engine (`control/policy.py`)

**Responsibility:** Gate every action before execution.

**Action classes and default gates:**

| Action Class     | Default Gate                              |
|------------------|-------------------------------------------|
| recon_passive    | allow (soft rate limit: 60/min per engagement) |
| active_scan      | allow (hard rate limit: 10/min per engagement) |
| exploit          | requires_approval                         |
| post_exploit     | requires_approval                         |
| data_exfil       | deny                                      |

Note: `recon_passive` has a soft rate limit (warns and logs on breach, does not block) to prevent runaway loops. `active_scan` has a hard token-bucket limit that blocks on breach.

**Inputs:** `ActionRequest` + current engagement + operator config YAML.

**Behaviour:**
- Deny by default if action class is unknown.
- Call `is_in_scope` before evaluating gate.
- Check token/tool budget limits.
- **Rate limiting:** `active_scan` actions are governed by a per-engagement token bucket. Default: 10 `active_scan` actions per 60-second window (`rate_limit_active_scan_per_minute: 10`). The token bucket is stored in memory (SQLite-backed for persistence across resume). Requests that would exceed the limit receive `PolicyDecision(verdict=DENY, reason=RATE_LIMIT_EXCEEDED)`.
- Check rate limits.
- Return a `PolicyDecision(verdict, reason, gate_type)`.

---

### 5.3 Approval Service (`control/approval.py`)

**Responsibility:** Queue, route, and resolve human approval for high-risk actions.

**Lifecycle states:**
```
PENDING → APPROVED | DENIED | DEFERRED | EXPIRED
```

**Persistence:** Every ticket is written to the `approval_tickets` database table immediately on creation. This ensures tickets survive process crashes. The in-process queue is a view over the database row; on startup, any PENDING rows are reloaded.

**Behaviour:**
- Create a ticket for every `requires_approval` decision; persist to DB before returning.
- Expose an operator-facing queue with action rationale and impact preview.
- Record resolution (actor, timestamp, reason) into the audit store.
- Unresolved tickets expire after a configurable TTL to prevent stale approvals.
- All ticket state transitions are wrapped in a database transaction to prevent partial writes.

---

### 5.4 Multi-Agent Layer (LangGraph)

The agent layer is implemented as a **LangGraph stateful graph**. LangGraph models the agentic loop as a directed graph of nodes (agents) connected by typed edges. The shared `AgentState` TypedDict flows through every node; each agent reads from it and writes a delta back. The graph runner (supervisor) drives execution.

#### 5.4.1 Agent Supervisor (`agent/supervisor.py`)

**Responsibility:** Define the LangGraph graph, wire nodes and edges, drive the execution loop.

**LangGraph graph definition:**
```python
graph = StateGraph(AgentState)
graph.add_node("planner",   planner_node)
graph.add_node("validator", validator_node)
graph.add_node("executor",  executor_node)
graph.add_node("reporter",  reporter_node)

graph.set_entry_point("planner")
graph.add_edge("planner",   "validator")
graph.add_conditional_edges("validator", route_after_validation, {
    "execute":  "executor",
    "replan":   "planner",
    "halt":     END,
})
graph.add_conditional_edges("executor", route_after_execution, {
    "continue": "planner",
    "report":   "reporter",
    "halt":     END,
})
graph.add_edge("reporter", END)
```

**Concurrency model:**
- The LangGraph runner executes on the main thread (synchronous graph compilation with `graph.compile()`).
- Tool subprocesses inside the Executor node are spawned via `concurrent.futures.ThreadPoolExecutor` (default max_workers=4).
- The TUI runs on a dedicated thread managed by Textual's event loop.
- All shared `AgentState` mutations occur only inside node functions, which LangGraph calls sequentially within a single step — no cross-node concurrent state writes.
- SIGTERM and SIGINT handlers registered at process start; both set the `kill_switch` field in `AgentState` and trigger graceful shutdown. See §17.

**Safety mechanisms:**
- `max_iterations` hard cap in `AgentState`; the supervisor increments a counter each cycle and routes to `END` if exceeded.
- Novelty check and repeated-state circuit breaker implemented inside `planner_node`.
- All agent outputs pass through the Policy Engine before becoming `ActionRequest` objects.

**State machine (graph-level):**
```
IDLE ──► RUNNING ──► AWAITING_APPROVAL ──► RUNNING
                  └──► HALTED (kill_switch set)
                  └──► COMPLETE (reporter finished)
                  └──► ERROR (unrecoverable node failure)
```

**Crash recovery:**
- `AgentState` is persisted to the database at the end of every graph step (LangGraph checkpoint via a custom `SqliteCheckpointer` or `PostgresCheckpointer`).
- On `pwnpilot resume <engagement_id>`, the supervisor loads the persisted checkpoint, re-validates engagement authorisation, reloads pending approvals, and resumes from the last saved state.

---

#### 5.4.2 Planner Agent (`agent/planner.py`)

**Role:** Decides the next action given current engagement state.

**LLM model:** Local (Ollama/vLLM). Cloud fallback if circuit open and policy permits (§5.5).

**Input (reads from AgentState):**
- `recon_summary` — current hosts, services, findings graph.
- `previous_actions` — list of completed action IDs and results.
- `engagement_scope` — normalised scope object.
- `iteration_count` — current loop iteration.

**Output (writes to AgentState):**
- `proposed_action` — a `PlannerProposal` typed dict: `{action_type, tool_name, rationale, estimated_risk}`.

**Behaviour:**
- Produces a structured JSON `PlannerProposal` (never free-form text).
- Performs novelty check against `previous_actions` before proposing.
- Halts and sets `kill_switch=True` in state if repeated-state breaker triggers.

---

#### 5.4.3 Validator Agent (`agent/validator.py`)

**Role:** Provides an independent second-opinion risk assessment on the Planner's proposal before the Policy Engine sees it.

**LLM model:** Local (same or separate model instance via LLM Router — configurable).

**Input (reads from AgentState):**
- `proposed_action` — `PlannerProposal` from Planner.
- `engagement_scope` — for scope confirmation.
- `policy_context` — current policy gates and budget state.

**Output (writes to AgentState):**
- `validation_result` — a `ValidationResult` typed dict:
  `{verdict: "approve"|"reject"|"escalate", risk_override: RiskLevel|None, rationale: str}`.

**Behaviour:**
- `approve` → supervisor routes to Executor.
- `reject` → supervisor routes back to Planner (with rejection reason in state).
- `escalate` → risk_level is upgraded one tier (e.g. medium → high) before Policy Engine evaluation; may trigger approval gate.
- The Validator never calls tools and never writes to the data stores directly.

---

#### 5.4.4 Executor Agent (`agent/executor.py`)

**Role:** Converts the validated proposal into a concrete, typed `ActionRequest`, passes it through the Policy Engine, and triggers tool execution.

**LLM model:** Local LLM used only for parameter generation if tool param schema is complex. For standard adapters, params are derived deterministically from `PlannerProposal` fields without LLM involvement.

**Input (reads from AgentState):**
- `proposed_action` — validated `PlannerProposal`.
- `validation_result` — final risk level after Validator override.

**Output (writes to AgentState):**
- `last_result` — `ToolExecutionResult` from the Tool Runner.
- `evidence_ids` — list of new evidence IDs written to the Evidence Store.

**Behaviour:**
1. Construct `ActionRequest` from proposal + validation result.
2. Call `policy_engine.evaluate(ActionRequest)` — deny or approval-gate if required.
3. If approved: call `tool_runner.execute(ActionRequest)` → writes evidence.
4. On completion: upsert results to Recon Store / Findings Store.
5. Audit event appended at each step.

---

#### 5.4.5 Reporter Agent (`agent/reporter.py`)

**Role:** Summarises findings, generates the human-readable and machine-readable report bundle, and signs the output.

**LLM model:** Local LLM for natural-language summary generation. Structured JSON bundle is generated deterministically from the Findings Store (no LLM involved in JSON output).

**Input (reads from AgentState):**
- `engagement_id` — used to query all stores for the engagement.

**Output:**
- Calls `reporting.generator.build_bundle(engagement_id)`.
- Calls `reporting.signer.sign(bundle)`.
- Writes `ReportGenerated` audit event.
- Writes `report_complete=True` to `AgentState`.

**Trigger condition:** The supervisor routes to Reporter when:
- `iteration_count >= max_iterations`, or
- `tool_runner` returns no new findings for 3 consecutive cycles (convergence), or
- Operator issues `pwnpilot report now <engagement_id>`.

---

#### 5.4.6 Shared AgentState (`agent/state.py`)

```python
class AgentState(TypedDict):
    engagement_id:      str
    iteration_count:    int
    max_iterations:     int
    recon_summary:      dict              # snapshot from ReconStore
    previous_actions:   list[dict]        # completed ActionRequest IDs + results
    proposed_action:    PlannerProposal | None
    validation_result:  ValidationResult | None
    last_result:        ToolExecutionResult | None
    evidence_ids:       list[str]
    kill_switch:        bool              # set by signal handler or Planner breaker
    report_complete:    bool
    error:              str | None
```

LangGraph persists a full snapshot of this dict to the checkpoint store at the end of every node execution.

---

### 5.5 LLM Router (`control/llm_router.py`)

**Responsibility:** Route inference requests to the appropriate model with redaction and fallback.

**Multi-Provider Support:** The LLM Router uses **LiteLLM** to support 100+ LLM providers:
- **Cloud**: OpenAI (GPT-4, GPT-3.5), Anthropic (Claude 3), Google (Gemini), Mistral AI, Cohere, Replicate
- **Self-Hosted**: Ollama, vLLM, LocalAI, HuggingFace TGI
- **Private**: Any OpenAI-compatible API endpoint

Configuration is unified: just specify `model_name`, `api_key`, and optional `api_base_url`. LiteLLM auto-detects the provider.

**Routing logic:**
1. Always attempt primary model first (local by default, cloud optional).
2. Retry primary up to 3 times (configurable) with exponential backoff (base 1s, max 8s) on transient errors.
3. After 3 consecutive failures, open the circuit breaker for 60s; all subsequent requests skip to step 4 until reset.
4. If primary is circuit-open and policy allows: evaluate fallback model option (e.g., cheaper cloud provider).
5. If fallback is denied by policy, raise `PolicyDeniedError`; the orchestrator records this as a loop error and halts.
6. Before sending to cloud: run `redactor.scrub(prompt)` to remove scope targets, credentials, and PII.
7. Log routing decision (primary vs fallback, circuit state, provider) to audit store.

**Circuit breaker states:** `CLOSED` (normal) → `OPEN` (failing; skip primary) → `HALF_OPEN` (probe after cooldown) → `CLOSED`.

**Outputs:** Structured action envelope (not free-form text). The envelope parser validates before use.

**Timeouts:** 
- Primary model timeout: 120s (for local inference)
- Fallback/cloud timeout: 60s
- Both configurable via `config.yaml` or environment variables

**Configuration example:**

```yaml
# Primary: Local Ollama, Fallback: OpenAI GPT-4o
llm:
  model_name: "ollama/llama3"
  api_key: ""
  api_base_url: "http://localhost:11434"
  
  fallback_model_name: "gpt-4o-mini"
  fallback_api_key: "sk-..."
  
  cloud_allowed: true  # Allow fallback if primary fails
  max_retries: 3
  timeout_seconds: 120
```

See `examples/config.example.yaml` for comprehensive configuration examples.

---

### 5.6 Plugin SDK (`plugins/sdk.py`)

**Responsibility:** Define the contract every tool adapter must satisfy.

**Plugin manifest fields:**
```yaml
name: string
version: string
risk_class: recon_passive | active_scan | exploit | post_exploit
input_schema: $ref to JSON Schema
output_schema: $ref to JSON Schema
checksum_sha256: string
```

**BaseAdapter interface:**
```python
class BaseAdapter:
    manifest: PluginManifest
    def build_command(self, params: ToolParams) -> list[str]: ...
    def parse_output(self, stdout: str, stderr: str) -> ParsedOutput: ...
    def validate_params(self, params: dict) -> ToolParams: ...
```

**Constraints:**
- `build_command` must return a list; string interpolation from LLM output is forbidden.
- Every adapter is version-pinned and checksum-verified at load time (`plugins/trust.py`).

**Plugin trust root:**
- The project ships a `plugins/trust_store/pwnpilot_plugin_signing.pub` Ed25519 public key (committed to repository).
- Every first-party adapter manifest is signed by the corresponding private key (held by the project maintainer, never committed).
- Third-party plugins must supply their own signing key, which the operator explicitly adds to the `trust_store/` directory and approves via `pwnpilot plugin trust <name>`.
- `plugins/trust.py` verifies the manifest signature against the trust store before loading any adapter. An adapter with an unrecognised or invalid signature raises `PluginTrustError` and is not loaded.

---

### 5.7 Tool Runner (`plugins/runner.py`)

**Responsibility:** Execute adapter commands in a hardened, isolated context.

**Isolation strategy (v1):**
- `subprocess.run` with explicit argument list (no `shell=True`).
- Process group timeout enforced by `SIGKILL`.
- stdout/stderr are streamed in 64 KB chunks directly to the evidence store (never fully buffered in memory). See §5.8 Evidence Store for the streaming write contract.
- Resource limits via `resource` module (CPU time, memory).

**Isolation strategy (v1.1 upgrade path):**
- Rootless Podman containers per invocation.

**Output contract:**
- Returns `ToolExecutionResult` with `exit_code`, `duration_ms`, `stdout_hash`, `stderr_hash`, `parsed_output`, `parser_confidence`, `error_class`.

---

### 5.8 Data Stores

#### Recon Store (`data/recon_store.py`)
- Entity types: `Host`, `Service`, `Port`, `Technology`, `Domain`.
- Relationships: host → services → ports.
- Backend: SQLite (lab mode) / PostgreSQL (production).
- **SQLite WAL mode:** SQLite connections are opened with `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL`. WAL mode allows concurrent readers and one writer without reader-writer blocking, which is required for the TUI and orchestrator reading while the tool runner writes.
- **Connection management:** A single `SQLAlchemy` `sessionmaker` factory with `check_same_thread=False` for SQLite. For PostgreSQL, connection pool uses `QueuePool` with `pool_size=5`, `max_overflow=10`. Sessions are scoped per-operation (not per-process) and always closed in a `finally` block.

#### Findings Store (`data/finding_store.py`)
- Deduplication: fingerprint = `hash(asset_ref + vuln_ref + tool_name)`.
- Severity scoring: `CVSS_base * exposure_weight * confidence_weight * criticality_weight`.
- Status lifecycle: `NEW → CONFIRMED → REMEDIATED | FALSE_POSITIVE`.

#### Evidence Store (`data/evidence_store.py`)
- Stores raw stdout/stderr blobs on filesystem under `evidence/{engagement_id}/{evidence_id}.bin`.
- All file paths are constructed from UUID components only — no user-controlled input enters path construction (path traversal mitigation).
- **Streaming writes:** tool output is written to the evidence file in 64 KB chunks as it arrives from the subprocess stdout/stderr pipe; it is never buffered fully in memory. This handles tools (e.g., nuclei, ZAP) that produce large outputs.
- Size limit: configurable `max_evidence_bytes` per action (default 256 MB); tool subprocess is killed if output exceeds limit and truncation is recorded in the result.
- Hashing: SHA-256 is computed incrementally during streaming using `hashlib.sha256` update loop; final digest stored in index.
- Index: `{evidence_id, action_id, file_path, sha256_hash, size_bytes, timestamp}` in DB.
- Immutable: files are write-once; deletion only via retention governance.

#### Audit Store (`data/audit_store.py`)
- Append-only event stream.
- Each event: `{event_id, prev_event_hash, payload_hash, timestamp, actor, event_type}`.
- Hash chain: `prev_event_hash = SHA256(prev_event payload)`.
- **Verification:** Full chain replay is O(n). For large engagements, a checkpoint record is written every 500 events containing the cumulative chain hash up to that point. Full verification replays each 500-event segment independently, enabling parallel verification and bounding single-segment replay to a constant size.
- **SQLite exclusive writes:** The audit store writer acquires an advisory lock (`PRAGMA locking_mode=EXCLUSIVE` on SQLite, `SELECT ... FOR UPDATE` on PostgreSQL) for each append to prevent concurrent writers breaking the chain.

---

### 5.9 Reporting (`reporting/generator.py`)

**Outputs:**
- `report_<engagement_id>.json` — full machine-readable bundle.
- `report_<engagement_id>.md` — human-readable summary (Jinja2 rendered).

**Bundle contents:**
- Engagement metadata + ROE hash.
- Findings list with evidence links.
- Audit chain summary + verification status.
- Risk score breakdown.

**Signing:**
- `signer.py` computes SHA-256 over the JSON bundle and signs with the operator's Ed25519 private key.
- The operator key pair is generated once via `pwnpilot keys generate` and stored: private key in the vault (encrypted at rest), public key in `~/.pwnpilot/operator.pub` and embedded in the report bundle for verification.
- Signature stored in `report.sig` alongside the bundle.
- Verification: `pwnpilot report verify <report.json> <report.sig>` uses the embedded public key, validated against a locally trusted keyring.

---

### 5.10 Secrets and Redaction (`secrets/`)

**Vault (`secrets/vault.py`):**
- Secrets encrypted at rest using `cryptography` Fernet symmetric key.
- Key stored outside the repository (env var `INTRUDER_VAULT_KEY` or key file at path set by `INTRUDER_VAULT_KEY_FILE`; env var takes precedence; never committed).
- **Key rotation:** The vault supports multi-key envelopes. When a new key is provided via `INTRUDER_VAULT_KEY_NEW`, the vault decrypts all secrets with the old key and re-encrypts them with the new key in a single atomic transaction on next startup. After successful rotation, the old key is invalidated. This follows the `cryptography.fernet.MultiFernet` pattern.
- Scoped short-lived tokens provided to adapters at execution time, not stored in adapter scope.
- Keys are never logged, never included in audit payloads, and never passed through the redactor (they are excluded from LLM context entirely).

**Redactor (`secrets/redactor.py`):**
- Before any LLM call: scrub patterns for IPs, domains, credentials, API keys.
- Applied to prompts (cloud fallback) and LLM responses before logging.

---

### 5.11 Governance (`governance/`)

**Authorization (`governance/authorization.py`):**
- `AuthorizationArtifact` persisted per engagement.
- Expiry check runs on every `Orchestrator.run()` call.

**Kill Switch (`governance/kill_switch.py`):**
- Implemented as a `threading.Event` (not a plain boolean) so it is safe to check and set from any thread without a race condition.
- `KillSwitch.trigger(reason: str)` sets the event and writes a `KillSwitchTriggered` audit event atomically.
- The tool runner calls `KillSwitch.is_set()` before every subprocess spawn. If set, it raises `HaltedError` immediately.
- `ThreadPoolExecutor` futures that are already in-flight are cancelled via `future.cancel()`; running subprocesses receive `SIGTERM` followed by `SIGKILL` after a 5s drain window.
- All queued actions are rejected with `HALT` reason.
- Cleanup outcomes (which subprocesses were killed, which were cancelled, which completed) are logged to audit store.

**Simulation (`governance/simulation.py`):**
- Alternate orchestrator mode: policy decisions are returned but no tool invocations occur.
- Used for ROE preflight and policy change validation.

**Retention (`governance/retention.py`):**
- TTL per engagement classification (e.g. CTF: 30 days, external: 90 days).
- Legal hold: block deletion, document hold reason and holder.
- Secure delete: overwrite evidence files before `unlink`.

---

## 6. Data Flow Diagrams

### 6.1 Standard Recon Action Flow

```
Operator
  │
  ▼ create_engagement(scope, auth)
Engagement Service ──validates──► scope_validator
  │
  ▼ engagement object
Agent Orchestrator
  │
  ▼ plan_step()
LLM Router ──local model──► ActionEnvelope (JSON)
  │
  ▼ parse_action_envelope()
Action Validator ──schema check──► ActionRequest
  │
  ▼ evaluate(ActionRequest)
Policy Engine ──► PolicyDecision(allow)
  │
  ▼ execute(ActionRequest)
Tool Runner ──► nmap adapter ──► subprocess
  │                              │
  │                   (streaming 64 KB chunks)
  │                              ▼
  │                        Evidence Store (streaming write + incremental SHA-256)
  │
  ▼ ToolExecutionResult
nmap Parser ──► ParsedOutput (hosts/services)
  │
  ▼
Recon Store (upsert hosts/services/ports)
  │
  ▼
AuditStore.append(ActionExecuted event)
  │
  ▼
Orchestrator.update_state() ──► next loop iteration
```

### 6.2 High-Risk Action Requiring Approval

```
Policy Engine ──► PolicyDecision(requires_approval)
  │
  ▼
Approval Service.create_ticket(ActionRequest, rationale, impact_preview)
  │
  ▼ (operator reviews in TUI/CLI)
Operator ──► approve(ticket_id, reason) | deny(ticket_id, reason)
  │
  ▼
AuditStore.append(ApprovalResolved event)
  │
  ▼ (if approved)
Tool Runner.execute(ActionRequest)
```

### 6.3 Report Generation Flow

```
Findings Store ──► deduplicated findings list
  │
Evidence Store ──► evidence links per finding
  │
Recon Store ──► asset context
  │
  ▼
ReportGenerator.build_bundle()
  │
Signer.sign(bundle) ──► report.json + report.sig
  │
  ▼ (optional)
AuditStore.append(ReportGenerated event)
```

---

## 7. Interface Contracts (Summary)

### 7.1 ActionRequest
```python
class ActionRequest(BaseModel):
    action_id: UUID
    engagement_id: UUID
    action_type: ActionType          # Enum: recon_passive | active_scan | exploit | post_exploit
    tool_name: str
    params: Annotated[dict, AfterValidator(_validate_tool_params)]
    # ^ params is validated at model construction time by calling the tool adapter's
    #   validate_params() method via a Pydantic AfterValidator. This is NOT deferred to
    #   a separate runtime step; invalid params cause model construction to fail.
    expected_evidence: list[str]
    risk_level: RiskLevel            # Enum: low | medium | high | critical
    requires_approval: bool
    schema_version: str = "v1"
```

Note: `_validate_tool_params` is a Pydantic `AfterValidator` that looks up the tool adapter by `tool_name` and calls `adapter.validate_params(params)`, raising `ValidationError` on schema mismatch. This ensures `ActionRequest` is never constructed with structurally invalid tool parameters.

### 7.2 ToolExecutionResult
```python
class ToolExecutionResult(BaseModel):
    action_id: UUID
    tool_name: str
    exit_code: int
    duration_ms: int
    stdout_hash: str                 # SHA-256
    stderr_hash: str
    stdout_evidence_id: UUID | None  # immutable raw stdout artifact id
    stderr_evidence_id: UUID | None
    stdout_evidence_path: str | None # artifact path for post-run inspection
    stderr_evidence_path: str | None
    parsed_output: Annotated[dict, AfterValidator(_validate_parsed_output)]
    # ^ validated against the adapter's output_schema at model construction time,
    #   same pattern as ActionRequest.params. Raises ValidationError on mismatch.
    parser_confidence: float         # 0.0 – 1.0
    error_class: str | None          # TIMEOUT | PARSE_ERROR | SCOPE_VIOLATION | ...
    schema_version: str = "v1"
```

### 7.3 Finding
```python
class Exploitability(str, Enum):
    NONE        = "none"         # No known exploit technique
    LOW         = "low"          # Theoretical / difficult
    MEDIUM      = "medium"       # Exploit exists but requires conditions
    HIGH        = "high"         # Reliable exploit publicly available
    FUNCTIONAL  = "functional"   # Working exploit in framework (e.g. Metasploit)
    WEAPONIZED  = "weaponized"   # Deployed in active campaigns

class Finding(BaseModel):
    finding_id: UUID
    engagement_id: UUID
    asset_ref: str
    title: str
    vuln_ref: str                    # CVE-XXXX-XXXX | CWE-XXX | custom
    severity: Severity               # Enum: info | low | medium | high | critical
    confidence: float                # 0.0 – 1.0
    exploitability: Exploitability   # Enum; used in risk scoring formula
    cvss_vector: str | None          # CVSS v3.1 vector string if available
    evidence_ids: list[UUID]
    remediation: str
    status: FindingStatus            # Enum: new | confirmed | remediated | false_positive
    schema_version: str = "v1"
```

### 7.4 AuditEvent
```python
class AuditEvent(BaseModel):
    event_id: UUID
    engagement_id: UUID
    timestamp: datetime
    actor: str                       # planner | validator | executor | reporter | operator:<id> | system
    event_type: str                  # AgentInvoked | ActionExecuted | ApprovalResolved | ReportGenerated | ...
    payload_hash: str
    prev_event_hash: str
    decision_context: dict | None
    schema_version: str = "v1"
```

---

## 8. Technology Mapping

| Layer                    | Technology (v1)                          |
|--------------------------|------------------------------------------|
| CLI                      | Python 3.11+ · Typer                     |
| TUI                      | Textual                                  |
| API (optional)           | FastAPI                                  |
| Data models              | Pydantic v2                              |
| Database (lab mode)      | SQLite via SQLAlchemy                    |
| Database (production)    | PostgreSQL via SQLAlchemy                |
| Migrations               | Alembic                                  |
| Evidence storage         | Local filesystem + hash index            |
| LLM local                | Ollama (llama3 / mistral)                |
| LLM cloud fallback       | Policy-gated OpenAI/Anthropic client     |
| Agent framework          | LangGraph 0.2+                           |
| Tool isolation (v1)      | `subprocess` with resource limits        |
| Tool isolation (v1.1)    | Rootless Podman                          |
| Secrets encryption       | cryptography (Fernet)                    |
| Report signing           | cryptography (RSA/Ed25519)               |
| Schema validation        | jsonschema / Pydantic                    |
| Testing                  | pytest + pytest-cov                      |
| Static analysis          | ruff · mypy                              |
| CI matrix                | GitHub Actions (Kali + Ubuntu images)    |

---

## 9. Security Architecture

### 9.1 Threat Model Summary

| Threat                    | Mitigation                                                    |
|---------------------------|---------------------------------------------------------------|
| Prompt injection          | Structured envelope parser; LLM output never executed raw.    |
| Command injection         | `build_command()` returns list; `shell=False` always enforced.|
| Scope bypass              | `is_in_scope()` called by policy engine before every action.  |
| Parser poisoning          | Contract tests; fallback parser; error envelope on failure.   |
| Credential leakage        | Redactor on all LLM paths; vault for secrets.                 |
| Audit tampering           | Append-only + hash chain; no update/delete API.               |
| Stale authorisation       | Expiry check on every orchestrator run.                       |
| Supply chain (plugins)    | Checksum and signature verification at plugin load.           |
| Resource exhaustion (DoS) | Evidence size cap (256 MB); active_scan hard rate limit; `max_iterations` cap; subprocess CPU/memory limits via `resource` module. Excessive output kills subprocess and records truncation event. |
| Runaway loop              | Novelty check and repeated-state circuit breaker in orchestrator halt the loop before unbounded execution. |

### 9.2 Trust Boundary Diagram

```
┌──────────────── Trusted boundary ─────────────────────────────┐
│  Engagement Service                                            │
│  Policy Engine                                                 │
│  Approval Service                                              │
│  Audit Store                                                   │
│  Secrets Vault                                                 │
└───────────────────────────────────────────────────────────────┘
          │                              │
          │ validate before crossing     │ scrub before crossing
          ▼                              ▼
┌─── Semi-trusted ────┐      ┌─── External / untrusted ─────────┐
│  Agent Orchestrator │      │  LLM (local and cloud)           │
│  Plugin SDK         │      │  Tool subprocess output          │
│  Tool Runner        │      │  CVE/threat intel APIs           │
└─────────────────────┘      └──────────────────────────────────┘
```

---

## 10. Deployment Topology (Single-Node)

```
┌──────────────────────────────────────────────────────────────┐
│                      Single Linux Machine                     │
│         (Kali Linux or Ubuntu 22.04 / 24.04 LTS)             │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐    │
│  │   pwnpilot process (Python 3.11+)                    │    │
│  │   ├── CLI / TUI                                      │    │
│  │   ├── Control Plane (engagement, policy, approval)   │    │
│  │   ├── Agent Orchestrator                             │    │
│  │   ├── Plugin Runner (subprocess / podman)            │    │
│  │   └── Data Plane (SQLite or Postgres client)         │    │
│  └──────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌───────────────────┐     ┌──────────────────────────────┐  │
│  │  Ollama / vLLM    │     │  SQLite (lab) / PostgreSQL   │  │
│  │  (local LLM)      │     │  + Evidence filesystem       │  │
│  └───────────────────┘     └──────────────────────────────┘  │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐   │
│  │  Installed security tools (managed by installer)      │   │
│  │  nmap · nuclei · zaproxy · nikto · sqlmap             │   │
│  │  whatweb · whois · dnsutils                           │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                               │
│  Optional: Podman (rootless containers for tool isolation)    │
└──────────────────────────────────────────────────────────────┘
            │ (outbound only, policy-gated)
            ▼
   Cloud LLM fallback · CVE/NVD APIs · Nuclei template updates
```

---

## 11. Schema Versioning Strategy

- All canonical schemas live under `pwnpilot/data/schemas/v1/`.
- Schema version field present on every model (`schema_version: str`).
- New versions land in `v2/` etc; migration scripts in `pwnpilot/data/migrations/`.
- Replay and resume workflows check schema version before deserialisation.
- Breaking changes require a version bump; non-breaking changes are additive and backward-compatible.

---

## 12. Module Dependency Rules

To prevent circular imports and maintain architectural discipline:

```
cli          → control, agent, tui
control      → data, secrets, governance, observability
agent        → control, plugins, data, observability
plugins      → data, observability
data         → (no internal dependencies; only stdlib + third-party)
reporting    → data, secrets
governance   → data, observability
               # governance.kill_switch writes to data.audit_store directly;
               # this is the only permitted intra-data import from governance.
tui          → control, agent
```

Rule: `data` is the lowest layer. Nothing in `data` may import from `control`, `agent`, or `plugins`.
Rule: `governance` may only access `data` sub-modules (stores); it must not import from `control` or `agent`.

---

## 13. CI/CD Architecture

```
Push / PR
  │
  ▼
┌────────────────────────────────────────────────────────────┐
│ GitHub Actions                                             │
│                                                            │
│  Job 1: Lint + Static Analysis (ruff, mypy)                │
│  Job 2: Unit Tests (pytest, coverage ≥ 80%)
          # Enforced via `--cov-fail-under=80` in pyproject.toml [tool.pytest.ini_options].
          # The CI job fails if coverage drops below threshold.                │
│  Job 3: Contract Tests (adapter schema validation)         │
│  Job 4: Security Tests (scope bypass, injection, fuzzing)  │
│                                                            │
│  (Release candidate only)                                  │
│  Job 5: Integration Tests (mocked tools, end-to-end)       │
│  Job 6: Installer + Verifier on Kali image                 │
│  Job 7: Installer + Verifier on Ubuntu 22.04 image         │
│  Job 8: Installer + Verifier on Ubuntu 24.04 image         │
│  Job 9: Audit chain integrity verification                 │
└────────────────────────────────────────────────────────────┘
```

---

## 14. Architecture Decision Records (ADRs)

### ADR-001: Deny-by-default policy engine
**Decision:** Every action class not explicitly permitted is denied.
**Rationale:** Fail-safe posture. LLM can generate unexpected action types; unknown = blocked.

### ADR-002: Structured action envelope (no free-form shell)
**Decision:** LLM output is parsed into a typed `ActionRequest`; `build_command()` constructs subprocess args list.
**Rationale:** Eliminates command injection from LLM output.

### ADR-003: Append-only audit with hash chain
**Decision:** Audit events are never updated or deleted; each event hashes the previous.
**Rationale:** Tamper-evident log that does not depend on database access controls alone.

### ADR-004: Local-first LLM with redacted cloud fallback
**Decision:** Always attempt local model; cloud only when policy permits and after redaction.
**Rationale:** Minimises scope data leaving the operator's machine.

### ADR-005: SQLite for lab mode, PostgreSQL for production
**Decision:** Single codebase, SQLAlchemy abstraction; backend selected by config.
**Rationale:** Zero-dependency lab setup; production-grade store for real engagements.

### ADR-006: Plugin manifest with checksum verification
**Decision:** Every adapter ships with a manifest including `checksum_sha256`; verified at load.
**Rationale:** Prevents tampered adapter code from executing without detection.

### ADR-007: subprocess list invocation enforced in runner
**Decision:** `runner.py` raises `ValueError` if `build_command()` returns a string.
**Rationale:** Structural enforcement of ADR-002 at the execution boundary.

### ADR-008: Thread-based concurrency (not asyncio)
**Decision:** Orchestrator is a synchronous loop; parallelism is achieved via `ThreadPoolExecutor` for tool subprocesses and a dedicated Textual thread for the TUI.
**Rationale:** Security tool adapters rely on synchronous subprocess I/O. asyncio subprocess wrappers add complexity without benefit here. Thread-based model is simpler to reason about for safety-critical paths and easier to audit.

### ADR-009: SIGTERM triggers kill switch and graceful drain
**Decision:** SIGTERM and SIGINT both call `KillSwitch.trigger()`, which initiates a graceful 30s drain before `sys.exit(0)`.
**Rationale:** Prevents orphaned subprocesses and ensures all in-flight audit events are flushed before process exit.

### ADR-010: Structured JSON logging via structlog
**Decision:** All log output uses `structlog` with `JSONRenderer` bound to stdout. Log level is configurable via `INTRUDER_LOG_LEVEL` env var.
**Rationale:** Structured logs are machine-parseable, compatible with log aggregation stacks, and preserve context (engagement_id, action_id) without string interpolation.

### ADR-011: pip hash-pinned requirements
**Decision:** `requirements.txt` uses `--require-hashes` format. All transitive dependencies are pinned with SHA-256 hashes.
**Rationale:** Prevents dependency substitution attacks. Installation fails if any package hash does not match.

### ADR-012: Fernet multi-key envelope for key rotation
**Decision:** The vault uses `cryptography.fernet.MultiFernet` to support decryption with multiple keys. Rotation is triggered by providing `INTRUDER_VAULT_KEY_NEW` at startup.
**Rationale:** Zero-downtime key rotation without losing access to previously encrypted secrets.

### ADR-013: LangGraph as multi-agent framework
**Decision:** The agent layer uses LangGraph (not AutoGen, CrewAI, or a custom loop) to define and run the Planner → Validator → Executor → Reporter graph.
**Rationale:** LangGraph's explicit `StateGraph` with typed `AgentState` maps directly onto the existing loop structure. It provides built-in checkpointing (crash recovery), conditional edge routing (policy-aware branching), and deterministic node sequencing — all required for audit reproducibility. Unlike AutoGen/CrewAI, LangGraph does not introduce hidden agent-to-agent messaging that could bypass the policy engine.

### ADR-014: Validator agent as independent LLM second-opinion
**Decision:** A separate Validator agent (with its own LLM call) reviews every Planner proposal before it reaches the Policy Engine.
**Rationale:** A single LLM can hallucinate risk classifications. An independent second-opinion with a different system prompt catches misclassification before tool execution. The Validator can escalate risk upward but never downgrade it below the policy engine's minimum threshold.

### ADR-015: Reporter agent triggered by convergence, not just max_iterations
**Decision:** The Reporter is triggered by three conditions: max_iterations reached, 3 consecutive cycles with no new findings (convergence), or explicit operator command.
**Rationale:** Convergence detection prevents wasted inference and tool calls once the engagement is effectively complete. Operator command gives immediate control without waiting for natural termination.

---

## 19. Multi-Agent Architecture Detail

### 19.1 Agent Roles Summary

| Agent     | LLM Used | Primary Input          | Primary Output              | Calls Tools? |
|-----------|----------|------------------------|-----------------------------|--------------|
| Planner   | Yes      | Recon state, history   | PlannerProposal             | No           |
| Validator | Yes      | PlannerProposal        | ValidationResult            | No           |
| Executor  | Optional | ValidationResult       | ActionRequest + tool result | Yes          |
| Reporter  | Yes      | Engagement findings    | Report bundle + signature   | No           |

### 19.2 LangGraph Graph Definition

```
                  ┌──────────────┐
     ┌────────────►   PLANNER    │
     │            │    Node      │
     │            └──────┬───────┘
     │                   │ PlannerProposal
     │            ┌──────▼───────┐
     │            │  VALIDATOR   │
     │            │    Node      │
     │            └──────┬───────┘
     │                   │ ValidationResult
     │         ┌─────────▼──────────────────┐
     │         │   conditional_edge         │
     │         │   verdict == "reject"  ────┼──► back to PLANNER
     │         │   verdict == "approve" ────┼──► EXECUTOR
     │         │   verdict == "escalate"────┼──► EXECUTOR (risk elevated)
     │         └────────────────────────────┘
     │                   │
     │            ┌──────▼───────┐
     │            │  EXECUTOR    │
     │            │    Node      │
     │            └──────┬───────┘
     │                   │ ToolExecutionResult
     │         ┌─────────▼──────────────────┐
     │         │   conditional_edge         │
     │         │   continue ────────────────┼──► back to PLANNER
     │         │   converged ───────────────┼──► REPORTER
     │         │   max_iter reached ────────┼──► REPORTER
     │         │   kill_switch set  ────────┼──► END (halted)
     │         └────────────────────────────┘
     │                   │
     │            ┌──────▼───────┐
     │            │  REPORTER    │
     │            │    Node      │
     │            └──────┬───────┘
     │                   │
     │                  END
     └── (on "reject": PlannerProposal updated with rejection reason)
```

### 19.3 Inter-Agent Message Contracts

All agents communicate exclusively through `AgentState`. No direct agent-to-agent function calls exist. This is enforced by module dependency rules: `planner.py`, `validator.py`, `executor.py`, and `reporter.py` do not import each other.

**PlannerProposal:**
```python
class PlannerProposal(TypedDict):
    action_type:      str          # recon_passive | active_scan | exploit | post_exploit
    tool_name:        str
    rationale:        str          # human-readable justification (logged to audit)
    estimated_risk:   str          # low | medium | high | critical
    rejection_reason: str | None   # populated by Validator on reject; used in next Planner call
```

**ValidationResult:**
```python
class ValidationResult(TypedDict):
    verdict:        str            # approve | reject | escalate
    risk_override:  str | None     # if escalate: new risk level (always >= estimated_risk)
    rationale:      str            # logged to audit store
```

### 19.4 Policy Engine Integration

The Policy Engine is called **only by the Executor agent**, never by Planner or Validator. This preserves separation: LLM agents reason; the Policy Engine enforces.

```
Executor node
  │
  ├─► construct ActionRequest(proposed_action, validation_result)
  │
  ├─► policy_engine.evaluate(ActionRequest)
  │       ├─► DENY         → record PolicyDenied audit event → write rejection to AgentState → route back to Planner
  │       ├─► ALLOW        → proceed to tool_runner.execute()
  │       └─► NEEDS_APPROVAL → approval_service.create_ticket() → set AgentState.awaiting_approval=True
  │                             Supervisor polls approval store each step until resolved
  │
  └─► tool_runner.execute(ActionRequest) → ToolExecutionResult
```

### 19.4.1 Missing Tool/Binary Recovery

If `tool_runner.execute()` fails because a tool is unavailable or its binary is missing:

1. Executor writes `ActionFailed` with full error details.
2. Executor injects `rejection_reason` into planner state.
3. Executor marks that tool in `temporarily_unavailable_tools` for 3 planner iterations.
4. Planner context includes `temporarily_unavailable_tools` and avoids those tools.
5. Planner selects a different executable tool from runtime-available tools.

Important: the runtime does not auto-install missing binaries during engagement execution. Installation is an explicit operator action.

### 19.5 LLM Model Assignment per Agent

Each agent can be configured to use a different model, which allows optimising cost vs capability:

```yaml
agents:
  planner:
    model: llama3          # complex reasoning; largest local model
  validator:
    model: mistral         # faster second-opinion; smaller model acceptable
  executor:
    model: mistral         # param generation only; or none for deterministic adapters
  reporter:
    model: llama3          # quality narrative generation
```

All agents share the same LLM Router so circuit-breaker state, redaction, and cloud fallback policy apply uniformly.

### 19.6 Multi-Agent Audit Trail

Every agent invocation writes an `AgentInvoked` audit event containing:
- `agent_name` (planner | validator | executor | reporter)
- `input_state_hash` — SHA-256 of the AgentState snapshot fed into the node
- `output_state_hash` — SHA-256 of the delta written back
- `llm_model_used`
- `llm_routing_decision` (local | cloud)
- `duration_ms`

This ensures the audit chain captures not just tool executions but every LLM reasoning step.

### 19.7 Agent Security Properties

| Property                          | Mechanism                                                       |
|-----------------------------------|-----------------------------------------------------------------|
| No agent has direct tool access   | Only Executor calls tool_runner; others have no import path to it |
| No agent output executed raw      | All proposals go through ActionRequest schema validation         |
| Validator cannot lower risk       | `risk_override` is rejected if < `estimated_risk` by Executor   |
| Agents cannot read vault secrets  | Secrets module not in any agent module's import closure         |
| Agent LLM calls are all redacted  | LLM Router's redactor runs on all agent prompts before dispatch |
| Agent output logged immutably     | AgentInvoked audit events are hash-chained like all other events|

### 15.1 Config File Format
- Primary config: `config.yaml` (TOML also accepted via `config.toml`).
- Location search order: `$INTRUDER_CONFIG`, then `./config.yaml`, then `~/.pwnpilot/config.yaml`.
- All values have explicit defaults; the application validates the config schema on startup using Pydantic and fails fast with a clear error if required fields are missing.

### 15.2 Environment Variable Overrides
Every config key can be overridden by an environment variable prefixed `INTRUDER_`. Nested keys use `__` as separator (e.g., `INTRUDER_POLICY__MAX_ACTIVE_SCAN_PER_MINUTE=5`).

### 15.3 Canonical Config Schema (top-level keys)
```yaml
database:
  backend: sqlite | postgresql
  url: str
  # SECURITY: Never embed credentials in this field for PostgreSQL.
  # Use the format: postgresql+psycopg2://user@host/db and set
  # PGPASSWORD or a .pgpass file, or use the vault:
  # url: postgresql+psycopg2://${INTRUDER_DB_USER}:${INTRUDER_DB_PASS}@host/db
  # where INTRUDER_DB_USER and INTRUDER_DB_PASS are injected from the vault at startup.

llm:
  local_endpoint: str               # Ollama/vLLM base URL
  local_model: str
  local_timeout_s: int              # default 120
  cloud_provider: openai | anthropic | none
  cloud_model: str
  cloud_timeout_s: int              # default 60
  circuit_breaker_threshold: int    # consecutive local failures before open (default 3)
  circuit_breaker_cooldown_s: int   # default 60

policy:
  max_active_scan_per_minute: int   # default 10
  max_iterations: int               # default 50
  approval_ttl_s: int               # default 3600

governance:
  default_retention_days: int       # default 90
  max_evidence_bytes: int           # default 268435456 (256 MB)

secrets:
  vault_key_env: INTRUDER_VAULT_KEY
  vault_key_file: str | null

observability:
  log_level: DEBUG | INFO | WARNING | ERROR   # default INFO
  metrics_enabled: bool             # default true
  trace_enabled: bool               # default false

plugins:
  trust_store_path: str             # default plugins/trust_store/
  # allow_unsigned is intentionally not a config file option.
  # Unsigned plugins are always rejected. To load an unsigned plugin during
  # development only, set the environment variable INTRUDER_DEV_ALLOW_UNSIGNED=1.
  # This env var is checked at startup and emits a CRITICAL log warning.
  # It is explicitly blocked if INTRUDER_ENV=production.
```

### 15.4 Startup Validation
On every start, the application:
1. Loads and validates config against the schema.
2. Verifies toolchain (`verify_toolchain.sh` equivalent in Python).
3. Checks vault key availability.
4. Checks database connectivity and runs pending Alembic migrations.
5. Verifies all loaded plugin checksums against the trust store.
6. Logs startup summary (config path, backend, LLM endpoint, plugin count) at INFO level.
7. Exits with code 1 and a human-readable error if any check fails.

---

## 16. Structured Logging

### 16.1 Library
`structlog` with `JSONRenderer` bound to `sys.stdout`. Log records are newline-delimited JSON.

### 16.2 Standard Fields on Every Log Record
```json
{
  "timestamp": "2026-04-07T10:00:00.000Z",
  "level": "info",
  "event": "action_executed",
  "engagement_id": "uuid",
  "action_id": "uuid",
  "tool_name": "nmap",
  "duration_ms": 1234,
  "logger": "pwnpilot.plugins.runner"
}
```

### 16.3 Log Levels per Component
| Component            | Default Level |
|----------------------|---------------|
| cli                  | WARNING        |
| control.policy       | INFO           |
| control.approval     | INFO           |
| agent.orchestrator   | INFO           |
| plugins.runner       | INFO           |
| data.audit_store     | DEBUG          |
| llm_router           | INFO           |
| governance           | WARNING        |

### 16.4 What Is Never Logged
- Secret values or vault key material.
- Raw LLM prompts containing unredacted scope data (only redacted prompts are logged).
- File paths containing absolute engagement data directories (replaced with `<evidence_path>`).

### 16.5 Log Rotation
- If writing to a file (`logging.file` in `config.yaml`, or env override `PWNPILOT_LOGGING__FILE`), logs are rotated daily with retention set by `logging.rotation_days`.
- Default output is stdout; rotation is the responsibility of the process supervisor (e.g., systemd journal).

---

## 17. Graceful Shutdown

### 17.1 Signal Handling
Both `SIGTERM` and `SIGINT` are caught by a signal handler registered at process startup.

The signal handler itself does only one thing — it sets a `threading.Event` flag (`_SHUTDOWN_REQUESTED`). The main thread polls this flag at the top of every orchestrator loop iteration. When detected:
1. Call `KillSwitch.trigger(reason="SIGTERM")`.
2. Set a process-level `_SHUTTING_DOWN` flag.
3. Wait up to 30s for the `ThreadPoolExecutor` to drain running tool subprocesses.
4. Any subprocess still running after 30s is sent `SIGKILL`.
5. Flush all pending audit events to the database.
6. Close all database connections.
7. Call `sys.exit(0)` from the main thread (never from the signal handler itself).

Note: `sys.exit()` and most I/O are not async-signal-safe and must never be called directly inside a signal handler. Only `threading.Event.set()` is called in the handler.

### 17.2 Orphan Prevention
- All subprocesses are created in a new process group (`os.setpgrp` via `preexec_fn`).
- On shutdown, `os.killpg` is used to signal the process group, ensuring child processes of tool subprocesses are also terminated.

### 17.3 Process Supervision
- A systemd unit file template is provided at `scripts/pwnpilot.service`.
- `Restart=on-failure`, `RestartSec=5s`.
- On restart, the orchestrator uses crash recovery (section 5.4) to resume from last checkpoint.

---

## 18. Production Readiness Assessment

### 18.1 Gap Register (All Resolved in This Document)

| ID  | Severity | Gap Description                                          | Resolution Section       |
|-----|----------|----------------------------------------------------------|--------------------------|
| G01 | CRITICAL | No concurrency model; orchestrator loop not thread-safe  | §5.4 (updated)           |
| G02 | CRITICAL | Approval tickets not crash-durable (in-memory only)      | §5.3 (updated)           |
| G03 | CRITICAL | LLM router has no retry/backoff/circuit breaker          | §5.5 (updated)           |
| G04 | CRITICAL | Kill switch used plain boolean (not thread-safe)         | §5.11 (updated)          |
| G05 | CRITICAL | stdout/stderr buffered in memory (OOM risk)              | §5.8 Evidence (updated)  |
| G06 | CRITICAL | ActionRequest.params is untyped dict (bypass risk)       | §7.1 (updated)           |
| G07 | HIGH     | No crash recovery / resume on process restart            | §5.4 (updated)           |
| G08 | HIGH     | SQLite WAL mode not specified (deadlock under concurrency)| §5.8 Recon (updated)    |
| G09 | HIGH     | No DB connection pooling / session lifecycle             | §5.8 Recon (updated)     |
| G10 | HIGH     | Fernet key rotation strategy missing                     | §5.10 (updated)          |
| G11 | HIGH     | Plugin trust root (who signs, key distribution) undefined| §5.6 (updated)           |
| G12 | HIGH     | Rate limiting implementation not specified               | §5.2 (updated)           |
| G13 | HIGH     | Audit chain full-replay O(n); no scalability bound       | §5.8 Audit (updated)     |
| G14 | HIGH     | No config management system                              | §15 (new)                |
| G15 | HIGH     | No structured logging strategy                           | §16 (new)                |
| G16 | HIGH     | No graceful shutdown / SIGTERM handling                  | §17 (new)                |
| G17 | MEDIUM   | No process supervision (systemd)                         | §17.3 (new)              |
| G18 | MEDIUM   | Evidence file path traversal risk not addressed          | §5.8 Evidence (updated)  |
| G19 | MEDIUM   | No requirements hash-pinning                             | ADR-011 (new)            |
| G20 | MEDIUM   | No TLS requirement for FastAPI                           | §15.3 (documented)       |
| G21 | MEDIUM   | No health check / liveness endpoint defined              | §15.4 (new)              |
| G22 | MEDIUM   | No SLO/error budget values                               | §18.2 (new)              |
| G23 | MEDIUM   | Redactor is pattern-only; novel secrets may leak         | §5.10 (allowlist note)   |
| G24 | MEDIUM   | No backup/restore strategy for data stores               | §18.3 (new)              |
| G25 | MEDIUM   | No file descriptor limit management for subprocesses     | §18.4 (new)              |

### 18.2 SLO Baselines (Minimum for Production Tag)
| SLO                             | Target           |
|---------------------------------|------------------|
| Policy evaluation latency p99   | < 50 ms          |
| Approval ticket persist latency | < 200 ms         |
| Audit append latency p99        | < 100 ms         |
| Tool runner spawn latency       | < 500 ms         |
| Parser failure rate             | < 5%             |
| Policy deny enforcement rate    | 100%             |
| Audit chain verification        | 100% pass        |
| Process crash recovery time     | < 30s to resume  |

### 18.3 Backup and Restore
- **SQLite (lab):** `pwnpilot db backup` command runs `sqlite3 .backup` to a timestamped copy.
- **PostgreSQL (production):** `pg_dump` scheduled daily via cron; dumps stored outside the evidence directory.
- **Evidence filesystem:** Rsynced to a separate local path or cold storage. Evidence files are immutable so incremental rsync is safe.
- **Audit store:** Included in DB backup. The hash chain itself is the integrity guarantee; backup is for availability only.
- Restore procedure validated in CI on a quarterly cadence.

### 18.4 File Descriptor and Resource Limits
- On startup, the process attempts `resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))`. If the system hard limit is below 4096, this raises `ValueError`; the application catches it, logs a WARNING with the actual limit, and continues (it does not abort, since the system limit may still be sufficient for the expected concurrency level).
- `ThreadPoolExecutor` max_workers is bounded to prevent uncontrolled subprocess fan-out.
- Each tool subprocess inherits only the file descriptors it needs (`close_fds=True` in subprocess call, which is already the default in Python 3.2+; explicitly stated here for auditing purposes).
