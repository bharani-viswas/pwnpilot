# Detailed Implementation Plan: LLM-Driven Pentesting Framework

> Architecture document: [ARCHITECTURE.md](ARCHITECTURE.md)
> Status: **Sprint 1–9 COMPLETE** — 248 tests passing

## Implementation Progress Summary

| Sprint | Scope | Status | Notes |
|--------|-------|--------|-------|
| Sprint 1 (Week 1) | Schema foundation, scope validator, Pydantic v2 models, YAML schemas | ✅ COMPLETE | `models.py`, `engagement.py`, YAML schemas |
| Sprint 2 (Week 2) | Policy engine, approval service, audit store, data stores | ✅ COMPLETE | `policy.py`, `approval.py`, `audit_store.py`, `recon_store.py`, `finding_store.py`, `evidence_store.py` |
| Sprint 3 (Week 3) | LangGraph StateGraph, AgentState, agent nodes, action envelope | ✅ COMPLETE | `supervisor.py`, `planner.py`, `validator.py`, `executor.py`, `reporter.py`, `action_envelope.py`, `action_validator.py` |
| Sprint 4 (Week 4) | LLM router (circuit breaker), secrets vault, redactor, governance | ✅ COMPLETE | `llm_router.py`, `vault.py`, `redactor.py`, `kill_switch.py`, `authorization.py`, `simulation.py` |
| Sprint 5 (Week 5) | Plugin SDK, tool runner, Ed25519 trust, nmap/nuclei adapters | ✅ COMPLETE | `sdk.py`, `runner.py`, `trust.py`, `nmap.py`, `nuclei.py` |
| Sprint 6 (Week 6) | CLI, runtime factory, report generator, full test suite | ✅ COMPLETE | `cli.py`, `runtime.py`, `generator.py`, report template |
| Sprint 7 (Week 7) | ZAP, nikto, sqlmap, whatweb adapters + CVE enrichment | ✅ COMPLETE | `zap.py`, `nikto.py`, `sqlmap.py`, `whatweb.py`, `searchsploit.py`; 210 tests at 81.48% |
| Sprint 8 (Week 8) | SqliteCheckpointer, `pwnpilot resume`, correlation engine | ✅ COMPLETE | `checkpointer.py`, `resume_engagement()` fully implemented, `correlation.py`, `services_for_engagement()`; 13 new tests |
| Sprint 9 (Week 9) | Textual TUI, observability metrics, config management | ✅ COMPLETE | `config.py` (Pydantic v2, env-override, YAML), `observability/metrics.py` (EngagementMetrics + MetricsRegistry), `tui/app.py` (TUIDashboard + CLI `pwnpilot tui`); 25 new tests; **248 total tests** |
| Sprint 10 (Week 10) | Alembic migrations, PostgreSQL pool, hash-pinned deps | ✅ COMPLETE | `pwnpilot/migrations/` with Alembic `env.py` combining all 4 ORM bases; `alembic.ini`; initial migration covering all 5 tables; `requirements.txt` + `requirements-dev.txt` with SHA-256 hashes via pip-compile; 16 new tests; **264 total tests** |

### Gate G3 Status: ✅ PASSED (Sprint 10 complete)
- 264 unit / adversarial / contract tests passing (0 failures)
- Alembic `upgrade head` / `downgrade base` both verified on fresh SQLite DB
- Hash-pinned `requirements.txt` (2436 lines) and `requirements-dev.txt` (2776 lines)
- All known pending items resolved

### Known Pending Items
*None — all 10 sprints complete.*

## 1. Goal
Build a policy-first, agentic pentesting framework that is safe, auditable, and practical for authorized testing across:
- CTF/lab environments
- Web applications and APIs
- Internal network infrastructure
- IoT device ranges
- External perimeter assets

The system is a single-machine, **multi-agent**, human-in-the-loop for high-risk actions. A coordinated team of LLM-backed agents — **Planner, Validator, Executor, Reporter** — drives the engagement loop, implemented in **LangGraph** (a stateful graph-based orchestration library); the safety core governs every agent-to-agent and agent-to-tool boundary. Hybrid local-plus-cloud LLM routing operates under strict policy controls.

## 2. Guiding Principles
- Safety before capability: no unrestricted command execution.
- Evidence-first findings: every claim must be backed by raw tool evidence.
- Deterministic execution: typed actions and validated parameters only.
- Strong governance: immutable audit trails, explicit approvals, and scope constraints.
- Extensibility: plugin-based tool layer with standardized schemas.
- Agent isolation: agents communicate only through typed message schemas (`AgentState`); no agent can invoke a tool directly or access another agent's internal state.
- Local first: LLM inference is local by default; cloud is policy-gated and redacted before dispatch.

## 3. Scope and Non-Goals
### In Scope
- Single-node runtime
- Multi-agent loop (Planner → Validator → Executor → Reporter) implemented in LangGraph with typed `AgentState`
- Policy engine with approval gates
- Tool adapters (v1): nmap, nuclei, ZAP baseline, nikto, sqlmap, whatweb, whois, dnsutils, CVE/search enrichment
- Linux compatibility: Kali and Ubuntu LTS as first-class supported platforms
- Installer-driven dependency provisioning (security tools installed during setup)
- Recon/finding/evidence storage model
- JSON + human-readable reports with Ed25519 signing
- Resume/checkpoint and replay via LangGraph checkpointing (`SqliteCheckpointer` / `PostgresCheckpointer`)
- Structured logging (structlog), config management, and graceful shutdown


### Out of Scope
- Multi-tenant SaaS control plane
- Fully autonomous unrestricted exploitation
- Internet-exposed orchestration services


## 4. Reference Patterns to Adopt
- METATRON: iterative agentic loop and practical CLI-first orchestration
- Metasploit: module taxonomy and exploitation capability boundaries
- Nuclei: declarative template-driven action definitions
- OWASP ZAP: phased web scanning model and evidence handling
- Faraday: deduplication and correlation across tools
- MITRE CALDERA: ATT&CK-style planning taxonomy
- SpiderFoot: event-driven enrichment graph for recon entities
- LangGraph: stateful graph-based agent orchestration; chosen over AutoGen/CrewAI for explicit `StateGraph`, built-in checkpointing, and deterministic conditional-edge routing that maps directly onto the Observe→Plan→Validate→Execute→Parse→Update→Decide loop (see ADR-013)

## 5. Target Architecture
## 5.1 Control Plane
- Engagement Service
  - Defines scope: CIDRs, domains, URLs, IoT ranges
  - Rule of engagement (ROE), time windows, operator identity
  - `is_in_scope(target: str) -> bool` enforced by every downstream component before execution
  - Blocks instantiation if authorisation metadata is missing or expired
- Policy Engine
  - Action classes and default gates: `recon_passive` (allow, soft rate limit 60/min), `active_scan` (allow, hard token-bucket 10/min), `exploit` (requires_approval), `post_exploit` (requires_approval), `data_exfil` (deny)
  - Deny-by-default for unknown action classes
  - Rate limiting: `active_scan` token bucket is memory-resident, SQLite-backed for resume persistence; breach returns `PolicyDecision(verdict=DENY, reason=RATE_LIMIT_EXCEEDED)`
  - Checks token/tool budget limits; returns `PolicyDecision(verdict, reason, gate_type)`
- Agent Orchestrator (LangGraph `StateGraph`)
  - Multi-agent graph: Planner → Validator → Executor → Reporter nodes
  - Shared `AgentState` TypedDict flows through every node; each agent reads and writes a delta
  - Conditional edges: Validator verdict routes to Executor, back to Planner (reject), or halt; Executor routes to Planner (continue), Reporter (converged/max_iter), or END (kill_switch)
  - `max_iterations` hard cap; novelty check and repeated-state circuit breaker in Planner
  - Crash recovery via `SqliteCheckpointer` / `PostgresCheckpointer`; `pwnpilot resume <engagement_id>` restores last saved checkpoint
- LLM Router
  - Local-first inference (Ollama/vLLM); retry up to 3× with exponential backoff (base 1s, max 8s)
  - Circuit breaker: CLOSED → OPEN (after 3 consecutive local failures) → HALF_OPEN (after 60s cooldown) → CLOSED
  - Policy-gated cloud fallback; raises `PolicyDeniedError` if cloud policy is denied
  - **Multi-Provider Support via LiteLLM**: Supports 100+ providers (OpenAI, Claude, Gemini, Ollama, vLLM, LocalAI, Mistral, and more). Configuration: `model_name`, `api_key`, `api_base_url`. LiteLLM auto-detects provider.
  - Redactor scrubs all prompts before cloud dispatch; routing decision logged to audit store
  - Per-agent model config (e.g., planner: ollama/llama3; validator: ollama/mistral; fallback: gpt-4o-mini)
- Approval Service
  - Queue of pending high-risk actions with approve / deny / defer / annotate + reason
  - Tickets persisted to DB atomically on creation (survive process crash); PENDING state reloaded on startup
  - Lifecycle: PENDING → APPROVED | DENIED | DEFERRED | EXPIRED
  - Unresolved tickets expire after configurable TTL; all transitions written to audit store

## 5.2 Execution Plane
- Plugin SDK
  - Tool metadata, risk class, input schema, output schema, per-tool parser
  - `build_command()` must return `list[str]`; the runner raises `ValueError` on any string value (ADR-007)
  - Adapter manifest includes `checksum_sha256`; Ed25519 signature verified against trust store at load (ADR-006)
- Tool Runner
  - v1: `subprocess.run` with explicit arg list (`shell=False`), `resource` module CPU/memory limits, SIGKILL process-group timeout
  - v1.1 upgrade path: rootless Podman containers per invocation
  - stdout/stderr streamed in 64 KB chunks directly to Evidence Store (never fully buffered in memory)
  - Evidence size cap: 256 MB per action; subprocess killed and truncation recorded on breach
- Initial Adapters (v1)
  - nmap, nuclei, ZAP baseline, nikto, sqlmap, whatweb, whois, dnsutils, CVE/search enrichment

## 5.3 Data Plane
- Recon Store
  - Hosts, services, ports, technologies, graph relationships
  - SQLite in WAL mode (`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`) for lab; PostgreSQL (`QueuePool pool_size=5, max_overflow=10`) for production
- Findings Store
  - CVE/CWE, severity, confidence, exploitability (Exploitability enum: none | low | medium | high | functional | weaponized), remediation
  - Deduplication fingerprint: `hash(asset_ref + vuln_ref + tool_name)`
  - Status lifecycle: NEW → CONFIRMED → REMEDIATED | FALSE_POSITIVE
- Evidence Store
  - Raw stdout/stderr streamed to filesystem (`evidence/{engagement_id}/{evidence_id}.bin`)
  - Paths constructed from UUID components only; no user-controlled input enters path construction
  - SHA-256 computed incrementally during streaming write; stored in DB index
  - Immutable (write-once); deletion only via retention governance
- Audit Store
  - Append-only event stream; exclusive write lock per append
  - Hash chain: `prev_event_hash = SHA256(prev_event_payload)`
  - Checkpoint record every 500 events; enables parallel segment verification

## 5.4 UX Plane
- Operator TUI/CLI dashboard (Typer CLI + Textual TUI on a dedicated thread)
  - Live status, current action, pending approvals, policy blocks
  - All shared `AgentState` mutations occur only inside LangGraph node functions (main thread); TUI reads state as a view only
- Report Generator
  - JSON bundle (`report_<id>.json`) + Jinja2-rendered Markdown summary
  - Ed25519-signed bundle (`report.sig`); verifiable via `pwnpilot report verify <report.json> <report.sig>`
  - Reporter agent triggered by: `max_iterations` reached, 3 consecutive cycles with no new findings (convergence), or explicit `pwnpilot report now <engagement_id>` operator command

## 5.5 Multi-Agent Layer (LangGraph)
- **Planner** (`agent/planner.py`): reads recon_summary and previous_actions from `AgentState`; produces a `PlannerProposal`; performs novelty check; triggers repeated-state circuit breaker; uses largest local model (e.g. llama3)
- **Validator** (`agent/validator.py`): independent second-opinion `ValidationResult` (approve / reject / escalate); can raise risk level but never lower it below policy minimum; uses faster model (e.g. mistral)
- **Executor** (`agent/executor.py`): constructs typed `ActionRequest` from the proposal; calls Policy Engine (**only agent to do so**); calls Tool Runner on approval; writes evidence IDs and last_result to `AgentState`; appends audit events at each step
- **Reporter** (`agent/reporter.py`): builds and signs report bundle; triggers on convergence, max_iterations, or operator command; writes `ReportGenerated` audit event
- Agents communicate exclusively via `AgentState` TypedDict; no direct cross-agent function calls; enforced by module dependency rules
- Every agent invocation writes an `AgentInvoked` audit event with: `agent_name`, `input_state_hash`, `output_state_hash`, `llm_model_used`, `llm_routing_decision`, `duration_ms`

## 6. Data Contracts (Canonical — Pydantic v2, all include `schema_version: str = "v1"`)
## 6.1 ActionRequest
- action_id: UUID
- engagement_id: UUID
- action_type: ActionType enum (recon_passive | active_scan | exploit | post_exploit)
- tool_name: str
- params: dict — validated at model construction time via Pydantic `AfterValidator` calling `adapter.validate_params()`; invalid params fail model construction, never silently passed through
- expected_evidence: list[str]
- risk_level: RiskLevel enum (low | medium | high | critical)
- requires_approval: bool
- schema_version: str = "v1"

## 6.2 ToolExecutionResult
- action_id: UUID
- tool_name: str
- exit_code: int
- duration_ms: int
- stdout_hash: str (SHA-256)
- stderr_hash: str (SHA-256)
- parsed_output: dict — validated against adapter output_schema at construction time via `AfterValidator`
- parser_confidence: float (0.0–1.0)
- error_class: str | None (TIMEOUT | PARSE_ERROR | SCOPE_VIOLATION | ...)
- schema_version: str = "v1"

## 6.3 Finding
- finding_id: UUID
- engagement_id: UUID
- asset_ref: str
- title: str
- vuln_ref: str (CVE-XXXX-XXXX | CWE-XXX | custom)
- severity: Severity enum (info | low | medium | high | critical)
- confidence: float (0.0–1.0)
- exploitability: Exploitability enum (none | low | medium | high | functional | weaponized)
- cvss_vector: str | None (CVSS v3.1 vector string if available)
- evidence_ids: list[UUID]
- remediation: str
- status: FindingStatus enum (new | confirmed | remediated | false_positive)
- schema_version: str = "v1"

## 6.4 AuditEvent
- event_id: UUID
- engagement_id: UUID
- timestamp: datetime
- actor: str (planner | validator | executor | reporter | operator:<id> | system)
- event_type: str (AgentInvoked | ActionExecuted | ApprovalResolved | ReportGenerated | KillSwitchTriggered | PolicyDenied | ...)
- payload_hash: str (SHA-256)
- prev_event_hash: str (SHA-256)
- decision_context: dict | None
- schema_version: str = "v1"

## 6.5 PlannerProposal (inter-agent message via `AgentState`)
- action_type: str
- tool_name: str
- rationale: str (logged to audit)
- estimated_risk: str (low | medium | high | critical)
- rejection_reason: str | None (populated by Validator on reject; fed into the next Planner call)

## 6.6 ValidationResult (inter-agent message via `AgentState`)
- verdict: str (approve | reject | escalate)
- risk_override: str | None (if escalate: new risk level, always >= estimated_risk; Executor rejects downgrades)
- rationale: str (logged to audit store)

## 6.7 AgentState (LangGraph shared state `TypedDict`)
- engagement_id: str
- iteration_count: int
- max_iterations: int
- recon_summary: dict (snapshot from ReconStore)
- previous_actions: list[dict] (completed ActionRequest IDs + results)
- proposed_action: PlannerProposal | None
- validation_result: ValidationResult | None
- last_result: ToolExecutionResult | None
- evidence_ids: list[str]
- kill_switch: bool (set by SIGTERM/SIGINT handler or Planner repeated-state circuit breaker)
- report_complete: bool
- error: str | None

## 7. Security and Governance Model
## 7.1 Hard Controls
- Deny-by-default action policy; unknown action class is blocked automatically
- Scope enforcement (`is_in_scope()`) called before every action; denial is logged to audit store
- Tool parameter whitelist; `build_command()` must return `list[str]`; runner raises `ValueError` on string values (ADR-007)
- No shell interpolation from LLM output; all proposals parsed through `ActionEnvelope` schema validator before ActionRequest construction (ADR-002)
- Mandatory approval for exploit and post-exploit action classes
- Kill switch implemented as `threading.Event` (thread-safe); setting it writes a `KillSwitchTriggered` audit event atomically (ADR-009)
- Evidence file paths constructed from UUID components only; no user-controlled input in path construction (path traversal prevention)
- Approval tickets persisted to DB atomically before returning; all ticket state transitions are wrapped in a DB transaction
- `active_scan` rate-limited by per-engagement token bucket (default 10/min); hard block on breach with `PolicyDecision(verdict=DENY, reason=RATE_LIMIT_EXCEEDED)`
- LLM output never executed raw; parsed through typed ActionRequest with AfterValidator before any tool call

## 7.2 Soft Controls
- Token/tool budgets per run
- LLM Router backoff for repeated local failures (exponential: base 1s, max 8s; circuit breaker after 3 failures)
- Repeated-state circuit breaker in Planner; halts loop by setting `kill_switch=True` if no novel actions can be generated
- Convergence detection: Reporter is triggered after 3 consecutive Executor cycles yield no new findings
- Confidence thresholds: Validator can escalate risk level but never downgrade below policy engine minimum
- `recon_passive` soft rate limit (warns and logs on breach; does not block)

## 7.3 Data Privacy Controls
- Redactor (`secrets/redactor.py`) scrubs IPs, domains, credentials, and API keys from all LLM prompts before dispatch; applied to cloud fallback path and logged responses
- Secrets never passed to LLM Router; vault keys excluded from LLM context entirely
- Configurable residency policy for logs and evidence
- Optional local-only mode for restricted engagements (blocks cloud fallback at policy level)

## 8. Detailed Phase Plan
## Phase 0: Foundation and Threat Model (Week 1)
Deliverables:
- Threat model (prompt injection, command injection, scope bypass, parser poisoning)
- v1 requirements and acceptance criteria
- Architecture decision records for runtime, isolation, and datastore
Tasks:
1. Define engagement object and policy object schemas.
2. Define approval matrix by action class.
3. Define release gates and KPIs.
Exit Criteria:
- Stakeholders approve scope, threat model, and acceptance tests.

## Phase 1: Safety Core (Weeks 2-3)
Deliverables:
- Scope validator
- Policy engine
- Immutable audit layer
Tasks:
1. Implement scope parser for CIDR/domain/URL/device ranges.
2. Implement policy evaluation function with deny-by-default.
3. Implement approval ticket model and lifecycle.
4. Build append-only audit stream with chain integrity verification.
5. Unit-test out-of-scope and malformed actions.
Exit Criteria:
- 100% of out-of-scope actions blocked.
- All high-risk action requests require approvals.

## Phase 2: Multi-Agent Runtime and LLM Routing (Weeks 4-5)
Deliverables:
- LangGraph `StateGraph` with Planner, Validator, Executor, Reporter nodes and conditional edges
- `AgentState` TypedDict; `SqliteCheckpointer` for crash recovery and `pwnpilot resume` support
- `ActionEnvelope` structured output parser; all free-form LLM output rejected before ActionRequest construction
- **Multi-Provider LLM Router (via LiteLLM)** supporting 100+ providers: Ollama, vLLM, LocalAI, OpenAI, Claude, Gemini, and more
- Local-first inference with automatic retry, exponential backoff, and circuit breaker
- Policy-gated cloud fallback with redaction middleware
Tasks:
1. Define `AgentState` TypedDict; compile LangGraph `StateGraph` with four agent nodes.
2. Implement conditional edge routing: Validator verdict → Executor / Planner / halt; Executor result → Planner / Reporter / halt.
3. Add `max_iterations` cap, novelty check, and repeated-state circuit breaker in Planner node.
4. Implement `ActionEnvelope` parser; enforce typed `ActionRequest` construction (AfterValidator on params).
5. Build unified LLM Router with LiteLLM supporting local inference (Ollama/vLLM) and cloud providers with 3× retry and exponential backoff.
6. Implement circuit breaker: CLOSED → OPEN (after 3 consecutive failures) → HALF_OPEN → CLOSED (60s cooldown).
6. Build cloud fallback path with redaction middleware and policy gate.
7. Configure `SqliteCheckpointer`; validate crash-recovery via `pwnpilot resume <engagement_id>`.
Exit Criteria:
- End-to-end dry run with mock tools produces valid action/result/audit artifacts and `AgentInvoked` events.
- No free-form shell commands accepted; all proposals flow through typed `ActionRequest` schema.
- `pwnpilot resume` restores last LangGraph checkpoint successfully after simulated crash.

## Phase 3: Plugin Layer and Core Tool Adapters (Weeks 6-8)
Deliverables:
- Plugin SDK
- nmap/nuclei/ZAP/CVE adapters
Tasks:
1. Define plugin manifest and input/output schema contracts.
2. Implement runner isolation and resource quotas.
3. Implement parser modules and evidence extraction.
4. Add standardized error envelopes for failed tool runs.
5. Add replayable execution trace for each action.
Exit Criteria:
- Each adapter passes schema contract tests.
- Every tool output links to evidence artifacts.

## Phase 4: Correlation, Scoring, and Reporting (Weeks 9-10)
Deliverables:
- Correlation engine
- Risk score model
- Report generation pipeline
Tasks:
1. Build deduplication by asset + vulnerability fingerprint.
2. Correlate service/version to CVE and exploitability context.
3. Implement risk score formula: CVSS + exposure + confidence + criticality.
4. Generate JSON report bundle and human summary.
Exit Criteria:
- No duplicate findings in baseline regression datasets.
- Findings produced only with evidence references.

## Phase 5: Human Workflow and Operational UX (Week 11)
Deliverables:
- TUI/CLI operator console
- Approval queue
- Pause/resume/checkpoint support
Tasks:
1. Show action rationale and impact preview before approval.
2. Support approve, deny, defer, and annotate actions.
3. Add checkpoint snapshots and replay controls.
Exit Criteria:
- Operators can control and audit full run lifecycle.

## Phase 6: Validation and Hardening (Week 12)
Deliverables:
- Adversarial test suite
- Performance and reliability baselines
- Release readiness report
Tasks:
1. Run prompt-injection and parser-poisoning scenarios.
2. Run scope bypass and command-injection attempts.
3. Validate across target classes (CTF, web/API, infra, IoT, perimeter).
4. Measure false positives, run time, and policy compliance.
Exit Criteria:
- Release gates passed for safety, audit integrity, and finding quality.

## 9. Metrics and Release Gates
- Policy pass rate: 100% enforcement in test suite
- Audit integrity: 100% chain verification success
- Evidence coverage: 100% findings linked to artifacts
- False-positive threshold: agreed cap per target class
- Loop safety: zero infinite-loop incidents in stress tests
- Runtime SLA: baseline scan completion under defined limits

## 10. Engineering Backlog (Execution Order)
1. Engagement schema + scope validator
2. Policy engine + approval matrix
3. Immutable audit event bus
4. Orchestrator state machine
5. Action schema validator
6. LLM router (local-first + cloud fallback)
7. Plugin SDK
8. nmap adapter
9. nuclei adapter
10. ZAP baseline adapter
11. CVE/search enrichment adapter
12. Correlation and dedup engine
13. Reporting pipeline
14. TUI/CLI operator controls
15. Checkpoint/replay subsystem
16. Adversarial and regression test harness
17. Engagement authorization artifact capture
18. Secret and credential handling subsystem
19. Global kill switch and emergency stop handling
20. Plugin trust model (signing/checksums/version pinning)
21. Signed evidence and report bundle manifests
22. Data retention, legal hold, and secure deletion policy
23. Policy simulation mode (no-execution dry run)
24. Tool/template update governance and rollback controls
25. Observability metrics and tracing package
26. Schema versioning and migration framework
27. Structured logging setup (structlog JSONRenderer; engagement_id and action_id bound to every log record)
28. Config management system (config.yaml schema + Pydantic validation + `INTRUDER_` env var overrides)
29. Graceful shutdown and SIGTERM/SIGINT signal handling (`threading.Event`, 30s drain window, audit flush)
30. SQLite WAL mode and PostgreSQL connection pool configuration (QueuePool, session lifecycle)
31. Hash-pinned requirements (`pip --require-hashes`; all transitive dependencies pinned with SHA-256 hashes)
32. Backup and restore procedures (`pwnpilot db backup`, `pg_dump`, incremental evidence rsync)
33. Startup validation sequence (config schema, toolchain check, vault key, DB connectivity, Alembic migrations, plugin checksums)

## 11. Technology Stack (Definitive v1)

| Layer                    | Technology                                                   |
|--------------------------|--------------------------------------------------------------|
| Language                 | Python 3.11+                                                 |
| CLI                      | Typer (primary entry point)                                  |
| TUI                      | Textual (dedicated thread)                                   |
| API (optional)           | FastAPI                                                      |
| Data models              | Pydantic v2                                                  |
| Agent framework          | LangGraph 0.2+                                               |
| Database (lab mode)      | SQLite via SQLAlchemy (WAL mode)                             |
| Database (production)    | PostgreSQL via SQLAlchemy (QueuePool)                        |
| Migrations               | Alembic                                                      |
| Evidence storage         | Local filesystem + SHA-256 hash index                        |
| LLM local                | Ollama (llama3 / mistral)                                    |
| LLM cloud fallback       | Policy-gated OpenAI / Anthropic client                       |
| Tool isolation (v1)      | `subprocess` with `resource` module limits                   |
| Tool isolation (v1.1)    | Rootless Podman                                              |
| Secrets encryption       | `cryptography` (Fernet + MultiFernet key rotation)           |
| Report / plugin signing  | `cryptography` (Ed25519)                                     |
| Schema validation        | Pydantic v2 + jsonschema                                     |
| Structured logging       | structlog (JSONRenderer, stdout)                             |
| Testing                  | pytest + pytest-cov (coverage ≥ 80%)                         |
| Static analysis          | ruff · mypy                                                  |
| CI matrix                | GitHub Actions (Kali + Ubuntu 22.04 + Ubuntu 24.04)          |
| Dependency pinning       | pip `--require-hashes` (all transitive deps, SHA-256)        |
| Process supervision      | systemd (`scripts/pwnpilot.service`)                         |

## 11.1 Platform Compatibility Matrix (Required)
- OS targets:
  - Kali Linux rolling (latest stable)
  - Ubuntu LTS (22.04 and 24.04)
- CPU targets:
  - x86_64 required for v1
  - arm64 optional (best-effort until CI parity is added)
- Runtime assumptions:
  - sudo/root access during installation
  - outbound internet during first install for package retrieval
  - systemd available for optional background services

## 11.2 Installer-Managed Security Tool Dependencies
The installer must provision security tools ahead of first run and fail fast if dependencies cannot be installed.

Required toolchain (v1):
- Core runtime:
  - python3, python3-venv, python3-pip, git, curl, jq
- Recon/scanning tools:
  - nmap, nuclei, zaproxy, nikto, sqlmap, whatweb, whois, dnsutils
- Optional execution isolation:
  - podman or docker.io
- Ollama (local LLM inference server) installed and configured separately

Installer behavior:
1. Detect distro (Kali or Ubuntu) and package manager support.
2. Install apt dependencies in non-interactive mode.
3. Install Python dependencies in a dedicated virtual environment.
4. Verify installed tool versions and write a local dependency manifest.
5. Abort setup if required tools are missing after installation attempts.

## 11.3 Packaging and Installation Strategy
- Provide a single bootstrap entrypoint: scripts/install_security_tools.sh
- Provide a verification entrypoint: scripts/verify_toolchain.sh
- Ship a deterministic dependency list for apt packages and Python requirements.
- During CI, run installer and verifier on both Kali and Ubuntu images.

## 12. Immediate 7-Day Sprint Plan (✅ COMPLETED — Expanded to 6-Week Build)

> The original 7-day plan was expanded into 6 iterative implementation sprints. All items below are complete.

Day 1 ✅:
- Initialize repository structure, Linux installer scripts, and core domain models.
Day 2 ✅:
- Build and test scope validator + policy evaluator; run dependency verifier.
Day 3 ✅:
- Implement immutable audit events and verifier.
Day 4 ✅:
- Implement LangGraph agent graph (Planner, Validator, Executor, Reporter nodes with conditional edges) using mocked tools.
- `SqliteCheckpointer` integration pending (Sprint 8).
Day 5 ✅:
- Add action schema validation and deny malformed actions.
Day 6 ✅:
- Integrate local LLM path and cloud fallback with redaction stubs.
Day 7 ✅:
- Vertical slice complete: CLI entry point, runtime factory, report generator, 157 tests passing at 80% coverage.

## 12.1 Next Sprint Plan (Sprint 7)
- Implement ZAP baseline adapter (`plugins/adapters/zap.py`)
- Implement nikto adapter (`plugins/adapters/nikto.py`)
- Implement sqlmap adapter (`plugins/adapters/sqlmap.py`)
- Implement whatweb adapter (`plugins/adapters/whatweb.py`)
- Implement CVE search enrichment adapter (`plugins/adapters/cve_search.py`)
- Add contract tests for all new adapters
- Update pyproject.toml with any new adapter dependencies

## 13. Linux Installation Acceptance Criteria
- Fresh Kali install completes bootstrap without manual package intervention.
- Fresh Ubuntu LTS install completes bootstrap without manual package intervention.
- Post-install verifier confirms all required tools are available in PATH.
- Application startup hard-fails with clear guidance if toolchain is incomplete.

## 14. v1.1 Operational Hardening Features
- Engagement authorization artifacts
  - Persist authorization evidence for every engagement: approver identity, ticket/reference ID, validity window, and signed document hash.
  - Block execution if authorization metadata is missing or expired.
- Secret and credential handling
  - Store credentials and API tokens encrypted at rest.
  - Use short-lived scoped tokens for adapters where possible.
  - Redact secrets from logs, audit payloads, and evidence exports.
- Emergency stop and deterministic cleanup
  - Implement a global kill switch to halt queued and running actions.
  - Record stop reason and cleanup outcomes as audit events.
- Plugin trust and supply chain control
  - Require pinned versions and checksum/signature verification before plugin/adaptor load.
  - Deny execution for untrusted or tampered plugin bundles.
- Evidence non-repudiation for exports
  - Sign report bundles and evidence manifests.
  - Verify signatures during replay/import workflows.
- Data lifecycle governance
  - Define retention TTL by engagement classification.
  - Add legal hold mode and secure deletion workflows.
- Policy-as-code simulation
  - Add dry-run policy simulation mode that returns decisions without tool execution.
  - Use simulation in preflight checks for ROE and policy updates.
- Tool/template update governance
  - Add update channels for nuclei templates and scanner rule packs.
  - Require compatibility checks and rollback paths.
- Observability and reliability telemetry
  - Track policy deny rate, approval latency, parser error rate, timeout rate, and tool failure taxonomy.
  - Expose structured metrics/logs for release hardening and SLO checks.
- Schema evolution strategy
  - Version all core contracts (action, finding, audit, evidence).
  - Provide forward/backward migration rules for resume/replay compatibility.
- Structured logging (structlog JSONRenderer)
  - All log output is newline-delimited JSON with `engagement_id` and `action_id` bound to every record.
  - Log levels per component enforced; secrets, unredacted prompts, and evidence file paths never logged.
  - File rotation via `TimedRotatingFileHandler` (daily, 30-day retention) when `INTRUDER_LOG_FILE` is set.
- Config management system
  - Primary config: `config.yaml` (TOML also accepted); location resolved via `$PWNPILOT_CONFIG`, `./config.yaml`, `~/.pwnpilot/config.yaml`.
  - All config keys overridable via `INTRUDER_` env vars (nested keys use `__` separator).
  - Config validated against Pydantic schema on startup; hard fail with clear error if required fields missing.
- Graceful shutdown
  - SIGTERM and SIGINT set a `threading.Event` flag; main thread polls at top of each loop iteration.
  - 30s drain window for in-flight tool subprocesses; overflow processes sent `SIGKILL` to process group.
  - All pending audit events flushed to DB before `sys.exit(0)` (never called inside signal handler).
  - systemd unit file provided (`scripts/pwnpilot.service`); `Restart=on-failure`, `RestartSec=5s`.
- Dependency supply chain hardening
  - `requirements.txt` uses `--require-hashes` format; all transitive dependencies pinned with SHA-256 hashes (ADR-011).
  - Installation fails if any hash does not match; no silent package substitution.

Exit Criteria:
- Authorization, secret safety, and emergency stop controls are verified in integration tests.
- Exported evidence/report bundles pass signature verification.
- Policy simulation and schema migration tests pass in CI.
- Structured logging, config validation, and graceful shutdown verified in integration tests.
- `requirements.txt` hash verification passes on clean install; unsigned plugins blocked in production mode.

## 15. Risks and Mitigations
- Risk: LLM hallucinated actions
  - Mitigation: `ActionEnvelope` struct parser; typed `ActionRequest` with Pydantic AfterValidator; proposals never executed raw.
- Risk: scope bypass
  - Mitigation: `is_in_scope()` called by policy engine before every action; deny-by-default blocks unknown action classes.
- Risk: parser fragility
  - Mitigation: adapter contract tests; standardised error envelopes; parser_confidence score; fallback parser for partial payloads.
- Risk: noisy findings
  - Mitigation: fingerprint-based deduplication; evidence confidence thresholds; convergence detection reduces tail-end iterations.
- Risk: operator overload
  - Mitigation: risk-tiered approval gates; concise rationale + impact preview per ticket; convergence detection minimises unnecessary approvals.
- Risk: credential leakage via LLM context
  - Mitigation: redactor scrubs IPs, domains, credentials, and API keys from all prompts before dispatch; vault secrets excluded from LLM Router entirely.
- Risk: audit log tampering
  - Mitigation: append-only store with SHA-256 hash chain; exclusive write lock per append; no update/delete API exposed.
- Risk: resource exhaustion (DoS via large tool output)
  - Mitigation: 256 MB evidence size cap per action; stdout/stderr streamed without full buffering; subprocess killed and truncation recorded on breach.
- Risk: runaway loop / infinite iteration
  - Mitigation: `max_iterations` hard cap; novelty check in Planner; repeated-state circuit breaker; convergence detection triggers Reporter after 3 empty cycles.
- Risk: supply chain (tampered plugin)
  - Mitigation: Ed25519 signature verification against trust store at plugin load; `PluginTrustError` raised on invalid/missing signature; `INTRUDER_DEV_ALLOW_UNSIGNED=1` blocked in production.
- Risk: stale engagement authorisation
  - Mitigation: authorisation expiry check on every `Orchestrator.run()` call; execution halted with clear error if expired.
- Risk: kill switch race condition
  - Mitigation: `threading.Event` (not a plain boolean); safe to set and check from any thread; SIGTERM/SIGINT handler calls only `Event.set()` (async-signal-safe).

## 16. Definition of Done (v1)
- Core workflow executes safely end-to-end.
- Policy and approval gates are always enforced.
- Audit logs are immutable and verifiable.
- Findings are evidence-backed and reproducible.
- Core tool adapters are stable and tested.
- Validation suite passes agreed release gates.

## 17. Implementation-Ready Delivery Plan

This section converts the strategy above into an execution plan that can be started immediately with clear workstreams, dependencies, and release gates.

### 17.1 Team Topology and Ownership
- Workstream A: Safety and Governance Core
  - Scope validator, policy engine, approvals, audit chain.
  - Primary owner: Backend engineer.
- Workstream B: Agent Runtime and Tooling
  - LangGraph agent graph (Planner/Validator/Executor/Reporter), plugin SDK, tool runner isolation, adapters.
  - Primary owner: Platform engineer.
- Workstream C: Data and Reporting
  - Recon/finding/evidence stores, dedup, scoring, report pipeline.
  - Primary owner: Data/backend engineer.
- Workstream D: Operator Experience and Release Quality
  - CLI/TUI, checkpoint/replay, adversarial tests, CI matrices.
  - Primary owner: QA/release engineer.

Execution rule:
- Each workstream must produce testable artifacts every week.
- No feature merges without associated tests and policy impact notes.

### 17.2 Milestone Plan (12 Weeks)

Milestone M1 (Weeks 1-2): Safety Baseline
- Deliverables:
  - Engagement schema and scope validator.
  - Deny-by-default policy engine with approval matrix.
  - Append-only audit events with hash-chain verifier.
- Hard acceptance:
  - Out-of-scope action block rate = 100% in test suite.
  - Audit chain verification passes for all generated events.

Milestone M2 (Weeks 3-4): Multi-Agent Skeleton
- Deliverables:
  - LangGraph `StateGraph` with Planner, Validator, Executor, Reporter nodes and conditional edges.
  - `AgentState` TypedDict; `SqliteCheckpointer` for crash recovery.
  - `ActionEnvelope` schema validator; all free-form LLM output rejected before `ActionRequest` construction.
  - Local LLM route (Ollama/vLLM) with retry and exponential backoff; LLM circuit breaker.
  - Policy-gated cloud fallback with redaction; per-agent model configuration.
- Hard acceptance:
  - Mock end-to-end run produces valid action/result/audit artifacts and `AgentInvoked` events.
  - No shell string execution path exists in runtime.
  - `pwnpilot resume <engagement_id>` restores last LangGraph checkpoint successfully after simulated crash.

Milestone M3 (Weeks 5-7): Tool Execution Plane
- Deliverables:
  - Plugin SDK contracts with Ed25519 trust store signature verification.
  - Isolated tool runner with time, CPU, and memory resource limits; 64 KB streaming evidence writes.
  - nmap, nuclei, ZAP baseline, nikto, sqlmap, whatweb, whois, dnsutils, and CVE enrichment adapters with per-tool parsers.
- Hard acceptance:
  - Adapter contract tests pass for all nine adapters.
  - Evidence references are generated for all findings.
  - Unsigned or checksum-mismatched plugins are rejected at load time.

Milestone M4 (Weeks 8-9): Correlation and Reporting
- Deliverables:
  - Finding deduplication and correlation engine.
  - Risk scoring implementation.
  - JSON + human-readable report bundle generation.
- Hard acceptance:
  - Regression dataset produces zero duplicate findings.
  - Reports are reproducible from replay.

Milestone M5 (Weeks 10-11): Operator Control and Hardening
- Deliverables:
  - Approval queue UX (approve/deny/defer/annotate).
  - Pause/resume/checkpoint/replay.
  - Kill switch and deterministic cleanup flow.
- Hard acceptance:
  - Full run lifecycle controllable by operator.
  - Kill switch stops queued and active actions and logs outcomes.

Milestone M6 (Week 12): Release Qualification
- Deliverables:
  - Adversarial suite and reliability baseline report.
  - Signed release report and open-risk register.
- Hard acceptance:
  - Policy, audit, and evidence release gates are all green.

### 17.3 Dependency Graph (Critical Path)
1. Engagement schema -> scope validator -> policy evaluator.
2. Policy evaluator -> approval service -> orchestrator execution gate.
3. Action schema validator -> plugin SDK -> tool adapters.
4. Tool execution results -> parser outputs -> evidence store.
5. Evidence + findings -> dedup/correlation -> reporting.
6. Reporting + audit stream -> release qualification.

Critical path rule:
- Do not start full adapter integration before schema validator and policy gates are passing in CI.

### 17.4 Implementation Backlog by Sprint (Ready to Execute)

Sprint 1 (Week 1)
- Define canonical schemas for engagement, policy, action, result, finding, and audit.
- Implement schema validation layer and negative test fixtures.
- Implement scope parsing for CIDR/domain/URL/device range targets.

Sprint 2 (Week 2)
- Implement deny-by-default policy evaluator.
- Implement approval ticket lifecycle and storage.
- Implement append-only audit writer and chain verifier.

Sprint 3 (Week 3)
- Define `AgentState` TypedDict and compile LangGraph `StateGraph` with Planner, Validator, Executor, Reporter nodes.
- Implement conditional edge routing (Validator verdict → Executor / Planner / halt; Executor result → Planner / Reporter / halt).
- Add `max_iterations` cap, novelty check, and repeated-state circuit breaker in Planner node.
- Implement `ActionEnvelope` parser; enforce typed `ActionRequest` construction with Pydantic AfterValidator on params.
- Configure `SqliteCheckpointer`; validate crash-recovery via `pwnpilot resume`.

Sprint 4 (Week 4)
- Integrate local model invocation (Ollama/vLLM) with 3× retry and exponential backoff (base 1s, max 8s).
- Implement LLM circuit breaker (CLOSED → OPEN → HALF_OPEN → CLOSED); log routing decision to audit store.
- Add policy-gated cloud fallback path with redaction middleware.
- Add policy simulation mode for no-execution decision tests.
- Set up structlog with JSONRenderer; bind `engagement_id` and `action_id` context to every log record.
- Implement `config.yaml` schema with Pydantic validation and `INTRUDER_` env var overrides.
- Register SIGTERM/SIGINT handlers (`threading.Event`); implement 30s drain window and audit event flush on shutdown.

Sprint 5 (Week 5)
- Implement plugin manifest contracts.
- Implement isolated tool runner (timeouts, memory, CPU budget).
- Add standardized tool error envelopes.

Sprint 6 (Week 6)
- Implement nmap and nuclei adapters with parser modules.
- Persist raw stdout/stderr with hashes to evidence store.
- Add adapter contract tests.

Sprint 7 (Week 7)
- Implement ZAP baseline and CVE enrichment adapters.
- Add replay trace generation for every action.
- Add failure taxonomy metrics.

Sprint 8 (Week 8)
- Build finding fingerprinting and dedup logic.
- Build service/version to vulnerability correlation logic.
- Implement risk scoring formula and unit tests.

Sprint 9 (Week 9)
- Generate machine-readable report bundle and human summary.
- Add evidence manifest signing and verification.
- Add report consistency tests across replayed runs.

Sprint 10 (Week 10)
- Implement operator approval queue and rationale preview.
- Implement checkpoint save/load and resume controls.
- Implement global kill switch and cleanup flow.

Sprint 11 (Week 11)
- Add secrets management flow and redaction validation tests.
- Add retention TTL, legal hold, and secure delete operations.
- Add plugin trust checks (checksum/signature/version pin).

Sprint 12 (Week 12)
- Run adversarial suite and policy bypass scenarios.
- Run cross-target validation benchmarks.
- Produce release readiness report and unresolved-risk list.

### 17.5 CI/CD and Quality Gates (Blocking)
- Gate G1: Lint and static checks pass.
- Gate G2: Unit tests pass with coverage ≥ 80% (enforced via `--cov-fail-under=80` in `pyproject.toml`).
- Gate G3: Contract tests pass for all adapters.
- Gate G4: Security tests pass (scope bypass, injection, parser poisoning).
- Gate G5: Audit chain integrity verification passes.
- Gate G6: Evidence coverage check passes (all findings have evidence IDs).
- Gate G7: Kali and Ubuntu installer plus verifier jobs pass.

Merge policy:
- Pull request merges require G1-G4.
- Release candidate tags require G1-G7.

### 17.6 Test Matrix (Minimum)
- Target classes:
  - CTF/lab
  - Web/API
  - Internal infra
  - IoT range
  - External perimeter
- OS matrix:
  - Kali latest stable
  - Ubuntu 22.04 LTS
  - Ubuntu 24.04 LTS
- Modes:
  - Local-only LLM
  - Local + cloud fallback
  - Policy simulation (no execution)

Success criteria:
- No out-of-scope execution events.
- No unsigned report/evidence export.
- No findings without linked evidence.

### 17.7 Operational Runbooks Required Before v1 Tag
- Runbook R1: Engagement creation and authorization validation.
- Runbook R2: Approval queue handling and escalation rules.
- Runbook R3: Emergency stop and recovery.
- Runbook R4: Checkpoint/replay and incident reconstruction.
- Runbook R5: Dependency bootstrap and verifier troubleshooting.
- Runbook R6: Data retention and legal hold procedures.

### 17.8 v1 Exit Checklist (Implementation Ready)
- All milestones M1-M6 meet hard acceptance.
- All release gates G1-G7 are green in CI.
- Installer and verifier pass on Kali and Ubuntu.
- Adversarial suite has no critical safety failures.
- Operational runbooks R1-R6 are reviewed and approved.

---

## 18. Production Readiness

### 18.1 Gap Register (All Resolved in Architecture)

| ID  | Severity | Gap Description                                           | Resolution              |
|-----|----------|-----------------------------------------------------------|-------------------------|
| G01 | CRITICAL | No concurrency model; orchestrator loop not thread-safe   | §5.5 / ADR-008          |
| G02 | CRITICAL | Approval tickets not crash-durable (in-memory only)       | §5.1 Approval Service   |
| G03 | CRITICAL | LLM router has no retry/backoff/circuit breaker           | §5.1 LLM Router         |
| G04 | CRITICAL | Kill switch used plain boolean (not thread-safe)          | §7.1 / ADR-009          |
| G05 | CRITICAL | stdout/stderr buffered in memory (OOM risk)               | §5.2 Tool Runner        |
| G06 | CRITICAL | ActionRequest.params is untyped dict (bypass risk)        | §6.1 AfterValidator     |
| G07 | HIGH     | No crash recovery / resume on process restart             | §5.1 LangGraph ckpt     |
| G08 | HIGH     | SQLite WAL mode not specified (deadlock under concurrency) | §5.3 Recon Store        |
| G09 | HIGH     | No DB connection pooling / session lifecycle              | §5.3 Recon Store        |
| G10 | HIGH     | Fernet key rotation strategy missing                      | §14 / ADR-012           |
| G11 | HIGH     | Plugin trust root (who signs, key distribution) undefined | §5.2 Plugin SDK         |
| G12 | HIGH     | Rate limiting implementation not specified                | §5.1 Policy Engine      |
| G13 | HIGH     | Audit chain full-replay O(n); no scalability bound        | §5.3 Audit Store        |
| G14 | HIGH     | No config management system                               | §14 Config Management   |
| G15 | HIGH     | No structured logging strategy                            | §14 Structured Logging  |
| G16 | HIGH     | No graceful shutdown / SIGTERM handling                   | §14 Graceful Shutdown   |
| G17 | MEDIUM   | No process supervision (systemd)                          | §14 / ADR-009           |
| G18 | MEDIUM   | Evidence file path traversal risk not addressed           | §5.3 Evidence Store     |
| G19 | MEDIUM   | No requirements hash-pinning                              | §14 / ADR-011           |
| G20 | MEDIUM   | No health check / liveness validation on startup          | §14 Startup Validation  |
| G21 | MEDIUM   | No SLO / error budget values defined                      | §18.2 below             |
| G22 | MEDIUM   | Redactor is pattern-only; novel secrets may leak          | §7.3 (known limitation) |
| G23 | MEDIUM   | No backup/restore strategy for data stores                | §18.3 below             |
| G24 | MEDIUM   | No file descriptor limit management for subprocesses      | §18.4 below             |

### 18.2 SLO Baselines (Minimum for Production Tag)

| SLO                              | Target                |
|----------------------------------|-----------------------|
| Policy evaluation latency p99    | < 50 ms               |
| Approval ticket persist latency  | < 200 ms              |
| Audit append latency p99         | < 100 ms              |
| Tool runner spawn latency        | < 500 ms              |
| Parser failure rate              | < 5%                  |
| Policy deny enforcement rate     | 100%                  |
| Audit chain verification         | 100% pass             |
| Process crash recovery time      | < 30s to resume       |
| Unit test coverage               | ≥ 80%                 |

### 18.3 Backup and Restore
- **SQLite (lab):** `pwnpilot db backup` runs `sqlite3 .backup` to a timestamped copy.
- **PostgreSQL (production):** `pg_dump` scheduled daily; dumps stored outside the evidence directory.
- **Evidence filesystem:** Incremental rsync to a separate local path; evidence files are immutable so rsync is safe.
- **Audit store:** Included in DB backup; hash chain is the integrity guarantee; backup is for availability.
- Restore procedure validated in CI on a quarterly cadence.

### 18.4 File Descriptor and Resource Limits
- On startup, the process attempts `resource.setrlimit(RLIMIT_NOFILE, (4096, 4096))`.
- If the system hard limit is below 4096, a `WARNING` is logged with the actual limit; the application does not abort.
- `ThreadPoolExecutor` max_workers bounded to prevent uncontrolled subprocess fan-out.

### 18.5 Architecture Decision Records (Summary)

| ADR | Decision                                                                          |
|-----|-----------------------------------------------------------------------------------|
| 001 | Deny-by-default policy engine; unknown action class = blocked                     |
| 002 | Structured action envelope (no free-form shell); `build_command()` returns list   |
| 003 | Append-only audit with SHA-256 hash chain                                         |
| 004 | Local-first LLM with redacted cloud fallback                                      |
| 005 | SQLite for lab, PostgreSQL for production; SQLAlchemy abstraction                 |
| 006 | Plugin manifest with checksum verification at load                                |
| 007 | `runner.py` raises `ValueError` if `build_command()` returns a string             |
| 008 | Thread-based concurrency (not asyncio); `ThreadPoolExecutor` for tool subprocesses |
| 009 | SIGTERM/SIGINT set `threading.Event`; graceful 30s drain before `sys.exit(0)`    |
| 010 | structlog with JSONRenderer; `INTRUDER_LOG_LEVEL` env var for log level           |
| 011 | pip `--require-hashes`; all transitive deps pinned with SHA-256 hashes            |
| 012 | Fernet `MultiFernet` for zero-downtime vault key rotation                         |
| 013 | LangGraph as agent framework (over AutoGen/CrewAI); explicit StateGraph + checkpointing |
| 014 | Validator agent as independent LLM second-opinion; can escalate but never downgrade |
| 015 | Reporter triggered by convergence (3 empty cycles), max_iterations, or operator command |
