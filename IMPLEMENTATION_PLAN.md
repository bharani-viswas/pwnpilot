# PwnPilot Implementation Plan

## Known Issues & Fixes

Issues discovered via post-mortem analysis of engagements `22cde589` and `d62ca713` against OWASP Juice Shop (`http://localhost:3000`).

---

### FIXED

#### Fix 1 — Nikto 300s timeout cuts scans short
- **File:** `pwnpilot/plugins/adapters/nikto.py`
- **Problem:** Default `maxtime` was 300 seconds. Nikto exited mid-scan with `ERROR: Host maximum execution time of 300 seconds reached`.
- **Fix Applied:** Increased `maxtime` default from 300 → 600 seconds in both the schema default and `validate_params` fallback.
- **Status:** ✅ Fixed (2026-04-14)

---

#### Fix 2 — WhatWeb always marked `DEGRADED` (false positive)
- **File:** `pwnpilot/plugins/runner.py` — `_classify_outcome()`
- **Problem:** The runner's final fallback rule `if new_findings_count == 0 and exit_code == 0 → DEGRADED / NoActionableOutput` fired on WhatWeb because fingerprinting tools produce `services`/`technologies`, not `findings`. WhatWeb could never achieve `OutcomeStatus.SUCCESS`, preventing it from counting toward `min_successful_tool_families` and `min_evidence_artifacts` readiness gates.
- **Fix Applied:** The fallback now checks for non-empty `services`, `hosts`, `technologies`, or `routes` in parsed output before marking `DEGRADED`. Tools producing structured non-finding output are correctly classified as `SUCCESS`.
- **Status:** ✅ Fixed (2026-04-14)

---

#### Fix 3 — ZAP false `AuthFailure` from scan output
- **File:** `pwnpilot/plugins/runner.py` — `_classify_outcome()`
- **Problem:** Auth failure detection scanned the combined stdout+stderr blob. ZAP reports target URL responses (e.g. `(403 Forbidden)`) in its stdout findings output, causing a false `AUTH_FAILURE` classification on an otherwise successful ZAP scan.
- **Fix Applied:** Auth failure detection now only inspects `stderr`. HTTP status codes appearing in tool scan output (stdout) no longer trigger false positives.
- **Status:** ✅ Fixed (2026-04-14)

---

#### Fix 4 — `evidence_ids` never accumulated in agent state
- **File:** `pwnpilot/agent/executor.py` — `ExecutorNode.__call__()`
- **Problem:** The executor returned `"evidence_ids": state.get("evidence_ids", [])` — passing through the existing list unchanged and never appending the new `stdout_evidence_id` / `stderr_evidence_id` from each tool result. The readiness policy gate `min_evidence_artifacts` checked `len(evidence_ids)` which was always 0, causing every engagement to be marked `completed_with_degradation`.
- **Fix Applied:** The executor now appends `result.stdout_evidence_id` and `result.stderr_evidence_id` to the accumulated `evidence_ids` list after each tool run.
- **Status:** ✅ Fixed (2026-04-14)

---

### OPEN

#### Issue 1 — Planner circuit breaker kills engagement instead of routing to reporter
- **File:** `pwnpilot/agent/planner.py` — `_MAX_REPEATED_STATE = 3`, line ~43
- **Problem:** When the LLM re-proposes the same `(tool, target, action_type)` triple 3 times consecutively (e.g. re-proposing nikto after it timed out), the circuit breaker sets `kill_switch=True` and terminates the entire engagement with no report generated. Engagement `22cde589` was killed at iteration 13 this way.
- **Root cause:** The timeout hint emitted by nikto (`"execution_error"`) is not in `_LOW_VALUE_HINT_CODES`, so the planner doesn't suppress re-proposals. The LLM lacks enough context to pivot to a different tool.
- **Options:**
  - Add `"execution_error"` to `_LOW_VALUE_HINT_CODES` so repeated proposals after a timeout are suppressed.
  - Route to reporter instead of halting when the breaker fires (`kill_switch` → `force_report`).
  - Increase `_MAX_REPEATED_STATE` to give the LLM more chances to recover first.
- **Priority:** High — causes silent engagement termination with no findings report.

---

#### Issue 2 — sqlmap targets SPA root instead of REST API endpoints
- **File:** LLM planner context / `pwnpilot/plugins/adapters/sqlmap.py`
- **Problem:** The LLM passes `http://localhost:3000` with `forms=True` to sqlmap. Juice Shop is an Angular SPA; its forms are JavaScript-rendered. sqlmap's static HTML crawler finds zero forms and exits: `[CRITICAL] there were no forms found at the given target URL`.
- **Root cause:** The planner does not surface known REST API paths (discovered by ZAP/gobuster) to sqlmap as direct injection targets.
- **Options:**
  - The planner should pass a specific endpoint (e.g. `http://localhost:3000/rest/user/login`) with an explicit `data` POST body when calling sqlmap against SPAs.
  - Add attack surface endpoint propagation from ZAP findings to sqlmap parameters in the executor's feedback loop.
- **Priority:** Medium — sqlmap produces no results against Juice Shop in current form.

---

#### Issue 3 — Gobuster can't filter SPA wildcard responses
- **File:** `pwnpilot/plugins/adapters/gobuster.py`
- **Problem:** Juice Shop (Angular SPA) returns HTTP 200 for every URL path. Gobuster without `--exclude-length` treats all responses as valid and reports hundreds of false "discovered paths". The adapter has no parameter for `--exclude-length` (`-bl`), so the LLM cannot instruct gobuster to filter by response body size.
- **Fix needed:** Add an `exclude_length` (integer) parameter to `GobusterAdapter.validate_params()` and `build_command()` that passes `-bl <size>` to gobuster when provided.
- **Priority:** Medium — gobuster results are currently meaningless against SPAs.

---

#### Issue 4 — Findings stored with empty `evidence_ids` backlinks
- **File:** `pwnpilot/agent/executor.py` line ~722
- **Problem:** `finding_store.upsert()` is always called with `evidence_ids=[]` (hardcoded). Even though evidence is now correctly accumulated in state (Fix 4 above), the per-finding evidence backlinks are never populated in the database.
- **Fix needed:** Pass `updated_evidence_ids` (or the specific evidence IDs from the current tool run) when calling `finding_store.upsert()`.
- **Priority:** Low — findings are stored correctly; only the backlink is missing.

---

#### Issue 5 — Gobuster confidence score inflated on wildcard noise
- **File:** `pwnpilot/plugins/adapters/gobuster.py` — `parse()` method
- **Problem:** When `-fw` (force-wildcard) is active and produces hundreds of false-positive 200 paths, the parser assigns `confidence=0.85` because `findings > 0`. This misleads the planner into treating unreliable wildcard results as authoritative path discovery.
- **Fix needed:** Lower `confidence` to 0.4–0.5 when `wildcard_detected` hint is present alongside findings.
- **Priority:** Low — cosmetic but misleads planner strategy.

---

## Dead / Partially-Implemented Features

Discovered via comprehensive codebase wiring audit (2026-04-14). Each feature has working implementation code but is not reached by any live execution path.

---

### ✅ Issue 6 — `reflect()` method on LLMRouter is unreachable (indentation bug) — FIXED (2026-04-14)

- **File:** `pwnpilot/control/llm_router.py` — line 249
- **Root cause:** `reflect()` is defined with double-indent as a *nested function inside `plan()`*, not as a class method. It does not exist on `LLMRouter` instances. The planner guards the call with `hasattr(self._llm, "reflect")` (`planner.py` line 1214), which always evaluates `False`, so the defaultfallback path is always taken instead of the intended LLM reflector.
- **Impact:** Reject-churn recovery never uses the LLM. When the validator repeatedly rejects the same reason, the planner falls back to a deterministic candidate list instead of getting an LLM-guided pivot-or-terminate decision. This leads to more churn before the supervisor escalates.
- **Fix needed:**
  1. In `pwnpilot/control/llm_router.py`, un-nest `reflect()` from inside `plan()`: the method body starting at line 249 needs to be de-indented to class-method level (one level of indentation, not two).
  2. Update system-prompt indentation to match.
  3. Add a test asserting `hasattr(LLMRouter(...), "reflect")` is `True`.
- **Priority:** High — causes the reflector LLM call to be silently skipped on every engagement.

---

### ✅ Issue 7 — TUI `pwnpilot tui` command does not receive live events or operator session — FIXED (2026-04-14)

- **File:** `pwnpilot/cli.py` — `cmd_tui()` line 584; `pwnpilot/tui/app.py` — `run_dashboard()` line 568
- **Root cause:** `cmd_tui()` calls `run_dashboard(engagement_id=engagement_id, refresh_interval=refresh)` without passing `event_bus` or `operator_session`. `TUIDashboard` only subscribes to live execution events when `event_bus is not None and engagement_id is set` (line 416). Without this, live output, approval push, guided mode toggle, and the operator input panel are all inert.
- **Impact:** The TUI shows only stale metrics-registry data polled on a timer. Real-time tool output, policy denials, approvals, and operator guidance (the primary TUI value propositions) are non-functional.
- **Fix needed:**
  1. In `pwnpilot/runtime.py`, expose a `get_event_bus_and_session(engagement_id)` helper that returns the per-engagement `ExecutionEventBus` and `OperatorSessionManager` from the runtime dict (or a lightweight per-engagement registry).
  2. In `pwnpilot/cli.py` `cmd_tui()`, call this helper and pass `event_bus` and `operator_session` to `run_dashboard()`.
  3. Add a per-engagement session registry (dict keyed by engagement UUID) to `_build_runtime` and expose it for TUI lookup.
- **Priority:** High — TUI guided/live features are completely non-functional without this wiring.

---

### ✅ Issue 8 — `ActionEnvelope` and `ActionValidator` safety gates are orphaned — FIXED (2026-04-14)

- **File:** `pwnpilot/agent/action_envelope.py`; `pwnpilot/agent/action_validator.py`
- **Root cause:** `parse_action_envelope()` and `ActionValidator.validate()` have zero call sites outside their own files. The executor directly constructs `ActionRequest` from the planner proposal dict without passing through either gate. The docstring claims "no LLM output is ever executed without passing through this parser (ADR-002)" — but in practice, it is not called.
- **Impact:** The intended LLM-output structural gate is bypassed. Invalid or malformed action types could reach the tool runner without envelope-level rejection. This is a security-relevant gap (against ADR-002).
- **Fix needed:**
  1. In `pwnpilot/agent/executor.py` `ExecutorNode.__call__()`, after deserialising `proposal_dict`, call `parse_action_envelope(json.dumps(proposal_dict))` (or equivalent struct validation) before constructing `ActionRequest`.
  2. Alternatively wire `ActionValidator(adapters=rt["adapters"])` into `ExecutorNode.__init__()` and call `self._validator.validate(action)` before the policy engine call.
  3. Do not add both — pick one gate; the `ActionValidator` path is more Pythonic since `ActionEnvelope` duplicates pydantic validation already done in `ActionRequest`.
- **Priority:** Medium — not currently causing failures (pydantic `ActionRequest` catches most issues), but is a stated architectural invariant that should be true.

---

### ✅ Issue 9 — Shell `permission_context` is always empty; runtime-granted permissions never checked — FIXED (2026-04-14)

- **File:** `pwnpilot/plugins/adapters/shell.py` — `__init__` line 98; `pwnpilot/runtime.py` line 490; `pwnpilot/plugins/loader.py` line 107
- **Root cause:**
  - The plugin loader instantiates all adapters with `adapter = adapter_cls()` (no arguments). `ShellAdapter.__init__` accepts `permission_context` to allow runtime-approved commands, but loader always passes nothing.
  - In the static fallback in `runtime.py`, `ShellAdapter()` is also constructed without context.
  - `PermissionStore` is instantiated in `_build_runtime` and stored in the runtime dict but is never passed anywhere.
- **Impact:** The `has_permission()` branch in `ShellAdapter.validate_params()` is unreachable. Shell command allow-list expansion via operator approval is effectively disabled.
- **Fix needed:**
  1. In `pwnpilot/runtime.py`, after building `tool_runner`, retrieve the `shell` adapter from `tool_runner._adapters` and call `adapter._permission_context = {"permission_store": rt["permission_store"]}` (or add a setter method).
  2. Alternatively pass `permission_context` to `ShellAdapter` in the static fallback and/or add a post-load hook in `PluginLoader` that can inject engagement-level context into adapters that declare they need it.
  3. Add a CLI command `pwnpilot grant-shell-command <engagement-id> <command>` that calls `PermissionStore.grant_permission()`.
- **Priority:** Medium — the allow-list is the security boundary; the dynamic expansion path should either work or be removed.

---

### ✅ Issue 10 — `RetrievalStore` memory context is never written; planner `memory_context` is always empty — FIXED (2026-04-14)

- **File:** `pwnpilot/data/retrieval_store.py`; `pwnpilot/agent/state.py` line 86; `pwnpilot/agent/planner.py` line 321
- **Root cause:** `RetrievalStore` is constructed in `_build_runtime` and stored in the runtime dict. There are zero call sites of `retrieval_store.index_finding()`, `index_service()`, or `index_playbook()` anywhere in the run loop. `memory_context` is initialised to `{}` in `make_initial_state()` and is never updated by any agent or post-execution callback. The planner reads it (`if memory_context: context["memory_context"] = memory_context`) but it is always empty.
- **Impact:** The planner has no persisted cross-iteration memory. Every planning iteration starts with identical context (except `previous_actions`), reducing plan diversity and making it harder to avoid strategy loops on longer engagements.
- **Fix needed:**
  1. In `pwnpilot/agent/executor.py`, after each successful tool run, call `rt["retrieval_store"].index_finding()` for each finding and `index_service()` for each discovered service.
  2. Before each planner LLM call in `PlannerNode.__call__()`, call `retrieval_store.query(engagement_id, recon_summary_text, top_k=5)` and write the results into `state["memory_context"]`.
  3. Alternatively add a `MemoryRefreshNode` between executor and planner that performs the query and populates state. Emit a `RETRIEVAL_CONTEXT_REFRESHED` event (already defined in `data/models.py` line 76).
- **Priority:** Medium — planner quality degrades on longer engagements without this; implementing it completes a clearly designed subsystem.

---

### ✅ Issue 11 — `ReplayService` has no user-facing CLI command — FIXED (2026-04-14)

- **File:** `pwnpilot/services/replay_service.py`; `pwnpilot/cli.py`
- **Root cause:** `ReplayService.build_snapshot()` is fully implemented. `ExportService` is wired to `pwnpilot roe export`. But there is no `pwnpilot replay` command that calls `ReplayService`.
- **Impact:** Operators cannot reconstruct per-engagement event timelines, rejection sequences, and trace spans for post-mortem debugging via CLI. The TUI `OperatorMode.REPLAY` value is also declared in state but never set or branched on.
- **Fix needed:**
  1. Add `@app.command("replay")` in `pwnpilot/cli.py` that calls `ReplayService(audit_store, decision_store).build_snapshot(engagement_id)` and writes the snapshot to a JSON file.
  2. Wire `OperatorMode.REPLAY` in supervisor routing: when mode is `REPLAY`, run read-only and refuse executor steps.
- **Priority:** Low — data is there; surfacing it requires only CLI wiring.

---

### ✅ Issue 12 — `OperatorMode.MONITOR` and `OperatorMode.REPLAY` are declared but never branched on — FIXED (2026-04-14)

- **File:** `pwnpilot/agent/state.py` line 28; `pwnpilot/agent/supervisor.py`
- **Root cause:** `OperatorMode` enum has four values: `monitor`, `guided`, `autonomous`, `replay`. Supervisor routing only checks for `guided` and `autonomous` in `_is_guided_mode()` and `_escalate_to_hitl()`. The `monitor` and `replay` values are never tested in any conditional, making them cosmetically present but functionally inert.
- **Impact:** Setting `operator_mode=monitor` or `operator_mode=replay` at startup has no effect; the agent runs in autonomous mode regardless.
- **Fix needed:**
  1. In `pwnpilot/agent/supervisor.py`, add `_is_monitor_mode()` check: if mode is `monitor`, route after execution back to planner always (skip reporter) and skip executor (plan but do not execute).
  2. In `pwnpilot/agent/supervisor.py`, add `_is_replay_mode()` check: if mode is `replay`, skip planner/validator/executor entirely and route directly to reporter with no new actions.
  3. Expose `--mode monitor|replay|autonomous|guided` as a CLI flag on `pwnpilot start` and `pwnpilot resume`.
- **Priority:** Low — these are declared capability contracts; completing them avoids misleading operators.

---

### ✅ Issue 13 — Global `event_bus` singleton imported in `runtime.py` but never used — FIXED (2026-04-14)

- **File:** `pwnpilot/runtime.py` line 30
- **Root cause:** `from pwnpilot.agent.event_bus import ExecutionEventBus, event_bus as _global_event_bus` — `_global_event_bus` is imported but never referenced in the file. Every engagement creates its own `engagement_event_bus = ExecutionEventBus()` instance, so the module-level singleton is unused.
- **Impact:** Minor confusion about which bus is authoritative; potential for accidental dual-bus use in future code.
- **Fix needed:** Remove `event_bus as _global_event_bus` from the import statement on line 30. The singleton can remain in `event_bus.py` for external consumers but should not be imported where unused.
- **Priority:** Low — cosmetic, but misleads future contributors about the intended bus architecture.

---

### ✅ Issue 14 — `ApprovalService.approve()/deny()` CLI commands reach a different process-isolated instance; approved tickets never unblock the running agent — FIXED (2026-04-14)

- **File:** `pwnpilot/cli.py` — `cmd_approve()` line 461, `cmd_deny()` line 476; `pwnpilot/runtime.py` — `get_approval_service()` line 1035; `pwnpilot/agent/executor.py` — `REQUIRES_APPROVAL` branch line 447
- **Root cause:** Two independent problems together make the approval flow a dead end:
  1. When `REQUIRES_APPROVAL` fires, the executor returns `{**state, "kill_switch": True}` which terminates the engagement immediately. There is no "pause and wait" path — the engagement process exits.
  2. `get_approval_service()` calls `_build_runtime()` which is **not cached** — it constructs a fresh `ApprovalService` instance. The `pwnpilot approve <ticket_id>` CLI command runs in a completely different process and resolves the ticket in a freshly instantiated in-memory dict (backed by DB `upsert`). But there is no running agent left to receive the approval, because the engagement process already exited.
- **Impact:** The full approval ticket lifecycle (create → approve via CLI → resume) is broken. Running `pwnpilot approve <ticket_id>` does write to the DB, but no code path checks that ticket on resume — the engagement would simply restart from checkpoint and re-propose the same action, re-generate the same ticket, and halt again indefinitely.
- **Fix needed:**
  1. Instead of `kill_switch=True`, store the pending ticket ID in agent state (e.g. `pending_approval_ticket_id`) and return a new `"approval_gate"` edge that suspends the graph cleanly via the checkpointer.
  2. In `resume_engagement()`, check if the checkpointed state has a `pending_approval_ticket_id`. If so, load that ticket from `ApprovalStore` via `load_fn`. If the ticket is `APPROVED`, clear `pending_approval_ticket_id` and inject the approved action back into state so execution can continue. If `DENIED`, skip the action and let the planner re-plan.
  3. This requires adding a `"pending_approval_ticket_id"` field to `AgentState` and a pre-run ticket check in `resume_engagement()`.
- **Priority:** High — without this, the entire approval infrastructure is non-functional. `pwnpilot approve` is a no-op.

---

### ✅ Issue 15 — `assert_authorized()` / `AuthorizationArtifact` imported in `runtime.py` but never called; authorization check is unenforced — FIXED (2026-04-14)

- **File:** `pwnpilot/runtime.py` line 51; `pwnpilot/governance/authorization.py` — `assert_authorized()`
- **Root cause:** `from pwnpilot.governance.authorization import AuthorizationArtifact, assert_authorized` is imported but `assert_authorized()` is never invoked anywhere in `create_and_run_engagement()` or `resume_engagement()`. The module docstring explicitly states "called by the orchestrator before every run loop" — but this call does not exist.
- **Impact:** Any engagement can run without a valid `AuthorizationArtifact`. The authorization validity window (`valid_from` / `valid_until`) and ROE document hash check are completely bypassed. This is a governance and security invariant that is stated to be enforced but isn't.
- **Fix needed:**
  1. In `create_and_run_engagement()` and `resume_engagement()`, construct an `AuthorizationArtifact` from the ROE document hash (already computed by `roe_interpreter.interpret()` and stored in the engagement) and call `assert_authorized(artifact)` before the graph run.
  2. Propagate `AuthorizationError` up to the CLI so the user sees a clear rejection message.
  3. When ROE-derived validity windows are absent (e.g. CTF engagements with no time constraint), construct the artifact with a sensible default `valid_until` (e.g. ROE creation timestamp + 30 days).
- **Priority:** High — unenforced authorization check means a stated security invariant is silently ignored on every engagement.

---

### ✅ Issue 16 — `CorrelationEngine` (cross-tool CVE/exploit enrichment + risk roll-up) is never called during report generation — FIXED (2026-04-14)

- **File:** `pwnpilot/data/correlation.py` — `CorrelationEngine`; `pwnpilot/reporting/generator.py` — `build_bundle()`; `pwnpilot/agent/reporter.py`
- **Root cause:** `CorrelationEngine` has zero call sites outside its own docstring example. Neither `ReportGenerator.build_bundle()`, `ReporterNode.__call__()`, nor `runtime.generate_report()` import or invoke it. Reports are generated directly from raw `FindingStore.findings_for_engagement()` without correlation, deduplication, exploit escalation, or risk roll-up.
- **Impact:**
  - Findings from multiple tools scanning the same vulnerability (e.g. ZAP + nikto finding the same missing header) are not deduplicated in reports.
  - CVE references in findings are never cross-matched with searchsploit results — so `exploitability` scores are never escalated even when exploit code is known.
  - The engagement-level risk rating (`low/medium/high/critical`) in `risk_rollup()` is never computed and never appears in reports.
- **Fix needed:**
  1. In `runtime.py` `_build_runtime()`, construct a `CorrelationEngine(finding_store, recon_store)` and add it to the runtime dict.
  2. In `ReportGenerator.build_bundle()` or `ReporterNode.__call__()`, call `correlation_engine.correlate(engagement_id)` before reading `FindingStore.findings_for_engagement()`.
  3. Add `risk_rollup` dict to the report bundle JSON from `correlation_engine.risk_rollup(engagement_id)`.
- **Priority:** Medium — reports currently miss deduplication and CVE-to-exploit correlation that the codebase has fully implemented.

---

### ✅ Issue 17 — `RetentionManager` (evidence TTL + legal hold) is fully implemented but never wired into CLI or runtime — FIXED (2026-04-14)

- **File:** `pwnpilot/governance/retention.py` — `RetentionManager`; `pwnpilot/runtime.py`
- **Root cause:** `RetentionManager` is a complete implementation with `apply_ttl()`, `place_legal_hold()`, `release_legal_hold()`, and `is_expired()`. It has zero call sites outside its own file. It is not imported in `runtime.py`, not included in the runtime dict, and has no CLI commands.
- **Impact:** Evidence and audit data are never automatically purged per engagement classification. Legal hold capability (required for regulatory compliance scenarios) is unreachable.
- **Fix needed:**
  1. In `runtime.py`, import and construct `RetentionManager(evidence_store, audit_store)` and store in runtime dict.
  2. Add CLI commands: `pwnpilot retention apply <engagement-id> --classification [ctf|internal|external|red-team]` calling `apply_ttl()`, and `pwnpilot retention hold <engagement-id> --holder <name> --reason <reason>` calling `place_legal_hold()`.
  3. Optionally, enforce a check in `generate_report()` that surfaces a warning if `is_expired()` returns `True` for the engagement.
- **Priority:** Low — compliance and data governance feature; no functional impact on active engagements.
