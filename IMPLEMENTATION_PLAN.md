# Pwnpilot Implementation Plan

## 1. Problem Statement

Pwnpilot has become materially stronger in execution semantics, target handling, and report health metadata, but the operator experience still lags behind the current architecture.

The next major gap is not raw scanning capability. It is the lack of a cohesive operator-facing control plane.

Comparison against GH05TCREW/PentestAgent and a fresh repository scan highlight the same pattern:

- the backend is increasingly structured and auditable;
- the frontend operator experience is still monitor-oriented instead of guidance-oriented;
- tool output is captured for evidence and logs, but not surfaced as a first-class live experience;
- several existing subsystems already provide most of the underlying primitives needed to improve this holistically.

## 2. What Must Improve Next

The next implementation tranche should optimize for:

- guided operator interaction through chat-like execution control;
- rich, live visibility into each tool invocation;
- clearer run-state transitions and finalization behavior;
- stronger audit, replay, and export capabilities;
- better use of already-existing observability and approval infrastructure.

## 3. Benchmark-Derived Gaps

### 3.1 No Guided Chat Execution Surface

Observed gap:

- Pwnpilot exposes a CLI and a read-only TUI dashboard, but no interactive operator chat mode.
- Current TUI is explicitly a live dashboard rather than a conversational control surface.

Repository evidence:

- `pwnpilot/cli.py` only exposes `tui` as a dashboard entrypoint.
- `pwnpilot/tui/app.py` renders status, approvals, policy log, tool counts, and metrics only.

Improvement:

- Add a guided operator interaction mode with conversational control, similar in utility to PentestAgent's interact mode but aligned to Pwnpilot's governance model.
- The operator should be able to:
	- guide the next objective;
	- narrow or expand depth;
	- pause or stop a tool family;
	- request explanation of the current plan;
	- approve or redirect risky pivots inline.

Why this matters:

- This gives the operator tactical control without bypassing planner, validator, policy, and audit layers.

### 3.2 Tool Output Is Captured But Not Surfaced Live

Observed gap:

- The runner captures stdout and stderr, computes previews, stores evidence, and logs semantic completion.
- The TUI currently shows only aggregate tool invocation metrics, not per-tool live output.

Repository evidence:

- `pwnpilot/plugins/runner.py` captures stdout and stderr and logs previews.
- `pwnpilot/tui/app.py` only renders invocation counts and latencies.

Improvement:

- Introduce live tool-output streaming to both CLI and TUI.
- Show, for each running action:
	- tool name;
	- command;
	- elapsed time;
	- live stdout/stderr tail;
	- final exit code;
	- semantic outcome (`success|degraded|failed`);
	- typed failure reasons;
	- key execution hints.

Why this matters:

- Operators trust automation more when they can see what is actually happening instead of waiting for summarized log lines.

### 3.3 Missing Explicit UX Modes

Observed gap:

- Pwnpilot currently has execution and dashboard entrypoints, but it does not expose distinct operator modes.

Improvement:

- Add explicit modes:
	- `monitor`: current read-only dashboard;
	- `guided`: operator chat with controlled tool execution;
	- `autonomous`: current automated run path;
	- `replay`: inspect past engagement events, decisions, and outputs.

Why this matters:

- The system already supports several of these behaviors conceptually, but the operator has no clean mode model for invoking them.

### 3.4 No Operator Directive Contract

Observed gap:

- There is no typed place in `AgentState` for operator intentions beyond initial startup inputs.

Improvement:

- Add structured operator directives to state, for example:
	- `operator_objective`;
	- `operator_constraints`;
	- `operator_requested_focus`;
	- `operator_paused_tool_families`;
	- `operator_notes`;
	- `operator_interaction_mode`.
- Require planner and validator to consume these directives deterministically.

Why this matters:

- Chat UX without typed directive propagation becomes prompt-only behavior and will drift under load.

### 3.5 Approval UX Is Functional But Fragmented

Observed gap:

- Approval persistence and approval CLI controls exist.
- ROE approval flow also exists as a separate interactive path.
- The TUI shows pending approvals but does not appear to provide integrated operator resolution workflow.

Repository evidence:

- `pwnpilot/data/approval_store.py` persists approval tickets.
- `pwnpilot/control/roe_approval.py` implements a separate approval workflow.
- `pwnpilot/tui/app.py` displays pending approvals read-only.

Improvement:

- Unify approval handling into one operator approval experience across:
	- runtime risk approvals;
	- ROE-derived approvals;
	- policy exceptions;
	- deferred decisions.
- Add inline approve, deny, defer, and explain actions in the TUI or guided mode.

Why this matters:

- Governance is already a core product differentiator. The UX should reflect that.

### 3.6 Report UX Lags Behind Report Semantics

Observed gap:

- Report metadata includes run verdict, readiness, degradation reasons, and termination reason.
- The human-readable output still does not provide a full operator narrative of what happened during the run.

Repository evidence:

- `pwnpilot/agent/reporter.py` computes structured run metadata.
- `pwnpilot/reporting/generator.py` writes structured bundle metadata.

Improvement:

- Add report sections for:
	- execution timeline;
	- planner pivots and rejection causes;
	- approval decisions;
	- degraded actions and why they were still accepted;
	- top command transcripts and evidence references.

Why this matters:

- Final reports should explain not only what was found, but also how the system behaved and where confidence degraded.

## 4. Additional Repository-Scan Findings

### 4.1 Tracing Exists but Is Not Part of the Main Operator Story

Observed gap:

- `pwnpilot/observability/tracing.py` already provides an in-process tracer.
- It is not yet a visible part of run diagnostics, timeline export, or TUI drill-down.

Improvement:

- Instrument planner, validator, executor, reporter, approval flow, and tool execution with trace spans.
- Surface traces in replay mode and attach summarized span graphs to audit exports.

### 4.2 Audit Export Is Still Incomplete

Observed gap:

- CLI audit export paths still contain explicit TODOs for ROE file, approvals, and audit trail loading.

Repository evidence:

- `pwnpilot/cli.py` contains TODO markers in the ROE export path.

Improvement:

- Complete engagement export so one command yields:
	- ROE source;
	- approval chain;
	- audit timeline;
	- run verdict;
	- report metadata;
	- trace and metrics summaries.

Why this matters:

- This closes the loop between execution, compliance, and post-run review.

### 4.3 Replay and Historical Inspection Are Not First-Class

Observed gap:

- Audit store is append-only and already well-suited for timeline reconstruction.
- There is no dedicated replay or engagement-history UX.

Improvement:

- Add replay commands and UI views to inspect:
	- action sequence;
	- policy verdicts;
	- approval events;
	- planner rejections;
	- per-tool outputs;
	- final report generation.

Why this matters:

- Replay is essential for debugging, operator trust, and sales-quality demos.

### 4.4 Dashboard Is Strong for Monitoring but Weak for Actionability

Observed gap:

- Current TUI is useful for passive monitoring but cannot resolve approvals, inspect live output, or guide execution.

Improvement:

- Evolve the TUI into a split experience:
	- monitor pane;
	- live action pane;
	- approval pane;
	- tool output pane;
	- operator input pane.

### 4.5 Report Closure and Run Finalization Still Need Stronger Operational Guarantees

Observed gap:

- Earlier execution review showed that latest runs can still fail to produce final report artifacts consistently.

Improvement:

- Add explicit completion-path validation and reporter invocation guarantees.
- If report finalization cannot complete, emit a terminal failure artifact and audit event instead of silent run-end ambiguity.

### 4.6 Approval and Permission Models Can Be Unified Further

Observed gap:

- Approval tickets, ROE approvals, and permission exceptions appear to live in adjacent but still partially separate flows.

Improvement:

- Define one operator-decision model with normalized fields for:
	- decision type;
	- scope;
	- rationale;
	- actor;
	- expiry;
	- downstream effect.

## 5. Existing Strengths To Preserve

The plan should not regress current strengths:

- semantic outcome classification in the runner;
- typed failure taxonomy;
- canonical target resolution;
- capability-aware runtime filtering;
- structured approval persistence;
- report readiness and run-health evaluation;
- append-only audit storage;
- metrics and trace primitives already present in the codebase.

## 6. Architecture Additions

Add the following explicit components:

- `OperatorSessionManager`:
	- tracks current mode, active directives, pause state, and operator messages.
- `ExecutionEventBus`:
	- delivers live runner events to CLI, TUI, and replay/export systems.
- `ToolOutputStream`:
	- structured live stdout/stderr feed with per-action buffering and truncation policy.
- `OperatorDirectiveContract`:
	- typed contract consumed by planner and validator.
- `ReplayService`:
	- reconstructs run history from audit, evidence, metrics, and traces.
- `EngagementExportService`:
	- bundles ROE, approvals, audit trail, traces, metrics, and reports.

## 7. Data Contract Changes

Add to `AgentState`:

- `operator_mode`
- `operator_directives`
- `operator_messages`
- `active_action_id`
- `active_tool_name`
- `active_tool_command`
- `live_output_enabled`
- `completion_state`

Add to audit events:

- `operator.directive_submitted`
- `operator.mode_changed`
- `tool.output_chunk`
- `report.finalization_failed`
- `engagement.export_generated`
- `replay.snapshot_generated`

Add to report metadata:

- `execution_timeline`
- `approval_timeline`
- `planner_rejection_summary`
- `live_execution_summary`

## 8. Phased Execution Plan

### Phase A: Live Execution Visibility

- Add an event bus for runner lifecycle and chunked output events.
- Stream tool stdout/stderr to CLI in real time.
- Add TUI panels for active tool output, current command, and latest action result.
- Preserve existing evidence-store write path and final semantic classification.

Exit criteria:

- Operators can watch command output as tools run.
- Every completed action visibly reports command, exit code, outcome status, and failure reasons.

### Phase B: Guided Operator Mode

- Add guided mode entrypoints in CLI and TUI.
- Add typed operator directives to `AgentState`.
- Feed directives into planner and validator context.
- Add inline pause, resume, skip-family, and focus controls.

Exit criteria:

- Operators can steer execution without bypassing policy or audit layers.
- Planner behavior changes are attributable to typed operator directives.

### Phase C: Approval Workflow Unification

- Consolidate runtime approvals, ROE approvals, and deferred decisions into one operator decision workflow.
- Add TUI-based approval resolution.
- Audit all operator decisions with a single normalized schema.

Exit criteria:

- Operators can resolve all approval classes from one workflow.
- Approval records are queryable and replayable with consistent structure.

### Phase D: Replay, Timeline, and Export

- Implement replay service over audit store, evidence references, metrics, and traces.
- Complete ROE export/audit export CLI TODOs.
- Add report timeline sections and historical run inspection commands.

Exit criteria:

- A completed engagement can be replayed and exported end-to-end.
- Audit export includes ROE, approvals, timeline, and report metadata.

### Phase E: Observability Activation and Closure Guarantees

- Wire tracing into planner, validator, executor, reporter, approvals, and export paths.
- Surface trace summaries in replay and diagnostics.
- Add hard guarantees around report finalization and failure artifact emission.

Exit criteria:

- Failed report closure is visible, audited, and diagnosable.
- Trace data helps explain run latency, stalls, and degradation.

## 9. Validation Strategy

- Unit tests:
	- event bus publishing and subscriber delivery;
	- tool output chunk handling and truncation policy;
	- operator directive propagation through planner and validator;
	- approval workflow normalization;
	- replay timeline reconstruction;
	- report finalization failure fallback.
- Integration tests:
	- guided mode operator changes tool choice without violating policy;
	- TUI/CLI live output reflects runner execution in near real time;
	- approval issued in execution path can be resolved from the UI;
	- replay reconstructs a completed engagement correctly.
- Replay tests:
	- use a recorded engagement to validate export bundle completeness.

## 10. Success Metrics

- Reduced operator uncertainty during tool execution.
- Reduced need to inspect raw log files for routine run diagnosis.
- Faster approval turnaround during active engagements.
- Increased consistency of final report generation.
- Increased usability of post-run audit exports.
- Improved operator trust through visible planner and execution reasoning.

## 11. Immediate Next Slice

Implement the highest-leverage slice first:

- live tool output streaming for CLI and TUI;
- active-action display in the TUI;
- typed operator directive scaffolding in `AgentState`;
- completion of audit export TODOs for ROE, approvals, and audit timeline.

This slice gives immediate user-visible gains while reusing the strongest parts of the current architecture.
