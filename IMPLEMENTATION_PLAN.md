# PwnPilot Stabilization Implementation Plan

## 1. Executive Summary

This plan turns the latest orchestration and log-forensics findings into a concrete implementation roadmap.

Primary objective:
- Eliminate planner-validator churn loops that can run for hours with little or no executor progress.

Secondary objectives:
- Guarantee terminal run finalization and report outcomes for every engagement.
- Improve operator visibility of loop and rejection state in real time.
- Add hard safeguards and intervention logic inspired by mature orchestration patterns.

---

## 2. Findings Consolidation

## 2.1 Local Forensics Findings (authoritative)

Evidence source: active SQLite DB at `/var/lib/pwnpilot/pwnpilot.db`.

Key engagement analyzed:
- `f46b4598-9dda-4b95-9218-750c5a29d08b`

Observed event distribution:
- `AgentInvoked`: 9477
- `ToolExecutionStarted`: 9
- `ToolExecutionCompleted`: 8
- `ActionExecuted`: 8
- `ActionFailed`: 1

Actor breakdown for `AgentInvoked`:
- `planner`: 4738
- `validator`: 4738
- `executor`: 8

Conclusion:
- System entered prolonged planner-validator reject churn with almost no executor progress.

Secondary observation:
- Report generation/finalization events are not guaranteed across active engagements; some engagements show activity without a clear terminal/report event sequence.

## 2.2 Cross-Repository Pattern Findings

Compared systems show common resilience patterns that are either missing or only partially present:

1. Hard execution monitors and loop budgets
- Example pattern: same-tool and total-call thresholds, forced reflective intervention before continuing.

2. Explicit lifecycle stream events
- Example pattern: structured streaming of loop transitions, handoffs, tool starts/ends, and completion sentinels.

3. Mentor/reflector intervention mode
- Example pattern: when repeated low-value actions are detected, switch to corrective analysis mode to pivot or terminate.

4. Deterministic terminal closure
- Example pattern: every run produces one terminal status event and one report status outcome.

---

## 3. Root Cause Hypothesis

The immediate defect is not tool execution itself, but orchestration control:

1. Planner and validator can repeatedly reject/replan without a guaranteed terminal watchdog path.
2. Existing nonproductive counters and forced-pivot logic are insufficient under real reject patterns.
3. Finalization/reporting is not enforced as a mandatory terminal phase for all run outcomes.

---

## 4. Scope of Changes

In scope:
- Supervisor routing and watchdogs.
- Planner reject-loop handling.
- Validator rejection telemetry enrichment.
- Reporter/finalization lifecycle guarantees.
- CLI live output for rejection-loop observability.
- Metrics/audit events for churn detection.
- Tests (unit + integration).

Out of scope:
- Major plugin/tool adapter rewrites.
- New UI product surfaces beyond existing CLI event output.
- Data model redesign not required for this fix.

---

## 5. Target Architecture Changes

## 5.1 Add Supervisor Progress Watchdog

Files:
- `pwnpilot/agent/supervisor.py`

Change:
- Track consecutive planner-validator transitions where executor is not entered.
- Add a hard threshold (configurable) that forces report routing with explicit termination reason.

New termination reason values:
- `planner_validator_churn`
- `executor_starvation`

Expected behavior:
- No engagement can continue indefinitely without executor progress.

## 5.2 Add Hard Orchestration Budgets

Files:
- `pwnpilot/agent/supervisor.py`
- `pwnpilot/agent/planner.py`
- `pwnpilot/config.py` (new config keys)

Change:
- Add max planner-validator cycles per engagement.
- Add max consecutive rejects per reason code/class.
- Add max wall-clock duration for autonomous loops.

Expected behavior:
- Deterministic upper bound on churn and runtime.

## 5.3 Add Mentor/Reflector Intervention Step

Files:
- `pwnpilot/agent/planner.py`
- `pwnpilot/control/llm_router.py` (if required for new prompt route)

Change:
- On threshold breach, invoke a short corrective reflection prompt that must return one of:
  - Valid pivot strategy using a different tool family and target shape, or
  - Explicit terminate recommendation with reason.

Expected behavior:
- Better recovery from repeated low-value action proposals before hard termination.

## 5.4 Guarantee Terminal Finalization and Report Outcome

Files:
- `pwnpilot/agent/reporter.py`
- `pwnpilot/reporting/generator.py`
- `pwnpilot/runtime.py`

Change:
- Enforce terminal lifecycle events for every engagement:
  - `EngagementCompleted` or `EngagementFailed`
  - `ReportGenerated` or `ReportGenerationFailed`
- Ensure reporter is invoked (or explicit failure recorded) when watchdog/kill conditions terminate a run.

Expected behavior:
- No orphan engagements with missing terminal/report state.

## 5.5 Improve Live Rejection/Loop Observability

Files:
- `pwnpilot/cli.py`

Change:
- Stream concise structured lines for:
  - validator rejection code/class
  - rejection repeat count
  - nonproductive streak
  - watchdog threshold proximity and trigger

Expected behavior:
- Operators can see loop risk in real time and intervene early.

## 5.6 Strengthen Metrics and Audit Semantics

Files:
- `pwnpilot/observability/metrics.py`
- `pwnpilot/data/audit_store.py`

Change:
- Add counters/histograms for churn and starved execution windows.
- Emit explicit audit events for watchdog state transitions and forced termination causes.

Expected behavior:
- Easier postmortems and objective SLO tracking.

---

## 6. Detailed Implementation Plan (Phased)

## Phase A: Guardrails and Config Plumbing

Deliverables:
1. New config keys with defaults:
	- `agent.max_planner_validator_cycles_without_executor` (default: 40)
	- `agent.max_consecutive_rejects_per_reason` (default: 12)
	- `agent.max_autonomous_runtime_seconds` (default: 3600)
2. Config validation and env override support.
3. Runtime wiring into supervisor/planner.

Acceptance criteria:
- Keys load correctly from config and env.
- Backward compatibility maintained when keys are absent.

## Phase B: Supervisor Watchdog and Hard Stop Routing

Deliverables:
1. Stateful counters for planner-validator-only loops.
2. Executor starvation detection logic.
3. Forced report routing with explicit termination reason.

Acceptance criteria:
- Synthetic tests prove churn termination occurs at threshold.
- No false trigger when executor progresses normally.

## Phase C: Planner Reflector/Pivot Intervention

Deliverables:
1. Reflective pivot function and prompt template.
2. Safe fallback path if reflection fails.
3. Tool-family diversity constraints for pivot candidate generation.

Acceptance criteria:
- Reject-loop simulation shows either meaningful pivot or deterministic termination.
- No regressions in existing planner proposal schema.

## Phase D: Finalization and Reporting Guarantees

Deliverables:
1. Mandatory terminal event emission in all exit paths.
2. Report outcome events emitted on success/failure.
3. Reporter metadata consistently includes run_verdict and termination reason.

Acceptance criteria:
- Every engagement ends with exactly one terminal engagement event.
- Every engagement has exactly one report outcome event.

## Phase E: CLI and Observability Enhancements

Deliverables:
1. Live stdout lines for rejection and churn telemetry.
2. New metrics for loop severity and executor starvation.
3. Audit events for watchdog state changes.

Acceptance criteria:
- Operator can identify churn from stdout alone.
- Metrics show expected increments during replayed churn case.

## Phase F: Validation, Rollout, and Post-Deploy Checks

Deliverables:
1. Unit tests for watchdog, planner reject handling, and terminal events.
2. Integration tests for long-loop synthetic engagement.
3. Staged rollout instructions and rollback procedure.

Acceptance criteria:
- Failing scenario reproduces pre-fix and resolves post-fix.
- No regression in standard short engagement completion.

---

## 7. Test Plan

## 7.1 Unit Tests

1. Supervisor watchdog triggers report at threshold.
2. Supervisor does not trigger when executor runs within window.
3. Planner reflect/pivot path chooses different family or terminates.
4. Reporter emits terminal/report failure events on exception paths.
5. CLI formatting of rejection telemetry remains stable.

## 7.2 Integration Tests

1. Simulated validator reject churn:
	- Expected: terminate with `planner_validator_churn`, report outcome emitted.
2. Simulated executor starvation:
	- Expected: terminate with `executor_starvation`, report outcome emitted.
3. Healthy engagement:
	- Expected: no watchdog trigger, normal report generation.

## 7.3 Forensics Regression Test

Replay profile based on observed engagement characteristics:
- Very high planner/validator invocations.
- Low executor invocation count.

Expected:
- Post-fix run terminates early with explicit reason, not thousands of loops.

---

## 8. Rollout Plan

1. Implement under feature flags (default on in dev, configurable in prod).
2. Deploy to staging with forced-churn scenario.
3. Validate terminal/report event invariants in DB.
4. Deploy to production with watch metrics:
	- churn termination count
	- average run duration
	- report generation failure rate
5. After stability window, remove temporary feature flags if desired.

Rollback strategy:
- Disable watchdog/reflector via config flags while retaining telemetry emission.

---

## 9. Risks and Mitigations

Risk 1: Premature termination of valid long-running assessments.
- Mitigation: conservative defaults, per-engagement override, staged rollout.

Risk 2: Reflector prompt introduces unstable behavior.
- Mitigation: strict schema output, timeout, deterministic fallback to termination.

Risk 3: Additional telemetry noise on stdout.
- Mitigation: concise one-line event format and log level gating.

---

## 10. Definition of Done

This effort is complete when all are true:

1. No uncontrolled planner-validator churn can exceed configured budgets.
2. Every engagement writes deterministic terminal and report outcome events.
3. Operators can observe reject-loop progression in real time via CLI output.
4. New unit/integration tests pass and cover the previously observed failure mode.
5. Staging and production validation confirms reduced stuck-run incidence.

---

## 11. Suggested Work Breakdown (Engineer Tasks)

1. Config and runtime wiring (Phase A).
2. Supervisor watchdog and thresholds (Phase B).
3. Planner reflector/pivot logic (Phase C).
4. Reporter/finalization invariants (Phase D).
5. CLI telemetry and metrics/audit additions (Phase E).
6. Tests and rollout validation (Phase F).

Estimated sequence:
- Day 1-2: A+B
- Day 3: C
- Day 4: D+E
- Day 5: F and staged validation

