"""
AgentState v2 — shared LangGraph TypedDict that flows through every agent node.

All inter-agent communication happens ONLY through this state (ADR-013).
No direct cross-agent function calls are permitted.

v2 changes (breaking cutover — no backward compatibility):
- Adds operator_mode, operator_directives, operator_messages for guided control.
- Adds active_action_id, active_tool_name, active_tool_command, live_output_enabled
  for real-time execution visibility.
- Adds completion_state / finalization_failed for deterministic run closure.
- Adds memory_context for planner-accessible persisted findings/retrieval.
- Adds repetition tracking fields for anti-loop controls.
- schema_version must equal "v2"; nodes must reject incompatible state.
"""
from __future__ import annotations

import time
from enum import Enum
from typing import Any, TypedDict


class OperatorMode(str, Enum):
    """Explicit operator interaction mode."""
    MONITOR = "monitor"       # read-only dashboard
    GUIDED = "guided"         # operator chat with controlled tool execution
    AUTONOMOUS = "autonomous" # automated run (default)
    REPLAY = "replay"         # inspect past engagement events


class CompletionState(str, Enum):
    """Run finalization state."""
    PENDING = "pending"
    FINALIZED = "finalized"
    FAILED = "failed"


class AgentState(TypedDict, total=False):
    # -----------------------------------------------------------------------
    # Identity / contract version
    # -----------------------------------------------------------------------
    engagement_id: str
    schema_version: str  # must be "v2"

    # -----------------------------------------------------------------------
    # Operator control plane
    # -----------------------------------------------------------------------
    operator_mode: str                       # OperatorMode value
    operator_directives: dict[str, Any]      # typed directive map
    operator_messages: list[dict[str, Any]]  # operator → agent chat messages

    # -----------------------------------------------------------------------
    # Active action tracking (live visibility)
    # -----------------------------------------------------------------------
    active_action_id: str | None
    active_tool_name: str | None
    active_tool_command: str | None
    live_output_enabled: bool

    # -----------------------------------------------------------------------
    # Completion / finalization state
    # -----------------------------------------------------------------------
    completion_state: str | None          # CompletionState value
    finalization_failed: bool
    finalization_failure_reason: str | None

    # -----------------------------------------------------------------------
    # Loop control
    # -----------------------------------------------------------------------
    iteration_count: int
    max_iterations: int
    no_new_findings_streak: int           # convergence counter
    nonproductive_cycle_streak: int       # reject/invalid-action churn counter
    planner_validator_cycle_streak: int   # consecutive planner/validator loops without executor
    reject_reason_streak_count: int       # consecutive rejects for same code/class
    last_reject_reason_fingerprint: str | None
    max_pv_cycles_without_executor: int
    max_consecutive_rejects_per_reason: int
    run_started_at_epoch: float

    # -----------------------------------------------------------------------
    # Memory context (sourced from persisted findings + retrieval service)
    # -----------------------------------------------------------------------
    recon_summary: dict[str, Any]
    memory_context: dict[str, Any]        # retrieved findings/strategies
    assessment_objectives: list[dict[str, Any]]
    objective_progress: dict[str, Any]
    depth_metrics: dict[str, Any]
    attack_surface_graph: dict[str, Any]
    generated_payloads: list[str]
    pending_mutation_payload: dict[str, str]
    roe_disallow_patterns: list[str]

    # -----------------------------------------------------------------------
    # Repetition detection
    # -----------------------------------------------------------------------
    repeated_action_count: int
    last_repeated_action_key: str | None

    # -----------------------------------------------------------------------
    # Previous actions (list of serialised ActionRequest summaries)
    # -----------------------------------------------------------------------
    previous_actions: list[dict[str, Any]]

    # Cooldown map: tool_name → remaining planner iterations to skip
    temporarily_unavailable_tools: dict[str, int]

    # -----------------------------------------------------------------------
    # Inter-agent messages
    # -----------------------------------------------------------------------
    proposed_action: dict[str, Any] | None    # PlannerProposal serialised
    validation_result: dict[str, Any] | None  # ValidationResult serialised

    # -----------------------------------------------------------------------
    # Execution result
    # -----------------------------------------------------------------------
    last_result: dict[str, Any] | None        # ToolExecutionResult serialised
    last_execution_hints: list[dict[str, Any]]
    evidence_ids: list[str]

    # -----------------------------------------------------------------------
    # Control flags
    # -----------------------------------------------------------------------
    pending_approval_ticket_id: str | None  # set when executor halts awaiting approval
    kill_switch: bool
    force_report: bool
    report_complete: bool
    report_bundle_path: str | None
    report_summary_path: str | None
    report_trigger_reason: str | None
    stall_state: str
    termination_reason: str | None
    run_verdict: str | None
    readiness_gate_results: dict[str, Any]
    degradation_reasons: list[str]
    last_rejection_code: str
    last_rejection_class: str
    rejection_repeat_count: int

    # -----------------------------------------------------------------------
    # Error state
    # -----------------------------------------------------------------------
    error: str | None


def make_initial_state(
    engagement_id: str,
    max_iterations: int = 50,
    max_pv_cycles_without_executor: int = 40,
    max_consecutive_rejects_per_reason: int = 12,
    operator_mode: OperatorMode = OperatorMode.AUTONOMOUS,
    operator_directives: dict[str, Any] | None = None,
    live_output_enabled: bool = True,
) -> AgentState:
    """Return a fully-initialised v2 AgentState for a new engagement run."""
    return AgentState(
        engagement_id=engagement_id,
        schema_version="v2",
        operator_mode=operator_mode.value,
        operator_directives=operator_directives or {},
        operator_messages=[],
        active_action_id=None,
        active_tool_name=None,
        active_tool_command=None,
        live_output_enabled=live_output_enabled,
        completion_state=CompletionState.PENDING.value,
        finalization_failed=False,
        finalization_failure_reason=None,
        iteration_count=0,
        max_iterations=max_iterations,
        no_new_findings_streak=0,
        nonproductive_cycle_streak=0,
        planner_validator_cycle_streak=0,
        reject_reason_streak_count=0,
        last_reject_reason_fingerprint=None,
        max_pv_cycles_without_executor=max_pv_cycles_without_executor,
        max_consecutive_rejects_per_reason=max_consecutive_rejects_per_reason,
        run_started_at_epoch=time.time(),
        recon_summary={},
        memory_context={},
        assessment_objectives=[],
        objective_progress={},
        depth_metrics={},
        attack_surface_graph={},
        generated_payloads=[],
        pending_mutation_payload={},
        roe_disallow_patterns=[],
        repeated_action_count=0,
        last_repeated_action_key=None,
        previous_actions=[],
        temporarily_unavailable_tools={},
        proposed_action=None,
        validation_result=None,
        last_result=None,
        last_execution_hints=[],
        evidence_ids=[],
        pending_approval_ticket_id=None,
        kill_switch=False,
        force_report=False,
        report_complete=False,
        report_bundle_path=None,
        report_summary_path=None,
        report_trigger_reason=None,
        stall_state="ok",
        termination_reason=None,
        run_verdict=None,
        readiness_gate_results={},
        degradation_reasons=[],
        last_rejection_code="",
        last_rejection_class="",
        rejection_repeat_count=0,
        error=None,
    )
