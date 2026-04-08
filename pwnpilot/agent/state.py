"""
AgentState — shared LangGraph TypedDict that flows through every agent node.

All inter-agent communication happens ONLY through this state (ADR-013).
No direct cross-agent function calls are permitted.
"""
from __future__ import annotations

from typing import Any, TypedDict

from pwnpilot.data.models import PlannerProposal, ValidationResult, ToolExecutionResult


class AgentState(TypedDict, total=False):
    # Identity
    engagement_id: str

    # Loop control
    iteration_count: int
    max_iterations: int
    no_new_findings_streak: int   # convergence counter (trigger reporter at 3)

    # Recon context (snapshot from ReconStore, serialisable)
    recon_summary: dict[str, Any]

    # Previous actions (list of serialised ActionRequest summaries)
    previous_actions: list[dict[str, Any]]

    # Inter-agent messages
    proposed_action: dict[str, Any] | None    # PlannerProposal serialised
    validation_result: dict[str, Any] | None  # ValidationResult serialised

    # Execution result
    last_result: dict[str, Any] | None        # ToolExecutionResult serialised
    evidence_ids: list[str]

    # Control flags
    kill_switch: bool
    report_complete: bool

    # Error state
    error: str | None
