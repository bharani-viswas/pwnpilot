"""
Planner Agent — decides the next action given current engagement state.

Reads from AgentState:
  recon_summary, previous_actions, engagement_scope, iteration_count

Writes to AgentState:
  proposed_action (PlannerProposal serialised), kill_switch (if circuit breaker fires)

Novelty check: proposes actions not already in previous_actions.
Repeated-state circuit breaker: if no novel action can be generated for 3 consecutive
iterations, sets kill_switch=True.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import structlog

from pwnpilot.agent.state import AgentState
from pwnpilot.data.models import PlannerProposal, RiskLevel

log = structlog.get_logger(__name__)

_MAX_REPEATED_STATE: int = 3


def _proposal_key(proposal: dict[str, Any]) -> str:
    """Stable hash of a proposal for novelty checking."""
    key = f"{proposal.get('tool_name')}:{proposal.get('target')}:{proposal.get('action_type')}"
    return hashlib.sha256(key.encode()).hexdigest()


class PlannerNode:
    """
    Stateless callable that can be used as a LangGraph node function.

    The LLM call is delegated to *llm_router*.  In simulation/test mode, *llm_router*
    can be replaced with a stub.
    """

    def __init__(
        self,
        llm_router: Any,
        engagement_summary: dict[str, Any],
        audit_store: Any | None = None,
    ) -> None:
        self._llm = llm_router
        self._engagement = engagement_summary
        self._no_novel_count: int = 0
        self._audit = audit_store

    def __call__(self, state: AgentState) -> AgentState:
        if state.get("kill_switch"):
            return state

        _t0 = time.monotonic()
        _input_hash = hashlib.sha256(
            json.dumps(state, default=str, sort_keys=True).encode()
        ).hexdigest()

        iteration = state.get("iteration_count", 0)
        previous = state.get("previous_actions", [])
        recon = state.get("recon_summary", {})
        rejection_reason = None

        # Carry forward rejection reason from previous validation (if any)
        prev_proposal = state.get("proposed_action")
        if prev_proposal:
            rejection_reason = prev_proposal.get("rejection_reason")

        # Build LLM prompt context
        context = {
            "engagement": self._engagement,
            "iteration": iteration,
            "recon_summary": recon,
            "previous_actions": previous[-10:],  # last 10 for context window efficiency
            "rejection_reason": rejection_reason,
        }

        try:
            raw_proposal = self._llm.plan(context)
        except Exception as exc:
            log.error("planner.llm_error", exc=str(exc))
            return {**state, "error": f"Planner LLM error: {exc}"}

        # Validate proposal structure
        try:
            proposal = PlannerProposal(**raw_proposal)
        except Exception as exc:
            log.error("planner.invalid_proposal", exc=str(exc))
            return {**state, "error": f"Invalid planner proposal: {exc}"}

        # Novelty check
        prop_key = _proposal_key(raw_proposal)
        known_keys = {
            _proposal_key(a) for a in previous if isinstance(a, dict)
        }

        if prop_key in known_keys:
            self._no_novel_count += 1
            log.warning(
                "planner.repeated_state",
                count=self._no_novel_count,
                tool=proposal.tool_name,
            )
            if self._no_novel_count >= _MAX_REPEATED_STATE:
                log.error("planner.circuit_breaker_triggered")
                return {**state, "kill_switch": True, "error": "Repeated-state circuit breaker fired."}
        else:
            self._no_novel_count = 0

        log.info(
            "planner.proposed",
            tool=proposal.tool_name,
            action_type=proposal.action_type,
            risk=proposal.estimated_risk,
            iteration=iteration,
        )

        output = {
            **state,
            "proposed_action": proposal.model_dump(),
            "iteration_count": iteration + 1,
        }
        self._emit_agent_invoked(state, output, _input_hash, _t0)
        return output

    def _emit_agent_invoked(
        self,
        input_state: AgentState,
        output_state: AgentState,
        input_hash: str,
        t0: float,
    ) -> None:
        if not self._audit:
            return
        try:
            from uuid import UUID
            duration_ms = round((time.monotonic() - t0) * 1000, 2)
            output_hash = hashlib.sha256(
                json.dumps(output_state, default=str, sort_keys=True).encode()
            ).hexdigest()
            self._audit.append(
                engagement_id=UUID(input_state["engagement_id"]),
                actor="planner",
                event_type="AgentInvoked",
                payload={
                    "agent_name": "planner",
                    "input_state_hash": input_hash,
                    "output_state_hash": output_hash,
                    "llm_model_used": getattr(self._llm, "model", "unknown"),
                    "llm_routing_decision": "local",
                    "duration_ms": duration_ms,
                },
            )
        except Exception as exc:
            log.warning("planner.audit_invoked_failed", exc=str(exc))
