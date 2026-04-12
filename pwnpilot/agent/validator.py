"""
Validator Agent — independent LLM second-opinion risk assessment.

Reads from AgentState:
  proposed_action, engagement_scope, policy_context

Writes to AgentState:
  validation_result (ValidationResult serialised)

The Validator never calls tools and never writes to data stores directly.
It can escalate risk upward but NEVER downgrade below the proposal's estimated_risk.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from typing import Any

import structlog

from pwnpilot.agent.state import AgentState
from pwnpilot.data.models import RiskLevel, ValidationResult

log = structlog.get_logger(__name__)

# Risk level ordering for escalation enforcement
_RISK_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def _classify_target_type(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return "unknown"
    if raw.startswith("http://") or raw.startswith("https://"):
        return "url"
    if "/" in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
            return "cidr"
        except Exception:
            pass
    try:
        ipaddress.ip_address(raw)
        return "ip"
    except Exception:
        pass
    if re.match(r"^[a-zA-Z0-9.-]+$", raw):
        return "domain"
    return "unknown"


class ValidatorNode:
    """
    Stateless callable used as a LangGraph validator node.

    The LLM call is delegated to *llm_router*.  The node enforces the
    no-downgrade invariant regardless of what the LLM returns.
    """

    def __init__(
        self,
        llm_router: Any,
        policy_context: dict[str, Any],
        audit_store: Any | None = None,
    ) -> None:
        self._llm = llm_router
        self._policy_context = policy_context
        self._audit = audit_store

    def __call__(self, state: AgentState) -> AgentState:
        if state.get("kill_switch"):
            return state

        _t0 = time.monotonic()
        _input_hash = hashlib.sha256(
            json.dumps(state, default=str, sort_keys=True).encode()
        ).hexdigest()

        proposal = state.get("proposed_action")
        if not proposal:
            log.error("validator.no_proposal")
            return {
                **state,
                "validation_result": {
                    "verdict": "reject",
                    "risk_override": None,
                    "rationale": "No proposal present.",
                },
            }

        context = {
            "proposal": proposal,
            "policy_context": self._policy_context,
        }

        deterministic_error = self._deterministic_capability_check(proposal)
        if deterministic_error:
            log.warning("validator.capability_reject", reason=deterministic_error)
            return {
                **state,
                "validation_result": {
                    "verdict": "reject",
                    "risk_override": None,
                    "rationale": deterministic_error,
                },
            }

        try:
            raw_result = self._llm.validate(context)
        except Exception as exc:
            log.error("validator.llm_error", exc=str(exc))
            # Fail-safe: reject on LLM error
            return {
                **state,
                "validation_result": {
                    "verdict": "reject",
                    "risk_override": None,
                    "rationale": f"Validator LLM error (fail-safe reject): {exc}",
                },
            }

        try:
            result = ValidationResult(**raw_result)
        except Exception as exc:
            log.error("validator.invalid_result", exc=str(exc))
            return {
                **state,
                "validation_result": {
                    "verdict": "reject",
                    "risk_override": None,
                    "rationale": f"Invalid validator output: {exc}",
                },
            }

        # Enforce no-downgrade invariant
        if result.risk_override is not None:
            proposed_risk = proposal.get("estimated_risk", "low")
            override_level = _RISK_ORDER.get(result.risk_override.value, 0)
            proposed_level = _RISK_ORDER.get(proposed_risk, 0)
            if override_level < proposed_level:
                log.warning(
                    "validator.downgrade_rejected",
                    proposed=proposed_risk,
                    override=result.risk_override,
                )
                # Force override to match the proposed risk (no downgrade)
                result = result.model_copy(
                    update={"risk_override": RiskLevel(proposed_risk)}
                )

        log.info(
            "validator.result",
            verdict=result.verdict,
            risk_override=result.risk_override,
        )

        output = {**state, "validation_result": result.model_dump()}
        self._emit_agent_invoked(state, output, _input_hash, _t0)
        return output

    def _deterministic_capability_check(self, proposal: dict[str, Any]) -> str | None:
        available_tools = self._policy_context.get("available_tools") or []
        tools_catalog = self._policy_context.get("tools_catalog") or []

        tool_name = str(proposal.get("tool_name", ""))
        if available_tools and tool_name not in available_tools:
            return (
                f"Tool '{tool_name}' is not enabled or trusted in this runtime. "
                f"Choose from: {available_tools}"
            )

        if not tools_catalog:
            return None

        tool_meta = None
        for item in tools_catalog:
            if isinstance(item, dict) and item.get("tool_name") == tool_name:
                tool_meta = item
                break

        if tool_meta is None:
            return None

        required = list(tool_meta.get("required_params", []))
        params = proposal.get("params") if isinstance(proposal.get("params"), dict) else {}

        missing = [p for p in required if p != "target" and p not in params]
        if missing:
            return f"Proposal missing required parameters for tool '{tool_name}': {missing}"

        target = str(proposal.get("target", ""))
        supported = list(tool_meta.get("supported_target_types", []))
        if supported:
            target_type = _classify_target_type(target)
            if target_type not in supported and "unknown" not in supported:
                return (
                    f"Target type '{target_type}' is not supported by tool '{tool_name}'. "
                    f"Supported target types: {supported}"
                )

        return None

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
                actor="validator",
                event_type="AgentInvoked",
                payload={
                    "agent_name": "validator",
                    "input_state_hash": input_hash,
                    "output_state_hash": output_hash,
                    "llm_model_used": getattr(self._llm, "model", "unknown"),
                    "llm_routing_decision": "local",
                    "duration_ms": duration_ms,
                },
            )
        except Exception as exc:
            log.warning("validator.audit_invoked_failed", exc=str(exc))
