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
from numbers import Real
from typing import Any
from uuid import UUID

import structlog

from pwnpilot.agent.state import AgentState
from pwnpilot.data.models import ExecutionEvent, ExecutionEventType, RiskLevel, ValidationResult
from pwnpilot.observability.tracing import tracer

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


def _is_valid_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_valid_number(value: Any) -> bool:
    return isinstance(value, Real) and not isinstance(value, bool)


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
        metrics: Any | None = None,
        event_bus: Any | None = None,
    ) -> None:
        self._llm = llm_router
        self._policy_context = policy_context
        self._audit = audit_store
        self._metrics = metrics
        self._event_bus = event_bus

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
            if self._metrics:
                self._metrics.record_nonproductive_cycle()
            self._emit_rejection_event(
                state,
                rejection_reason_code="NO_PROPOSAL",
                rejection_class="capability",
                rationale="No proposal present.",
                next_streak=int(state.get("nonproductive_cycle_streak", 0) or 0) + 1,
            )
            return {
                **state,
                "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
                "validation_result": {
                    "verdict": "reject",
                    "risk_override": None,
                    "rationale": "No proposal present.",
                    "rejection_reason_code": "NO_PROPOSAL",
                    "rejection_reason_detail": "Validator received an empty proposal payload.",
                    "rejection_class": "capability",
                },
            }

        context = {
            "proposal": proposal,
            "policy_context": self._policy_context,
        }

        deterministic_error = self._deterministic_capability_check(proposal)
        if deterministic_error:
            log.warning("validator.capability_reject", reason=deterministic_error["rationale"])
            if self._metrics:
                self._metrics.record_nonproductive_cycle()
            self._emit_rejection_event(
                state,
                rejection_reason_code=deterministic_error["rejection_reason_code"],
                rejection_class=deterministic_error["rejection_class"],
                rationale=deterministic_error["rationale"],
                next_streak=int(state.get("nonproductive_cycle_streak", 0) or 0) + 1,
            )
            return {
                **state,
                "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
                "validation_result": {
                    "verdict": "reject",
                    "risk_override": None,
                    "rationale": deterministic_error["rationale"],
                    "rejection_reason_code": deterministic_error["rejection_reason_code"],
                    "rejection_reason_detail": deterministic_error["rejection_reason_detail"],
                    "rejection_class": deterministic_error["rejection_class"],
                },
            }

        try:
            with tracer.span(
                "validator.llm_call",
                engagement_id=str(state.get("engagement_id", "")),
                iteration=state.get("iteration_count", 0),
            ) as _vspan:
                raw_result = self._llm.validate(context)
                _vspan.set_attribute("verdict", raw_result.get("verdict", ""))
        except Exception as exc:
            log.error("validator.llm_error", exc=str(exc))
            # Fail-safe: reject on LLM error
            if self._metrics:
                self._metrics.record_nonproductive_cycle()
            self._emit_rejection_event(
                state,
                rejection_reason_code="VALIDATOR_LLM_ERROR",
                rejection_class="policy",
                rationale=f"Validator LLM error (fail-safe reject): {exc}",
                next_streak=int(state.get("nonproductive_cycle_streak", 0) or 0) + 1,
            )
            return {
                **state,
                "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
                "validation_result": {
                    "verdict": "reject",
                    "risk_override": None,
                    "rationale": f"Validator LLM error (fail-safe reject): {exc}",
                    "rejection_reason_code": "VALIDATOR_LLM_ERROR",
                    "rejection_reason_detail": str(exc),
                    "rejection_class": "policy",
                },
            }

        try:
            result = ValidationResult(**raw_result)
        except Exception as exc:
            log.error("validator.invalid_result", exc=str(exc))
            if self._metrics:
                self._metrics.record_nonproductive_cycle()
            self._emit_rejection_event(
                state,
                rejection_reason_code="INVALID_VALIDATOR_OUTPUT",
                rejection_class="policy",
                rationale=f"Invalid validator output: {exc}",
                next_streak=int(state.get("nonproductive_cycle_streak", 0) or 0) + 1,
            )
            return {
                **state,
                "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
                "validation_result": {
                    "verdict": "reject",
                    "risk_override": None,
                    "rationale": f"Invalid validator output: {exc}",
                    "rejection_reason_code": "INVALID_VALIDATOR_OUTPUT",
                    "rejection_reason_detail": str(exc),
                    "rejection_class": "policy",
                },
            }

        if result.verdict == "reject" and not result.rejection_reason_code:
            result = result.model_copy(
                update={
                    "rejection_reason_code": "VALIDATOR_REJECT",
                    "rejection_reason_detail": result.rationale,
                    "rejection_class": "policy",
                }
            )

        if result.verdict == "reject":
            self._emit_rejection_event(
                state,
                rejection_reason_code=str(result.rejection_reason_code or "VALIDATOR_REJECT"),
                rejection_class=str(result.rejection_class or "policy"),
                rationale=str(result.rationale or ""),
                next_streak=int(state.get("nonproductive_cycle_streak", 0) or 0) + 1,
            )

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

        next_nonproductive_streak = state.get("nonproductive_cycle_streak", 0)
        if result.verdict == "reject":
            next_nonproductive_streak += 1
            if self._metrics:
                self._metrics.record_nonproductive_cycle()
        elif result.verdict in {"approve", "escalate"}:
            next_nonproductive_streak = 0

        output = {
            **state,
            "validation_result": result.model_dump(),
            "nonproductive_cycle_streak": next_nonproductive_streak,
        }
        self._emit_agent_invoked(state, output, _input_hash, _t0)
        return output

    def _emit_rejection_event(
        self,
        state: AgentState,
        rejection_reason_code: str,
        rejection_class: str,
        rationale: str,
        next_streak: int,
    ) -> None:
        if self._event_bus is None:
            return
        try:
            engagement_id = UUID(str(state.get("engagement_id", "")))
            self._event_bus.publish(
                engagement_id,
                ExecutionEvent(
                    engagement_id=engagement_id,
                    event_type=ExecutionEventType.VALIDATOR_REJECTED,
                    actor="validator",
                    payload={
                        "rejection_reason_code": str(rejection_reason_code or "").strip() or "VALIDATOR_REJECT",
                        "rejection_class": str(rejection_class or "").strip() or "policy",
                        "rationale": rationale,
                        "nonproductive_cycle_streak": int(next_streak),
                    },
                ),
            )
        except Exception:
            # Rejection telemetry must never interrupt validator decisions.
            return

    def _deterministic_capability_check(self, proposal: dict[str, Any]) -> dict[str, str] | None:
        available_tools = self._policy_context.get("available_tools") or []
        tools_catalog = self._policy_context.get("tools_catalog") or []
        capability_contracts = self._policy_context.get("capability_contracts") or []
        runtime_mode = str(self._policy_context.get("runtime_mode", "headless")).strip().lower()
        has_display = bool(self._policy_context.get("has_display", False))

        tool_name = str(proposal.get("tool_name", ""))
        if available_tools and tool_name not in available_tools:
            return {
                "rationale": (
                    f"Tool '{tool_name}' is not enabled or trusted in this runtime. "
                    f"Choose from: {available_tools}"
                ),
                "rejection_reason_code": "TOOL_NOT_ENABLED",
                "rejection_reason_detail": f"{tool_name} is outside available_tools.",
                "rejection_class": "capability",
            }

        if isinstance(capability_contracts, list):
            for contract in capability_contracts:
                if not isinstance(contract, dict):
                    continue
                if str(contract.get("tool_name", "")).strip() != tool_name:
                    continue
                supported_modes = {
                    str(v).strip().lower()
                    for v in contract.get("runtime_modes_supported", [])
                    if str(v).strip()
                }
                if supported_modes and runtime_mode not in supported_modes:
                    return {
                        "rationale": (
                            f"Tool '{tool_name}' is not compatible with runtime mode '{runtime_mode}'. "
                            f"Supported modes: {sorted(supported_modes)}"
                        ),
                        "rejection_reason_code": "TOOL_MODE_MISMATCH",
                        "rejection_reason_detail": f"runtime_mode={runtime_mode}",
                        "rejection_class": "capability",
                    }
                if bool(contract.get("requires_display", False)) and not has_display:
                    return {
                        "rationale": f"Tool '{tool_name}' requires a display but runtime is headless.",
                        "rejection_reason_code": "TOOL_MODE_MISMATCH",
                        "rejection_reason_detail": "display_required=true",
                        "rejection_class": "capability",
                    }
                break

        if not tools_catalog:
            return None

        tool_meta = None
        for item in tools_catalog:
            if isinstance(item, dict) and item.get("tool_name") == tool_name:
                tool_meta = item
                break

        if tool_meta is None:
            return None

        risk_class = str(tool_meta.get("risk_class", "")).strip().lower()
        action_type = str(proposal.get("action_type", "")).strip().lower()
        if risk_class and action_type and risk_class != action_type:
            return {
                "rationale": (
                    f"Tool '{tool_name}' has risk class '{risk_class}' but the proposal action_type is "
                    f"'{action_type}'. Choose a tool whose risk class matches the requested action."
                ),
                "rejection_reason_code": "RISK_CLASS_MISMATCH",
                "rejection_reason_detail": f"tool risk_class={risk_class}, action_type={action_type}",
                "rejection_class": "capability",
            }

        required = list(tool_meta.get("required_params", []))
        params = proposal.get("params") if isinstance(proposal.get("params"), dict) else {}

        schema_props = tool_meta.get("parameter_schema", {}) if isinstance(tool_meta.get("parameter_schema"), dict) else {}
        allowed_params = {
            str(name).strip()
            for name in schema_props.keys()
            if str(name).strip() and str(name).strip() != "target"
        }
        unknown = sorted(
            param
            for param in params.keys()
            if param not in allowed_params and param not in {"target", "target_resolved"}
        )
        if allowed_params and unknown:
            return {
                "rationale": f"Proposal includes unsupported parameters for tool '{tool_name}': {unknown}",
                "rejection_reason_code": "UNSUPPORTED_PARAMETERS",
                "rejection_reason_detail": ", ".join(unknown),
                "rejection_class": "capability",
            }

        missing = [p for p in required if p != "target" and p not in params]
        if missing:
            return {
                "rationale": f"Proposal missing required parameters for tool '{tool_name}': {missing}",
                "rejection_reason_code": "MISSING_REQUIRED_PARAMETERS",
                "rejection_reason_detail": ", ".join(missing),
                "rejection_class": "capability",
            }

        for param_name, value in params.items():
            param_schema = schema_props.get(param_name)
            if not isinstance(param_schema, dict):
                continue
            type_name = str(param_schema.get("type", "")).strip().lower()
            if type_name == "string" and not isinstance(value, str):
                return {
                    "rationale": f"Parameter '{param_name}' for tool '{tool_name}' must be a string.",
                    "rejection_reason_code": "INVALID_PARAMETER_TYPE",
                    "rejection_reason_detail": f"{param_name} expected string",
                    "rejection_class": "capability",
                }
            if type_name == "integer" and not _is_valid_integer(value):
                return {
                    "rationale": f"Parameter '{param_name}' for tool '{tool_name}' must be an integer.",
                    "rejection_reason_code": "INVALID_PARAMETER_TYPE",
                    "rejection_reason_detail": f"{param_name} expected integer",
                    "rejection_class": "capability",
                }
            if type_name == "number" and not _is_valid_number(value):
                return {
                    "rationale": f"Parameter '{param_name}' for tool '{tool_name}' must be numeric.",
                    "rejection_reason_code": "INVALID_PARAMETER_TYPE",
                    "rejection_reason_detail": f"{param_name} expected number",
                    "rejection_class": "capability",
                }
            if type_name == "boolean" and not isinstance(value, bool):
                return {
                    "rationale": f"Parameter '{param_name}' for tool '{tool_name}' must be a boolean.",
                    "rejection_reason_code": "INVALID_PARAMETER_TYPE",
                    "rejection_reason_detail": f"{param_name} expected boolean",
                    "rejection_class": "capability",
                }
            if type_name == "array" and not isinstance(value, list):
                return {
                    "rationale": f"Parameter '{param_name}' for tool '{tool_name}' must be an array.",
                    "rejection_reason_code": "INVALID_PARAMETER_TYPE",
                    "rejection_reason_detail": f"{param_name} expected array",
                    "rejection_class": "capability",
                }

            enum_values = param_schema.get("enum")
            if isinstance(enum_values, list) and enum_values and value not in enum_values:
                return {
                    "rationale": (
                        f"Parameter '{param_name}' for tool '{tool_name}' must be one of "
                        f"{enum_values}, got {value!r}."
                    ),
                    "rejection_reason_code": "INVALID_PARAMETER_ENUM",
                    "rejection_reason_detail": f"{param_name} enum mismatch",
                    "rejection_class": "capability",
                }

            if _is_valid_number(value):
                minimum = param_schema.get("minimum")
                maximum = param_schema.get("maximum")
                if minimum is not None and value < minimum:
                    return {
                        "rationale": (
                            f"Parameter '{param_name}' for tool '{tool_name}' must be >= {minimum}, "
                            f"got {value!r}."
                        ),
                        "rejection_reason_code": "INVALID_PARAMETER_RANGE",
                        "rejection_reason_detail": f"{param_name} below minimum {minimum}",
                        "rejection_class": "capability",
                    }
                if maximum is not None and value > maximum:
                    return {
                        "rationale": (
                            f"Parameter '{param_name}' for tool '{tool_name}' must be <= {maximum}, "
                            f"got {value!r}."
                        ),
                        "rejection_reason_code": "INVALID_PARAMETER_RANGE",
                        "rejection_reason_detail": f"{param_name} above maximum {maximum}",
                        "rejection_class": "capability",
                    }

        target = str(proposal.get("target", ""))
        supported = list(tool_meta.get("supported_target_types", []))
        if supported:
            target_type = _classify_target_type(target)
            if target_type not in supported and "unknown" not in supported:
                return {
                    "rationale": (
                        f"Target type '{target_type}' is not supported by tool '{tool_name}'. "
                        f"Supported target types: {supported}"
                    ),
                    "rejection_reason_code": "TARGET_TYPE_NOT_SUPPORTED",
                    "rejection_reason_detail": f"target_type={target_type}, supported={supported}",
                    "rejection_class": "target",
                }

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
