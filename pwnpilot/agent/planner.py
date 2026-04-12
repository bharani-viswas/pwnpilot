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
import ipaddress
import json
import re
import time
from typing import Any

import structlog

from pwnpilot.agent.state import AgentState
from pwnpilot.data.models import PlannerProposal, RiskLevel

log = structlog.get_logger(__name__)

_MAX_REPEATED_STATE: int = 3
_LOW_VALUE_HINT_CODES = frozenset({
    "wildcard_detected",
    "no_forms_detected",
    "no_matches",
    "output_format_invalid",
})


def _proposal_key(proposal: dict[str, Any]) -> str:
    """Stable hash of a proposal for novelty checking."""
    key = f"{proposal.get('tool_name')}:{proposal.get('target')}:{proposal.get('action_type')}"
    return hashlib.sha256(key.encode()).hexdigest()


def _action_signature(tool_name: str, target: str, action_type: str) -> str:
    return f"{tool_name}:{target}:{action_type}"


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


def _strategy_progress(
    strategy_plan: dict[str, Any],
    previous: list[dict[str, Any]],
) -> dict[str, Any]:
    sequence = strategy_plan.get("sequence", []) if isinstance(strategy_plan, dict) else []
    if not isinstance(sequence, list) or not sequence:
        return {}

    used_tools = {
        str(item.get("tool_name", "")).strip()
        for item in previous
        if isinstance(item, dict)
    }

    completed_steps: list[str] = []
    current_step: dict[str, Any] | None = None

    for step in sequence:
        if not isinstance(step, dict):
            continue
        step_tools = {
            str(t).strip()
            for t in (step.get("preferred_tools", []) + step.get("fallback_tools", []))
            if str(t).strip()
        }
        step_id = str(step.get("step_id", "")).strip()
        if step_tools & used_tools:
            if step_id:
                completed_steps.append(step_id)
            continue
        current_step = step
        break

    return {
        "completed_steps": completed_steps,
        "current_step": current_step,
        "remaining_steps": max(0, len(sequence) - len(completed_steps)),
    }


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
        finding_store: Any | None = None,
        available_tools: list[str] | None = None,
        tools_catalog: list[dict[str, Any]] | None = None,
    ) -> None:
        self._llm = llm_router
        self._engagement = engagement_summary
        self._no_novel_count: int = 0
        self._audit = audit_store
        self._finding_store = finding_store
        self._available_tools = available_tools or []
        self._tools_catalog = tools_catalog or []

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
        cooldown_map = self._decay_tool_cooldowns(
            state.get("temporarily_unavailable_tools", {})
        )
        rejection_reason = None

        # Carry forward rejection reason from previous validation (if any)
        prev_proposal = state.get("proposed_action")
        if prev_proposal:
            rejection_reason = prev_proposal.get("rejection_reason")

        # If validator rejected the previous proposal, cool that tool down briefly
        # so fallback logic does not loop on the same incompatible candidate.
        validation_result = state.get("validation_result") or {}
        if (
            isinstance(validation_result, dict)
            and validation_result.get("verdict") == "reject"
            and isinstance(prev_proposal, dict)
        ):
            rejected_tool = str(prev_proposal.get("tool_name", "")).strip()
            if rejected_tool:
                try:
                    current = int(cooldown_map.get(rejected_tool, 0))
                except Exception:
                    current = 0
                cooldown_map[rejected_tool] = max(current, 2)
                log.warning(
                    "planner.rejected_tool_cooldown",
                    tool=rejected_tool,
                    reason=str(validation_result.get("rationale", "")),
                    cooldown=cooldown_map[rejected_tool],
                )

        # Build LLM prompt context with findings data (NEW: Rich context for LLM)
        context = {
            "engagement": self._engagement,
            "iteration": iteration,
            "recon_summary": recon,
            "previous_actions": previous[-10:],  # last 10 for context window efficiency
            "rejection_reason": rejection_reason,
            "available_tools": self._available_tools,
            "tools_catalog": self._tools_catalog,
            "temporarily_unavailable_tools": sorted(cooldown_map.keys()),
        }

        strategy_plan = self._engagement.get("strategy_plan")
        if isinstance(strategy_plan, dict) and strategy_plan:
            context["target_strategy"] = strategy_plan
            context["target_strategy_progress"] = _strategy_progress(strategy_plan, previous)
        
        # Extract canonical tool parameter schemas for LLM (NEW: Schema guidance for accurate params)
        if self._tools_catalog:
            try:
                # Build inline tool registry view from catalog for schema extraction
                # Note: This is a lightweight extraction; full registry not needed
                tool_schemas = {}
                for tool_info in self._tools_catalog:
                    tool_name = tool_info.get("tool_name", "")
                    if tool_name and tool_name in self._available_tools:
                        # Extract key schema fields from catalog
                        tool_schema = {
                            "description": tool_info.get("description", ""),
                            "risk_class": tool_info.get("risk_class", ""),
                            "required_params": tool_info.get("required_params", []),
                            "parameters": tool_info.get("parameter_schema", {}),
                        }
                        tool_schemas[tool_name] = tool_schema
                
                if tool_schemas:
                    context["tool_parameter_schemas"] = tool_schemas
            except Exception as e:
                log.warning("planner.schema_extraction_error", exc=str(e))
        
        # Add findings context if available
        if self._finding_store:
            try:
                engagement_id = self._engagement.get("engagement_id")
                if engagement_id:
                    from uuid import UUID
                    try:
                        eng_uuid = UUID(engagement_id)
                    except (ValueError, TypeError):
                        eng_uuid = None
                    
                    if eng_uuid:
                        all_findings = self._finding_store.findings_for_engagement(eng_uuid)
                        unverified_high = [
                            {
                                "finding_id": str(f.finding_id),
                                "title": f.title,
                                "asset_ref": f.asset_ref,
                                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                                "confidence": f.confidence,
                                "status": f.status.value if hasattr(f.status, 'value') else str(f.status),
                            }
                            for f in all_findings
                            if (f.status.value if hasattr(f.status, 'value') else str(f.status)) == "new"
                            and (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)) in ["critical", "high"]
                        ][:5]  # Top 5 unverified high-risk findings
                        
                        context["unverified_high_findings"] = unverified_high
                        context["findings_count"] = {
                            "total": len(all_findings),
                            "unverified": len([f for f in all_findings if (f.status.value if hasattr(f.status, 'value') else str(f.status)) == "new"]),
                            "verified": len([f for f in all_findings if (f.status.value if hasattr(f.status, 'value') else str(f.status)) == "confirmed"]),
                        }
            except Exception as e:
                log.warning("planner.findings_context_error", exc=str(e))

        try:
            raw_proposal = self._llm.plan(context)
        except Exception as exc:
            log.error("planner.llm_error", exc=str(exc))
            return {**state, "error": f"Planner LLM error: {exc}"}

        proposed_tool = str(raw_proposal.get("tool_name", ""))
        if self._recent_low_value_outcome(
            tool_name=proposed_tool,
            target=str(raw_proposal.get("target", "")),
            action_type=str(raw_proposal.get("action_type", "")),
            previous=previous,
        ):
            fallback_tool = self._select_fallback_tool(
                blocked_tool=proposed_tool,
                cooldown_map=cooldown_map,
                target=str(raw_proposal.get("target", "")),
                action_type=str(raw_proposal.get("action_type", "")),
                previous=previous,
            )
            if fallback_tool:
                log.warning(
                    "planner.low_value_tool_avoided",
                    blocked_tool=proposed_tool,
                    fallback_tool=fallback_tool,
                )
                raw_proposal["tool_name"] = fallback_tool
                raw_proposal["rationale"] = (
                    str(raw_proposal.get("rationale", "")).strip()
                    + f" Switched from '{proposed_tool}' because the same action recently produced low-value runtime hints."
                ).strip()

        if proposed_tool and proposed_tool in cooldown_map:
            fallback_tool = self._select_fallback_tool(
                blocked_tool=proposed_tool,
                cooldown_map=cooldown_map,
                target=str(raw_proposal.get("target", "")),
                action_type=str(raw_proposal.get("action_type", "")),
                previous=previous,
            )
            if fallback_tool:
                log.warning(
                    "planner.unavailable_tool_avoided",
                    blocked_tool=proposed_tool,
                    fallback_tool=fallback_tool,
                )
                raw_proposal["tool_name"] = fallback_tool
                raw_proposal["rationale"] = (
                    str(raw_proposal.get("rationale", "")).strip()
                    + f" Switched from '{proposed_tool}' because it recently failed as unavailable."
                ).strip()

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
            "temporarily_unavailable_tools": cooldown_map,
        }
        self._emit_agent_invoked(state, output, _input_hash, _t0)
        return output

    def _decay_tool_cooldowns(self, cooldowns: dict[str, Any]) -> dict[str, int]:
        """Reduce tool cooldown counters by one planner step."""
        decayed: dict[str, int] = {}
        for tool, value in cooldowns.items():
            try:
                remaining = int(value)
            except Exception:
                continue
            if remaining > 1:
                decayed[tool] = remaining - 1
        return decayed

    def _select_fallback_tool(
        self,
        blocked_tool: str,
        cooldown_map: dict[str, int],
        target: str,
        action_type: str,
        previous: list[dict[str, Any]],
    ) -> str | None:
        """Pick a deterministic fallback tool not in cooldown and not recently repeated."""
        blocked = set(cooldown_map.keys())
        blocked.add(blocked_tool)

        recent_keys = {
            f"{a.get('tool_name')}:{a.get('target')}:{a.get('action_type')}"
            for a in previous[-10:]
            if isinstance(a, dict)
        }

        for candidate in self._available_tools:
            if candidate in blocked:
                continue
            if self._tool_requires_extra_params(candidate):
                continue
            if not self._tool_supports_target(candidate, target):
                continue
            key = f"{candidate}:{target}:{action_type}"
            if key in recent_keys:
                continue
            return candidate
        return None

    def _tool_requires_extra_params(self, tool_name: str) -> bool:
        """Return True when a tool requires mandatory params beyond target.

        Automatic fallback pivots only swap tools, they do not synthesize new
        mandatory parameters, so tools with required non-target params are
        skipped during fallback selection.
        """
        for tool in self._tools_catalog:
            if str(tool.get("tool_name", "")) != tool_name:
                continue
            required = {
                str(param).strip()
                for param in tool.get("required_params", [])
                if str(param).strip()
            }
            required.discard("target")
            return bool(required)
        return False

    def _tool_supports_target(self, tool_name: str, target: str) -> bool:
        """Return True when a tool advertises compatibility with the target type."""
        target_type = _classify_target_type(target)
        for tool in self._tools_catalog:
            if str(tool.get("tool_name", "")) != tool_name:
                continue
            supported = {
                str(item).strip().lower()
                for item in tool.get("supported_target_types", [])
                if str(item).strip()
            }
            if not supported:
                return True
            if target_type in supported:
                return True
            return "unknown" in supported
        return True

    def _recent_low_value_outcome(
        self,
        tool_name: str,
        target: str,
        action_type: str,
        previous: list[dict[str, Any]],
    ) -> bool:
        signature = _action_signature(tool_name, target, action_type)
        for action in reversed(previous[-5:]):
            if not isinstance(action, dict):
                continue
            action_signature = _action_signature(
                str(action.get("tool_name", "")),
                str(action.get("target", "")),
                str(action.get("action_type", "")),
            )
            if action_signature != signature:
                continue
            hint_codes = set(action.get("execution_hint_codes", []))
            if hint_codes & _LOW_VALUE_HINT_CODES:
                return True
        return False

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
