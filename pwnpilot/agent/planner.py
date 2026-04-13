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
from copy import deepcopy
from typing import Any
from urllib.parse import urlparse

import structlog

from pwnpilot.agent.state import AgentState
from pwnpilot.data.models import PlannerProposal, RiskLevel

log = structlog.get_logger(__name__)

_MAX_REPEATED_STATE: int = 3
_MAX_NONPRODUCTIVE_REJECT_STREAK_FOR_PIVOT: int = 5
_MAX_NONPRODUCTIVE_REJECT_STREAK_FOR_KILL: int = 12
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


def _schema_property_names(tool_meta: dict[str, Any]) -> set[str]:
    props = tool_meta.get("parameter_schema", {}) if isinstance(tool_meta, dict) else {}
    if not isinstance(props, dict):
        return set()
    return {str(name).strip() for name in props.keys() if str(name).strip()}


def _target_has_query_params(target: str) -> bool:
    parsed = urlparse(str(target or "").strip())
    return bool(parsed.query)


def _normalize_base_url(url: str) -> str:
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return str(url or "").strip()


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
        step_actions = [
            item for item in previous
            if isinstance(item, dict) and str(item.get("tool_name", "")).strip() in step_tools
        ]
        step_id = str(step.get("step_id", "")).strip()
        if step_actions:
            latest_action = step_actions[-1]
            hint_codes = {
                str(code).strip()
                for code in latest_action.get("execution_hint_codes", [])
                if str(code).strip()
            }
            latest_error = str(latest_action.get("error", "")).strip()
            recovery_policy = None
            for rule in step.get("recovery_rules", []):
                rule_codes = {
                    str(code).strip()
                    for code in rule.get("hint_codes", [])
                    if str(code).strip()
                }
                if hint_codes & rule_codes:
                    recovery_policy = rule
                    break

            if hint_codes & _LOW_VALUE_HINT_CODES or latest_error:
                current_step = {
                    **step,
                    "recovery_hint_codes": sorted(hint_codes),
                    "recovery_preferred_tools": list(recovery_policy.get("preferred_tools", [])) if recovery_policy else [],
                    "active_recovery_rule": recovery_policy or {},
                }
                break

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
        per_step_budget: int = 3,
        adaptive_cooldown_enabled: bool = True,
        adaptive_cooldown_max: int = 6,
        metrics: Any | None = None,
    ) -> None:
        self._llm = llm_router
        self._engagement = engagement_summary
        self._no_novel_count: int = 0
        self._audit = audit_store
        self._finding_store = finding_store
        self._available_tools = available_tools or []
        self._tools_catalog = tools_catalog or []
        self._per_step_budget = max(1, int(per_step_budget))
        self._adaptive_cooldown_enabled = bool(adaptive_cooldown_enabled)
        self._adaptive_cooldown_max = max(1, int(adaptive_cooldown_max))
        self._metrics = metrics

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
        cooldown_map = self._apply_adaptive_cooldowns(cooldown_map, previous)
        rejection_reason = None

        # Carry forward rejection reason from previous validation (if any)
        prev_proposal = state.get("proposed_action")
        if prev_proposal:
            rejection_reason = prev_proposal.get("rejection_reason")

        # If validator rejected the previous proposal, cool that tool down briefly
        # so fallback logic does not loop on the same incompatible candidate.
        validation_result = state.get("validation_result") or {}
        nonproductive_streak = int(state.get("nonproductive_cycle_streak", 0) or 0)
        rejection_reason_code = ""
        rejection_class = ""
        rejection_repeat_count = int(state.get("rejection_repeat_count", 0) or 0)
        last_rejection_code = str(state.get("last_rejection_code", "")).strip()
        last_rejection_class = str(state.get("last_rejection_class", "")).strip()
        blocked_families: set[str] = set()
        if (
            isinstance(validation_result, dict)
            and validation_result.get("verdict") == "reject"
            and isinstance(prev_proposal, dict)
        ):
            rejection_reason_code = str(validation_result.get("rejection_reason_code", "")).strip()
            rejection_class = str(validation_result.get("rejection_class", "")).strip()
            if rejection_reason_code and rejection_reason_code == last_rejection_code and rejection_class == last_rejection_class:
                rejection_repeat_count += 1
            else:
                rejection_repeat_count = 1
            rejected_tool = str(prev_proposal.get("tool_name", "")).strip()
            if rejection_repeat_count >= 2 and rejection_class:
                family = self._tool_family(rejected_tool)
                if family:
                    blocked_families.add(family)
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
              "rejection_reason_code": rejection_reason_code,
              "rejection_class": rejection_class,
        }

        strategy_plan = self._engagement.get("strategy_plan")
        strategy_progress: dict[str, Any] = {}
        current_step: dict[str, Any] | None = None
        step_budget_next_candidates: list[str] = []
        step_budget_next_step_id: str | None = None
        if isinstance(strategy_plan, dict) and strategy_plan:
            strategy_progress = _strategy_progress(strategy_plan, previous)
            current_step = strategy_progress.get("current_step") if isinstance(strategy_progress, dict) else None
            context["target_strategy"] = strategy_plan
            context["target_strategy_progress"] = strategy_progress

            if isinstance(current_step, dict):
                step_attempts = self._step_attempt_count(previous, current_step)
                context["current_step_attempt_count"] = step_attempts
                context["per_step_budget"] = self._per_step_budget
                if step_attempts >= self._per_step_budget:
                    next_candidates, next_step_id = self._next_strategy_step_candidates(
                        strategy_plan,
                        str(current_step.get("step_id", "")).strip(),
                    )
                    if next_candidates:
                        step_budget_next_candidates = next_candidates
                        step_budget_next_step_id = next_step_id
                        context["step_budget_exhausted"] = True
                        context["step_budget_exhausted_step_id"] = str(current_step.get("step_id", "")).strip()
        
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

        raw_proposal = self._apply_attack_surface_targeting(raw_proposal, recon)

        proposed_tool = str(raw_proposal.get("tool_name", ""))
        step_recovery_candidates = self._step_recovery_candidates(current_step)
        recovery_override_applied = False

        raw_proposal, recovery_override_applied = self._apply_recovery_param_overrides(
            raw_proposal,
            current_step,
            proposed_tool,
        )
        proposed_tool = str(raw_proposal.get("tool_name", ""))

        if step_recovery_candidates and proposed_tool not in step_recovery_candidates:
            recovery_tool = self._select_fallback_tool(
                blocked_tool=proposed_tool,
                cooldown_map=cooldown_map,
                target=str(raw_proposal.get("target", "")),
                action_type=str(raw_proposal.get("action_type", "")),
                previous=previous,
                candidate_tools=step_recovery_candidates,
            )
            if recovery_tool:
                log.warning(
                    "planner.step_recovery_override",
                    blocked_tool=proposed_tool,
                    fallback_tool=recovery_tool,
                    step_id=str(current_step.get("step_id", "")),
                    hint_codes=list(current_step.get("recovery_hint_codes", [])),
                )
                raw_proposal = self._rebuild_fallback_proposal(
                    raw_proposal,
                    recovery_tool,
                    (
                        "Stayed within the current target-strategy step because the "
                        "previous attempt returned recoverable low-value hints."
                    ),
                )
                raw_proposal, recovery_override_applied = self._apply_recovery_param_overrides(
                    raw_proposal,
                    current_step,
                    recovery_tool,
                )
                proposed_tool = str(raw_proposal.get("tool_name", ""))

        if not recovery_override_applied and self._recent_low_value_outcome(
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
                candidate_tools=step_recovery_candidates,
                blocked_families=blocked_families,
            )
            if fallback_tool:
                log.warning(
                    "planner.low_value_tool_avoided",
                    blocked_tool=proposed_tool,
                    fallback_tool=fallback_tool,
                )
                raw_proposal = self._rebuild_fallback_proposal(
                    raw_proposal,
                    fallback_tool,
                    (
                        f"Switched from '{proposed_tool}' because the same action "
                        "recently produced low-value runtime hints."
                    ),
                )

        if proposed_tool and proposed_tool in cooldown_map:
            fallback_tool = self._select_fallback_tool(
                blocked_tool=proposed_tool,
                cooldown_map=cooldown_map,
                target=str(raw_proposal.get("target", "")),
                action_type=str(raw_proposal.get("action_type", "")),
                previous=previous,
                blocked_families=blocked_families,
            )
            if fallback_tool:
                log.warning(
                    "planner.unavailable_tool_avoided",
                    blocked_tool=proposed_tool,
                    fallback_tool=fallback_tool,
                )
                raw_proposal = self._rebuild_fallback_proposal(
                    raw_proposal,
                    fallback_tool,
                    f"Switched from '{proposed_tool}' because it recently failed as unavailable.",
                )

        if step_budget_next_candidates and current_step:
            budget_tool = self._select_fallback_tool(
                blocked_tool=str(raw_proposal.get("tool_name", "")),
                cooldown_map=cooldown_map,
                target=str(raw_proposal.get("target", "")),
                action_type=str(raw_proposal.get("action_type", "")),
                previous=previous,
                candidate_tools=step_budget_next_candidates,
                blocked_families=blocked_families,
            )
            if budget_tool:
                raw_proposal = self._rebuild_fallback_proposal(
                    raw_proposal,
                    budget_tool,
                    (
                        f"Advanced from step '{str(current_step.get('step_id', '')).strip()}' "
                        "after exhausting per-step budget."
                    ),
                )
                if step_budget_next_step_id:
                    raw_proposal["strategy_step_id"] = step_budget_next_step_id
                log.info(
                    "planner.step_budget_advance",
                    from_step=str(current_step.get("step_id", "")).strip(),
                    to_step=step_budget_next_step_id,
                    tool=budget_tool,
                )

        if isinstance(current_step, dict) and not raw_proposal.get("strategy_step_id"):
            raw_proposal["strategy_step_id"] = str(current_step.get("step_id", "")).strip()

        # Guardrail for prolonged validator reject churn: force a tool pivot.
        # This prevents planner/validator deadlocks where the loop keeps proposing
        # semantically similar low-value actions.
        if (
            isinstance(validation_result, dict)
            and validation_result.get("verdict") == "reject"
            and isinstance(prev_proposal, dict)
            and nonproductive_streak >= _MAX_NONPRODUCTIVE_REJECT_STREAK_FOR_PIVOT
        ):
            rejected_tool = str(prev_proposal.get("tool_name", "")).strip()
            forced_tool = self._select_fallback_tool(
                blocked_tool=rejected_tool,
                cooldown_map=cooldown_map,
                target=str(raw_proposal.get("target", "")),
                action_type=str(raw_proposal.get("action_type", "")),
                previous=previous,
                blocked_families=blocked_families,
            )
            if forced_tool and forced_tool != str(raw_proposal.get("tool_name", "")).strip():
                raw_proposal = self._rebuild_fallback_proposal(
                    raw_proposal,
                    forced_tool,
                    (
                        "Forced strategy pivot after consecutive validator rejections "
                        "to break nonproductive loop."
                    ),
                )
                log.warning(
                    "planner.reject_streak_forced_pivot",
                    from_tool=rejected_tool,
                    to_tool=forced_tool,
                    streak=nonproductive_streak,
                    reason=str(validation_result.get("rationale", "")),
                    reason_code=str(validation_result.get("rejection_reason_code", "")),
                    rejection_class=str(validation_result.get("rejection_class", "")),
                )
                if self._metrics:
                    self._metrics.record_loop_break_event("forced_pivot")
            elif nonproductive_streak >= _MAX_NONPRODUCTIVE_REJECT_STREAK_FOR_KILL:
                log.error(
                    "planner.nonproductive_reject_loop",
                    streak=nonproductive_streak,
                    rejected_tool=rejected_tool,
                )
                return {
                    **state,
                    "kill_switch": True,
                    "stall_state": "terminal",
                    "termination_reason": "stalled_nonproductive_loop",
                    "error": "Nonproductive reject loop detected; no viable planner pivot available.",
                }
        else:
            rejection_repeat_count = 0
            rejection_reason_code = ""
            rejection_class = ""

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
            "last_rejection_code": rejection_reason_code,
            "last_rejection_class": rejection_class,
            "rejection_repeat_count": rejection_repeat_count,
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

    def _apply_adaptive_cooldowns(
        self,
        cooldown_map: dict[str, int],
        previous: list[dict[str, Any]],
    ) -> dict[str, int]:
        if not self._adaptive_cooldown_enabled:
            return cooldown_map

        updated = dict(cooldown_map)
        tool_stats: dict[str, dict[str, int]] = {}
        for action in previous[-20:]:
            if not isinstance(action, dict):
                continue
            tool = str(action.get("tool_name", "")).strip()
            if not tool:
                continue
            stats = tool_stats.setdefault(tool, {"attempts": 0, "new_findings": 0, "low_value": 0})
            stats["attempts"] += 1
            stats["new_findings"] += int(action.get("new_findings_count", 0) or 0)
            hint_codes = {
                str(code).strip()
                for code in action.get("execution_hint_codes", [])
                if str(code).strip()
            }
            if hint_codes & _LOW_VALUE_HINT_CODES:
                stats["low_value"] += 1

        for tool, stats in tool_stats.items():
            attempts = int(stats.get("attempts", 0))
            findings = int(stats.get("new_findings", 0))
            low_value = int(stats.get("low_value", 0))
            if attempts < 2 or findings > 0 or low_value < 2:
                continue
            adaptive_window = min(self._adaptive_cooldown_max, max(2, low_value + 1))
            updated[tool] = max(int(updated.get(tool, 0) or 0), adaptive_window)
            log.info(
                "planner.adaptive_cooldown_applied",
                tool=tool,
                attempts=attempts,
                low_value_hints=low_value,
                cooldown=updated[tool],
            )
        return updated

    def _step_attempt_count(
        self,
        previous: list[dict[str, Any]],
        current_step: dict[str, Any],
    ) -> int:
        if not isinstance(current_step, dict):
            return 0

        step_id = str(current_step.get("step_id", "")).strip()
        if not step_id:
            return 0

        attempts = 0
        for action in previous:
            if not isinstance(action, dict):
                continue
            if str(action.get("strategy_step_id", "")).strip() == step_id:
                attempts += 1
        return attempts

    def _next_strategy_step_candidates(
        self,
        strategy_plan: dict[str, Any],
        current_step_id: str,
    ) -> tuple[list[str], str | None]:
        sequence = strategy_plan.get("sequence", []) if isinstance(strategy_plan, dict) else []
        if not isinstance(sequence, list) or not sequence:
            return [], None

        current_index = -1
        for idx, step in enumerate(sequence):
            if not isinstance(step, dict):
                continue
            if str(step.get("step_id", "")).strip() == current_step_id:
                current_index = idx
                break

        if current_index < 0 or current_index >= len(sequence) - 1:
            return [], None

        next_step = sequence[current_index + 1]
        if not isinstance(next_step, dict):
            return [], None

        candidates: list[str] = []
        for key in ("preferred_tools", "fallback_tools"):
            for tool_name in next_step.get(key, []):
                candidate = str(tool_name).strip()
                if candidate and candidate not in candidates:
                    candidates.append(candidate)

        return candidates, str(next_step.get("step_id", "")).strip() or None

    def _select_fallback_tool(
        self,
        blocked_tool: str,
        cooldown_map: dict[str, int],
        target: str,
        action_type: str,
        previous: list[dict[str, Any]],
        candidate_tools: list[str] | None = None,
        blocked_families: set[str] | None = None,
    ) -> str | None:
        """Pick a deterministic fallback tool not in cooldown and not recently repeated."""
        blocked = set(cooldown_map.keys())
        if blocked_tool:
            blocked.add(blocked_tool)

        recent_keys = {
            f"{a.get('tool_name')}:{a.get('target')}:{a.get('action_type')}"
            for a in previous[-10:]
            if isinstance(a, dict)
        }

        candidate_pool = candidate_tools or self._available_tools
        blocked_families = blocked_families or set()

        for candidate in candidate_pool:
            if candidate in blocked:
                continue
            if candidate not in self._available_tools:
                continue
            if blocked_families and self._tool_family(candidate) in blocked_families:
                continue
            if self._tool_requires_extra_params(candidate):
                continue
            if not self._tool_matches_action_type(candidate, action_type):
                continue
            if not self._tool_supports_target(candidate, target):
                continue
            key = f"{candidate}:{target}:{action_type}"
            if key in recent_keys:
                continue
            return candidate
        return None

    def _tool_family(self, tool_name: str) -> str:
        tool_meta = self._tool_meta(tool_name)
        if not tool_meta:
            return str(tool_name or "").strip()
        categories = tool_meta.get("categories", []) if isinstance(tool_meta.get("categories", []), list) else []
        if categories:
            return str(categories[0]).strip().lower()
        risk_class = str(tool_meta.get("risk_class", "")).strip().lower()
        if risk_class:
            return risk_class
        return str(tool_name or "").strip().lower()

    def _rebuild_fallback_proposal(
        self,
        proposal: dict[str, Any],
        fallback_tool: str,
        rationale_suffix: str,
    ) -> dict[str, Any]:
        rebuilt = deepcopy(proposal)
        rebuilt["tool_name"] = fallback_tool

        tool_meta = self._tool_meta(fallback_tool)
        filtered_params: dict[str, Any] = {}
        if isinstance(proposal.get("params"), dict):
            source_params = dict(proposal.get("params", {}))
            allowed_params = _schema_property_names(tool_meta) if tool_meta else set()
            allowed_params.discard("target")
            if allowed_params:
                filtered_params = {
                    key: value
                    for key, value in source_params.items()
                    if key in allowed_params
                }

        rebuilt["params"] = filtered_params

        if tool_meta and str(tool_meta.get("risk_class", "")).strip():
            rebuilt["action_type"] = str(tool_meta.get("risk_class", "")).strip()

        rebuilt["rationale"] = (
            str(proposal.get("rationale", "")).strip() + " " + rationale_suffix.strip()
        ).strip()
        return rebuilt

    def _tool_meta(self, tool_name: str) -> dict[str, Any] | None:
        for tool in self._tools_catalog:
            if str(tool.get("tool_name", "")).strip() == tool_name:
                return tool
        return None

    def _tool_matches_action_type(self, tool_name: str, action_type: str) -> bool:
        tool_meta = self._tool_meta(tool_name)
        if not tool_meta:
            return True
        risk_class = str(tool_meta.get("risk_class", "")).strip().lower()
        requested = str(action_type or "").strip().lower()
        if not risk_class or not requested:
            return True
        return risk_class == requested

    def _step_recovery_candidates(self, current_step: dict[str, Any] | None) -> list[str]:
        if not isinstance(current_step, dict):
            return []

        ordered: list[str] = []
        for key in ("recovery_preferred_tools", "preferred_tools", "fallback_tools"):
            for tool_name in current_step.get(key, []):
                candidate = str(tool_name).strip()
                if candidate and candidate not in ordered:
                    ordered.append(candidate)
        return ordered

    def _apply_recovery_param_overrides(
        self,
        proposal: dict[str, Any],
        current_step: dict[str, Any] | None,
        tool_name: str,
    ) -> tuple[dict[str, Any], bool]:
        if not isinstance(current_step, dict):
            return proposal, False

        recovery_rule = current_step.get("active_recovery_rule", {})
        if not isinstance(recovery_rule, dict):
            return proposal, False

        overrides_map = recovery_rule.get("param_overrides", {})
        if not isinstance(overrides_map, dict):
            return proposal, False

        tool_overrides = overrides_map.get(tool_name)
        if not isinstance(tool_overrides, dict) or not tool_overrides:
            return proposal, False

        merged = deepcopy(proposal)
        existing_params = merged.get("params") if isinstance(merged.get("params"), dict) else {}
        merged["params"] = {**existing_params, **tool_overrides}
        merged["rationale"] = (
            str(merged.get("rationale", "")).strip()
            + " Applied step recovery parameter overrides based on recent runtime hints."
        ).strip()
        return merged, True

    def _apply_attack_surface_targeting(
        self,
        proposal: dict[str, Any],
        recon_summary: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(proposal, dict):
            return proposal
        if not isinstance(recon_summary, dict):
            return proposal

        tool_name = str(proposal.get("tool_name", "")).strip()
        if not tool_name:
            return proposal

        tool_meta = self._tool_meta(tool_name)
        if not tool_meta:
            return proposal

        supported = {
            str(item).strip().lower()
            for item in tool_meta.get("supported_target_types", [])
            if str(item).strip()
        }
        if "url" not in supported:
            return proposal

        surface = recon_summary.get("attack_surface")
        if not isinstance(surface, dict):
            return proposal

        endpoints = [str(v).strip() for v in surface.get("endpoints", []) if str(v).strip()]
        web_targets = [str(v).strip() for v in surface.get("web_targets", []) if str(v).strip()]
        auth_paths = {str(v).strip() for v in surface.get("auth_paths", []) if str(v).strip()}
        parameters = [str(v).strip() for v in surface.get("parameters", []) if str(v).strip()]

        if not endpoints and not web_targets:
            return proposal

        current_target = str(proposal.get("target", "")).strip()

        preferred_endpoint = ""
        if endpoints:
            auth_endpoint = next(
                (
                    endpoint
                    for endpoint in endpoints
                    if urlparse(endpoint).path in auth_paths
                ),
                "",
            )
            param_endpoint = next((endpoint for endpoint in endpoints if _target_has_query_params(endpoint)), "")
            preferred_endpoint = auth_endpoint or param_endpoint or endpoints[0]

        preferred_base = web_targets[0] if web_targets else ""
        preferred_target = preferred_endpoint or preferred_base

        if not preferred_target:
            return proposal

        current_base = _normalize_base_url(current_target)
        preferred_base_norm = _normalize_base_url(preferred_target)
        if current_target == preferred_target:
            return proposal
        if current_target == preferred_base and preferred_endpoint:
            pass
        elif current_base == preferred_base_norm and not preferred_endpoint:
            return proposal

        updated = deepcopy(proposal)
        updated["target"] = preferred_target
        rationale_suffix = ""
        if preferred_endpoint and _target_has_query_params(preferred_endpoint):
            rationale_suffix = " Prioritized discovered endpoint with query parameters from attack_surface."
        elif preferred_endpoint:
            rationale_suffix = " Prioritized discovered endpoint from attack_surface."
        else:
            rationale_suffix = " Prioritized discovered web target from attack_surface."

        if parameters:
            rationale_suffix += f" Known parameters: {', '.join(parameters[:5])}."

        updated["rationale"] = (str(updated.get("rationale", "")).strip() + rationale_suffix).strip()
        log.info(
            "planner.attack_surface_target_override",
            tool=tool_name,
            from_target=current_target,
            to_target=preferred_target,
        )
        return updated

    def _tool_requires_extra_params(self, tool_name: str) -> bool:
        """Return True when a tool requires mandatory params beyond target.

        Automatic fallback pivots only swap tools, they do not synthesize new
        mandatory parameters, so tools with required non-target params are
        skipped during fallback selection.
        """
        tool = self._tool_meta(tool_name)
        if tool:
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
        tool = self._tool_meta(tool_name)
        if tool:
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
