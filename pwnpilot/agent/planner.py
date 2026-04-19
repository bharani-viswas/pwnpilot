"""
Planner Agent — decides the next action given current engagement state.

Reads from AgentState:
  recon_summary, previous_actions, engagement_scope, iteration_count
  operator_directives, memory_context (v2)

Writes to AgentState:
  proposed_action (PlannerProposal serialised), kill_switch (if circuit breaker fires)
  repeated_action_count, last_repeated_action_key (v2 repetition tracking)

v2 additions:
  - Consumes operator_directives (objective, requested_focus, constraints,
    paused_tool_families, notes) and injects them into the LLM prompt.
  - Consumes memory_context (retrieved findings/strategies) for context stability.
  - Uses RepetitionDetector to suppress redundant action proposals before LLM call.
  - Emits repetition.detected audit events when suppression occurs.

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
from urllib.parse import urlencode, urlparse

import structlog

from pwnpilot.agent.repetition_detector import RepetitionDetector
from pwnpilot.agent.state import AgentState
from pwnpilot.data.models import PlannerProposal, RiskLevel
from pwnpilot.observability.tracing import tracer

log = structlog.get_logger(__name__)

_MAX_REPEATED_STATE: int = 3
_MAX_NONPRODUCTIVE_REJECT_STREAK_FOR_PIVOT: int = 5
_MAX_NONPRODUCTIVE_REJECT_STREAK_FOR_KILL: int = 12
_REFLECTOR_INTERVENTION_REJECT_STREAK: int = 6
_REFLECTOR_TERMINATE_REJECT_STREAK: int = 10
_LOW_VALUE_HINT_CODES = frozenset({
    "wildcard_detected",
    "no_forms_detected",
    "no_matches",
    "output_format_invalid",
    "execution_error",
    "target_projection_invalid",
    "no_attack_surface",
    "parser_schema_mismatch",
    "low_value_repetition",
})

_LOW_VALUE_FAILURE_REASONS = frozenset({
    "TargetUnreachable",
    "ToolModeMismatch",
    "Timeout",
    "ParserDegraded",
    "NoActionableOutput",
    "UnknownRuntimeFailure",
})

_OBJECTIVE_TOOL_CANDIDATES: dict[str, tuple[str, ...]] = {
    "injection": ("sqlmap", "zap", "nuclei"),
    "auth": ("zap", "nuclei", "sqlmap"),
    "access_control": ("zap", "nuclei", "sqlmap"),
    "exposure": ("nuclei", "nikto", "zap"),
    "headers": ("zap", "nuclei", "nikto"),
    "session": ("zap", "nuclei", "sqlmap"),
    "generic": ("nuclei", "zap", "nikto", "sqlmap"),
}

_SPECIALIST_TOOL_CANDIDATES: dict[str, tuple[str, ...]] = {
    "recon": ("nmap", "whatweb", "nuclei", "nikto", "gobuster"),
    "injection": ("sqlmap", "zap", "nuclei"),
    "auth_session": ("zap", "nuclei", "sqlmap"),
}

_SCAN_CHURN_HINT_CODES = frozenset({
    "wildcard_detected",
    "no_forms_detected",
    "no_matches",
    "execution_error",
    "output_format_invalid",
    "target_projection_invalid",
    "no_attack_surface",
    "parser_schema_mismatch",
    "low_value_repetition",
})


def _action_has_meaningful_progress(action: dict[str, Any]) -> bool:
    if not isinstance(action, dict):
        return False

    telemetry_keys = {
        "outcome_status",
        "new_findings_count",
        "exploit_signal_score",
        "confirmation_candidate_count",
        "execution_hint_codes",
        "failure_reasons",
    }
    if not any(key in action for key in telemetry_keys):
        # Backward compatibility: older history entries only recorded tool names.
        return True

    outcome = str(action.get("outcome_status", "")).strip().lower()
    if outcome not in {"success", "degraded"}:
        return False

    action_type = str(action.get("action_type", "")).strip().lower()
    new_findings = int(action.get("new_findings_count", 0) or 0)
    exploit_score = int(action.get("exploit_signal_score", 0) or 0)
    confirmation_candidates = int(action.get("confirmation_candidate_count", 0) or 0)
    hint_codes = {
        str(code).strip()
        for code in action.get("execution_hint_codes", [])
        if str(code).strip()
    }
    failure_reasons = {
        str(reason).strip()
        for reason in action.get("failure_reasons", [])
        if str(reason).strip()
    }

    low_value_only = bool(hint_codes) and hint_codes.issubset(_LOW_VALUE_HINT_CODES)
    low_value_failure = bool(failure_reasons & _LOW_VALUE_FAILURE_REASONS)

    # Exploit phases require stronger proof signals than scan/recon phases.
    if action_type in {"exploit", "post_exploit", "data_exfil"}:
        return (exploit_score > 0 or confirmation_candidates > 0) and not low_value_only

    if exploit_score > 0 or confirmation_candidates > 0:
        return True

    if new_findings > 0 and not low_value_failure and not low_value_only:
        return True

    return False

# v2: RepetitionDetector singleton used by PlannerNode
_repetition_detector = RepetitionDetector(repeat_threshold=3, similarity_threshold=5)


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


def _objective_priority(objective: dict[str, Any]) -> int:
    severity = str(objective.get("severity", "")).strip().lower()
    status = str(objective.get("status", "")).strip().lower()
    base = {
        "critical": 400,
        "high": 300,
        "medium": 200,
        "low": 100,
        "info": 50,
    }.get(severity, 25)
    status_bonus = {
        "open": 30,
        "in_progress": 20,
        "disproved": 10,
        "confirmed": 0,
    }.get(status, 0)
    return base + status_bonus


def _base_target_match(left: str, right: str) -> bool:
    left_base = _normalize_base_url(left)
    right_base = _normalize_base_url(right)
    return bool(left_base) and left_base == right_base


def _recent_no_forms_hint(previous: list[dict[str, Any]], target: str, lookback: int = 8) -> bool:
    recent = previous[-max(1, lookback):]
    for action in reversed(recent):
        if not isinstance(action, dict):
            continue
        if str(action.get("tool_name", "")).strip() != "sqlmap":
            continue
        if not _base_target_match(str(action.get("target", "")), target):
            continue
        hint_codes = {
            str(code).strip()
            for code in action.get("execution_hint_codes", [])
            if str(code).strip()
        }
        if "no_forms_detected" in hint_codes:
            return True
    return False


def _safe_mode_reason(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text)


def _scan_churn_detected(
    previous: list[dict[str, Any]],
    target: str,
    action_type: str,
) -> bool:
    recent = previous[-6:]
    if len(recent) < 3:
        return False

    churn_events = 0
    for action in recent:
        if not isinstance(action, dict):
            continue
        if str(action.get("action_type", "")).strip() != action_type:
            continue
        if not _base_target_match(str(action.get("target", "")), target):
            continue

        hints = {
            str(code).strip()
            for code in action.get("execution_hint_codes", [])
            if str(code).strip()
        }
        reasons = {
            str(reason).strip()
            for reason in action.get("failure_reasons", [])
            if str(reason).strip()
        }
        if (hints & _SCAN_CHURN_HINT_CODES) or ("NoActionableOutput" in reasons):
            churn_events += 1

    return churn_events >= 3


class PlannerNode:
    """
    Stateless callable that can be used as a LangGraph node function.

    The LLM call is delegated to *llm_router*.  In simulation/test mode, *llm_router*
    can be replaced with a stub.

    v2: Consumes operator_directives and memory_context from AgentState.
        Uses RepetitionDetector to suppress redundant proposals.
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
        repetition_detector: RepetitionDetector | None = None,
        operator_session_manager: Any | None = None,
        retrieval_store: Any | None = None,
        rag_retriever: Any | None = None,
        task_tree_store: Any | None = None,
        specialist_router: Any | None = None,
        policy_prior: Any | None = None,
        task_tree_context_limit: int = 8,
        tactical_memory_window: int = 12,
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
        self._repetition_detector = repetition_detector or _repetition_detector
        self._operator_session = operator_session_manager
        self._retrieval_store = retrieval_store
        self._rag_retriever = rag_retriever
        self._task_tree_store = task_tree_store
        self._specialist_router = specialist_router
        self._policy_prior = policy_prior
        self._task_tree_context_limit = max(1, int(task_tree_context_limit))
        self._tactical_memory_window = max(1, int(tactical_memory_window))

    def __call__(self, state: AgentState) -> AgentState:
        if state.get("kill_switch"):
            return state

        # Pull fresh operator directives/messages each planning iteration.
        if self._operator_session is not None:
            try:
                patch = self._operator_session.state_patch()  # type: ignore[attr-defined]
                if isinstance(patch, dict) and patch:
                    state = {**state, **patch}
            except Exception as exc:
                log.warning("planner.operator_session_patch_failed", exc=str(exc))

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
        reject_reason_streak = int(state.get("reject_reason_streak_count", 0) or 0)
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

        # v2: Inject operator directives into planning context
        operator_directives = state.get("operator_directives") or {}
        operator_context: dict[str, Any] = {}
        if operator_directives:
            if operator_directives.get("objective"):
                operator_context["operator_objective"] = operator_directives["objective"]
            if operator_directives.get("requested_focus"):
                operator_context["operator_requested_focus"] = operator_directives["requested_focus"]
            if operator_directives.get("constraints"):
                operator_context["operator_constraints"] = operator_directives["constraints"]
            if operator_directives.get("paused_tool_families"):
                paused = operator_directives["paused_tool_families"]
                operator_context["operator_paused_tool_families"] = paused
                # Add paused families to blocked set
                blocked_families.update(paused)
            if operator_directives.get("notes"):
                operator_context["operator_notes"] = operator_directives["notes"]

            # v2 run-quality: record operator intervention for any active directive
            try:
                from pwnpilot.observability.metrics import metrics_registry
                m = metrics_registry.get(str(state.get("engagement_id", "")))
                if m is not None:
                    m.record_operator_intervention()
            except Exception:
                pass

        # v2: Inject retrieval memory context — query RetrievalStore for relevant context
        memory_context = state.get("memory_context") or {}
        if self._retrieval_store is not None:
            try:
                engagement_id_str = str(state.get("engagement_id", ""))
                recon_hint = recon if isinstance(recon, str) else str(recon or "")
                from uuid import UUID as _UUID
                retrieved = self._retrieval_store.query(
                    _UUID(engagement_id_str),
                    query_text=recon_hint[:500] or "penetration test findings",
                    top_k=5,
                )
                if retrieved:
                    memory_context = {"retrieved_context": retrieved}
            except Exception as _re:
                log.debug("planner.retrieval_query_error", exc=str(_re))

        # RAG context — ATT&CK knowledge base + engagement history via RagRetriever
        rag_context: list[dict] = []
        if self._rag_retriever is not None:
            try:
                from uuid import UUID as _UUID2
                engagement_id_str = str(state.get("engagement_id", ""))
                recon_hint = recon if isinstance(recon, str) else str(recon or "")
                if self._audit:
                    try:
                        self._audit.append(
                            engagement_id=_UUID2(engagement_id_str),
                            actor="planner",
                            event_type="rag.retrieve.started",
                            payload={"query": recon_hint[:200]},
                        )
                    except Exception:
                        pass
                eng_uuid: _UUID2 | None = None
                try:
                    eng_uuid = _UUID2(engagement_id_str)
                except (ValueError, TypeError):
                    pass
                rag_context = self._rag_retriever.retrieve(
                    query_text=recon_hint[:500] or "penetration test attack techniques",
                    engagement_id=eng_uuid,
                )
                if self._audit:
                    try:
                        self._audit.append(
                            engagement_id=_UUID2(engagement_id_str),
                            actor="planner",
                            event_type="rag.retrieve.completed",
                            payload={
                                "result_count": len(rag_context),
                                "top_technique": rag_context[0].get("technique_id") if rag_context else None,
                                "top_confidence": rag_context[0].get("confidence") if rag_context else None,
                            },
                        )
                        if not rag_context:
                            self._audit.append(
                                engagement_id=_UUID2(engagement_id_str),
                                actor="planner",
                                event_type="rag.retrieve.fallback",
                                payload={"reason": "empty_result", "fallback": "legacy_memory_context"},
                            )
                    except Exception:
                        pass
            except Exception as _rag_err:
                log.debug("planner.rag_retrieval_error", exc=str(_rag_err))
                if self._audit:
                    try:
                        from uuid import UUID as _UUID3
                        self._audit.append(
                            engagement_id=_UUID3(str(state.get("engagement_id", ""))),
                            actor="planner",
                            event_type="rag.retrieve.error",
                            payload={"error": str(_rag_err)},
                        )
                    except Exception:
                        pass

        # Phase 6B: strategic task-tree memory context
        task_tree_context: dict[str, Any] = {}
        if self._task_tree_store is not None:
            try:
                from uuid import UUID as _UUID4
                task_tree_context = self._task_tree_store.summarize_for_planner(
                    _UUID4(str(state.get("engagement_id", ""))),
                    limit=self._task_tree_context_limit,
                )
            except Exception as task_exc:
                log.debug("planner.task_tree_summary_error", exc=str(task_exc))

        # Phase 6B: tactical rolling memory summary
        tactical_memory: dict[str, Any] = {}
        try:
            from pwnpilot.control.session_memory import summarize_tactical_memory

            tactical_memory = summarize_tactical_memory(
                previous_actions=previous,
                max_items=self._tactical_memory_window,
            )
        except Exception:
            tactical_memory = {}

        # Build LLM prompt context with findings data
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

        # Inject operator context deterministically
        if operator_context:
            context["operator_guidance"] = operator_context

        # Inject retrieval memory context (backward compat — legacy key)
        if memory_context:
            context["memory_context"] = memory_context

        # Inject RAG context (preferred key — ATT&CK + engagement history)
        if rag_context:
            context["rag_context"] = rag_context

        if task_tree_context:
            context["task_tree_context"] = task_tree_context

        if tactical_memory:
            context["tactical_memory"] = tactical_memory

        objective_focus = self._current_objective_focus(state)
        if objective_focus:
            context["objective_focus"] = objective_focus

        # Phase 6D: specialist routing hint
        specialist_decision: dict[str, Any] = {}
        if self._specialist_router is not None:
            try:
                graph_snapshot = (state.get("attack_surface_graph") or {}) if isinstance(state, dict) else {}
                specialist_decision = self._specialist_router.select_profile(
                    graph_snapshot=graph_snapshot,
                    objective_focus=objective_focus,
                    rag_context=rag_context,
                )
                if specialist_decision:
                    context["specialist_guidance"] = specialist_decision
            except Exception as spec_exc:
                log.debug("planner.specialist_router_error", exc=str(spec_exc))

        specialist_profile = str(specialist_decision.get("specialist_profile", "")).strip().lower()
        
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
            with tracer.span(
                "planner.llm_call",
                engagement_id=str(state.get("engagement_id", "")),
                iteration=iteration,
            ) as span:
                raw_proposal = self._llm.plan(context)
                span.set_attribute("proposed_tool", raw_proposal.get("tool_name", ""))
        except Exception as exc:
            log.error("planner.llm_error", exc=str(exc))
            return {**state, "error": f"Planner LLM error: {exc}"}

        raw_proposal = self._apply_attack_surface_targeting(raw_proposal, recon)

        proposal_target = str(raw_proposal.get("target", "")).strip()
        proposal_action_type = str(raw_proposal.get("action_type", "")).strip() or "active_scan"
        scan_churn_active = _scan_churn_detected(
            previous=previous,
            target=proposal_target,
            action_type=proposal_action_type,
        )
        objective_followup_required = bool(objective_focus) and (
            scan_churn_active
            or int(state.get("nonproductive_cycle_streak", 0) or 0) >= 2
            or str(objective_focus.get("status", "")).strip().lower() in {"open", "disproved"}
        )
        if objective_followup_required:
            raw_proposal = self._apply_objective_followup(
                proposal=raw_proposal,
                objective=objective_focus or {},
                cooldown_map=cooldown_map,
                previous=previous,
                blocked_families=blocked_families,
            )
            if scan_churn_active:
                raw_proposal["rationale"] = (
                    str(raw_proposal.get("rationale", "")).strip()
                    + " Detected repeated low-value scan churn; forcing objective-driven follow-up."
                ).strip()
                log.warning(
                    "planner.scan_churn_objective_pivot",
                    tool=raw_proposal.get("tool_name"),
                    target=raw_proposal.get("target"),
                )

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

        # Phase 6D: specialist-guided pivot (behavioral, not just metadata)
        # If specialist profile is known and current proposal does not align,
        # try a deterministic in-family fallback to reduce low-value churn.
        if specialist_profile in _SPECIALIST_TOOL_CANDIDATES:
            specialist_candidates = list(_SPECIALIST_TOOL_CANDIDATES.get(specialist_profile, ()))
            current_tool = str(raw_proposal.get("tool_name", "")).strip()
            if current_tool and current_tool not in specialist_candidates:
                specialist_tool = self._select_fallback_tool(
                    blocked_tool=current_tool,
                    cooldown_map=cooldown_map,
                    target=str(raw_proposal.get("target", "")),
                    action_type=str(raw_proposal.get("action_type", "")),
                    previous=previous,
                    candidate_tools=specialist_candidates,
                    blocked_families=blocked_families,
                )
                if specialist_tool and specialist_tool != current_tool:
                    raw_proposal = self._rebuild_fallback_proposal(
                        raw_proposal,
                        specialist_tool,
                        (
                            f"Specialist router selected '{specialist_profile}' profile; "
                            f"pivoting tool from '{current_tool}' to '{specialist_tool}'."
                        ),
                    )
                    log.info(
                        "planner.specialist_pivot",
                        specialist_profile=specialist_profile,
                        from_tool=current_tool,
                        to_tool=specialist_tool,
                    )

        # Guardrail for prolonged validator reject churn: force a tool pivot.
        # This prevents planner/validator deadlocks where the loop keeps proposing
        # semantically similar low-value actions.
        if (
            isinstance(validation_result, dict)
            and validation_result.get("verdict") == "reject"
            and isinstance(prev_proposal, dict)
            and reject_reason_streak >= _REFLECTOR_INTERVENTION_REJECT_STREAK
        ):
            rejected_tool = str(prev_proposal.get("tool_name", "")).strip()
            reflection = self._reflect_reject_churn_decision(
                state=state,
                raw_proposal=raw_proposal,
                rejected_tool=rejected_tool,
                reject_reason_code=str(validation_result.get("rejection_reason_code", "")).strip(),
                rejection_class=str(validation_result.get("rejection_class", "")).strip(),
                reject_reason_streak=reject_reason_streak,
            )

            if reflection.get("decision") == "terminate":
                termination_reason = str(
                    reflection.get("termination_reason") or "reflector_terminate"
                ).strip() or "reflector_terminate"
                rationale = str(reflection.get("rationale") or "").strip()
                log.error(
                    "planner.reflector_terminate",
                    streak=reject_reason_streak,
                    rejected_tool=rejected_tool,
                    termination_reason=termination_reason,
                )
                return {
                    **state,
                    "force_report": True,
                    "report_trigger_reason": termination_reason,
                    "stall_state": "terminal",
                    "termination_reason": termination_reason,
                    "error": rationale or "Reflector terminated nonproductive reject churn.",
                }

            reflector_candidates = reflection.get("candidate_tools")
            if not isinstance(reflector_candidates, list) or not reflector_candidates:
                reflector_candidates = None

            forced_tool = self._select_fallback_tool(
                blocked_tool=rejected_tool,
                cooldown_map=cooldown_map,
                target=str(raw_proposal.get("target", "")),
                action_type=str(raw_proposal.get("action_type", "")),
                previous=previous,
                candidate_tools=reflector_candidates,
                blocked_families=blocked_families,
            )
            if forced_tool and forced_tool != str(raw_proposal.get("tool_name", "")).strip():
                raw_proposal = self._rebuild_fallback_proposal(
                    raw_proposal,
                    forced_tool,
                    (
                        "Reflector-triggered strategy pivot after repeated validator "
                        "rejects to break planner-validator churn."
                    ),
                )
                log.warning(
                    "planner.reflector_pivot",
                    from_tool=rejected_tool,
                    to_tool=forced_tool,
                    streak=reject_reason_streak,
                    reason=str(validation_result.get("rationale", "")),
                    reason_code=str(validation_result.get("rejection_reason_code", "")),
                    rejection_class=str(validation_result.get("rejection_class", "")),
                )
                if self._metrics:
                    self._metrics.record_loop_break_event("forced_pivot")
            elif reject_reason_streak >= _REFLECTOR_TERMINATE_REJECT_STREAK:
                log.error(
                    "planner.nonproductive_reject_loop",
                    streak=reject_reason_streak,
                    rejected_tool=rejected_tool,
                )
                return {
                    **state,
                    "force_report": True,
                    "report_trigger_reason": "reflector_terminate",
                    "stall_state": "terminal",
                    "termination_reason": "reflector_terminate",
                    "error": "Nonproductive reject loop detected; no viable planner pivot available.",
                }
        else:
            rejection_repeat_count = 0
            rejection_reason_code = ""
            rejection_class = ""

        # Normalize params before proposal validation.
        proposal_tool = str(raw_proposal.get("tool_name", "")).strip()
        proposal_params = raw_proposal.get("params")

        # Phase 6A/6D/6E proposal metadata enrichment.
        technique_ids = [
            str(item.get("technique_id", "")).strip()
            for item in rag_context
            if isinstance(item, dict) and str(item.get("technique_id", "")).strip()
        ]
        raw_proposal["attack_technique_ids"] = technique_ids[:5]
        raw_proposal["retrieval_sources"] = sorted(
            {
                str(item.get("source", "")).strip()
                for item in rag_context
                if isinstance(item, dict) and str(item.get("source", "")).strip()
            }
        )
        if rag_context:
            top_conf = max(
                float(item.get("confidence", 0.0) or 0.0)
                for item in rag_context
                if isinstance(item, dict)
            )
            raw_proposal["retrieval_confidence"] = round(top_conf, 4)
        if specialist_decision:
            raw_proposal["specialist_profile"] = str(
                specialist_decision.get("specialist_profile", "")
            ).strip() or None
        if self._policy_prior is not None:
            try:
                raw_proposal["policy_prior_score"] = float(self._policy_prior.score(raw_proposal, state))
            except Exception:
                raw_proposal["policy_prior_score"] = None

        if isinstance(proposal_params, dict):
            raw_proposal["params"] = self._sanitize_tool_params(proposal_tool, proposal_params)
        else:
            raw_proposal["params"] = {}

        # Validate proposal structure
        try:
            proposal = PlannerProposal(**raw_proposal)
        except Exception as exc:
            log.error("planner.invalid_proposal", exc=str(exc))
            return {**state, "error": f"Invalid planner proposal: {exc}"}

        # v2: Repetition detection — suppress redundant proposals before LLM loop
        repetition_result = self._repetition_detector.check(
            tool_name=proposal.tool_name,
            target=proposal.target,
            action_type=proposal.action_type,
            previous_actions=previous,
        )
        repeated_action_count = int(state.get("repeated_action_count", 0))
        last_repeated_key = state.get("last_repeated_action_key")

        if repetition_result.is_repeated:
            repeated_action_count += 1
            last_repeated_key = f"{proposal.tool_name}:{proposal.target}:{proposal.action_type}"
            log.warning(
                "planner.repetition_suppressed",
                reason_code=repetition_result.reason_code,
                occurrences=repetition_result.occurrences,
                tool=proposal.tool_name,
                hint=repetition_result.hint,
            )
            if self._audit:
                try:
                    from uuid import UUID
                    self._audit.append(
                        engagement_id=UUID(state["engagement_id"]),
                        actor="planner",
                        event_type="repetition.detected",
                        payload={
                            "reason_code": repetition_result.reason_code,
                            "occurrences": repetition_result.occurrences,
                            "tool": proposal.tool_name,
                            "target": proposal.target,
                            "hint": repetition_result.hint,
                        },
                    )
                except Exception:
                    pass
            # Inject repetition context into rejection_reason so LLM can pivot
            raw_proposal_with_hint = raw_proposal.copy()
            raw_proposal_with_hint["rejection_reason"] = repetition_result.hint
            return {
                **state,
                "proposed_action": raw_proposal_with_hint,
                "iteration_count": iteration + 1,
                "temporarily_unavailable_tools": cooldown_map,
                "repeated_action_count": repeated_action_count,
                "last_repeated_action_key": last_repeated_key,
                "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
            }

        # Novelty check (hash-based deduplification)
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
                return {
                    **state,
                    "force_report": True,
                    "report_trigger_reason": "repeated_state_circuit_breaker",
                    "stall_state": "terminal",
                    "termination_reason": "repeated_state_circuit_breaker",
                    "error": "Repeated-state circuit breaker fired.",
                }
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
            "repeated_action_count": repeated_action_count,
            "last_repeated_action_key": last_repeated_key,
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
            failure_reasons = {
                str(reason).strip()
                for reason in action.get("failure_reasons", [])
                if str(reason).strip()
            }
            if hint_codes & _LOW_VALUE_HINT_CODES or failure_reasons & _LOW_VALUE_FAILURE_REASONS:
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
        original_tool = str(proposal.get("tool_name", "")).strip()
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

        rebuilt["params"] = self._sanitize_tool_params(fallback_tool, filtered_params)

        if tool_meta and str(tool_meta.get("risk_class", "")).strip():
            rebuilt["action_type"] = str(tool_meta.get("risk_class", "")).strip()

        transition_note = (
            f"Planner fallback selected '{fallback_tool}'"
            + (f" instead of '{original_tool}'" if original_tool and original_tool != fallback_tool else "")
            + " due to runtime guardrails."
        )
        rebuilt["rationale"] = (
            transition_note + " " + rationale_suffix.strip()
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
        if risk_class == requested:
            return True
        # Also accept if tool declares this action_type as explicitly compatible.
        compatible = [
            str(v).strip().lower()
            for v in (tool_meta.get("compatible_action_types") or [])
            if str(v).strip()
        ]
        return requested in compatible

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

        if tool_name == "sqlmap":
            params_obj = updated.get("params") if isinstance(updated.get("params"), dict) else {}
            sqlmap_params = dict(params_obj)
            # Form discovery is usually low-value on SPA roots and API-first targets.
            sqlmap_params["forms"] = False
            sqlmap_params["mode_selection_reason"] = "attack_surface_parameterized"

            if parameters and not sqlmap_params.get("data") and not _target_has_query_params(str(updated.get("target", ""))):
                sqlmap_params["data"] = f"{parameters[0]}=1"

            if parameters and not _target_has_query_params(str(updated.get("target", ""))):
                sep = "&" if "?" in str(updated["target"]) else "?"
                updated["target"] = f"{updated['target']}{sep}{urlencode({parameters[0]: '1'})}"

            updated["params"] = sqlmap_params

        rationale_suffix = ""
        if preferred_endpoint and _target_has_query_params(preferred_endpoint):
            rationale_suffix = " Prioritized discovered endpoint with query parameters from attack_surface."
        elif preferred_endpoint:
            rationale_suffix = " Prioritized discovered endpoint from attack_surface."
        else:
            rationale_suffix = " Prioritized discovered web target from attack_surface."

        if tool_name == "sqlmap":
            rationale_suffix += " Configured sqlmap for parameterized API-aware testing."

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

    def _enforce_sqlmap_mode_from_history(
        self,
        proposal: dict[str, Any],
        previous: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if not isinstance(proposal, dict):
            return proposal

        tool_name = str(proposal.get("tool_name", "")).strip()
        if tool_name != "sqlmap":
            return proposal

        target = str(proposal.get("target", "")).strip()
        if not target or not _recent_no_forms_hint(previous, target):
            return proposal

        updated = deepcopy(proposal)
        params_obj = updated.get("params") if isinstance(updated.get("params"), dict) else {}
        sqlmap_params = dict(params_obj)
        sqlmap_params["forms"] = False
        if not _safe_mode_reason(sqlmap_params.get("mode_selection_reason")):
            sqlmap_params["mode_selection_reason"] = "no_forms_hint_recovery"
        updated["params"] = sqlmap_params
        updated["rationale"] = (
            str(updated.get("rationale", "")).strip()
            + " Disabled sqlmap form discovery because this target recently returned no_forms_detected."
        ).strip()
        return updated

    def _sanitize_tool_params(self, tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
        sanitized = dict(params or {})
        if tool_name == "gobuster":
            exclude_length = sanitized.get("exclude_length")
            if exclude_length not in (None, ""):
                try:
                    sanitized["exclude_length"] = max(1, int(exclude_length))
                except (TypeError, ValueError):
                    sanitized.pop("exclude_length", None)
        elif tool_name == "sqlmap":
            forms_value = sanitized.get("forms")
            if forms_value is not None:
                if isinstance(forms_value, bool):
                    sanitized["forms"] = forms_value
                else:
                    sanitized["forms"] = str(forms_value).strip().lower() in {
                        "1",
                        "true",
                        "yes",
                        "on",
                    }
        return sanitized

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
            hint_codes = {
                str(code).strip()
                for code in action.get("execution_hint_codes", [])
                if str(code).strip()
            }
            failure_reasons = {
                str(reason).strip()
                for reason in action.get("failure_reasons", [])
                if str(reason).strip()
            }
            if hint_codes & _LOW_VALUE_HINT_CODES or failure_reasons & _LOW_VALUE_FAILURE_REASONS:
                return True
        return False

    def _current_objective_focus(self, state: AgentState) -> dict[str, Any] | None:
        objectives = state.get("assessment_objectives", [])
        if not isinstance(objectives, list):
            return None

        candidates = [
            obj for obj in objectives
            if isinstance(obj, dict)
            and str(obj.get("status", "")).strip().lower() in {"open", "in_progress", "disproved"}
        ]
        if not candidates:
            return None

        ranked = sorted(candidates, key=_objective_priority, reverse=True)
        return ranked[0]

    def _apply_objective_followup(
        self,
        proposal: dict[str, Any],
        objective: dict[str, Any],
        cooldown_map: dict[str, int],
        previous: list[dict[str, Any]],
        blocked_families: set[str],
    ) -> dict[str, Any]:
        updated = deepcopy(proposal)
        objective_class = str(objective.get("objective_class", "generic")).strip().lower() or "generic"
        objective_target = str(objective.get("asset_ref", "")).strip()
        objective_id = str(objective.get("objective_id", "")).strip()
        objective_status = str(objective.get("status", "")).strip().lower()

        candidate_tools = list(_OBJECTIVE_TOOL_CANDIDATES.get(objective_class, _OBJECTIVE_TOOL_CANDIDATES["generic"]))
        selected = self._select_fallback_tool(
            blocked_tool="",
            cooldown_map=cooldown_map,
            target=objective_target or str(updated.get("target", "")),
            action_type=str(updated.get("action_type", "")),
            previous=previous,
            candidate_tools=candidate_tools,
            blocked_families=blocked_families,
        )

        if selected:
            updated = self._rebuild_fallback_proposal(
                updated,
                selected,
                "Pivoted to objective-focused follow-up for pending validation.",
            )

        if objective_target and self._tool_supports_target(str(updated.get("tool_name", "")), objective_target):
            updated["target"] = objective_target

        updated["rationale"] = (
            str(updated.get("rationale", "")).strip()
            + f" Objective focus: {objective_class} ({objective_status})"
            + (f" [id:{objective_id}]" if objective_id else "")
            + "."
        ).strip()
        return updated

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

    def _reflect_reject_churn_decision(
        self,
        state: AgentState,
        raw_proposal: dict[str, Any],
        rejected_tool: str,
        reject_reason_code: str,
        rejection_class: str,
        reject_reason_streak: int,
    ) -> dict[str, Any]:
        """Return a reflector decision dict: pivot or terminate."""
        context = {
            "iteration": int(state.get("iteration_count", 0) or 0),
            "rejected_tool": rejected_tool,
            "reject_reason_code": reject_reason_code,
            "rejection_class": rejection_class,
            "reject_reason_streak": reject_reason_streak,
            "candidate_tools": [
                t for t in self._available_tools if t != rejected_tool
            ],
            "target": str(raw_proposal.get("target", "")),
            "action_type": str(raw_proposal.get("action_type", "")),
        }

        if hasattr(self._llm, "reflect"):
            try:
                decision = self._llm.reflect(context)
                if isinstance(decision, dict) and decision.get("decision") in {"pivot", "terminate"}:
                    return decision
            except Exception as exc:
                log.warning("planner.reflector_failed", exc=str(exc))

        if reject_reason_streak >= _REFLECTOR_TERMINATE_REJECT_STREAK:
            return {
                "decision": "terminate",
                "termination_reason": "reflector_terminate",
                "rationale": "Reject reason streak exceeded reflector terminate threshold.",
            }

        return {
            "decision": "pivot",
            "candidate_tools": [t for t in self._available_tools if t != rejected_tool],
            "rationale": "Default pivot fallback when reflector response is unavailable.",
        }
