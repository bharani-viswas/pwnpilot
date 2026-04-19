"""
Executor Agent — converts validated proposals into ActionRequests, gates through the
Policy Engine, and triggers tool execution.

Reads from AgentState:
  proposed_action, validation_result

Writes to AgentState:
  last_result, evidence_ids, no_new_findings_streak
  active_action_id, active_tool_name, active_tool_command (live visibility)

v2 additions:
  - Sets active_action_id/active_tool_name/active_tool_command before execution.
  - Emits executor.policy_checked and executor.recovery_hint events via event bus.
  - Clears active_action fields on completion.

This is the ONLY agent that calls the Policy Engine and the Tool Runner.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any
from urllib.parse import parse_qsl, urlparse
from uuid import UUID

import structlog

from pwnpilot.agent.state import AgentState
from pwnpilot.control.approval import ApprovalService
from pwnpilot.control.invocation_compiler import InvocationCompiler
from pwnpilot.control.payload_engine import (
    classify_reflection_outcome,
    generate_payload_candidates,
    mutate_payload,
    preflight_validate_payload,
)
from pwnpilot.control.session_memory import prune_low_value_memory, summarize_tactical_memory
from pwnpilot.control.target_resolver import TargetResolver
from pwnpilot.agent.action_validator import ActionValidationError, ActionValidator
from pwnpilot.data.retrieval_store import RetrievalStore
from pwnpilot.control.policy import PolicyEngine
from pwnpilot.data.models import (
    ActionRequest,
    ActionType,
    ExecutionEvent,
    ExecutionEventType,
    PolicyVerdict,
    PlannerProposal,
    RiskLevel,
    ValidationResult,
)
from pwnpilot.observability.tracing import tracer
from pwnpilot.plugins.parsers.contracts import (
    canonicalize_finding,
    infer_host_from_service,
    infer_service_port,
)

log = structlog.get_logger(__name__)


# Severity order from highest to lowest
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_AUTH_PATH_MARKERS = (
    "login",
    "signin",
    "auth",
    "oauth",
    "token",
    "session",
    "admin",
)

_EXPLOIT_KEYWORDS = (
    "sql injection",
    "sqli",
    "command injection",
    "remote code execution",
    "rce",
    "xss",
    "cross-site scripting",
    "path traversal",
    "directory traversal",
    "idor",
    "broken access control",
    "ssrf",
    "lfi",
    "rfi",
    "deserialization",
    "auth bypass",
    "privilege escalation",
)

_LOW_VALUE_HINT_CODES = {
    "wildcard_detected",
    "no_forms_detected",
    "no_matches",
    "output_format_invalid",
    "execution_error",
}

_OBJECTIVE_CLASS_KEYWORDS: dict[str, tuple[str, ...]] = {
    "injection": (
        "sql injection",
        "sqli",
        "command injection",
        "xss",
        "cross-site scripting",
        "deserialization",
        "rce",
        "remote code execution",
    ),
    "access_control": (
        "idor",
        "broken access control",
        "authorization",
        "insecure direct object",
        "privilege escalation",
    ),
    "auth": (
        "auth",
        "login",
        "signin",
        "token",
        "session",
        "password",
    ),
    "exposure": (
        "exposure",
        "metrics",
        "prometheus",
        "disclosure",
        "directory listing",
        "debug",
    ),
    "headers": (
        "header",
        "csp",
        "x-content-type-options",
        "x-frame-options",
        "cross-origin",
    ),
    "session": (
        "session",
        "cookie",
        "csrf",
    ),
}


def _finding_severity_weight(raw_severity: str) -> int:
    sev = str(raw_severity or "").strip().lower()
    if sev == "critical":
        return 3
    if sev == "high":
        return 2
    if sev == "medium":
        return 1
    return 0


def _finding_has_repro_evidence(finding: dict[str, Any]) -> bool:
    if not isinstance(finding, dict):
        return False
    for key in ("curl_command", "matched_at", "proof", "evidence", "request", "response"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return True
    return False


def _score_exploitation_progress(parsed_output: dict[str, Any]) -> tuple[int, int]:
    findings = parsed_output.get("findings", [])
    if not isinstance(findings, list):
        return 0, 0

    exploit_signal_score = 0
    confirmation_candidate_count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        title = str(finding.get("title", "")).strip().lower()
        vuln_ref = str(finding.get("vuln_ref", "")).strip().lower()
        severity = str(finding.get("severity", "")).strip().lower()

        has_exploit_pattern = any(keyword in title or keyword in vuln_ref for keyword in _EXPLOIT_KEYWORDS)
        has_repro_evidence = _finding_has_repro_evidence(finding)

        score = _finding_severity_weight(severity)
        if has_exploit_pattern:
            score += 3
        if has_repro_evidence:
            score += 1

        exploit_signal_score += score
        if score > 0 and (has_exploit_pattern or has_repro_evidence or severity in {"high", "critical", "medium"}):
            confirmation_candidate_count += 1

    return exploit_signal_score, confirmation_candidate_count


def _classify_objective_class(text: str) -> str:
    normalized = str(text or "").strip().lower()
    if not normalized:
        return "generic"
    for objective_class, keywords in _OBJECTIVE_CLASS_KEYWORDS.items():
        if any(keyword in normalized for keyword in keywords):
            return objective_class
    return "generic"


def _extract_objective_tags(
    parsed_output: dict[str, Any],
    target: str,
    execution_hints: list[dict[str, Any]],
) -> list[str]:
    tags: set[str] = set()

    findings = parsed_output.get("findings", [])
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title", "")).strip()
            vuln_ref = str(finding.get("vuln_ref", "")).strip()
            tags.add(_classify_objective_class(f"{title} {vuln_ref}"))

    parsed_target = urlparse(str(target or "").strip())
    path_lower = parsed_target.path.lower()
    if any(marker in path_lower for marker in _AUTH_PATH_MARKERS):
        tags.add("auth")

    for hint in execution_hints:
        code = str(hint.get("code", "")).strip().lower()
        if code in {"no_forms_detected", "wildcard_detected"}:
            tags.add("generic")

    tags.discard("")
    return sorted(tags)


def _build_assessment_objectives(
    findings_summary: dict[str, Any],
    previous_actions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    objectives: dict[str, dict[str, Any]] = {}

    top_findings = findings_summary.get("top_findings", []) if isinstance(findings_summary, dict) else []
    if isinstance(top_findings, list):
        for finding in top_findings:
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title", "")).strip()
            asset_ref = str(finding.get("asset_ref", "")).strip()
            severity = str(finding.get("severity", "medium")).strip().lower() or "medium"
            objective_class = _classify_objective_class(f"{title} {finding.get('vuln_ref', '')}")
            objective_id = f"{objective_class}:{asset_ref or title}".lower()
            objectives[objective_id] = {
                "objective_id": objective_id,
                "objective_class": objective_class,
                "title": title,
                "asset_ref": asset_ref,
                "severity": severity,
                "status": "open",
                "attempts": 0,
                "confirmations": 0,
                "low_value_attempts": 0,
            }

    for action in previous_actions:
        if not isinstance(action, dict):
            continue

        action_target = str(action.get("target", "")).strip()
        action_severity = "medium"
        action_tags = [
            str(tag).strip().lower()
            for tag in action.get("objective_tags", [])
            if str(tag).strip()
        ]
        if not action_tags:
            action_tags = ["generic"]

        for tag in action_tags:
            objective_id = f"{tag}:{action_target or 'global'}".lower()
            obj = objectives.setdefault(
                objective_id,
                {
                    "objective_id": objective_id,
                    "objective_class": tag,
                    "title": f"Follow-up for {tag}",
                    "asset_ref": action_target,
                    "severity": action_severity,
                    "status": "open",
                    "attempts": 0,
                    "confirmations": 0,
                    "low_value_attempts": 0,
                },
            )

            obj["attempts"] = int(obj.get("attempts", 0) or 0) + 1
            if bool(action.get("requires_followup_validation", False)) or int(action.get("confirmation_candidate_count", 0) or 0) > 0:
                obj["confirmations"] = int(obj.get("confirmations", 0) or 0) + 1
            if bool(action.get("objective_low_value", False)):
                obj["low_value_attempts"] = int(obj.get("low_value_attempts", 0) or 0) + 1

    for obj in objectives.values():
        attempts = int(obj.get("attempts", 0) or 0)
        confirmations = int(obj.get("confirmations", 0) or 0)
        low_value_attempts = int(obj.get("low_value_attempts", 0) or 0)
        if confirmations > 0:
            obj["status"] = "confirmed"
        elif attempts >= 2 and low_value_attempts >= 2:
            obj["status"] = "disproved"
        elif attempts > 0:
            obj["status"] = "in_progress"
        else:
            obj["status"] = "open"

    objective_list = sorted(
        objectives.values(),
        key=lambda item: (str(item.get("status", "")) != "open", -_finding_severity_weight(str(item.get("severity", "")))),
    )
    progress = {
        "total": len(objective_list),
        "open": sum(1 for item in objective_list if str(item.get("status", "")) == "open"),
        "in_progress": sum(1 for item in objective_list if str(item.get("status", "")) == "in_progress"),
        "confirmed": sum(1 for item in objective_list if str(item.get("status", "")) == "confirmed"),
        "disproved": sum(1 for item in objective_list if str(item.get("status", "")) == "disproved"),
    }
    return objective_list, progress


def _service_host_fields(service: dict[str, Any], fallback_target: str) -> tuple[str, str | None]:
    host = infer_host_from_service(service)
    if host:
        return str(host.get("ip_address") or ""), host.get("hostname")

    parsed = urlparse(str(service.get("url") or fallback_target))
    hostname = parsed.hostname or None
    ip_address = hostname if hostname and hostname.replace(".", "").isdigit() else ""
    if hostname == "localhost" and not ip_address:
        ip_address = "127.0.0.1"
    return ip_address, hostname


def _normalize_params(params: dict[str, Any], tool_name: str) -> dict[str, Any]:
    """
    Normalize tool parameters from LLM output.
    
    Handles cases where LLM mistakenly passes arrays where strings are expected,
    e.g., nuclei severity filter expects a single string, not a list.
    """
    normalized = params.copy()
    
    # For tools that expect a single severity level
    if tool_name in ("nuclei", "nikto", "sqlmap") and "severity" in normalized:
        severity = normalized["severity"]
        
        # If severity is a list, pick the highest severity level
        if isinstance(severity, (list, tuple)):
            valid_severities = [s.lower() for s in severity if isinstance(s, str) and s.lower() in _SEVERITY_ORDER]
            if valid_severities:
                # Pick the highest severity (earliest in order)
                highest = min(valid_severities, key=lambda s: _SEVERITY_ORDER.index(s))
                normalized["severity"] = highest
                log.info(
                    "executor.param_normalized",
                    tool=tool_name,
                    param="severity",
                    from_value=severity,
                    to_value=highest,
                )
            else:
                # If no valid severities found, default to medium
                normalized["severity"] = "medium"
                log.warning(
                    "executor.param_normalized_to_default",
                    tool=tool_name,
                    param="severity",
                    original=severity,
                )
        elif isinstance(severity, str):
            # Already a string, ensure it's lowercase and valid
            normalized["severity"] = severity.lower() if severity.lower() in _SEVERITY_ORDER else "medium"
    
    return normalized


def _normalize_base_url(url: str) -> str:
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return str(url or "").strip()


def _base_target_match(left: str, right: str) -> bool:
    left_base = _normalize_base_url(left)
    right_base = _normalize_base_url(right)
    return bool(left_base) and left_base == right_base


def _payload_state_key(tool_name: str, target: str) -> str:
    return f"{str(tool_name or '').strip().lower()}::{_normalize_base_url(target)}"


def _recent_no_forms_hint(previous_actions: list[dict[str, Any]], target: str, lookback: int = 8) -> bool:
    recent = previous_actions[-max(1, lookback):]
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


def _enforce_sqlmap_non_forms_mode(
    params: dict[str, Any],
    target: str,
    previous_actions: list[dict[str, Any]],
) -> tuple[dict[str, Any], bool]:
    normalized = dict(params or {})
    if not _recent_no_forms_hint(previous_actions, target):
        return normalized, False

    if bool(normalized.get("forms", False)):
        normalized["forms"] = False
        if not str(normalized.get("mode_selection_reason", "")).strip():
            normalized["mode_selection_reason"] = "no_forms_hint_enforced_executor"
    return normalized, True


def _merge_attack_surface(
    existing: dict[str, Any] | None,
    updates: dict[str, Any],
) -> dict[str, Any]:
    base = existing if isinstance(existing, dict) else {}

    def _as_set(name: str) -> set[str]:
        values = base.get(name, [])
        if not isinstance(values, list):
            return set()
        return {str(v).strip() for v in values if str(v).strip()}

    web_targets = _as_set("web_targets")
    endpoints = _as_set("endpoints")
    routes = _as_set("routes")
    parameters = _as_set("parameters")
    auth_paths = _as_set("auth_paths")

    for key, bucket in (
        ("web_targets", web_targets),
        ("endpoints", endpoints),
        ("routes", routes),
        ("parameters", parameters),
        ("auth_paths", auth_paths),
    ):
        values = updates.get(key, [])
        if isinstance(values, list):
            bucket.update({str(v).strip() for v in values if str(v).strip()})

    return {
        "web_targets": sorted(web_targets),
        "endpoints": sorted(endpoints),
        "routes": sorted(routes),
        "parameters": sorted(parameters),
        "auth_paths": sorted(auth_paths),
        "counts": {
            "web_targets": len(web_targets),
            "endpoints": len(endpoints),
            "routes": len(routes),
            "parameters": len(parameters),
            "auth_paths": len(auth_paths),
        },
    }


def _extract_attack_surface_updates(
    parsed_output: dict[str, Any],
    findings_summary: dict[str, Any],
    recon_summary: dict[str, Any],
) -> dict[str, Any]:
    web_targets: set[str] = set()
    endpoints: set[str] = set()
    routes: set[str] = set()
    parameters: set[str] = set()
    auth_paths: set[str] = set()

    # Derive web targets from discovered services in recon summary.
    for host in recon_summary.get("discovered_hosts", []):
        if not isinstance(host, dict):
            continue
        ip_or_host = str(host.get("hostname") or host.get("ip_address") or "").strip()
        if not ip_or_host:
            continue
        host_services = host.get("services", [])
        host_ports = [
            int(port)
            for port in host.get("ports", [])
            if isinstance(port, int)
        ]
        if not isinstance(host_services, list):
            continue
        for svc in host_services:
            name = str(svc).lower()
            if "http" in name:
                if ":443" in name or "https" in name:
                    if 443 in host_ports:
                        web_targets.add(f"https://{ip_or_host}")
                    for port in host_ports:
                        if port != 443:
                            web_targets.add(f"https://{ip_or_host}:{port}")
                else:
                    if 80 in host_ports or not host_ports:
                        web_targets.add(f"http://{ip_or_host}")
                    for port in host_ports:
                        if port != 80:
                            web_targets.add(f"http://{ip_or_host}:{port}")

    # Parse explicit service URLs from the latest tool output.
    services = parsed_output.get("services", [])
    if isinstance(services, list):
        for svc in services:
            if not isinstance(svc, dict):
                continue
            url = str(svc.get("url", "")).strip()
            if not url:
                continue
            parsed = urlparse(url)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                web_targets.add(f"{parsed.scheme}://{parsed.netloc}")
                endpoints.add(url)
                if parsed.path and parsed.path != "/":
                    routes.add(parsed.path)
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    if key:
                        parameters.add(key)

    # Use top findings to infer routes, auth paths, and parameters.
    top_findings = findings_summary.get("top_findings", []) if isinstance(findings_summary, dict) else []
    if isinstance(top_findings, list):
        for finding in top_findings:
            if not isinstance(finding, dict):
                continue
            asset_ref = str(finding.get("asset_ref", "")).strip()
            parsed = urlparse(asset_ref)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                web_targets.add(f"{parsed.scheme}://{parsed.netloc}")
                endpoints.add(asset_ref)
                if parsed.path and parsed.path != "/":
                    routes.add(parsed.path)
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    if key:
                        parameters.add(key)

                path_lower = parsed.path.lower()
                if any(marker in path_lower for marker in _AUTH_PATH_MARKERS):
                    auth_paths.add(parsed.path)

            title = str(finding.get("title", "")).lower()
            if "auth" in title or "login" in title:
                if parsed.path and parsed.path != "/":
                    auth_paths.add(parsed.path)

    return {
        "web_targets": sorted(web_targets),
        "endpoints": sorted(endpoints),
        "routes": sorted(routes),
        "parameters": sorted(parameters),
        "auth_paths": sorted(auth_paths),
    }


class ExecutorNode:
    """
    Stateless callable used as a LangGraph executor node.

    Converts the validated PlannerProposal into a typed ActionRequest, evaluates it
    through the Policy Engine, and calls the tool runner on approval.

    v2: Sets active_action fields in state for live visibility.
        Emits policy check and recovery hint events via event bus.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        tool_runner: Any,
        approval_service: ApprovalService,
        audit_store: Any,
        finding_store: Any = None,
        recon_store: Any = None,
        planner_available_tools: list[str] | None = None,
        metrics: Any | None = None,
        target_family: str = "unknown",
        target_resolver: TargetResolver | None = None,
        capability_registry: Any | None = None,
        invocation_compiler: InvocationCompiler | None = None,
        event_bus: object | None = None,
        retrieval_store: Any | None = None,
        task_tree_store: Any | None = None,
        payload_cfg: Any | None = None,
        attack_surface_graph: Any | None = None,
        memory_summary_every_n_actions: int = 4,
        memory_prune_keep_last_actions: int = 60,
    ) -> None:
        self._policy = policy_engine
        self._runner = tool_runner
        self._approval = approval_service
        self._audit = audit_store
        self._finding_store = finding_store
        self._recon_store = recon_store
        self._planner_available_tools = planner_available_tools or []
        self._metrics = metrics
        self._target_family = str(target_family or "unknown")
        self._target_resolver = target_resolver
        self._capability_registry = capability_registry
        self._invocation_compiler = invocation_compiler or InvocationCompiler()
        self._event_bus = event_bus  # ExecutionEventBus | None
        self._retrieval_store = retrieval_store
        self._task_tree_store = task_tree_store
        self._payload_cfg = payload_cfg
        self._attack_surface_graph = attack_surface_graph
        self._memory_summary_every_n_actions = max(1, int(memory_summary_every_n_actions))
        self._memory_prune_keep_last_actions = max(10, int(memory_prune_keep_last_actions))
        # ActionValidator is lazily initialised once the tool_runner adapters are available
        self._action_validator: ActionValidator | None = None
        if hasattr(tool_runner, "_adapters") and tool_runner._adapters:
            self._action_validator = ActionValidator(adapters=tool_runner._adapters)

    def __call__(self, state: AgentState) -> AgentState:
        if state.get("kill_switch"):
            return state

        _t0 = time.monotonic()
        _input_hash = hashlib.sha256(
            json.dumps(state, default=str, sort_keys=True).encode()
        ).hexdigest()

        proposal_dict = state.get("proposed_action")
        validation_dict = state.get("validation_result")

        if not proposal_dict or not validation_dict:
            if self._metrics:
                self._metrics.record_nonproductive_cycle()
            return {**state, "error": "Missing proposal or validation result in executor."}

        try:
            proposal = PlannerProposal(**proposal_dict)
            validation = ValidationResult(**validation_dict)
        except Exception as exc:
            if self._metrics:
                self._metrics.record_nonproductive_cycle()
            return {**state, "error": f"Executor: invalid proposal/validation: {exc}"}

        # Determine effective risk level (validation can escalate, never downgrade)
        effective_risk = validation.risk_override or proposal.estimated_risk
        engagement_id = UUID(state["engagement_id"])

        if self._capability_registry:
            compatible, reason = self._capability_registry.is_runtime_compatible(proposal.tool_name)
            if not compatible:
                updated_proposal = proposal_dict.copy()
                updated_proposal["rejection_reason"] = reason
                return {
                    **state,
                    "proposed_action": updated_proposal,
                    "validation_result": {
                        "verdict": "reject",
                        "risk_override": None,
                        "rationale": reason,
                        "rejection_reason_code": "TOOL_MODE_MISMATCH",
                        "rejection_reason_detail": reason,
                        "rejection_class": "capability",
                    },
                    "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
                    "error": None,
                }

        resolved_target_snapshot: dict[str, Any] = {}
        target_for_tool = proposal.target
        supported_target_types: list[str] = []
        tool_contract: dict[str, Any] = {}
        if self._target_resolver:
            if self._capability_registry:
                contract = self._capability_registry.contract_for(proposal.tool_name)
                if isinstance(contract, dict):
                    tool_contract = contract
                    supported_target_types = list(contract.get("supported_target_types", []))
            resolved = self._target_resolver.resolve(proposal.target)
            resolved_target_snapshot = resolved.model_dump()
            target_for_tool = self._target_resolver.target_for_tool(
                proposal.target,
                supported_target_types=supported_target_types,
            )
        elif self._capability_registry:
            contract = self._capability_registry.contract_for(proposal.tool_name)
            if isinstance(contract, dict):
                tool_contract = contract

        compile_result = self._invocation_compiler.compile(
            tool_name=proposal.tool_name,
            target=target_for_tool,
            params=proposal.params if isinstance(proposal.params, dict) else {},
            resolved_target=resolved_target_snapshot,
            supported_target_types=supported_target_types,
            previous_actions=list(state.get("previous_actions", []) or []),
        )
        if not compile_result.feasible:
            reason = compile_result.reason_detail or "Invocation is not feasible for selected tool."
            hint = compile_result.remediation_hint or "Adjust target/params and retry."
            updated_proposal = proposal_dict.copy()
            updated_proposal["rejection_reason"] = f"{reason} {hint}".strip()
            self._audit_event(
                state,
                "InvocationRejected",
                {
                    "tool": proposal.tool_name,
                    "target": target_for_tool,
                    "reason_code": compile_result.reason_code or "INVOCATION_UNFIT",
                    "reason_detail": reason,
                    "remediation_hint": hint,
                    "diagnostics": compile_result.diagnostics,
                },
            )
            if self._metrics:
                self._metrics.record_nonproductive_cycle()
            return {
                **state,
                "proposed_action": updated_proposal,
                "validation_result": {
                    "verdict": "reject",
                    "risk_override": None,
                    "rationale": reason,
                    "rejection_reason_code": compile_result.reason_code or "INVOCATION_UNFIT",
                    "rejection_reason_detail": reason,
                    "rejection_class": "invocation",
                },
                "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
                "last_execution_hints": [
                    {
                        "code": str(compile_result.diagnostics.get("invocation_subcode", "")).strip()
                        or "target_projection_invalid",
                        "message": reason,
                        "severity": "warning",
                        "recommended_action": hint,
                    }
                ],
                "error": None,
            }

        target_for_tool = compile_result.target or target_for_tool
        proposal_params_compiled = compile_result.params if isinstance(compile_result.params, dict) else {}

        # Phase 6C: payload generation + preflight (bounded, policy-safe).
        payload_generation_mode = "none"
        mutation_round = 0
        reflection_summary = ""
        semantic_outcome_code = "uncertain"
        generated_payload = None
        pending_mutation_payload = dict(state.get("pending_mutation_payload", {}) or {})
        mutation_key = _payload_state_key(proposal.tool_name, target_for_tool)
        carried_payload = str(pending_mutation_payload.pop(mutation_key, "")).strip()
        capabilities = tool_contract.get("capabilities", {}) if isinstance(tool_contract, dict) else {}
        accepts_payload = bool(capabilities.get("accepts_payload", False))
        payload_enabled = bool(getattr(self._payload_cfg, "enabled", True))
        allowed_classes = {
            str(x).strip().lower() for x in getattr(self._payload_cfg, "allow_classes", ["sqli", "xss"])
        }
        if payload_enabled and accepts_payload:
            action_type_guess = str(proposal.action_type or "").strip().lower()
            vuln_class = str(proposal.params.get("vuln_class", "")).strip().lower()
            if not vuln_class and accepts_payload:
                vuln_class = "sqli"
            if carried_payload and vuln_class in allowed_classes and action_type_guess in {"exploit", "active_scan"}:
                ok, reason = preflight_validate_payload(
                    payload=carried_payload,
                    vuln_class=vuln_class,
                    roe_disallow_patterns=list(state.get("roe_disallow_patterns", []) or []),
                )
                if ok:
                    generated_payload = carried_payload
                    proposal_params_compiled = {
                        **proposal_params_compiled,
                        "payload": generated_payload,
                        "payload_vuln_class": vuln_class,
                    }
                    payload_generation_mode = "carried_mutation"
                else:
                    payload_generation_mode = f"carried_preflight_rejected:{reason}"
            if not generated_payload and vuln_class in allowed_classes and action_type_guess in {"exploit", "active_scan"}:
                candidates = generate_payload_candidates(
                    vuln_class=vuln_class,
                    target=target_for_tool,
                    previous_payloads=list(state.get("generated_payloads", []) or []),
                    max_candidates=int(getattr(self._payload_cfg, "max_candidates", 4)),
                )
                if candidates:
                    candidate = candidates[0]
                    ok, reason = preflight_validate_payload(
                        payload=str(candidate.get("payload", "")),
                        vuln_class=vuln_class,
                        roe_disallow_patterns=list(state.get("roe_disallow_patterns", []) or []),
                    )
                    if ok:
                        generated_payload = str(candidate.get("payload", ""))
                        proposal_params_compiled = {
                            **proposal_params_compiled,
                            "payload": generated_payload,
                            "payload_vuln_class": vuln_class,
                        }
                        payload_generation_mode = "generated_template"
                    else:
                        payload_generation_mode = f"preflight_rejected:{reason}"

        # Construct typed ActionRequest
        try:
            normalized_params = _normalize_params(proposal_params_compiled, proposal.tool_name)
            sqlmap_mode_enforced = False
            if proposal.tool_name == "sqlmap":
                normalized_params, sqlmap_mode_enforced = _enforce_sqlmap_non_forms_mode(
                    params=normalized_params,
                    target=target_for_tool,
                    previous_actions=list(state.get("previous_actions", []) or []),
                )

            action = ActionRequest(
                engagement_id=engagement_id,
                action_type=ActionType(proposal.action_type),
                tool_name=proposal.tool_name,
                params={
                    **normalized_params,
                    "target": target_for_tool,
                    "target_resolved": resolved_target_snapshot,
                },
                risk_level=effective_risk,
            )
        except Exception as exc:
            if self._metrics:
                self._metrics.record_nonproductive_cycle()
            return {**state, "error": f"Executor: failed to build ActionRequest: {exc}"}

        # ADR-002 gate: validate action against adapter schema before policy engine
        if self._action_validator is not None:
            try:
                self._action_validator.validate(action)
            except ActionValidationError as exc:
                if self._metrics:
                    self._metrics.record_nonproductive_cycle()
                log.warning(
                    "executor.action_validation_failed",
                    tool=action.tool_name,
                    error=str(exc),
                )
                return {
                    **state,
                    "proposed_action": {**proposal_dict, "rejection_reason": str(exc)},
                    "validation_result": {
                        "verdict": "reject",
                        "risk_override": None,
                        "rationale": str(exc),
                        "rejection_reason_code": "ACTION_VALIDATION_FAILED",
                        "rejection_reason_detail": str(exc),
                        "rejection_class": "schema",
                    },
                    "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
                    "error": None,
                }

        # Policy Engine evaluation
        decision = self._policy.evaluate(action)

        # Emit policy check event
        self._emit_event(ExecutionEvent(
            engagement_id=engagement_id,
            action_id=action.action_id,
            event_type=ExecutionEventType.EXECUTOR_POLICY_CHECKED,
            tool_name=action.tool_name,
            actor="executor",
            payload={
                "verdict": decision.verdict.value,
                "reason": decision.reason,
                "gate_type": decision.gate_type.value,
                "risk_level": effective_risk.value if hasattr(effective_risk, "value") else str(effective_risk),
            },
        ))

        if decision.verdict == PolicyVerdict.DENY:
            log.warning(
                "executor.action_denied",
                reason=decision.reason,
                action_id=str(action.action_id),
            )
            self._audit_event(
                state,
                "PolicyDenied",
                {
                    "action_id": str(action.action_id),
                    "reason": decision.reason,
                    "gate": decision.gate_type.value,
                },
            )
            updated_proposal = proposal_dict.copy()
            updated_proposal["rejection_reason"] = decision.reason
            if self._metrics:
                self._metrics.record_policy_deny(decision.gate_type.value)
                self._metrics.record_nonproductive_cycle()
            return {
                **state,
                "proposed_action": updated_proposal,
                "validation_result": None,
                "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
            }

        if decision.verdict == PolicyVerdict.REQUIRES_APPROVAL:
            ticket = self._approval.create_ticket(
                action, rationale=proposal.rationale
            )
            log.info(
                "executor.awaiting_approval",
                ticket_id=str(ticket.ticket_id),
            )
            self._audit_event(
                state,
                "ApprovalRequested",
                {
                    "ticket_id": str(ticket.ticket_id),
                    "action_id": str(action.action_id),
                },
            )
            return {
                **state,
                "pending_approval_ticket_id": str(ticket.ticket_id),
                "kill_switch": True,
                "error": None,
            }

        # Set active action fields for live visibility
        command_hint = " ".join(
            str(v) for v in (action.params.get("cmd", action.params.get("command", [proposal.target])) or [])
            if str(v)
        )
        effective_sqlmap_mode = None
        if action.tool_name == "sqlmap":
            effective_sqlmap_mode = "forms" if bool(action.params.get("forms", False)) else "parameterized"

        self._audit_event(
            state,
            "ToolExecutionStarted",
            {
                "action_id": str(action.action_id),
                "tool": action.tool_name,
                "action_type": action.action_type.value,
                "target": target_for_tool,
                "target_resolved": resolved_target_snapshot,
                "params": action.params,
                "risk_level": (
                    action.risk_level.value
                    if hasattr(action.risk_level, "value")
                    else str(action.risk_level)
                ),
                "effective_sqlmap_mode": effective_sqlmap_mode,
                "sqlmap_mode_enforced": bool(sqlmap_mode_enforced) if action.tool_name == "sqlmap" else False,
            },
        )

        # Execute tool (active_action_id set before, cleared after)
        active_state_patch: dict[str, Any] = {
            "active_action_id": str(action.action_id),
            "active_tool_name": action.tool_name,
            "active_tool_command": command_hint,
        }

        try:
            with tracer.span(
                "executor.tool_run",
                engagement_id=str(state.get("engagement_id", "")),
                tool=action.tool_name,
                action_id=str(action.action_id),
            ):
                result = self._runner.execute(action)
        except (KeyError, FileNotFoundError) as exc:
            duration_ms = round((time.monotonic() - _t0) * 1000, 2)
            available = list(self._planner_available_tools)
            if not available and hasattr(self._runner, "available_tools"):
                try:
                    available = list(self._runner.available_tools)
                except Exception:
                    available = []

            log.warning("executor.tool_unavailable", exc=str(exc), tool=action.tool_name)
            self._audit_event(
                state,
                "ActionFailed",
                {
                    "action_id": str(action.action_id),
                    "tool": action.tool_name,
                    "target": target_for_tool,
                    "target_resolved": resolved_target_snapshot,
                    "params": action.params,
                    "error": str(exc),
                },
            )

            rejection_reason = (
                f"Tool '{action.tool_name}' is not available on this system. "
                f"Choose from available tools: {available}"
            )
            # Emit recovery hint event
            self._emit_event(ExecutionEvent(
                engagement_id=engagement_id,
                action_id=action.action_id,
                event_type=ExecutionEventType.EXECUTOR_RECOVERY_HINT,
                tool_name=action.tool_name,
                actor="executor",
                payload={
                    "hint_code": "tool_not_available",
                    "hint_detail": rejection_reason,
                    "available_tools": available,
                },
            ))

            updated_prev = list(state.get("previous_actions", []))
            updated_prev.append(
                {
                    "action_id": str(action.action_id),
                    "tool_name": action.tool_name,
                    "action_type": action.action_type.value,
                    "target": target_for_tool,
                    "error": "tool_not_available",
                    "strategy_step_id": str(proposal_dict.get("strategy_step_id", "")).strip(),
                }
            )

            cooldowns = dict(state.get("temporarily_unavailable_tools", {}))
            cooldowns[action.tool_name] = max(int(cooldowns.get(action.tool_name, 0)), 3)

            updated_proposal = proposal_dict.copy()
            updated_proposal["rejection_reason"] = rejection_reason

            if self._metrics:
                self._metrics.record_nonproductive_cycle()
                self._metrics.record_tool_invoked(action.tool_name, duration_ms, success=False)

            return {
                **state,
                **active_state_patch,
                "proposed_action": updated_proposal,
                "validation_result": None,
                "previous_actions": updated_prev,
                "temporarily_unavailable_tools": cooldowns,
                "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
                "active_action_id": None,
                "active_tool_name": None,
                "active_tool_command": None,
                "error": None,
            }
        except ValueError as exc:
            duration_ms = round((time.monotonic() - _t0) * 1000, 2)
            # Adapter parameter validation error - check if it's a permission request
            error_msg = str(exc)
            
            # Special handling for shell command permission requests
            if action.tool_name == "shell" and "not allow-listed" in error_msg.lower():
                # Extract the command from error message or params
                command = action.params.get("command", "unknown")
                
                log.info(
                    "executor.permission_required",
                    tool="shell",
                    command=command,
                )
                
                # Create approval ticket for permission to use this command
                ticket = self._approval.create_ticket(
                    action,
                    rationale=f"Request to use shell command '{command}' which is not in default allow-list. "
                              f"Operator permission required to proceed."
                )
                
                log.info(
                    "executor.permission_ticket_created",
                    ticket_id=str(ticket.ticket_id),
                    command=command,
                )
                
                self._audit_event(
                    state,
                    "PermissionRequested",
                    {
                        "ticket_id": str(ticket.ticket_id),
                        "action_id": str(action.action_id),
                        "resource_type": "shell_command",
                        "resource_identifier": command,
                        "error": error_msg,
                    },
                )
                
                # Halt and await operator decision
                return {
                    **state,
                    "pending_approval_ticket_id": str(ticket.ticket_id),
                    "kill_switch": True,
                    "error": None,
                }
            
            # Generic parameter validation error - ask planner to retry
            log.warning("executor.param_validation_error", exc=error_msg, tool=action.tool_name)
            self._audit_event(
                state,
                "ActionFailed",
                {
                    "action_id": str(action.action_id),
                    "tool": action.tool_name,
                    "target": target_for_tool,
                    "target_resolved": resolved_target_snapshot,
                    "params": action.params,
                    "error": "param_validation_failed",
                    "details": error_msg,
                },
            )

            updated_prev = list(state.get("previous_actions", []))
            updated_prev.append(
                {
                    "action_id": str(action.action_id),
                    "tool_name": action.tool_name,
                    "action_type": action.action_type.value,
                    "target": target_for_tool,
                    "error": "param_validation_failed",
                    "strategy_step_id": str(proposal_dict.get("strategy_step_id", "")).strip(),
                }
            )

            updated_proposal = proposal_dict.copy()
            updated_proposal["rejection_reason"] = (
                f"Parameter validation failed for {action.tool_name}: {error_msg}. "
                f"Please try different parameters."
            )

            if self._metrics:
                self._metrics.record_nonproductive_cycle()
                self._metrics.record_tool_invoked(action.tool_name, duration_ms, success=False)

            return {
                **state,
                "proposed_action": updated_proposal,
                "validation_result": None,
                "previous_actions": updated_prev,
                "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0) + 1,
                "error": None,
            }
        except Exception as exc:
            duration_ms = round((time.monotonic() - _t0) * 1000, 2)
            log.error("executor.tool_error", exc=str(exc), tool=action.tool_name)
            self._audit_event(
                state,
                "ActionFailed",
                {
                    "action_id": str(action.action_id),
                    "tool": action.tool_name,
                    "target": target_for_tool,
                    "target_resolved": resolved_target_snapshot,
                    "params": action.params,
                    "error": str(exc),
                },
            )
            if self._metrics:
                self._metrics.record_nonproductive_cycle()
                self._metrics.record_tool_invoked(action.tool_name, duration_ms, success=False)
            return {**state, "error": f"Tool execution failed: {exc}"}

        # Update convergence streak
        new_evidence = result.parsed_output.get("new_findings_count", 0)
        streak = state.get("no_new_findings_streak", 0)
        streak = 0 if new_evidence > 0 else streak + 1
        execution_hints = list(result.parsed_output.get("execution_hints", []))
        hint_codes = {
            str(hint.get("code", "")).strip()
            for hint in execution_hints
            if str(hint.get("code", "")).strip()
        }
        run_evidence_ids: list[str] = []
        if result.stdout_evidence_id is not None:
            run_evidence_ids.append(str(result.stdout_evidence_id))
        if result.stderr_evidence_id is not None:
            run_evidence_ids.append(str(result.stderr_evidence_id))
        has_structured_output = bool(
            result.parsed_output.get("services")
            or result.parsed_output.get("hosts")
            or result.parsed_output.get("technologies")
            or result.parsed_output.get("routes")
        )
        outcome_status_value = (
            result.outcome_status.value
            if hasattr(result.outcome_status, "value")
            else str(result.outcome_status)
        )
        semantic_outcome_code = classify_reflection_outcome(
            stdout=str(result.parsed_output),
            stderr="",
            exit_code=int(result.exit_code or 0),
        )
        reflection_summary = f"semantic_outcome={semantic_outcome_code}"
        max_mutation_rounds = int(getattr(self._payload_cfg, "max_mutation_rounds", 3)) if self._payload_cfg is not None else 3
        if payload_generation_mode.startswith("generated_template") and semantic_outcome_code in {
            "syntax_mismatch",
            "likely_blocked_by_waf",
        } and max_mutation_rounds > 0:
            mutation_round = 1
            if generated_payload:
                mutated = mutate_payload(generated_payload, round_idx=mutation_round)
                reflection_summary = f"semantic_outcome={semantic_outcome_code}; mutated_payload_preview={mutated[:80]}"
                pending_mutation_payload[mutation_key] = mutated
        exploit_signal_score, confirmation_candidate_count = _score_exploitation_progress(result.parsed_output)
        action_type_value = action.action_type.value if hasattr(action.action_type, "value") else str(action.action_type)
        recon_progress = bool(has_structured_output) and action_type_value in {"recon_passive", "active_scan"}
        finding_progress = bool(new_evidence) and (exploit_signal_score > 0 or confirmation_candidate_count > 0)
        low_value_only = bool(hint_codes) and hint_codes.issubset(_LOW_VALUE_HINT_CODES)
        objective_tags = _extract_objective_tags(
            parsed_output=result.parsed_output,
            target=target_for_tool,
            execution_hints=execution_hints,
        )

        is_productive_execution = recon_progress or finding_progress
        if low_value_only and not finding_progress:
            is_productive_execution = False
        current_nonproductive = int(state.get("nonproductive_cycle_streak", 0) or 0)
        next_nonproductive = 0 if is_productive_execution and outcome_status_value == "success" else current_nonproductive + 1

        # Store findings and hosts from tool output (NEW: Feedback loop)
        if self._finding_store and self._recon_store:
            try:
                # Extract and store findings
                findings_list = result.parsed_output.get("findings", [])
                for finding in findings_list:
                    normalized = canonicalize_finding(
                        finding,
                        action.tool_name,
                        proposal.target,
                    )
                    # Convert severity string to enum
                    severity_str = normalized.get("severity", "medium").lower()
                    try:
                        severity_enum = {
                            "info": RiskLevel.LOW,
                            "low": RiskLevel.LOW,
                            "medium": RiskLevel.MEDIUM,
                            "high": RiskLevel.HIGH,
                            "critical": RiskLevel.CRITICAL,
                        }.get(severity_str, RiskLevel.MEDIUM)
                    except KeyError:
                        severity_enum = RiskLevel.MEDIUM
                    
                    # Map RiskLevel to Severity enum
                    from pwnpilot.data.models import Severity
                    severity_map = {
                        RiskLevel.LOW: Severity.LOW,
                        RiskLevel.MEDIUM: Severity.MEDIUM,
                        RiskLevel.HIGH: Severity.HIGH,
                        RiskLevel.CRITICAL: Severity.CRITICAL,
                    }
                    severity = severity_map.get(severity_enum, Severity.MEDIUM)
                    
                    self._finding_store.upsert(
                        engagement_id=engagement_id,
                        asset_ref=normalized["asset_ref"],
                        title=normalized["title"],
                        vuln_ref=normalized["vuln_ref"],
                        tool_name=action.tool_name,
                        severity=severity,
                        confidence=normalized.get("confidence", 0.5),
                        evidence_ids=run_evidence_ids,
                        remediation=normalized.get("remediation", ""),
                    )

                # Extract and store hosts
                hosts_list = result.parsed_output.get("hosts", [])
                for host in hosts_list:
                    ip_address = host.get("ip_address", host.get("ip", ""))
                    if not ip_address and host.get("hostname") == "localhost":
                        ip_address = "127.0.0.1"
                    if not ip_address:
                        continue

                    host_id = self._recon_store.upsert_host(
                        engagement_id=engagement_id,
                        ip_address=ip_address,
                        hostname=host.get("hostname"),
                        os_guess=host.get("os_guess", host.get("os")),
                        status=host.get("status", "up"),
                    )
                    # Store services for this host
                    for port_info in host.get("ports", []):
                        port = port_info if isinstance(port_info, int) else port_info.get("port")
                        service_name = port_info.get("service") if isinstance(port_info, dict) else None
                        if not port:
                            continue
                        self._recon_store.upsert_service(
                            host_id=host_id,
                            engagement_id=engagement_id,
                            port=port,
                            service_name=service_name,
                        )

                services_list = result.parsed_output.get("services", [])
                for service in services_list:
                    ip_address, hostname = _service_host_fields(service, proposal.target)
                    if not ip_address and not hostname:
                        continue
                    if not ip_address and hostname == "localhost":
                        ip_address = "127.0.0.1"
                    if not ip_address:
                        continue

                    host_id = self._recon_store.upsert_host(
                        engagement_id=engagement_id,
                        ip_address=ip_address,
                        hostname=hostname,
                        status=service.get("status", "up"),
                    )
                    port = infer_service_port(service)
                    if port is None:
                        continue
                    self._recon_store.upsert_service(
                        host_id=host_id,
                        engagement_id=engagement_id,
                        port=port,
                        protocol=service.get("protocol", "tcp"),
                        service_name=service.get("service_name"),
                        product=service.get("product"),
                        version=service.get("version"),
                        banner=service.get("banner"),
                    )

                log.info(
                    "executor.data_stored",
                    findings_count=len(findings_list),
                    hosts_count=len(hosts_list),
                    services_count=len(result.parsed_output.get("services", [])),
                    execution_hints_count=len(execution_hints),
                )

                # Index findings and services into RetrievalStore for planner memory context.
                if self._retrieval_store is not None:
                    try:
                        for f in findings_list:
                            self._retrieval_store.index_finding(
                                engagement_id,
                                title=str(f.get("title", "")),
                                body=str(f.get("description", f.get("vuln_ref", ""))),
                            )
                        for svc in services_list:
                            self._retrieval_store.index_service(
                                engagement_id,
                                title=f"{svc.get('service_name', 'service')} on port {svc.get('port', '?')}",
                                body=str(svc),
                            )
                    except Exception as ridx_exc:
                        log.debug("executor.retrieval_index_error", exc=str(ridx_exc))

            except Exception as store_exc:
                log.warning("executor.store_error", exc=str(store_exc))
                # Don't fail the action if storage fails, just log it

        # Record completed action
        previous = list(state.get("previous_actions", []))
        previous.append(
            {
                "action_id": str(action.action_id),
                "tool_name": action.tool_name,
                "action_type": action.action_type.value,
                "target": target_for_tool,
                "target_resolved": resolved_target_snapshot,
                "strategy_step_id": str(proposal_dict.get("strategy_step_id", "")).strip(),
                "exit_code": result.exit_code,
                "outcome_status": (
                    result.outcome_status.value if hasattr(result.outcome_status, "value") else str(result.outcome_status)
                ),
                "failure_reasons": [
                    reason.value if hasattr(reason, "value") else str(reason)
                    for reason in (result.failure_reasons or [])
                ],
                "execution_hint_codes": [hint.get("code") for hint in execution_hints],
                "new_findings_count": int(result.parsed_output.get("new_findings_count", 0) or 0),
                "exploit_signal_score": int(exploit_signal_score),
                "confirmation_candidate_count": int(confirmation_candidate_count),
                "requires_followup_validation": bool(
                    confirmation_candidate_count > 0 or exploit_signal_score > 0
                ),
                "semantic_outcome_code": semantic_outcome_code,
                "reflection_summary": reflection_summary,
                "payload_generation_mode": payload_generation_mode,
                "mutation_round": mutation_round,
                "objective_tags": objective_tags,
                "objective_low_value": bool(low_value_only and not finding_progress),
                "parser_confidence": result.parser_confidence,
                "had_runtime_hints": bool(execution_hints),
                "effective_sqlmap_mode": effective_sqlmap_mode,
                "sqlmap_mode_enforced": bool(sqlmap_mode_enforced) if action.tool_name == "sqlmap" else False,
                "sqlmap_mode_selection_reason": (
                    str(action.params.get("mode_selection_reason", "")).strip()
                    if action.tool_name == "sqlmap"
                    else ""
                ),
                "invocation_compile": compile_result.diagnostics,
                "invocation_subcode": str(compile_result.diagnostics.get("invocation_subcode", "")).strip(),
            }
        )

        if self._metrics:
            hint_codes_list = [
                str(hint.get("code", "")).strip()
                for hint in execution_hints
                if str(hint.get("code", "")).strip()
            ]
            duration_val = float(result.duration_ms) if result.duration_ms is not None else 0.0
            self._metrics.record_tool_invoked(action.tool_name, duration_val, success=(result.exit_code == 0))
            self._metrics.record_action_outcome(
                tool_name=action.tool_name,
                new_findings_count=int(result.parsed_output.get("new_findings_count", 0) or 0),
                execution_hint_codes=hint_codes_list,
                target_family=self._target_family,
            )
            if result.error_class:
                error_class = result.error_class.value if hasattr(result.error_class, "value") else str(result.error_class)
                if error_class == "TIMEOUT":
                    self._metrics.record_timeout()
                if error_class == "PARSE_ERROR":
                    self._metrics.record_parser_error()

        # Phase 6D: update attack-surface graph snapshot from execution output.
        graph_snapshot: dict[str, Any] = {}
        if self._attack_surface_graph is not None:
            try:
                findings_for_graph = result.parsed_output.get("findings", []) if isinstance(result.parsed_output, dict) else []
                self._attack_surface_graph.update_from_execution(
                    engagement_id=str(engagement_id),
                    parsed_output=result.parsed_output,
                    findings=findings_for_graph,
                )
                graph_snapshot = self._attack_surface_graph.snapshot(str(engagement_id))
            except Exception as graph_exc:
                log.debug("executor.attack_surface_graph_error", exc=str(graph_exc))

        # Phase 6B: maintain strategic task tree memory.
        memory_write_refs: list[str] = []
        if self._task_tree_store is not None:
            try:
                objectives = list(state.get("assessment_objectives", []) or [])
                if objectives:
                    top_obj = objectives[0] if isinstance(objectives[0], dict) else {}
                    node_id = self._task_tree_store.create_node(
                        engagement_id=engagement_id,
                        objective_id=str(top_obj.get("id", "objective-0")),
                        tactic=str(top_obj.get("objective_class", "generic")),
                        target_asset=str(target_for_tool),
                        current_hypothesis=str(proposal.rationale),
                        confidence=0.65 if outcome_status_value == "success" else 0.45,
                        supporting_evidence_ids=run_evidence_ids,
                    )
                    memory_write_refs.append(node_id)
                    if outcome_status_value == "success":
                        self._task_tree_store.advance_node(
                            node_id=node_id,
                            new_state="in_progress",
                            confidence=0.72,
                            supporting_evidence_ids=run_evidence_ids,
                        )
                    elif semantic_outcome_code in {"no_attack_surface", "syntax_mismatch"}:
                        self._task_tree_store.invalidate_node(node_id, reason=semantic_outcome_code)
            except Exception as task_exc:
                log.debug("executor.task_tree_write_error", exc=str(task_exc))

        self._audit_event(
            state,
            "ToolExecutionCompleted",
            {
                "action_id": str(action.action_id),
                "tool": action.tool_name,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "stdout_hash": result.stdout_hash,
                "stderr_hash": result.stderr_hash,
                "stdout_evidence_id": str(result.stdout_evidence_id) if result.stdout_evidence_id else None,
                "stderr_evidence_id": str(result.stderr_evidence_id) if result.stderr_evidence_id else None,
                "stdout_evidence_path": result.stdout_evidence_path,
                "stderr_evidence_path": result.stderr_evidence_path,
                "parser_confidence": result.parser_confidence,
                "error_class": (
                    result.error_class.value if result.error_class else None
                ),
                "parsed_output": result.parsed_output,
                "execution_hints": execution_hints,
            },
        )

        self._audit_event(
            state,
            "ActionExecuted",
            {
                "action_id": str(action.action_id),
                "tool": action.tool_name,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "stdout_hash": result.stdout_hash,
                "stderr_hash": result.stderr_hash,
                "stdout_evidence_id": str(result.stdout_evidence_id) if result.stdout_evidence_id else None,
                "stderr_evidence_id": str(result.stderr_evidence_id) if result.stderr_evidence_id else None,
                "stdout_evidence_path": result.stdout_evidence_path,
                "stderr_evidence_path": result.stderr_evidence_path,
                "parser_confidence": result.parser_confidence,
                "error_class": (
                    result.error_class.value if result.error_class else None
                ),
                "parsed_output": result.parsed_output,
                "execution_hints": execution_hints,
            },
        )

        # Build recon summary for planner context (NEW: Feedback loop)
        recon_summary = state.get("recon_summary", {})
        assessment_objectives = list(state.get("assessment_objectives", []) or [])
        objective_progress = dict(state.get("objective_progress", {}) or {})
        depth_metrics = dict(state.get("depth_metrics", {}) or {})
        if self._recon_store and self._finding_store:
            try:
                recon_summary = self._recon_store.get_summary(engagement_id)
                findings_summary = self._finding_store.get_summary(engagement_id)
                # Merge with recon summary
                recon_summary["findings_summary"] = findings_summary
                attack_surface_updates = _extract_attack_surface_updates(
                    parsed_output=result.parsed_output,
                    findings_summary=findings_summary,
                    recon_summary=recon_summary,
                )
                recon_summary["attack_surface"] = _merge_attack_surface(
                    recon_summary.get("attack_surface"),
                    attack_surface_updates,
                )
                assessment_objectives, objective_progress = _build_assessment_objectives(
                    findings_summary=findings_summary,
                    previous_actions=previous,
                )
                depth_metrics = {
                    "exploit_signal_score_total": int(
                        sum(int(item.get("exploit_signal_score", 0) or 0) for item in previous if isinstance(item, dict))
                    ),
                    "confirmation_candidate_total": int(
                        sum(int(item.get("confirmation_candidate_count", 0) or 0) for item in previous if isinstance(item, dict))
                    ),
                    "followup_validation_actions": int(
                        sum(1 for item in previous if isinstance(item, dict) and bool(item.get("requires_followup_validation", False)))
                    ),
                    "objective_progress": objective_progress,
                }
            except Exception as summary_exc:
                log.warning("executor.summary_error", exc=str(summary_exc))

        # Accumulate evidence artifact IDs from this tool run into state so that
        # the readiness policy's min_evidence_artifacts gate counts them correctly.
        updated_evidence_ids = list(state.get("evidence_ids") or []) + run_evidence_ids

        should_refresh_tactical_summary = (
            len(previous) % self._memory_summary_every_n_actions == 0
            or "tactical_summary" not in dict(state.get("memory_context", {}) or {})
        )
        tactical_summary = (
            summarize_tactical_memory(previous)
            if should_refresh_tactical_summary
            else dict(state.get("memory_context", {}) or {}).get("tactical_summary", {})
        )

        output = {
            **state,
            "last_result": result.model_dump(mode="json"),
            "evidence_ids": updated_evidence_ids,
            "previous_actions": previous,
            "proposed_action": None,
            "validation_result": None,
            "no_new_findings_streak": streak,
            "nonproductive_cycle_streak": next_nonproductive,
            "recon_summary": recon_summary,
            "assessment_objectives": assessment_objectives,
            "objective_progress": objective_progress,
            "depth_metrics": depth_metrics,
            "memory_context": {
                **dict(state.get("memory_context", {}) or {}),
                "tactical_summary": tactical_summary,
                "memory_write_refs": memory_write_refs,
            },
            "attack_surface_graph": graph_snapshot,
            "last_execution_hints": execution_hints,
            "generated_payloads": (
                list(state.get("generated_payloads", []) or [])
                + ([generated_payload] if generated_payload else [])
            )[-30:],
            "pending_mutation_payload": pending_mutation_payload,
            # Clear active action fields after completion
            "active_action_id": None,
            "active_tool_name": None,
            "active_tool_command": None,
            "error": None,
        }

        output["previous_actions"] = prune_low_value_memory(
            output.get("previous_actions", []),
            keep_last=self._memory_prune_keep_last_actions,
        )

        # Emit recovery hints for planner consumption
        for hint in execution_hints:
            hint_code = str(hint.get("code", "")).strip()
            if hint_code:
                self._emit_event(ExecutionEvent(
                    engagement_id=engagement_id,
                    action_id=action.action_id,
                    event_type=ExecutionEventType.EXECUTOR_RECOVERY_HINT,
                    tool_name=action.tool_name,
                    actor="executor",
                    payload={
                        "hint_code": hint_code,
                        "hint_detail": hint.get("detail", ""),
                    },
                ))

        # Emit AgentInvoked for executor
        duration_ms = round((time.monotonic() - _t0) * 1000, 2)
        output_hash = hashlib.sha256(
            json.dumps(output, default=str, sort_keys=True).encode()
        ).hexdigest()
        self._audit_event(
            state,
            "AgentInvoked",
            {
                "agent_name": "executor",
                "input_state_hash": _input_hash,
                "output_state_hash": output_hash,
                "llm_model_used": "none",
                "llm_routing_decision": "none",
                "duration_ms": duration_ms,
            },
        )
        return output

    def _audit_event(
        self, state: AgentState, event_type: str, payload: dict[str, Any]
    ) -> None:
        try:
            self._audit.append(
                engagement_id=UUID(state["engagement_id"]),
                actor="executor",
                event_type=event_type,
                payload=payload,
            )
        except Exception as exc:
            log.error("executor.audit_write_failed", exc=str(exc))

    def _emit_event(self, event: ExecutionEvent) -> None:
        """Publish event to the bus if one is wired."""
        if self._event_bus is not None:
            try:
                self._event_bus.publish(event)  # type: ignore[attr-defined]
            except Exception as exc:
                log.warning("executor.event_emit_failed", exc=str(exc), event_type=event.event_type.value)
