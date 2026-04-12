"""
Executor Agent — converts validated proposals into ActionRequests, gates through the
Policy Engine, and triggers tool execution.

Reads from AgentState:
  proposed_action, validation_result

Writes to AgentState:
  last_result, evidence_ids, no_new_findings_streak

This is the ONLY agent that calls the Policy Engine and the Tool Runner.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import structlog

from pwnpilot.agent.state import AgentState
from pwnpilot.control.approval import ApprovalService
from pwnpilot.control.policy import PolicyEngine
from pwnpilot.data.models import (
    ActionRequest,
    ActionType,
    PolicyVerdict,
    PlannerProposal,
    RiskLevel,
    ValidationResult,
)
from pwnpilot.plugins.parsers.contracts import (
    canonicalize_finding,
    infer_host_from_service,
    infer_service_port,
)

log = structlog.get_logger(__name__)


# Severity order from highest to lowest
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


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


class ExecutorNode:
    """
    Stateless callable used as a LangGraph executor node.

    Converts the validated PlannerProposal into a typed ActionRequest, evaluates it
    through the Policy Engine, and calls the tool runner on approval.
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
    ) -> None:
        self._policy = policy_engine
        self._runner = tool_runner
        self._approval = approval_service
        self._audit = audit_store
        self._finding_store = finding_store
        self._recon_store = recon_store
        self._planner_available_tools = planner_available_tools or []

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
            return {**state, "error": "Missing proposal or validation result in executor."}

        try:
            proposal = PlannerProposal(**proposal_dict)
            validation = ValidationResult(**validation_dict)
        except Exception as exc:
            return {**state, "error": f"Executor: invalid proposal/validation: {exc}"}

        # Determine effective risk level (validation can escalate, never downgrade)
        effective_risk = validation.risk_override or proposal.estimated_risk
        engagement_id = UUID(state["engagement_id"])

        # Construct typed ActionRequest
        try:
            normalized_params = _normalize_params(proposal.params, proposal.tool_name)
            action = ActionRequest(
                engagement_id=engagement_id,
                action_type=ActionType(proposal.action_type),
                tool_name=proposal.tool_name,
                params={**normalized_params, "target": proposal.target},
                risk_level=effective_risk,
            )
        except Exception as exc:
            return {**state, "error": f"Executor: failed to build ActionRequest: {exc}"}

        # Policy Engine evaluation
        decision = self._policy.evaluate(action)

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
            # Inject rejection reason so Planner can try something different
            updated_proposal = proposal_dict.copy()
            updated_proposal["rejection_reason"] = decision.reason
            return {
                **state,
                "proposed_action": updated_proposal,
                "validation_result": None,
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
            # Halt the loop until the operator resolves the ticket
            return {**state, "kill_switch": True, "error": None}

        self._audit_event(
            state,
            "ToolExecutionStarted",
            {
                "action_id": str(action.action_id),
                "tool": action.tool_name,
                "action_type": action.action_type.value,
                "target": proposal.target,
                "params": action.params,
                "risk_level": (
                    action.risk_level.value
                    if hasattr(action.risk_level, "value")
                    else str(action.risk_level)
                ),
            },
        )

        # Execute tool
        try:
            result = self._runner.execute(action)
        except (KeyError, FileNotFoundError) as exc:
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
                    "target": proposal.target,
                    "params": action.params,
                    "error": str(exc),
                },
            )

            updated_prev = list(state.get("previous_actions", []))
            updated_prev.append(
                {
                    "action_id": str(action.action_id),
                    "tool_name": action.tool_name,
                    "action_type": action.action_type.value,
                    "target": proposal.target,
                    "error": "tool_not_available",
                }
            )

            cooldowns = dict(state.get("temporarily_unavailable_tools", {}))
            cooldowns[action.tool_name] = max(int(cooldowns.get(action.tool_name, 0)), 3)

            updated_proposal = proposal_dict.copy()
            updated_proposal["rejection_reason"] = (
                f"Tool '{action.tool_name}' is not available on this system. "
                f"Choose from available tools: {available}"
            )

            return {
                **state,
                "proposed_action": updated_proposal,
                "validation_result": None,
                "previous_actions": updated_prev,
                "temporarily_unavailable_tools": cooldowns,
                "error": None,
            }
        except ValueError as exc:
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
                return {**state, "kill_switch": True, "error": None}
            
            # Generic parameter validation error - ask planner to retry
            log.warning("executor.param_validation_error", exc=error_msg, tool=action.tool_name)
            self._audit_event(
                state,
                "ActionFailed",
                {
                    "action_id": str(action.action_id),
                    "tool": action.tool_name,
                    "target": proposal.target,
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
                    "target": proposal.target,
                    "error": "param_validation_failed",
                }
            )

            updated_proposal = proposal_dict.copy()
            updated_proposal["rejection_reason"] = (
                f"Parameter validation failed for {action.tool_name}: {error_msg}. "
                f"Please try different parameters."
            )

            return {
                **state,
                "proposed_action": updated_proposal,
                "validation_result": None,
                "previous_actions": updated_prev,
                "error": None,
            }
        except Exception as exc:
            log.error("executor.tool_error", exc=str(exc), tool=action.tool_name)
            self._audit_event(
                state,
                "ActionFailed",
                {
                    "action_id": str(action.action_id),
                    "tool": action.tool_name,
                    "target": proposal.target,
                    "params": action.params,
                    "error": str(exc),
                },
            )
            return {**state, "error": f"Tool execution failed: {exc}"}

        # Update convergence streak
        new_evidence = result.parsed_output.get("new_findings_count", 0)
        streak = state.get("no_new_findings_streak", 0)
        streak = 0 if new_evidence > 0 else streak + 1
        execution_hints = list(result.parsed_output.get("execution_hints", []))

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
                        evidence_ids=[],
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
                "target": proposal.target,
                "exit_code": result.exit_code,
                "execution_hint_codes": [hint.get("code") for hint in execution_hints],
            }
        )

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
        if self._recon_store and self._finding_store:
            try:
                recon_summary = self._recon_store.get_summary(engagement_id)
                findings_summary = self._finding_store.get_summary(engagement_id)
                # Merge with recon summary
                recon_summary["findings_summary"] = findings_summary
            except Exception as summary_exc:
                log.warning("executor.summary_error", exc=str(summary_exc))

        output = {
            **state,
            "last_result": result.model_dump(mode="json"),
            "evidence_ids": state.get("evidence_ids", []),
            "previous_actions": previous,
            "proposed_action": None,
            "validation_result": None,
            "no_new_findings_streak": streak,
            "recon_summary": recon_summary,
            "last_execution_hints": execution_hints,
            "error": None,
        }
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
