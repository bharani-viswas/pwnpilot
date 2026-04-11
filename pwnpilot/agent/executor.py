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

log = structlog.get_logger(__name__)


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
    ) -> None:
        self._policy = policy_engine
        self._runner = tool_runner
        self._approval = approval_service
        self._audit = audit_store
        self._finding_store = finding_store
        self._recon_store = recon_store

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
            action = ActionRequest(
                engagement_id=engagement_id,
                action_type=ActionType(proposal.action_type),
                tool_name=proposal.tool_name,
                params={**proposal.params, "target": proposal.target},
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

        # Execute tool
        try:
            result = self._runner.execute(action)
        except Exception as exc:
            log.error("executor.tool_error", exc=str(exc), tool=action.tool_name)
            self._audit_event(
                state,
                "ActionFailed",
                {"action_id": str(action.action_id), "error": str(exc)},
            )
            return {**state, "error": f"Tool execution failed: {exc}"}

        # Update convergence streak
        new_evidence = result.parsed_output.get("new_findings_count", 0)
        streak = state.get("no_new_findings_streak", 0)
        streak = 0 if new_evidence > 0 else streak + 1

        # Store findings and hosts from tool output (NEW: Feedback loop)
        if self._finding_store and self._recon_store:
            try:
                # Extract and store findings
                findings_list = result.parsed_output.get("findings", [])
                for finding in findings_list:
                    # Convert severity string to enum
                    severity_str = finding.get("severity", "medium").lower()
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
                        asset_ref=finding.get("target", proposal.target),
                        title=finding.get("description", ""),
                        vuln_ref=f"{action.tool_name}:{finding.get('type', 'unknown')}",
                        tool_name=action.tool_name,
                        severity=severity,
                        confidence=finding.get("confidence", 0.5),
                        evidence_ids=[],
                        remediation=finding.get("remediation", ""),
                    )

                # Extract and store hosts
                hosts_list = result.parsed_output.get("hosts", [])
                for host in hosts_list:
                    host_id = self._recon_store.upsert_host(
                        engagement_id=engagement_id,
                        ip_address=host.get("ip_address", host.get("ip", "")),
                        hostname=host.get("hostname"),
                        os_guess=host.get("os"),
                    )
                    # Store services for this host
                    for port_info in host.get("ports", []):
                        port = port_info if isinstance(port_info, int) else port_info.get("port")
                        service_name = port_info.get("service") if isinstance(port_info, dict) else None
                        self._recon_store.upsert_service(
                            host_id=host_id,
                            engagement_id=engagement_id,
                            port=port,
                            service_name=service_name,
                        )

                log.info("executor.data_stored", findings_count=len(findings_list), hosts_count=len(hosts_list))
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
            }
        )

        self._audit_event(
            state,
            "ActionExecuted",
            {
                "action_id": str(action.action_id),
                "tool": action.tool_name,
                "exit_code": result.exit_code,
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
