"""Report readiness policy for evidence-quality gating."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ReadinessThresholds:
    min_successful_tool_families: int = 1
    min_reachable_target_confirmations: int = 1
    min_evidence_artifacts: int = 1
    max_critical_tool_failures: int = 5
    min_exploit_validation_actions: int = 1
    min_confirmation_candidates: int = 1


class ReportReadinessPolicy:
    def __init__(self, thresholds: ReadinessThresholds | None = None) -> None:
        self._thresholds = thresholds or ReadinessThresholds()

    def evaluate(self, state: dict[str, Any]) -> dict[str, Any]:
        previous_actions = state.get("previous_actions", [])
        if not isinstance(previous_actions, list):
            previous_actions = []

        successful_tool_families = {
            str(item.get("tool_name", "")).strip()
            for item in previous_actions
            if isinstance(item, dict)
            and str(item.get("outcome_status", "")).strip() == "success"
            and str(item.get("tool_name", "")).strip()
        }

        reachable_confirmations = 0
        critical_failures = 0
        exploit_validation_actions = 0
        confirmation_candidates = 0
        for item in previous_actions:
            if not isinstance(item, dict):
                continue
            reasons = {str(r).strip() for r in item.get("failure_reasons", []) if str(r).strip()}
            if "TargetUnreachable" not in reasons:
                reachable_confirmations += 1
            if str(item.get("outcome_status", "")).strip() == "failed":
                critical_failures += 1

            action_type = str(item.get("action_type", "")).strip()
            requires_followup = bool(item.get("requires_followup_validation", False))
            if action_type in {"exploit", "post_exploit"} or requires_followup:
                exploit_validation_actions += 1

            try:
                confirmation_candidates += int(item.get("confirmation_candidate_count", 0) or 0)
            except Exception:
                pass

        evidence_ids = state.get("evidence_ids", [])
        evidence_count = len(evidence_ids) if isinstance(evidence_ids, list) else 0

        findings_total = 0
        recon_summary = state.get("recon_summary", {})
        if isinstance(recon_summary, dict):
            findings_summary = recon_summary.get("findings_summary", {})
            if isinstance(findings_summary, dict):
                try:
                    findings_total = int(findings_summary.get("total_findings", 0) or 0)
                except Exception:
                    findings_total = 0

        depth_required = findings_total > 0

        gates = {
            "min_successful_tool_families": len(successful_tool_families) >= self._thresholds.min_successful_tool_families,
            "min_reachable_target_confirmations": reachable_confirmations >= self._thresholds.min_reachable_target_confirmations,
            "min_evidence_artifacts": evidence_count >= self._thresholds.min_evidence_artifacts,
            "max_critical_tool_failures": critical_failures <= self._thresholds.max_critical_tool_failures,
            "min_exploit_validation_actions": (not depth_required)
            or exploit_validation_actions >= self._thresholds.min_exploit_validation_actions,
            "min_confirmation_candidates": (not depth_required)
            or confirmation_candidates >= self._thresholds.min_confirmation_candidates,
        }

        failed_gates = [name for name, passed in gates.items() if not passed]
        status = "completed" if not failed_gates else "incomplete_assessment"
        if failed_gates and gates.get("max_critical_tool_failures", True):
            status = "completed_with_degradation"

        return {
            "status": status,
            "gates": gates,
            "failed_gates": failed_gates,
            "metrics": {
                "successful_tool_families": len(successful_tool_families),
                "reachable_target_confirmations": reachable_confirmations,
                "evidence_artifacts": evidence_count,
                "critical_tool_failures": critical_failures,
                "exploit_validation_actions": exploit_validation_actions,
                "confirmation_candidates": confirmation_candidates,
                "depth_required": depth_required,
            },
        }
