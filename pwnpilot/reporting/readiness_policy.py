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
        for item in previous_actions:
            if not isinstance(item, dict):
                continue
            reasons = {str(r).strip() for r in item.get("failure_reasons", []) if str(r).strip()}
            if "TargetUnreachable" not in reasons:
                reachable_confirmations += 1
            if str(item.get("outcome_status", "")).strip() == "failed":
                critical_failures += 1

        evidence_ids = state.get("evidence_ids", [])
        evidence_count = len(evidence_ids) if isinstance(evidence_ids, list) else 0

        gates = {
            "min_successful_tool_families": len(successful_tool_families) >= self._thresholds.min_successful_tool_families,
            "min_reachable_target_confirmations": reachable_confirmations >= self._thresholds.min_reachable_target_confirmations,
            "min_evidence_artifacts": evidence_count >= self._thresholds.min_evidence_artifacts,
            "max_critical_tool_failures": critical_failures <= self._thresholds.max_critical_tool_failures,
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
            },
        }
