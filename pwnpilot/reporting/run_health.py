"""Run health evaluator: computes final run verdict and degradation reasons."""
from __future__ import annotations

from typing import Any


def evaluate_run_health(state: dict[str, Any], readiness_result: dict[str, Any]) -> dict[str, Any]:
    previous_actions = state.get("previous_actions", [])
    if not isinstance(previous_actions, list):
        previous_actions = []

    total_actions = max(1, len(previous_actions))
    failed_actions = sum(
        1
        for item in previous_actions
        if isinstance(item, dict) and str(item.get("outcome_status", "")).strip() == "failed"
    )
    degraded_actions = sum(
        1
        for item in previous_actions
        if isinstance(item, dict) and str(item.get("outcome_status", "")).strip() == "degraded"
    )

    failed_ratio = failed_actions / total_actions
    degraded_ratio = degraded_actions / total_actions

    degradation_reasons: list[str] = []
    failed_gates = list(readiness_result.get("failed_gates", [])) if isinstance(readiness_result, dict) else []
    if failed_gates:
        degradation_reasons.extend([f"readiness_gate_failed:{gate}" for gate in failed_gates])

    termination_reason = str(state.get("termination_reason", "")).strip() or None
    if termination_reason == "stalled_nonproductive_loop":
        degradation_reasons.append("stalled_nonproductive_loop")

    run_verdict = "completed"
    readiness_status = str(readiness_result.get("status", "completed"))

    if readiness_status == "incomplete_assessment":
        run_verdict = "failed"
    elif failed_ratio >= 0.5 or degraded_ratio >= 0.5:
        run_verdict = "completed_with_degradation"
    elif readiness_status == "completed_with_degradation":
        run_verdict = "completed_with_degradation"

    return {
        "run_verdict": run_verdict,
        "degradation_reasons": sorted(set(degradation_reasons)),
        "termination_reason": termination_reason,
        "action_health": {
            "total_actions": len(previous_actions),
            "failed_actions": failed_actions,
            "degraded_actions": degraded_actions,
            "failed_ratio": round(failed_ratio, 4),
            "degraded_ratio": round(degraded_ratio, 4),
        },
    }
