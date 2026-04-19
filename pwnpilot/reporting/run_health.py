"""Run health evaluator: computes final run verdict and degradation reasons."""
from __future__ import annotations

from typing import Any


def _normalize_terminal_reason(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or text.lower() in {"none", "null"}:
        return None
    return text


def _objective_counts(state: dict[str, Any]) -> dict[str, int]:
    progress = state.get("objective_progress", {})
    if isinstance(progress, dict) and progress:
        return {
            "total": int(progress.get("total", 0) or 0),
            "open": int(progress.get("open", 0) or 0),
            "in_progress": int(progress.get("in_progress", 0) or 0),
            "confirmed": int(progress.get("confirmed", 0) or 0),
            "disproved": int(progress.get("disproved", 0) or 0),
        }

    objectives = state.get("assessment_objectives", [])
    counts = {"total": 0, "open": 0, "in_progress": 0, "confirmed": 0, "disproved": 0}
    if not isinstance(objectives, list):
        return counts

    for item in objectives:
        if not isinstance(item, dict):
            continue
        counts["total"] += 1
        status = str(item.get("status", "")).strip().lower()
        if status in counts:
            counts[status] += 1
    return counts


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
    objective_counts = _objective_counts(state)
    unresolved_objectives = objective_counts["open"] + objective_counts["in_progress"]
    critical_tool_failures = int(
        ((readiness_result or {}).get("metrics", {}) or {}).get("critical_tool_failures", 0) or 0
    )

    degradation_reasons: list[str] = []
    failed_gates = list(readiness_result.get("failed_gates", [])) if isinstance(readiness_result, dict) else []
    if failed_gates:
        degradation_reasons.extend([f"readiness_gate_failed:{gate}" for gate in failed_gates])

    termination_reason = _normalize_terminal_reason(state.get("termination_reason"))
    if termination_reason == "stalled_nonproductive_loop":
        degradation_reasons.append("stalled_nonproductive_loop")
    elif termination_reason:
        degradation_reasons.append(f"termination_reason:{termination_reason}")

    if unresolved_objectives > 0:
        degradation_reasons.append(f"unresolved_objectives:{unresolved_objectives}")
    if failed_actions > 0:
        degradation_reasons.append(f"failed_actions:{failed_actions}")
    if degraded_actions > 0:
        degradation_reasons.append(f"degraded_actions:{degraded_actions}")
    if critical_tool_failures > 0:
        degradation_reasons.append(f"critical_tool_failures:{critical_tool_failures}")

    run_verdict = "completed"
    readiness_status = str(readiness_result.get("status", "completed"))

    if readiness_status == "incomplete_assessment":
        run_verdict = "failed"
    elif unresolved_objectives > 0 and (failed_actions > 0 or critical_tool_failures > 0):
        run_verdict = "failed"
    elif unresolved_objectives > 0:
        run_verdict = "completed_with_degradation"
    elif failed_ratio >= 0.5 or degraded_ratio >= 0.5:
        run_verdict = "completed_with_degradation"
    elif readiness_status == "completed_with_degradation":
        run_verdict = "completed_with_degradation"
    elif failed_actions > 0 or degraded_actions > 0 or critical_tool_failures > 0:
        run_verdict = "completed_with_degradation"

    return {
        "run_verdict": run_verdict,
        "degradation_reasons": sorted(set(degradation_reasons)),
        "termination_reason": termination_reason,
        "objective_health": objective_counts,
        "action_health": {
            "total_actions": len(previous_actions),
            "failed_actions": failed_actions,
            "degraded_actions": degraded_actions,
            "failed_ratio": round(failed_ratio, 4),
            "degraded_ratio": round(degraded_ratio, 4),
            "critical_tool_failures": critical_tool_failures,
        },
    }
