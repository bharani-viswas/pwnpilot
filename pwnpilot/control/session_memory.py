"""
Session memory utilities for Phase 6B.

Maintains deterministic tactical memory snapshots and pruning/summarisation logic
for planner context stability across long iterations.
"""
from __future__ import annotations

from typing import Any


def summarize_tactical_memory(previous_actions: list[dict[str, Any]], max_items: int = 12) -> dict[str, Any]:
    recent = [a for a in previous_actions[-max_items:] if isinstance(a, dict)]
    exploit_attempts = 0
    successful_actions = 0
    low_value_actions = 0
    tool_counts: dict[str, int] = {}
    for action in recent:
        tool = str(action.get("tool_name", "")).strip()
        if tool:
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        if str(action.get("action_type", "")).strip() in {"exploit", "post_exploit"}:
            exploit_attempts += 1
        if str(action.get("outcome_status", "")).strip() in {"success", "degraded"}:
            successful_actions += 1
        if bool(action.get("objective_low_value", False)):
            low_value_actions += 1

    top_tools = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    return {
        "window_size": len(recent),
        "exploit_attempts": exploit_attempts,
        "successful_actions": successful_actions,
        "low_value_actions": low_value_actions,
        "top_tools": [{"tool": t, "count": c} for t, c in top_tools],
    }


def prune_low_value_memory(previous_actions: list[dict[str, Any]], keep_last: int = 60) -> list[dict[str, Any]]:
    if len(previous_actions) <= keep_last:
        return previous_actions
    head = previous_actions[:-keep_last]
    tail = previous_actions[-keep_last:]
    pruned_head = [a for a in head if not bool(a.get("objective_low_value", False))]
    return pruned_head + tail
