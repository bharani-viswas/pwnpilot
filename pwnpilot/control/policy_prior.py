"""
Policy prior advisory scorer (Phase 6E).

Advisory-only ranking score for planner proposals using a simple learned prior
from historical trajectory stats.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PolicyPriorScorer:
    def __init__(self, enabled: bool = False, policy_file: str = "") -> None:
        self._enabled = bool(enabled)
        self._stats: dict[str, Any] = {}
        if self._enabled and policy_file:
            self._load(policy_file)

    def _load(self, policy_file: str) -> None:
        path = Path(policy_file)
        if not path.exists():
            return
        try:
            self._stats = json.loads(path.read_text())
        except Exception:
            self._stats = {}

    def score(self, proposal: dict[str, Any], state: dict[str, Any]) -> float:
        if not self._enabled:
            return 0.5

        tool = str(proposal.get("tool_name", "")).strip()
        action_type = str(proposal.get("action_type", "")).strip()

        base = 0.5
        tool_stats = self._stats.get("tool_success_rate", {}) if isinstance(self._stats, dict) else {}
        if tool in tool_stats:
            base = float(tool_stats.get(tool, base))

        if action_type in {"exploit", "post_exploit"}:
            base -= 0.05
        if int(state.get("nonproductive_cycle_streak", 0) or 0) >= 3:
            base -= 0.1
        if int(state.get("no_new_findings_streak", 0) or 0) >= 3:
            base -= 0.05

        return max(0.0, min(1.0, round(base, 4)))
