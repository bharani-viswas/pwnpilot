"""
Policy Simulation — dry-run mode that returns policy decisions without executing tools.

Used for:
- ROE preflight checks before real engagement start
- Policy change validation
- CI testing of policy configurations
"""
from __future__ import annotations

from typing import Any

import structlog

from pwnpilot.control.engagement import EngagementService
from pwnpilot.control.policy import PolicyEngine
from pwnpilot.data.models import ActionRequest, PolicyDecision

log = structlog.get_logger(__name__)


class SimulationEngine:
    """
    Wraps the real PolicyEngine but routes all evaluation results to simulation
    output without any tool side-effects.
    """

    def __init__(self, engagement_service: EngagementService) -> None:
        self._policy = PolicyEngine(engagement_service)
        self._results: list[dict[str, Any]] = []

    def simulate(self, action: ActionRequest) -> PolicyDecision:
        """Evaluate the action through the policy engine; record result, no execution."""
        decision = self._policy.evaluate(action)
        self._results.append(
            {
                "action_id": str(action.action_id),
                "action_type": action.action_type.value,
                "tool_name": action.tool_name,
                "verdict": decision.verdict.value,
                "reason": decision.reason,
                "gate_type": decision.gate_type.value,
            }
        )
        log.info(
            "simulation.evaluated",
            action_id=str(action.action_id),
            verdict=decision.verdict,
        )
        return decision

    @property
    def results(self) -> list[dict[str, Any]]:
        return list(self._results)

    def summary(self) -> dict[str, Any]:
        total = len(self._results)
        verdicts: dict[str, int] = {}
        for r in self._results:
            verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
        return {"total": total, "verdicts": verdicts, "results": self._results}
