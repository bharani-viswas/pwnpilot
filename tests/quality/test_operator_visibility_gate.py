"""
Quality benchmark gate: Operator visibility and intervention counting.

Validates that operator interventions are recorded via run-quality metrics,
and that intervention count is surfaced in the engagement summary.
"""
from __future__ import annotations

import pytest
from uuid import uuid4

from pwnpilot.observability.metrics import EngagementMetrics, metrics_registry


class TestOperatorInterventionCounting:
    """Pass/fail gates for operator intervention observability."""

    def test_intervention_count_increments(self) -> None:
        """Each recorded intervention increments the counter."""
        m = EngagementMetrics(engagement_id="test-intervention")
        assert m.operator_intervention_count == 0

        m.record_operator_intervention()
        m.record_operator_intervention()
        assert m.operator_intervention_count == 2

    def test_intervention_appears_in_summary(self) -> None:
        """Intervention count is present in the metrics summary."""
        m = EngagementMetrics(engagement_id="test-intervention-summary")
        m.record_operator_intervention()

        summary = m.summary()
        assert summary["operator_intervention_count"] == 1

    def test_intervention_count_thread_safe(self) -> None:
        """Concurrent intervention recording does not lose updates."""
        import threading

        m = EngagementMetrics(engagement_id="test-thread-safe")
        threads = [
            threading.Thread(target=m.record_operator_intervention)
            for _ in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert m.operator_intervention_count == 50

    def test_registry_get_for_active_engagement(self) -> None:
        """metrics_registry.get returns the correct instance for an active engagement."""
        eid = str(uuid4())
        m = metrics_registry.get_or_create(eid)
        m.record_operator_intervention()

        retrieved = metrics_registry.get(eid)
        assert retrieved is m
        assert retrieved.operator_intervention_count == 1

        # Cleanup
        metrics_registry.remove(eid)

    def test_registry_get_returns_none_for_missing(self) -> None:
        """metrics_registry.get returns None for an engagement not yet started."""
        result = metrics_registry.get("nonexistent-" + str(uuid4()))
        assert result is None
