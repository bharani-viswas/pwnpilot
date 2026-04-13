"""
Quality benchmark gate: Report finalization closure reliability.

Validates that:
  - Successful report finalization is tracked and reflected in closure_reliability.
  - Failed finalizations emit REPORT_FINALIZATION_FAILED events via the event bus.
  - closure_reliability is never None after at least one finalization attempt.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from pwnpilot.observability.metrics import EngagementMetrics


class TestClosureReliabilityMetric:
    """Pass/fail gates for report-finalization closure reliability."""

    def test_closure_reliability_none_before_any_attempt(self) -> None:
        m = EngagementMetrics(engagement_id="closure-empty")
        assert m.closure_reliability is None

    def test_closure_reliability_one_success(self) -> None:
        m = EngagementMetrics(engagement_id="closure-one-success")
        m.record_report_finalization(success=True)
        assert m.closure_reliability == 1.0

    def test_closure_reliability_one_failure(self) -> None:
        m = EngagementMetrics(engagement_id="closure-one-failure")
        m.record_report_finalization(success=False)
        assert m.closure_reliability == 0.0

    def test_closure_reliability_mixed(self) -> None:
        m = EngagementMetrics(engagement_id="closure-mixed")
        for _ in range(3):
            m.record_report_finalization(success=True)
        for _ in range(1):
            m.record_report_finalization(success=False)
        # 3 success / 4 total = 0.75
        assert m.closure_reliability == 0.75

    def test_closure_reliability_in_summary(self) -> None:
        m = EngagementMetrics(engagement_id="closure-summary")
        m.record_report_finalization(success=True)
        m.record_report_finalization(success=False)

        summary = m.summary()
        assert "closure_reliability" in summary
        assert summary["closure_reliability"] == 0.5
        assert summary["report_finalization_successes"] == 1
        assert summary["report_finalization_failures"] == 1


class TestReporterFinalizationFailureEmission:
    """Validate reporter emits REPORT_FINALIZATION_FAILED when build_bundle fails."""

    def test_reporter_emits_finalization_failed_event(self, tmp_path: Path) -> None:
        from pwnpilot.agent.reporter import ReporterNode
        from pwnpilot.data.models import ExecutionEventType

        events_emitted: list = []

        fake_event_bus = MagicMock()
        fake_event_bus.publish.side_effect = lambda eid, event: events_emitted.append(event)

        fake_generator = MagicMock()
        fake_generator.build_bundle.side_effect = RuntimeError("disk full")

        fake_audit = MagicMock()
        fake_audit.append.return_value = None

        reporter = ReporterNode(
            report_generator=fake_generator,
            audit_store=fake_audit,
            output_dir=tmp_path,
            event_bus=fake_event_bus,
        )

        state = {
            "engagement_id": str(uuid4()),
            "iteration_count": 5,
            "nonproductive_cycle_streak": 0,
            "previous_actions": [],
            "recon_summary": {},
            "kill_switch": False,
            "finalization_failed": False,
            "finalization_failure_reason": None,
        }

        result = reporter(state)

        # Must set completion_state to FAILED
        assert result.get("completion_state") == "failed"
        assert result.get("finalization_failed") is True
        assert "disk full" in result.get("finalization_failure_reason", "")

        # Event bus must have been called with REPORT_FINALIZATION_FAILED
        assert fake_event_bus.publish.called
        event_arg = events_emitted[0]
        assert event_arg.event_type == ExecutionEventType.REPORT_FINALIZATION_FAILED

    def test_reporter_sets_finalized_on_success(self, tmp_path: Path) -> None:
        from pwnpilot.agent.reporter import ReporterNode

        fake_generator = MagicMock()
        fake_generator.build_bundle.return_value = (
            tmp_path / "bundle.json",
            tmp_path / "summary.md",
        )

        fake_audit = MagicMock()
        fake_audit.append.return_value = None

        reporter = ReporterNode(
            report_generator=fake_generator,
            audit_store=fake_audit,
            output_dir=tmp_path,
        )

        state = {
            "engagement_id": str(uuid4()),
            "iteration_count": 5,
            "nonproductive_cycle_streak": 0,
            "previous_actions": [],
            "recon_summary": {},
            "kill_switch": False,
        }

        result = reporter(state)
        assert result.get("completion_state") == "finalized"
        assert result.get("report_complete") is True
