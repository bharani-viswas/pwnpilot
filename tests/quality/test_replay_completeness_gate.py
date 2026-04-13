"""
Quality benchmark gate: Replay completeness.

Validates that the ReplayService correctly reconstructs a full ReplaySnapshot
from persisted audit events and operator decisions.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from pwnpilot.services.replay_service import ReplayService


def _make_audit_mock(
    events: list[dict],
    execution_events: list[dict],
) -> MagicMock:
    audit = MagicMock()
    audit.events_for_engagement.return_value = events
    audit.execution_events_for_engagement.return_value = execution_events
    return audit


def _make_decision_mock(decisions: list) -> MagicMock:
    store = MagicMock()
    store.decisions_for_engagement.return_value = decisions
    return store


class TestReplayCompletenessGate:
    """Pass/fail gates for replay snapshot completeness."""

    def test_snapshot_contains_event_timeline(self) -> None:
        engagement_id = uuid4()
        events = [{"event_type": "action.started", "payload": {}}]
        audit = _make_audit_mock(events=[], execution_events=events)
        store = _make_decision_mock([])

        svc = ReplayService(audit, store)
        snap = svc.build_snapshot(engagement_id)

        assert snap.event_timeline == events

    def test_snapshot_contains_operator_decisions(self) -> None:
        engagement_id = uuid4()

        fake_decision = MagicMock()
        fake_decision.model_dump.return_value = {
            "decision_id": str(uuid4()),
            "decision_type": "approve",
        }

        audit = _make_audit_mock(events=[], execution_events=[])
        store = _make_decision_mock([fake_decision])

        svc = ReplayService(audit, store)
        snap = svc.build_snapshot(engagement_id)

        assert len(snap.operator_decisions) == 1
        assert snap.operator_decisions[0]["decision_type"] == "approve"

    def test_snapshot_contains_planner_rejections(self) -> None:
        engagement_id = uuid4()
        raw_events = [
            {"event_type": "PlanRejected", "payload": {"reason_code": "DUPLICATE"}},
            {"event_type": "ActionExecuted", "payload": {}},
        ]
        audit = _make_audit_mock(events=raw_events, execution_events=[])
        store = _make_decision_mock([])

        svc = ReplayService(audit, store)
        snap = svc.build_snapshot(engagement_id)

        assert len(snap.planner_rejections) == 1
        assert snap.planner_rejections[0]["event_type"] == "PlanRejected"

    def test_snapshot_run_metadata_from_report_event(self) -> None:
        engagement_id = uuid4()
        raw_events = [
            {"event_type": "ReportGenerated", "payload": {"run_verdict": "degraded"}},
        ]
        audit = _make_audit_mock(events=raw_events, execution_events=[])
        store = _make_decision_mock([])

        svc = ReplayService(audit, store)
        snap = svc.build_snapshot(engagement_id)

        assert snap.run_metadata.get("run_verdict") == "degraded"

    def test_snapshot_empty_engagement_graceful(self) -> None:
        """Snapshot for an engagement with no data returns valid empty structure."""
        engagement_id = uuid4()
        audit = _make_audit_mock(events=[], execution_events=[])
        store = _make_decision_mock([])

        svc = ReplayService(audit, store)
        snap = svc.build_snapshot(engagement_id)

        assert snap.engagement_id == engagement_id
        assert snap.event_timeline == []
        assert snap.operator_decisions == []
        assert snap.planner_rejections == []

    def test_snapshot_resilient_to_audit_error(self) -> None:
        """Replay service returns partial snapshot when audit store raises."""
        engagement_id = uuid4()
        audit = MagicMock()
        audit.events_for_engagement.side_effect = RuntimeError("db error")
        audit.execution_events_for_engagement.side_effect = RuntimeError("db error")
        store = _make_decision_mock([])

        svc = ReplayService(audit, store)
        snap = svc.build_snapshot(engagement_id)  # Must not raise

        assert snap.event_timeline == []
        assert snap.planner_rejections == []
