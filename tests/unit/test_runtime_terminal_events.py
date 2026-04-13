from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from pwnpilot.runtime import (
    _emit_terminal_lifecycle_events,
    _normalize_terminal_state,
    _persist_postmortem_artifact,
)


class _AuditStub:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []
        self._timeline: list[object] = []

    def append(self, engagement_id, actor, event_type, payload):
        self.events.append((event_type, payload))
        self._timeline.append(
            type(
                "Evt",
                (),
                {
                    "timestamp": datetime.now(timezone.utc),
                    "actor": actor,
                    "event_type": event_type,
                    "payload": payload,
                },
            )
        )

    def events_for_engagement(self, engagement_id):
        return iter(self._timeline)


def test_emit_completed_and_no_report_failure_when_report_complete() -> None:
    store = _AuditStub()
    eid = uuid4()

    _emit_terminal_lifecycle_events(
        store,
        eid,
        {
            "report_complete": True,
            "termination_reason": "convergence",
        },
    )

    assert store.events[0][0] == "EngagementCompleted"
    assert all(event_type != "ReportGenerationFailed" for event_type, _ in store.events)


def test_emit_failed_and_report_failure_when_report_missing() -> None:
    store = _AuditStub()
    eid = uuid4()

    _emit_terminal_lifecycle_events(
        store,
        eid,
        {
            "report_complete": False,
            "error": "planner loop stalled",
            "termination_reason": "planner_validator_churn",
        },
    )

    assert store.events[0][0] == "EngagementFailed"
    assert store.events[1][0] == "ReportGenerationFailed"
    assert store.events[1][1]["reason"] == "planner loop stalled"


def test_emit_report_failure_reason_uses_termination_when_no_error() -> None:
    store = _AuditStub()
    eid = uuid4()

    _emit_terminal_lifecycle_events(
        store,
        eid,
        {
            "report_complete": False,
            "termination_reason": "runtime_budget_exceeded",
        },
    )

    assert store.events[0][0] == "EngagementCompleted"
    assert store.events[1][0] == "ReportGenerationFailed"
    assert store.events[1][1]["reason"] == "runtime_budget_exceeded"


def test_emit_failed_when_finalization_failed_without_error() -> None:
    store = _AuditStub()
    eid = uuid4()

    _emit_terminal_lifecycle_events(
        store,
        eid,
        {
            "report_complete": False,
            "finalization_failed": True,
            "completion_state": "failed",
            "termination_reason": "planner_validator_churn",
        },
    )

    assert store.events[0][0] == "EngagementFailed"
    assert store.events[1][0] == "ReportGenerationFailed"


def test_postmortem_artifact_is_written_and_referenced() -> None:
    store = _AuditStub()
    eid = uuid4()
    out_dir = Path(".") / ".pytest-postmortem-artifacts"

    try:
        normalized = _normalize_terminal_state(
            {
                "report_complete": False,
                "termination_reason": "runtime_budget_exceeded",
            }
        )
        artifact_path = _persist_postmortem_artifact(
            store,
            out_dir,
            eid,
            normalized,
        )
        assert artifact_path is not None
        assert Path(artifact_path).exists()

        _emit_terminal_lifecycle_events(
            store,
            eid,
            normalized,
            postmortem_artifact_path=artifact_path,
        )

        assert store.events[-1][0] == "ReportGenerationFailed"
        assert store.events[-1][1]["postmortem_artifact_path"] == artifact_path
    finally:
        artifact_file = out_dir / f"postmortem_{eid}.json"
        if artifact_file.exists():
            artifact_file.unlink()
        if out_dir.exists():
            out_dir.rmdir()
