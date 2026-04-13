"""
Quality benchmark gate: No-silent-stop behavior.

Validates that the agent never stops silently:
  - kill_switch triggers produce an audit event
  - report finalization failure produces a visible artifact
  - The completion_state field reflects the actual terminal state
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4


class TestNoSilentStopGate:
    """Pass/fail gates for no-silent-stop behavior."""

    def test_kill_switch_produces_audit_event(self) -> None:
        """A kill switch trigger must produce an audit event, not silently abort."""
        from pwnpilot.governance.kill_switch import KillSwitch

        events_logged: list[str] = []

        def _audit_fn(reason: str) -> None:
            events_logged.append(reason)

        ks = KillSwitch(audit_fn=_audit_fn)
        ks.trigger("manual operator stop")

        assert len(events_logged) == 1
        assert "manual operator stop" in events_logged[0]

    def test_reporter_completion_state_on_success(self, tmp_path: Path) -> None:
        """On successful report generation, completion_state must be 'finalized'."""
        from pwnpilot.agent.reporter import ReporterNode

        fake_gen = MagicMock()
        fake_gen.build_bundle.return_value = (
            tmp_path / "bundle.json",
            tmp_path / "summary.md",
        )
        fake_audit = MagicMock()
        fake_audit.append.return_value = None

        reporter = ReporterNode(
            report_generator=fake_gen,
            audit_store=fake_audit,
            output_dir=tmp_path,
        )
        state = {
            "engagement_id": str(uuid4()),
            "iteration_count": 1,
            "nonproductive_cycle_streak": 0,
            "previous_actions": [],
            "recon_summary": {},
            "kill_switch": False,
        }
        result = reporter(state)
        assert result["completion_state"] == "finalized"
        assert result.get("report_complete") is True

    def test_reporter_completion_state_on_failure(self, tmp_path: Path) -> None:
        """On failed report generation, completion_state must be 'failed', not missing."""
        from pwnpilot.agent.reporter import ReporterNode

        fake_gen = MagicMock()
        fake_gen.build_bundle.side_effect = RuntimeError("storage unavailable")
        fake_audit = MagicMock()
        fake_event_bus = MagicMock()

        reporter = ReporterNode(
            report_generator=fake_gen,
            audit_store=fake_audit,
            output_dir=tmp_path,
            event_bus=fake_event_bus,
        )
        state = {
            "engagement_id": str(uuid4()),
            "iteration_count": 1,
            "nonproductive_cycle_streak": 0,
            "previous_actions": [],
            "recon_summary": {},
            "kill_switch": False,
        }
        result = reporter(state)
        # Must explicitly surface failure — not leave completion_state as PENDING
        assert result["completion_state"] == "failed"
        assert result.get("finalization_failed") is True
        assert "storage unavailable" in result.get("finalization_failure_reason", "")

    def test_export_bundle_surfaces_report_failure(self) -> None:
        """ExportService must include finalization status in its output."""
        from pwnpilot.services.export_service import ExportService

        eid = uuid4()
        audit = MagicMock()
        audit.events_for_engagement.return_value = [
            {"event_type": "ReportFinalizationFailed", "payload": {"reason": "out of disk"}},
        ]
        audit.execution_events_for_engagement.return_value = []
        decision_store = MagicMock()
        decision_store.decisions_for_engagement.return_value = []

        svc = ExportService(audit_store=audit, operator_decision_store=decision_store)
        bundle = svc.build_dict(eid)

        # Bundle must include audit trail with the failure event
        assert any(
            e.get("event_type") == "ReportFinalizationFailed"
            for e in bundle.get("audit_trail", [])
        )

    def test_state_completion_state_initialized_as_pending(self) -> None:
        """make_initial_state must start with completion_state = PENDING."""
        from pwnpilot.agent.state import make_initial_state, CompletionState

        state = make_initial_state(
            engagement_id=str(uuid4()),
        )
        assert state["completion_state"] == CompletionState.PENDING.value
