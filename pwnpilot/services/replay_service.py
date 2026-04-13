"""
ReplayService v2 — reconstructs a ReplaySnapshot for a completed engagement.

Aggregates:
  - Execution event timeline (from AuditStore)
  - Operator decisions (from OperatorDecisionStore)
  - Planner rejection events (from AuditStore)
  - Run-level metadata (from AuditStore ReportGenerated event)

Usage::

    svc = ReplayService(audit_store, operator_decision_store)
    snapshot = svc.build_snapshot(engagement_id)
    print(snapshot.model_dump_json(indent=2))
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog

from pwnpilot.data.models import ReplaySnapshot

log = structlog.get_logger(__name__)


class ReplayService:
    """
    Builds deterministic ReplaySnapshot objects from persisted stores.

    Both stores are required; the replay service is intentionally read-only
    and does not modify any persistent state.
    """

    def __init__(self, audit_store: Any, operator_decision_store: Any) -> None:
        self._audit = audit_store
        self._decisions = operator_decision_store

    def build_snapshot(self, engagement_id: UUID) -> ReplaySnapshot:
        """
        Reconstruct a full ReplaySnapshot for *engagement_id*.

        Returns a frozen v2 ReplaySnapshot with:
          - event_timeline: all ExecutionEvents in order
          - operator_decisions: all OperatorDecision records
          - planner_rejections: audit events where event_type == 'PlanRejected'
          - run_metadata: extracted from 'ReportGenerated' audit event (if present)
        """
        event_timeline = self._load_event_timeline(engagement_id)
        operator_decisions = self._load_decisions(engagement_id)
        planner_rejections = self._load_planner_rejections(engagement_id)
        run_metadata = self._extract_run_metadata(engagement_id)
        trace_spans = self._load_trace_spans(engagement_id)

        snapshot = ReplaySnapshot(
            engagement_id=engagement_id,
            event_timeline=event_timeline,
            operator_decisions=operator_decisions,
            planner_rejections=planner_rejections,
            run_metadata={**run_metadata, "trace_spans": trace_spans},
        )

        log.info(
            "replay.snapshot_built",
            engagement_id=str(engagement_id),
            events=len(event_timeline),
            decisions=len(operator_decisions),
            rejections=len(planner_rejections),
            trace_spans=len(trace_spans),
        )
        return snapshot

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_event_timeline(self, engagement_id: UUID) -> list[dict[str, Any]]:
        try:
            return list(self._audit.execution_events_for_engagement(engagement_id))
        except Exception as exc:
            log.error("replay.event_load_failed", error=str(exc))
            return []

    def _load_decisions(self, engagement_id: UUID) -> list[dict[str, Any]]:
        try:
            return [
                d.model_dump(mode="json")
                for d in self._decisions.decisions_for_engagement(engagement_id)
            ]
        except Exception as exc:
            log.error("replay.decision_load_failed", error=str(exc))
            return []

    def _load_planner_rejections(self, engagement_id: UUID) -> list[dict[str, Any]]:
        try:
            all_events = self._audit.events_for_engagement(engagement_id)
            return [
                e for e in all_events if e.get("event_type") == "PlanRejected"
            ]
        except Exception as exc:
            log.error("replay.rejection_load_failed", error=str(exc))
            return []

    def _extract_run_metadata(self, engagement_id: UUID) -> dict[str, Any]:
        try:
            all_events = self._audit.events_for_engagement(engagement_id)
            for event in reversed(all_events):
                if event.get("event_type") == "ReportGenerated":
                    return event.get("payload", {})
        except Exception as exc:
            log.error("replay.metadata_load_failed", error=str(exc))
        return {}

    @staticmethod
    def _load_trace_spans(engagement_id: UUID) -> list[dict[str, Any]]:
        """Return finished trace spans for this engagement."""
        try:
            from pwnpilot.observability.tracing import tracer
            return tracer.export(engagement_id=str(engagement_id))
        except Exception as exc:
            log.error("replay.trace_load_failed", error=str(exc))
            return []
