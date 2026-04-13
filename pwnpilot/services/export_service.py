"""
ExportService v2 — produces a complete audit export bundle for an engagement.

Bundle contents:
  - Engagement metadata
  - Event timeline (from AuditStore ExecutionEvents)
  - Operator decisions (ROE approval, runtime approvals, policy exceptions)
  - Audit chain summary
  - Report metadata (verdict, health, finalization status)

Usage::

    svc = ExportService(audit_store, operator_decision_store)
    path = svc.export(engagement_id, output_path=Path("roe-audit-abc123.json"))
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog

log = structlog.get_logger(__name__)

_DEFAULT_EXPORT_FILENAME_TEMPLATE = "roe-audit-{engagement_id}.json"


class ExportService:
    """
    Produces a JSON audit export bundle for a completed engagement.

    All stores are read-only; export never modifies persistent state.
    """

    def __init__(self, audit_store: Any, operator_decision_store: Any) -> None:
        self._audit = audit_store
        self._decisions = operator_decision_store

    def export(
        self,
        engagement_id: UUID,
        output_path: Path | None = None,
    ) -> Path:
        """
        Write the audit export bundle to *output_path* (or a default path).

        Returns the path of the written file.
        """
        if output_path is None:
            output_path = Path(
                _DEFAULT_EXPORT_FILENAME_TEMPLATE.format(engagement_id=engagement_id)
            )

        bundle = self._build_bundle(engagement_id)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(bundle, indent=2, default=str))

        log.info(
            "export.written",
            engagement_id=str(engagement_id),
            path=str(output_path),
            events=len(bundle.get("audit_trail", [])),
            decisions=len(bundle.get("operator_decisions", [])),
        )
        return output_path

    def build_dict(self, engagement_id: UUID) -> dict[str, Any]:
        """Return the export bundle as a plain dict (no file I/O)."""
        return self._build_bundle(engagement_id)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _build_bundle(self, engagement_id: UUID) -> dict[str, Any]:
        audit_trail = self._load_audit_trail(engagement_id)
        event_timeline = self._load_event_timeline(engagement_id)
        operator_decisions = self._load_decisions(engagement_id)
        report_metadata = self._extract_report_metadata(audit_trail)
        trace_summary = self._load_trace_summary(engagement_id)

        return {
            "engagement_id": str(engagement_id),
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "audit_trail": audit_trail,
            "event_timeline": event_timeline,
            "operator_decisions": operator_decisions,
            "report_metadata": report_metadata,
            "trace_summary": trace_summary,
            "schema_version": "v2",
        }

    def _load_audit_trail(self, engagement_id: UUID) -> list[dict[str, Any]]:
        try:
            return list(self._audit.events_for_engagement(engagement_id))
        except Exception as exc:
            log.error("export.audit_load_failed", error=str(exc))
            return []

    def _load_event_timeline(self, engagement_id: UUID) -> list[dict[str, Any]]:
        try:
            return list(self._audit.execution_events_for_engagement(engagement_id))
        except Exception as exc:
            log.error("export.event_load_failed", error=str(exc))
            return []

    def _load_decisions(self, engagement_id: UUID) -> list[dict[str, Any]]:
        try:
            return [
                d.model_dump(mode="json")
                for d in self._decisions.decisions_for_engagement(engagement_id)
            ]
        except Exception as exc:
            log.error("export.decision_load_failed", error=str(exc))
            return []

    @staticmethod
    def _extract_report_metadata(audit_trail: list[dict[str, Any]]) -> dict[str, Any]:
        for event in reversed(audit_trail):
            if event.get("event_type") == "ReportGenerated":
                return event.get("payload", {})
        return {}

    @staticmethod
    def _load_trace_summary(engagement_id: UUID) -> list[dict[str, Any]]:
        """Return finished trace spans for this engagement."""
        try:
            from pwnpilot.observability.tracing import tracer
            return tracer.export(engagement_id=str(engagement_id))
        except Exception as exc:
            log.error("export.trace_load_failed", error=str(exc))
            return []
