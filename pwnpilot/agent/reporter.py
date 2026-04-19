"""
Reporter Agent — summarises findings, generates report bundle, and signs the output.

Triggered by:
  - max_iterations reached
  - 3 consecutive cycles with no new findings (convergence)
  - Explicit operator command

Reads from AgentState:
  engagement_id

Writes to AgentState:
  report_complete = True
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog

from pwnpilot.agent.state import AgentState, CompletionState
from pwnpilot.observability.tracing import tracer
from pwnpilot.reporting.readiness_policy import ReportReadinessPolicy
from pwnpilot.reporting.run_health import evaluate_run_health

log = structlog.get_logger(__name__)


class ReporterNode:
    """
    Stateless callable used as a LangGraph reporter node.

    *report_generator* and *audit_store* are injected at construction.
    """

    def __init__(
        self,
        report_generator: Any,
        audit_store: Any,
        output_dir: Path,
        readiness_policy: ReportReadinessPolicy | None = None,
        event_bus: Any | None = None,
    ) -> None:
        self._generator = report_generator
        self._audit = audit_store
        self._output_dir = output_dir
        self._readiness_policy = readiness_policy or ReportReadinessPolicy()
        self._event_bus = event_bus

    def __call__(self, state: AgentState) -> AgentState:
        engagement_id = UUID(state["engagement_id"])
        _t0 = time.monotonic()
        _input_hash = hashlib.sha256(
            json.dumps(state, default=str, sort_keys=True).encode()
        ).hexdigest()

        log.info("reporter.building_report", engagement_id=str(engagement_id))

        readiness = self._readiness_policy.evaluate(state)
        health = evaluate_run_health(state, readiness)

        run_metadata = {
            "run_verdict": health["run_verdict"],
            "readiness_gate_results": readiness,
            "degradation_reasons": health["degradation_reasons"],
            "termination_reason": health["termination_reason"],
            "assessment_objectives": list(state.get("assessment_objectives", []) or []),
            "objective_progress": dict(state.get("objective_progress", {}) or {}),
            "depth_metrics": dict(state.get("depth_metrics", {}) or {}),
        }

        try:
            with tracer.span(
                "reporter.build_bundle",
                engagement_id=str(engagement_id),
            ) as _span:
                bundle_path, summary_path = self._generator.build_bundle(
                    engagement_id=engagement_id,
                    output_dir=self._output_dir,
                                    run_metadata=run_metadata,
                )
                _span.set_attribute("bundle_path", str(bundle_path))
        except Exception as exc:
            log.error("reporter.build_failed", exc=str(exc))
            self._emit_finalization_failed(state, str(exc))
            self._record_finalization_metric(state, success=False)
            return {
                **state,
                "error": f"Report generation failed: {exc}",
                "completion_state": CompletionState.FAILED.value,
                "finalization_failed": True,
                "finalization_failure_reason": str(exc),
            }

        self._record_finalization_metric(state, success=True)

        self._audit_event(
            state,
            "ReportGenerated",
            {
                "engagement_id": str(engagement_id),
                "bundle_path": str(bundle_path),
                "summary_path": str(summary_path),
                                "run_verdict": run_metadata["run_verdict"],
                                "termination_reason": run_metadata["termination_reason"],
            },
        )

        log.info(
            "reporter.complete",
            bundle=str(bundle_path),
            summary=str(summary_path),
        )

        output = {
            **state,
            "report_complete": True,
            "report_bundle_path": str(bundle_path),
            "report_summary_path": str(summary_path),
            "run_verdict": run_metadata["run_verdict"],
            "readiness_gate_results": run_metadata["readiness_gate_results"],
            "degradation_reasons": run_metadata["degradation_reasons"],
            "termination_reason": run_metadata["termination_reason"],
            "completion_state": CompletionState.FINALIZED.value,
        }
        duration_ms = round((time.monotonic() - _t0) * 1000, 2)
        output_hash = hashlib.sha256(
            json.dumps(output, default=str, sort_keys=True).encode()
        ).hexdigest()
        self._audit_event(
            state,
            "AgentInvoked",
            {
                "agent_name": "reporter",
                "input_state_hash": _input_hash,
                "output_state_hash": output_hash,
                "llm_model_used": "none",
                "llm_routing_decision": "none",
                "duration_ms": duration_ms,
            },
        )
        return output

    def _audit_event(
        self, state: AgentState, event_type: str, payload: dict[str, Any]
    ) -> None:
        try:
            self._audit.append(
                engagement_id=UUID(state["engagement_id"]),
                actor="reporter",
                event_type=event_type,
                payload=payload,
            )
        except Exception as exc:
            log.error("reporter.audit_write_failed", exc=str(exc))

    def _record_finalization_metric(self, state: AgentState, success: bool) -> None:
        """Update run-quality metrics for report finalization."""
        try:
            from pwnpilot.observability.metrics import metrics_registry
            m = metrics_registry.get(str(state.get("engagement_id", "")))
            if m is not None:
                m.record_report_finalization(success)
        except Exception:
            pass

    def _emit_finalization_failed(self, state: AgentState, reason: str) -> None:
        """Emit a REPORT_FINALIZATION_FAILED execution event and audit record."""
        from pwnpilot.agent.event_bus import ExecutionEvent
        from pwnpilot.data.models import ExecutionEventType

        engagement_id = UUID(state["engagement_id"])
        self._audit_event(state, "ReportFinalizationFailed", {"reason": reason})

        if self._event_bus is not None:
            try:
                event = ExecutionEvent(
                    engagement_id=engagement_id,
                    event_type=ExecutionEventType.REPORT_FINALIZATION_FAILED,
                    actor="reporter",
                    payload={"reason": reason},
                )
                self._event_bus.publish(engagement_id, event)
            except Exception as exc:
                log.error("reporter.event_bus_failed", exc=str(exc))
