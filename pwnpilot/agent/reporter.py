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

from pwnpilot.agent.state import AgentState

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
    ) -> None:
        self._generator = report_generator
        self._audit = audit_store
        self._output_dir = output_dir

    def __call__(self, state: AgentState) -> AgentState:
        engagement_id = UUID(state["engagement_id"])
        _t0 = time.monotonic()
        _input_hash = hashlib.sha256(
            json.dumps(state, default=str, sort_keys=True).encode()
        ).hexdigest()

        log.info("reporter.building_report", engagement_id=str(engagement_id))

        try:
            bundle_path, summary_path = self._generator.build_bundle(
                engagement_id=engagement_id,
                output_dir=self._output_dir,
            )
        except Exception as exc:
            log.error("reporter.build_failed", exc=str(exc))
            return {**state, "error": f"Report generation failed: {exc}"}

        self._audit_event(
            state,
            "ReportGenerated",
            {
                "engagement_id": str(engagement_id),
                "bundle_path": str(bundle_path),
                "summary_path": str(summary_path),
            },
        )

        log.info(
            "reporter.complete",
            bundle=str(bundle_path),
            summary=str(summary_path),
        )

        output = {**state, "report_complete": True}
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
