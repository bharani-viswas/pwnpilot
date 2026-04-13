from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.agent.reporter import ReporterNode
from pwnpilot.data.audit_store import AuditStore
from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.data.finding_store import FindingStore
from pwnpilot.data.recon_store import ReconStore
from pwnpilot.reporting.generator import ReportGenerator


def _session():
    engine = create_engine("sqlite:///:memory:")
    return sessionmaker(bind=engine)()


def test_report_bundle_contains_run_metadata_fields(tmp_path: Path) -> None:
    session = _session()
    eng_id = uuid4()

    generator = ReportGenerator(
        finding_store=FindingStore(session),
        recon_store=ReconStore(session),
        evidence_store=EvidenceStore(base_dir=tmp_path / "ev", session=session),
        audit_store=AuditStore(session),
    )
    reporter = ReporterNode(
        report_generator=generator,
        audit_store=AuditStore(session),
        output_dir=tmp_path,
    )

    state = {
        "engagement_id": str(eng_id),
        "previous_actions": [
            {
                "tool_name": "nmap",
                "outcome_status": "failed",
                "failure_reasons": ["TargetUnreachable"],
            }
        ],
        "evidence_ids": [],
        "termination_reason": "stalled_nonproductive_loop",
    }

    result = reporter(state)

    assert result["report_complete"] is True
    assert result["run_verdict"] in {"completed", "completed_with_degradation", "failed"}
    assert "readiness_gate_results" in result
    assert "degradation_reasons" in result
    assert result["termination_reason"] == "stalled_nonproductive_loop"
