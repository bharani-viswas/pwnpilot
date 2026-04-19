from __future__ import annotations

from pathlib import Path
import json
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.agent.reporter import ReporterNode
from pwnpilot.data.audit_store import AuditStore
from pwnpilot.data.correlation import CorrelationEngine
from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.data.finding_store import FindingStore
from pwnpilot.data.models import Severity
from pwnpilot.data.recon_store import ReconStore
from pwnpilot.reporting.generator import ReportGenerator
from pwnpilot.reporting.run_health import evaluate_run_health


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


def test_run_health_fails_when_unresolved_objectives_have_terminal_failures() -> None:
    health = evaluate_run_health(
        {
            "assessment_objectives": [
                {"objective_class": "headers", "status": "in_progress", "asset_ref": "http://localhost:3000"}
            ],
            "previous_actions": [
                {
                    "tool_name": "zap",
                    "outcome_status": "failed",
                    "failure_reasons": ["NoActionableOutput"],
                }
            ],
            "termination_reason": "stalled_nonproductive_loop",
        },
        {
            "status": "completed",
            "failed_gates": [],
            "metrics": {"critical_tool_failures": 1},
        },
    )

    assert health["run_verdict"] == "failed"
    assert "unresolved_objectives:1" in health["degradation_reasons"]
    assert "critical_tool_failures:1" in health["degradation_reasons"]


def test_run_health_degrades_when_objectives_are_left_open_without_terminal_failures() -> None:
    health = evaluate_run_health(
        {
            "objective_progress": {
                "total": 2,
                "open": 1,
                "in_progress": 0,
                "confirmed": 1,
                "disproved": 0,
            },
            "previous_actions": [],
            "termination_reason": None,
        },
        {
            "status": "completed",
            "failed_gates": [],
            "metrics": {"critical_tool_failures": 0},
        },
    )

    assert health["run_verdict"] == "completed_with_degradation"
    assert health["termination_reason"] is None
    assert health["objective_health"]["open"] == 1


def test_report_reconciles_finding_statuses_from_confirmed_objectives(tmp_path: Path) -> None:
    session = _session()
    eng_id = uuid4()

    finding_store = FindingStore(session)
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000",
        title="Content Security Policy (CSP) Header Not Set",
        vuln_ref="ZAP-10038",
        tool_name="zap",
        severity=Severity.MEDIUM,
    )
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000",
        title="Possible SQL injection",
        vuln_ref="sqli-test",
        tool_name="sqlmap",
        severity=Severity.MEDIUM,
    )

    generator = ReportGenerator(
        finding_store=finding_store,
        recon_store=ReconStore(session),
        evidence_store=EvidenceStore(base_dir=tmp_path / "ev", session=session),
        audit_store=AuditStore(session),
    )

    bundle_path, _ = generator.build_bundle(
        engagement_id=eng_id,
        output_dir=tmp_path,
        run_metadata={
            "assessment_objectives": [
                {
                    "objective_class": "headers",
                    "asset_ref": "http://localhost:3000",
                    "status": "confirmed",
                    "title": "Follow-up for headers",
                }
            ]
        },
    )

    bundle = json.loads(bundle_path.read_text())
    statuses = {entry["title"]: entry["status"] for entry in bundle["findings"]}

    assert statuses["Content Security Policy (CSP) Header Not Set"] == "confirmed"
    assert statuses["Possible SQL injection"] == "new"


def test_report_reconciles_generic_objective_when_title_corroborates_finding(tmp_path: Path) -> None:
    session = _session()
    eng_id = uuid4()

    finding_store = FindingStore(session)
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000/metrics",
        title="Prometheus Metrics - Detect",
        vuln_ref="cwe-200",
        tool_name="nuclei",
        severity=Severity.MEDIUM,
    )

    generator = ReportGenerator(
        finding_store=finding_store,
        recon_store=ReconStore(session),
        evidence_store=EvidenceStore(base_dir=tmp_path / "ev", session=session),
        audit_store=AuditStore(session),
    )

    bundle_path, summary_path = generator.build_bundle(
        engagement_id=eng_id,
        output_dir=tmp_path,
        run_metadata={
            "assessment_objectives": [
                {
                    "objective_class": "generic",
                    "asset_ref": "http://localhost:3000/metrics",
                    "status": "confirmed",
                    "title": "Validated exposed Prometheus metrics on target asset",
                }
            ]
        },
    )

    bundle = json.loads(bundle_path.read_text())
    assert bundle["findings"][0]["status"] == "confirmed"
    assert (
        bundle["finding_status_reconciliation"][bundle["findings"][0]["finding_id"]]["reason"]
        == "confirmed_by_corroborated_generic_objective"
    )
    assert "Status Rationale:" in summary_path.read_text()


def test_report_rollup_counts_match_reconciled_statuses(tmp_path: Path) -> None:
    session = _session()
    eng_id = uuid4()

    finding_store = FindingStore(session)
    recon_store = ReconStore(session)
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000",
        title="Content Security Policy (CSP) Header Not Set",
        vuln_ref="ZAP-10038",
        tool_name="zap",
        severity=Severity.MEDIUM,
    )
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000/login",
        title="Possible SQL injection",
        vuln_ref="sqli-test",
        tool_name="sqlmap",
        severity=Severity.MEDIUM,
    )

    generator = ReportGenerator(
        finding_store=finding_store,
        recon_store=recon_store,
        evidence_store=EvidenceStore(base_dir=tmp_path / "ev", session=session),
        audit_store=AuditStore(session),
        correlation_engine=CorrelationEngine(finding_store, recon_store),
    )

    bundle_path, _ = generator.build_bundle(
        engagement_id=eng_id,
        output_dir=tmp_path,
        run_metadata={
            "assessment_objectives": [
                {
                    "objective_class": "headers",
                    "asset_ref": "http://localhost:3000",
                    "status": "confirmed",
                    "title": "Follow-up for headers",
                }
            ]
        },
    )

    bundle = json.loads(bundle_path.read_text())
    findings = bundle["findings"]
    rollup = bundle["risk_rollup"]

    expected_new = sum(1 for finding in findings if finding.get("status") == "new")
    expected_confirmed = sum(1 for finding in findings if finding.get("status") == "confirmed")

    assert rollup["unconfirmed_findings"] == expected_new
    assert rollup["confirmed_findings"] == expected_confirmed


def test_report_leaves_generic_objective_unreconciled_without_corroboration(tmp_path: Path) -> None:
    session = _session()
    eng_id = uuid4()

    finding_store = FindingStore(session)
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000",
        title="Content Security Policy (CSP) Header Not Set",
        vuln_ref="ZAP-10038",
        tool_name="zap",
        severity=Severity.MEDIUM,
    )

    generator = ReportGenerator(
        finding_store=finding_store,
        recon_store=ReconStore(session),
        evidence_store=EvidenceStore(base_dir=tmp_path / "ev", session=session),
        audit_store=AuditStore(session),
    )

    bundle_path, _ = generator.build_bundle(
        engagement_id=eng_id,
        output_dir=tmp_path,
        run_metadata={
            "assessment_objectives": [
                {
                    "objective_class": "generic",
                    "asset_ref": "http://localhost:3000",
                    "status": "confirmed",
                    "title": "Validated follow-up behavior on root endpoint",
                }
            ]
        },
    )

    bundle = json.loads(bundle_path.read_text())
    assert bundle["findings"][0]["status"] == "new"
    assert (
        bundle["finding_status_reconciliation"][bundle["findings"][0]["finding_id"]]["reason"]
        == "generic_objective_requires_corroboration"
    )


def test_report_markdown_is_descriptive_for_findings(tmp_path: Path) -> None:
    session = _session()
    eng_id = uuid4()

    finding_store = FindingStore(session)
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000/metrics",
        title="Prometheus Metrics - Detect",
        vuln_ref="cwe-200",
        tool_name="nuclei",
        severity=Severity.MEDIUM,
    )

    generator = ReportGenerator(
        finding_store=finding_store,
        recon_store=ReconStore(session),
        evidence_store=EvidenceStore(base_dir=tmp_path / "ev", session=session),
        audit_store=AuditStore(session),
    )

    _, summary_path = generator.build_bundle(
        engagement_id=eng_id,
        output_dir=tmp_path,
    )

    summary = summary_path.read_text()
    assert "Issue Description:" in summary
    assert "How It Can Be Exploited:" in summary
    assert "Proof of Exploitation Performed:" in summary
    assert "Evidence Artifacts:" in summary


def test_report_markdown_uses_finding_specific_zap_proof(tmp_path: Path) -> None:
    session = _session()
    eng_id = uuid4()

    finding_store = FindingStore(session)
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000",
        title="Missing Anti-clickjacking Header",
        vuln_ref="ZAP-10020",
        tool_name="zap",
        severity=Severity.MEDIUM,
    )
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000",
        title="X-Content-Type-Options Header Missing",
        vuln_ref="ZAP-10021",
        tool_name="zap",
        severity=Severity.MEDIUM,
    )

    audit_store = AuditStore(session)
    audit_store.append(
        engagement_id=eng_id,
        actor="runner",
        event_type="tool.output_chunk",
        payload={
            "tool_name": "zap",
            "target": "http://localhost:3000",
            "data": "\n".join(
                [
                    "WARN-NEW: Missing Anti-clickjacking Header [10020] x 1",
                    "\thttp://localhost:3000\t",
                    "WARN-NEW: X-Content-Type-Options Header Missing [10021] x 1",
                    "\thttp://localhost:3000\t",
                ]
            ),
        },
    )

    generator = ReportGenerator(
        finding_store=finding_store,
        recon_store=ReconStore(session),
        evidence_store=EvidenceStore(base_dir=tmp_path / "ev", session=session),
        audit_store=audit_store,
    )

    _, summary_path = generator.build_bundle(engagement_id=eng_id, output_dir=tmp_path)

    summary = summary_path.read_text()
    assert "WARN-NEW: Missing Anti-clickjacking Header [10020] x 1" in summary
    assert "WARN-NEW: X-Content-Type-Options Header Missing [10021] x 1" in summary


def test_report_markdown_uses_structured_nuclei_proof(tmp_path: Path) -> None:
    session = _session()
    eng_id = uuid4()

    finding_store = FindingStore(session)
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000/metrics",
        title="Prometheus Metrics - Detect",
        vuln_ref="cwe-200",
        tool_name="nuclei",
        severity=Severity.MEDIUM,
    )

    audit_store = AuditStore(session)
    audit_store.append(
        engagement_id=eng_id,
        actor="runner",
        event_type="tool.output_chunk",
        payload={
            "tool_name": "nuclei",
            "target": "http://localhost:3000/metrics",
            "data": json.dumps(
                {
                    "template-id": "prometheus-metrics",
                    "matched-at": "http://localhost:3000/metrics",
                    "curl-command": "curl -i http://localhost:3000/metrics",
                    "info": {
                        "name": "Prometheus Metrics - Detect",
                        "classification": {"cwe-id": ["cwe-200"]},
                    },
                }
            ),
        },
    )

    generator = ReportGenerator(
        finding_store=finding_store,
        recon_store=ReconStore(session),
        evidence_store=EvidenceStore(base_dir=tmp_path / "ev", session=session),
        audit_store=audit_store,
    )

    _, summary_path = generator.build_bundle(engagement_id=eng_id, output_dir=tmp_path)

    summary = summary_path.read_text()
    assert "Template matched: Prometheus Metrics - Detect" in summary
    assert "Matched at: http://localhost:3000/metrics" in summary
    assert "Validation request: curl -i http://localhost:3000/metrics" in summary


def test_report_bundle_includes_finding_evidence_backlinks(tmp_path: Path) -> None:
    session = _session()
    eng_id = uuid4()

    evidence_store = EvidenceStore(base_dir=tmp_path / "ev", session=session)
    evidence = evidence_store.write_bytes(engagement_id=eng_id, action_id=uuid4(), data=b"proof")

    finding_store = FindingStore(session)
    finding_store.upsert(
        engagement_id=eng_id,
        asset_ref="http://localhost:3000/metrics",
        title="Prometheus Metrics - Detect",
        vuln_ref="cwe-200",
        tool_name="nuclei",
        severity=Severity.MEDIUM,
        evidence_ids=[evidence.evidence_id],
    )

    generator = ReportGenerator(
        finding_store=finding_store,
        recon_store=ReconStore(session),
        evidence_store=evidence_store,
        audit_store=AuditStore(session),
    )

    bundle_path, summary_path = generator.build_bundle(engagement_id=eng_id, output_dir=tmp_path)

    bundle = json.loads(bundle_path.read_text())
    assert bundle["findings"][0]["evidence_ids"] == [str(evidence.evidence_id)]
    assert str(evidence.evidence_id) in summary_path.read_text()
