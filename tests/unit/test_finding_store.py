from __future__ import annotations

from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.data.finding_store import FindingRow, FindingStore
from pwnpilot.data.models import Exploitability, FindingStatus, Severity


def _store() -> FindingStore:
    engine = create_engine("sqlite:///:memory:")
    session = sessionmaker(bind=engine)()
    return FindingStore(session)


def test_upsert_deduplicates_and_merges_evidence_ids() -> None:
    store = _store()
    engagement_id = uuid4()
    ev1 = uuid4()
    ev2 = uuid4()

    first = store.upsert(
        engagement_id=engagement_id,
        asset_ref="http://localhost:3000",
        title="Test finding",
        vuln_ref="test-ref",
        tool_name="zap",
        severity=Severity.MEDIUM,
        evidence_ids=[ev1],
    )
    second = store.upsert(
        engagement_id=engagement_id,
        asset_ref="http://localhost:3000",
        title="Test finding",
        vuln_ref="test-ref",
        tool_name="zap",
        severity=Severity.HIGH,
        confidence=0.8,
        evidence_ids=[ev1, ev2],
        exploitability=Exploitability.HIGH,
    )

    assert first.finding_id == second.finding_id
    findings = store.findings_for_engagement(engagement_id)
    assert len(findings) == 1
    assert set(findings[0].evidence_ids) == {ev1, ev2}


def test_findings_for_engagement_ignores_bad_evidence_uuid_strings() -> None:
    store = _store()
    engagement_id = uuid4()

    finding = store.upsert(
        engagement_id=engagement_id,
        asset_ref="http://localhost:3000",
        title="Malformed evidence handling",
        vuln_ref="test-ref-2",
        tool_name="nuclei",
        severity=Severity.MEDIUM,
        evidence_ids=[uuid4()],
    )

    row = store._session.query(FindingRow).filter_by(finding_id=str(finding.finding_id)).first()
    row.evidence_ids_json = '["not-a-uuid", "also-bad"]'
    store._session.commit()

    findings = store.findings_for_engagement(engagement_id)
    assert len(findings) == 1
    assert findings[0].evidence_ids == []


def test_status_updates_and_summary_counts() -> None:
    store = _store()
    engagement_id = uuid4()

    finding = store.upsert(
        engagement_id=engagement_id,
        asset_ref="http://localhost:3000/metrics",
        title="Prometheus Metrics - Detect",
        vuln_ref="cwe-200",
        tool_name="nuclei",
        severity=Severity.HIGH,
    )

    store.update_status(finding.finding_id, FindingStatus.CONFIRMED)

    summary = store.get_summary(engagement_id)
    assert summary["total_findings"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["by_status"]["confirmed"] == 1
    assert summary["top_findings"][0]["title"] == "Prometheus Metrics - Detect"
