"""
Finding Store — deduplication, correlation, and severity scoring.

Deduplication fingerprint: SHA-256(asset_ref + vuln_ref + tool_name)
Severity scoring: CVSS_base * exposure_weight * confidence_weight * criticality_weight
Status lifecycle: NEW → CONFIRMED → REMEDIATED | FALSE_POSITIVE
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

import structlog
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Session

from pwnpilot.data.models import (
    Exploitability,
    Finding,
    FindingStatus,
    Severity,
)

log = structlog.get_logger(__name__)


class Base(DeclarativeBase):
    pass


class FindingRow(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(36), nullable=False, unique=True, index=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    asset_ref = Column(String(512), nullable=False)
    title = Column(String(512), nullable=False)
    vuln_ref = Column(String(256), nullable=False)
    tool_name = Column(String(128), nullable=False)
    severity = Column(String(32), nullable=False)
    confidence = Column(Float, nullable=False, default=0.5)
    exploitability = Column(String(32), nullable=False, default="none")
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(256), nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    evidence_ids_json = Column(Text, nullable=False, default="[]")
    remediation = Column(Text, nullable=False, default="")
    status = Column(String(32), nullable=False, default="new")
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("engagement_id", "fingerprint", name="uq_eng_fingerprint"),
    )


# Severity → CVSS-like base scores for risk score calculation
_SEVERITY_BASE: dict[str, float] = {
    "info": 0.0,
    "low": 2.0,
    "medium": 5.0,
    "high": 7.5,
    "critical": 9.5,
}

# Exploitability multipliers
_EXPLOIT_MULT: dict[str, float] = {
    "none": 0.5,
    "low": 0.7,
    "medium": 0.85,
    "high": 1.0,
    "functional": 1.1,
    "weaponized": 1.25,
}


def _compute_risk_score(
    severity: str,
    confidence: float,
    exploitability: str,
    cvss_score: float | None,
) -> float:
    """
    Risk score = (CVSS_base or severity_base) * exploit_mult * confidence
    Clamped to [0.0, 10.0].
    """
    base = cvss_score if cvss_score is not None else _SEVERITY_BASE.get(severity, 5.0)
    exploit = _EXPLOIT_MULT.get(exploitability, 1.0)
    score = base * exploit * confidence
    return min(10.0, max(0.0, round(score, 2)))


def _fingerprint(asset_ref: str, vuln_ref: str, tool_name: str) -> str:
    raw = f"{asset_ref}:{vuln_ref}:{tool_name}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _coerce_uuid_list(values: list[str] | None) -> list[UUID]:
    result: list[UUID] = []
    for value in values or []:
        try:
            result.append(UUID(str(value)))
        except (ValueError, TypeError, AttributeError):
            log.warning("finding.invalid_evidence_id", evidence_id=str(value))
    return result


class FindingStore:
    def __init__(self, session: Session) -> None:
        self._session = session
        Base.metadata.create_all(session.bind)  # type: ignore[arg-type]

    def upsert(
        self,
        engagement_id: UUID,
        asset_ref: str,
        title: str,
        vuln_ref: str,
        tool_name: str,
        severity: Severity,
        confidence: float = 0.5,
        exploitability: Exploitability = Exploitability.NONE,
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        evidence_ids: list[UUID] | None = None,
        remediation: str = "",
    ) -> Finding:
        """
        Insert or update a finding.  Returns the canonical Finding model.
        Deduplicates by fingerprint(asset_ref + vuln_ref + tool_name).
        """
        fp = _fingerprint(asset_ref, vuln_ref, tool_name)
        risk = _compute_risk_score(severity.value, confidence, exploitability.value, cvss_score)
        now = datetime.now(timezone.utc)
        ev_ids = [str(e) for e in (evidence_ids or [])]

        existing = (
            self._session.query(FindingRow)
            .filter(
                FindingRow.engagement_id == str(engagement_id),
                FindingRow.fingerprint == fp,
            )
            .first()
        )

        if existing:
            # Merge evidence IDs (dedup)
            stored_ev = json.loads(existing.evidence_ids_json)
            merged = list(dict.fromkeys(stored_ev + ev_ids))
            existing.evidence_ids_json = json.dumps(merged)
            existing.confidence = max(existing.confidence, confidence)
            existing.risk_score = risk
            existing.updated_at = now
            self._session.commit()
            finding_id = UUID(existing.finding_id)
        else:
            finding_id = uuid4()
            row = FindingRow(
                finding_id=str(finding_id),
                engagement_id=str(engagement_id),
                fingerprint=fp,
                asset_ref=asset_ref,
                title=title,
                vuln_ref=vuln_ref,
                tool_name=tool_name,
                severity=severity.value,
                confidence=confidence,
                exploitability=exploitability.value,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                risk_score=risk,
                evidence_ids_json=json.dumps(ev_ids),
                remediation=remediation,
                status=FindingStatus.NEW.value,
                created_at=now,
                updated_at=now,
            )
            self._session.add(row)
            self._session.commit()
            log.info("finding.created", finding_id=str(finding_id), vuln_ref=vuln_ref)

        return Finding(
            finding_id=finding_id,
            engagement_id=engagement_id,
            asset_ref=asset_ref,
            title=title,
            vuln_ref=vuln_ref,
            severity=severity,
            confidence=confidence,
            exploitability=exploitability,
            cvss_vector=cvss_vector,
            evidence_ids=_coerce_uuid_list(ev_ids),
            remediation=remediation,
        )

    def findings_for_engagement(self, engagement_id: UUID) -> list[Finding]:
        rows = (
            self._session.query(FindingRow)
            .filter(FindingRow.engagement_id == str(engagement_id))
            .order_by(FindingRow.risk_score.desc())
            .all()
        )
        result = []
        for r in rows:
            try:
                stored_evidence = json.loads(r.evidence_ids_json)
            except (TypeError, ValueError, json.JSONDecodeError):
                stored_evidence = []
            ev_ids = _coerce_uuid_list(stored_evidence)
            result.append(
                Finding(
                    finding_id=UUID(r.finding_id),
                    engagement_id=UUID(r.engagement_id),
                    asset_ref=r.asset_ref,
                    title=r.title,
                    vuln_ref=r.vuln_ref,
                    severity=Severity(r.severity),
                    confidence=r.confidence,
                    exploitability=Exploitability(r.exploitability),
                    cvss_vector=r.cvss_vector,
                    evidence_ids=ev_ids,
                    remediation=r.remediation,
                    status=FindingStatus(r.status),
                )
            )
        return result

    def update_status(self, finding_id: UUID, status: FindingStatus) -> None:
        row = (
            self._session.query(FindingRow)
            .filter(FindingRow.finding_id == str(finding_id))
            .first()
        )
        if row:
            row.status = status.value
            row.updated_at = datetime.now(timezone.utc)
            self._session.commit()

    def get_summary(self, engagement_id: UUID) -> dict:
        """
        Return findings aggregated by severity and status for planner context.
        Provides rich context for LLM decision-making.
        """
        findings = self.findings_for_engagement(engagement_id)
        
        # Aggregate by severity
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_status = {"new": 0, "confirmed": 0, "remediated": 0, "false_positive": 0}
        
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            if sev in by_severity:
                by_severity[sev] += 1
            
            status = f.status.value if hasattr(f.status, 'value') else str(f.status)
            if status in by_status:
                by_status[status] += 1
        
        # Get top high-risk findings
        high_risk = [f for f in findings if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)) in ["critical", "high"]]
        top_findings = high_risk[:5]
        
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_status": by_status,
            "top_findings": [
                {
                    "finding_id": str(f.finding_id),
                    "title": f.title,
                    "asset_ref": f.asset_ref,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "confidence": f.confidence,
                    "risk_score": _compute_risk_score(
                        f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        f.confidence,
                        f.exploitability.value if hasattr(f.exploitability, 'value') else str(f.exploitability),
                        None,
                    ),
                    "status": f.status.value if hasattr(f.status, 'value') else str(f.status),
                    "tool_name": f.vuln_ref.split(":")[0] if ":" in f.vuln_ref else "unknown",
                }
                for f in top_findings
            ],
        }

    def mark_false_positive(self, finding_id: UUID, confidence: float = 0.9) -> None:
        """
        Mark a finding as a false positive.
        Reduces confidence and updates status to FALSE_POSITIVE.
        """
        row = (
            self._session.query(FindingRow)
            .filter(FindingRow.finding_id == str(finding_id))
            .first()
        )
        if row:
            row.status = FindingStatus.FALSE_POSITIVE.value
            row.confidence = min(row.confidence, 1.0 - confidence)  # Reduce confidence
            row.updated_at = datetime.now(timezone.utc)
            self._session.commit()
            log.info("finding.marked_false_positive", finding_id=str(finding_id))
