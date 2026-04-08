"""
Correlation Engine — cross-tool finding enrichment and risk roll-up.

Responsibilities:
1. Deduplicate findings produced by different tools for the same
   (asset_ref, vuln_ref) pair — reused by FindingStore's upsert but also
   available as a standalone batch pass.
2. Correlate searchsploit exploit records to vulnerability findings: if a
   finding has a CVE reference and searchsploit returned exploit entries for
   that CVE, escalate the exploitability score and attach the exploit path.
3. Compute an engagement-level risk roll-up: return a summary dict with
   severity distribution, top-5 highest-scored findings, tool coverage, and
   an overall risk rating (low / medium / high / critical).

Usage::

    from pwnpilot.data.correlation import CorrelationEngine

    engine = CorrelationEngine(finding_store, recon_store)
    engine.correlate(engagement_id)
    summary = engine.risk_rollup(engagement_id)
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any
from uuid import UUID

import structlog

from pwnpilot.data.finding_store import FindingStore
from pwnpilot.data.models import Exploitability, FindingStatus, Severity
from pwnpilot.data.recon_store import ReconStore

log = structlog.get_logger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_EDB_RE = re.compile(r"EDB-\d+", re.IGNORECASE)

# When an exploit is publicly available, escalate exploitability to at least this level
_EXPLOIT_ESCALATION: dict[str, str] = {
    "none": "low",
    "low": "medium",
    "medium": "functional",
    "high": "functional",
    "functional": "functional",
    "weaponized": "weaponized",
}

# Ordered severity tiers for roll-up
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


class CorrelationEngine:
    """
    Cross-tool finding correlation and risk roll-up for a single engagement.

    The engine is stateless with respect to the engagement; it reads from
    FindingStore and writes back updates via FindingStore methods.
    """

    def __init__(
        self,
        finding_store: FindingStore,
        recon_store: ReconStore,
    ) -> None:
        self._findings = finding_store
        self._recon = recon_store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self, engagement_id: UUID) -> int:
        """
        Run all correlation passes for *engagement_id*.

        Returns the number of findings that were escalated.
        """
        escalated = 0
        escalated += self._correlate_exploits(engagement_id)
        escalated += self._correlate_service_versions(engagement_id)
        log.info(
            "correlation.complete",
            engagement_id=str(engagement_id),
            escalated=escalated,
        )
        return escalated

    def risk_rollup(self, engagement_id: UUID) -> dict[str, Any]:
        """
        Compute an engagement-level risk summary.

        Returns a dict with:
        - severity_distribution: count per severity level
        - top_findings: top-5 findings by risk_score (as dicts)
        - tool_coverage: set of tool names that produced findings
        - overall_risk: lowest severity that covers ≥20 % of findings
        - total_findings: int
        - open_findings: int (status = new | confirmed)
        """
        findings = self._findings.findings_for_engagement(engagement_id)

        dist: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
        tool_names: set[str] = set()
        open_count = 0

        from pwnpilot.data.finding_store import FindingRow
        db_rows = (
            self._findings._session.query(FindingRow)
            .filter(FindingRow.engagement_id == str(engagement_id))
            .order_by(FindingRow.risk_score.desc())
            .all()
        )

        for row in db_rows:
            sev = row.severity
            if sev in dist:
                dist[sev] += 1
            tool_names.add(row.tool_name)
            if row.status in ("new", "confirmed"):
                open_count += 1

        total = len(db_rows)
        top_5 = [
            {
                "finding_id": r.finding_id,
                "title": r.title,
                "asset_ref": r.asset_ref,
                "severity": r.severity,
                "risk_score": r.risk_score,
                "vuln_ref": r.vuln_ref,
            }
            for r in db_rows[:5]
        ]

        overall = self._overall_risk(dist, total)

        return {
            "engagement_id": str(engagement_id),
            "total_findings": total,
            "open_findings": open_count,
            "severity_distribution": dist,
            "top_findings": top_5,
            "tool_coverage": sorted(tool_names),
            "overall_risk": overall,
        }

    # ------------------------------------------------------------------
    # Internal passes
    # ------------------------------------------------------------------

    def _correlate_exploits(self, engagement_id: UUID) -> int:
        """
        Cross-reference CVE-tagged findings with searchsploit exploit entries.

        Any finding whose vuln_ref matches a CVE referenced by an EDB-* or EDB
        finding for the same engagement will have its exploitability escalated.
        """
        from pwnpilot.data.finding_store import FindingRow

        session = self._findings._session  # type: ignore[attr-defined]
        rows = (
            session.query(FindingRow)
            .filter(FindingRow.engagement_id == str(engagement_id))
            .all()
        )

        # Build CVE → exploit FindingRow map
        exploit_cves: set[str] = set()
        for row in rows:
            if row.tool_name == "searchsploit":
                cves = _CVE_RE.findall(row.vuln_ref)
                exploit_cves.update(c.upper() for c in cves)
                # Also check title stored in vuln_ref for embedded CVE
                cves_in_ref = _CVE_RE.findall(row.title)
                exploit_cves.update(c.upper() for c in cves_in_ref)

        if not exploit_cves:
            return 0

        escalated = 0
        from datetime import datetime, timezone

        for row in rows:
            if row.tool_name == "searchsploit":
                continue
            # Normalise vuln_ref
            upper_ref = row.vuln_ref.upper().strip()
            if upper_ref not in exploit_cves:
                continue

            # Escalate exploitability
            new_exploit = _EXPLOIT_ESCALATION.get(
                row.exploitability, row.exploitability
            )
            if new_exploit != row.exploitability:
                row.exploitability = new_exploit
                row.updated_at = datetime.now(timezone.utc)
                escalated += 1
                log.info(
                    "correlation.exploit_escalation",
                    finding_id=row.finding_id,
                    vuln_ref=row.vuln_ref,
                    new_exploitability=new_exploit,
                )

        if escalated:
            session.commit()

        return escalated

    def _correlate_service_versions(self, engagement_id: UUID) -> int:
        """
        Match recon service version strings to findings.

        If a finding's asset_ref matches a discovered service and the service's
        product/version string can be extracted, add it to the finding title for
        context.  (No exploitability escalation — purely informational.)
        """
        # Retrieve raw service rows for richer data
        services = self._recon.services_for_engagement(engagement_id)
        if not services:
            return 0

        # Build a map {ip: [service_dict, ...]}
        svc_map: dict[str, list[Any]] = defaultdict(list)
        for svc in services:
            svc_map[svc.get("ip", "")].append(svc)

        from pwnpilot.data.finding_store import FindingRow
        from datetime import datetime, timezone

        session = self._findings._session  # type: ignore[attr-defined]
        rows = (
            session.query(FindingRow)
            .filter(FindingRow.engagement_id == str(engagement_id))
            .all()
        )

        updated = 0
        for row in rows:
            # Extract IP from asset_ref (e.g. "10.0.0.1:80" or "http://10.0.0.1/")
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", row.asset_ref)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            if ip not in svc_map:
                continue

            # Append service context if not already in title
            for svc in svc_map[ip]:
                product = svc.get("product", "")
                version = svc.get("version", "")
                if product and product not in row.title:
                    row.title = f"{row.title} [{product} {version}]".strip()
                    row.updated_at = datetime.now(timezone.utc)
                    updated += 1
                    break

        if updated:
            session.commit()

        return updated

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _overall_risk(dist: dict[str, int], total: int) -> str:
        """
        Determine the overall risk rating for the engagement.

        Returns the highest severity tier for which findings exist.
        Falls back to 'info' when there are no findings.
        """
        if total == 0:
            return "info"
        # Walk from highest to lowest
        for sev in reversed(_SEVERITY_ORDER):
            if dist.get(sev, 0) > 0:
                return sev
        return "info"
