"""
Report Generator — produces JSON bundle and Jinja2-rendered Markdown summary.

Bundle contents:
  - Engagement metadata
  - Findings list with evidence links
  - Audit chain summary
  - Risk score breakdown
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import jinja2
import structlog

from pwnpilot.data.audit_store import AuditStore
from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.data.finding_store import FindingStore
from pwnpilot.data.recon_store import ReconStore

log = structlog.get_logger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_SUMMARY_TEMPLATE = "summary.md.jinja2"


class ReportGenerator:
    def __init__(
        self,
        finding_store: FindingStore,
        recon_store: ReconStore,
        evidence_store: EvidenceStore,
        audit_store: AuditStore,
    ) -> None:
        self._findings = finding_store
        self._recon = recon_store
        self._evidence = evidence_store
        self._audit = audit_store
        self._jinja = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=False,
        )

    def build_bundle(
        self,
        engagement_id: UUID,
        output_dir: Path = Path("."),
        signer: "Any | None" = None,
    ) -> tuple[Path, Path]:
        """
        Build and write report bundle + Markdown summary.

        If *signer* is provided (a ``ReportSigner`` instance), the public key
        is embedded in the bundle and the bundle is signed, producing a
        ``<bundle>.sig`` file alongside the JSON.

        Returns (bundle_path, summary_path).
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        findings = self._findings.findings_for_engagement(engagement_id)
        hosts = self._recon.hosts_for_engagement(engagement_id)
        services = self._recon.services_for_engagement(engagement_id)

        bundle = {
            "engagement_id": str(engagement_id),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings_count": len(findings),
            "hosts_count": len(hosts),
            "services_count": len(services),
            "findings": [f.model_dump(mode="json") for f in findings],
            "hosts": hosts,
            "services": services,
            "schema_version": "v1",
        }

        bundle_path = output_dir / f"report_{engagement_id}.json"
        bundle_path.write_text(json.dumps(bundle, indent=2, default=str))

        # Optionally embed pubkey + sign
        if signer is not None:
            signer.embed_pubkey_in_bundle(bundle_path)
            signer.sign(bundle_path)
            log.info("report.signed", bundle=str(bundle_path))

        # Human-readable Markdown
        summary_path = output_dir / f"report_{engagement_id}.md"
        try:
            template = self._jinja.get_template(_SUMMARY_TEMPLATE)
            summary_md = template.render(
                engagement_id=str(engagement_id),
                findings=findings,
                hosts=hosts,
                services=services,
                generated_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception:
            # Fallback summary
            summary_md = (
                f"# Pwnpilot Report\n\n"
                f"**Engagement:** {engagement_id}\n\n"
                f"**Findings:** {len(findings)}\n\n"
                f"**Hosts discovered:** {len(hosts)}\n"
            )

        summary_path.write_text(summary_md)

        log.info(
            "report.generated",
            engagement_id=str(engagement_id),
            findings=len(findings),
            bundle=str(bundle_path),
        )
        return bundle_path, summary_path
