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
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import jinja2
import structlog

from pwnpilot.data.audit_store import AuditStore
from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.data.finding_store import FindingStore
from pwnpilot.data.models import Finding, FindingStatus
from pwnpilot.data.recon_store import ReconStore

log = structlog.get_logger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_SUMMARY_TEMPLATE = "summary.md.jinja2"


from pwnpilot.data.correlation import CorrelationEngine


_OBJECTIVE_CLASS_KEYWORDS: dict[str, tuple[str, ...]] = {
    "injection": (
        "sql injection",
        "sqli",
        "command injection",
        "xss",
        "cross-site scripting",
        "deserialization",
        "rce",
        "remote code execution",
    ),
    "access_control": (
        "idor",
        "broken access control",
        "authorization",
        "insecure direct object",
        "privilege escalation",
    ),
    "auth": (
        "auth",
        "login",
        "signin",
        "token",
        "session",
        "password",
    ),
    "exposure": (
        "exposure",
        "metrics",
        "prometheus",
        "disclosure",
        "directory listing",
        "debug",
    ),
    "headers": (
        "header",
        "csp",
        "x-content-type-options",
        "x-frame-options",
        "cross-origin",
    ),
    "session": (
        "session",
        "cookie",
        "csrf",
    ),
}


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_none_like(value: Any) -> str | None:
    text = _safe_text(value)
    if not text or text.lower() in {"none", "null"}:
        return None
    return text


def _infer_issue_description(title: str, vuln_ref: str) -> str:
    normalized = f"{title} {vuln_ref}".lower()
    if "csp" in normalized or "content security policy" in normalized:
        return "The application does not enforce a Content Security Policy, allowing untrusted script and content sources to be interpreted more easily by browsers."
    if "x-content-type-options" in normalized:
        return "Responses are missing the X-Content-Type-Options header, allowing MIME sniffing in some clients and increasing the chance of content-type confusion."
    if "anti-clickjacking" in normalized or "x-frame-options" in normalized:
        return "The anti-clickjacking protections are missing or incomplete, increasing exposure to UI redress attacks where users are tricked into unintended actions."
    if "cross-origin-embedder-policy" in normalized:
        return "The Cross-Origin-Embedder-Policy header is missing or invalid, weakening browser isolation controls for embedded resources."
    if "prometheus" in normalized or "metrics" in normalized:
        return "An operational metrics endpoint is exposed and can disclose service internals, request patterns, and environment details useful for attacker reconnaissance."
    if "sql injection" in normalized or "sqli" in normalized:
        return "Input appears to influence backend query behavior, which can allow unauthorized data access or manipulation if exploitable."
    if "session id in url" in normalized:
        return "Session identifiers are exposed in URL parameters, which can be leaked via logs, browser history, and referrer headers."
    if "dangerous js" in normalized:
        return "Client-side JavaScript includes potentially dangerous functions that may support DOM-based injection or unsafe code execution patterns."
    if "path-discovery" in normalized or "discovered web path" in normalized:
        return "A web path was enumerated that expands the known attack surface and may expose hidden functionality."
    return "A security weakness was identified by automated analysis and should be validated and triaged based on exploitability and business impact."


def _infer_exploitation_path(title: str, vuln_ref: str, asset_ref: str) -> str:
    normalized = f"{title} {vuln_ref}".lower()
    target = _safe_text(asset_ref) or "the affected endpoint"
    if "csp" in normalized or "content security policy" in normalized:
        return f"If an injection point exists on {target}, an attacker can execute arbitrary browser-side script with fewer CSP restrictions in place."
    if "x-content-type-options" in normalized:
        return f"An attacker can attempt MIME confusion attacks against {target} by serving crafted content that browsers may interpret as executable script."
    if "anti-clickjacking" in normalized or "x-frame-options" in normalized:
        return f"An attacker can embed {target} in a malicious frame and trick users into clicking concealed UI elements."
    if "prometheus" in normalized or "metrics" in normalized:
        return f"An unauthenticated request to {target} can disclose telemetry that helps map internals and prioritize follow-on attacks."
    if "sql injection" in normalized or "sqli" in normalized:
        return f"Crafted parameters sent to {target} may alter backend queries, enabling unauthorized read/write operations if server-side controls are weak."
    if "session id in url" in normalized:
        return f"Session tokens in URLs on {target} can be captured from logs or referrer leaks and reused for session hijacking."
    if "path-discovery" in normalized or "discovered web path" in normalized:
        return f"The discovered path on {target} can be probed for sensitive content, weak authorization, or vulnerable handlers."
    return f"An attacker can interact with {target} to reproduce the flagged behavior and chain it with adjacent weaknesses for impact escalation."


def _extract_proof_lines(raw_text: str, finding: Finding) -> list[str]:
    evidence_text = _safe_text(raw_text)
    if not evidence_text:
        return []

    finding_tokens = [
        _safe_text(finding.title),
        _safe_text(finding.vuln_ref),
        _safe_text(finding.asset_ref),
    ]
    parsed_asset = urlparse(_safe_text(finding.asset_ref))
    if parsed_asset.path:
        finding_tokens.append(parsed_asset.path)

    lines = []
    for line in evidence_text.splitlines():
        compact = line.strip()
        if not compact:
            continue
        if any(token and token.lower() in compact.lower() for token in finding_tokens):
            lines.append(compact)
        elif any(marker in compact.lower() for marker in ("matched-at", "curl-command", "warn-new", "fail-new", "vulnerable", "proof")):
            lines.append(compact)
        if len(lines) >= 4:
            break
    return lines


def _sanitize_proof_line(line: str) -> str:
    collapsed = re.sub(r"\s+", " ", _safe_text(line))
    return collapsed[:280]


def _infer_tool_family(finding: Finding) -> str:
    vuln_ref = _safe_text(finding.vuln_ref).lower()
    title = _safe_text(finding.title).lower()
    if vuln_ref.startswith("zap-") or "header" in title or "cross-origin" in title:
        return "zap"
    if vuln_ref.startswith("gobuster:") or "discovered web path" in title:
        return "gobuster"
    if vuln_ref == "nikto-finding" or vuln_ref.startswith("osvdb-"):
        return "nikto"
    if vuln_ref.startswith("cwe-") or "prometheus" in title or "metrics" in title:
        return "nuclei"
    if "sql injection" in title or "sqli" in vuln_ref:
        return "sqlmap"
    return "generic"


def _chunk_matches_finding(chunk: dict[str, Any], finding: Finding) -> bool:
    chunk_tool = _safe_text(chunk.get("tool_name")).lower()
    tool_family = _infer_tool_family(finding)
    if tool_family != "generic" and chunk_tool != tool_family:
        return False

    target = _safe_text(chunk.get("target"))
    action_asset = _safe_text(finding.asset_ref)
    if target and action_asset and not _asset_matches(target, action_asset):
        target_host = urlparse(_normalize_asset(target)).netloc
        asset_host = urlparse(_normalize_asset(action_asset)).netloc
        if target_host and asset_host and target_host != asset_host:
            return False
    return True


def _extract_zap_proof(raw_text: str, finding: Finding) -> list[str]:
    title = _safe_text(finding.title)
    vuln_suffix = _safe_text(finding.vuln_ref).replace("ZAP-", "")
    lines = raw_text.splitlines()
    for index, line in enumerate(lines):
        compact = line.strip()
        if title.lower() in compact.lower() or (vuln_suffix and f"[{vuln_suffix}]" in compact):
            proof = [_sanitize_proof_line(compact)]
            for follow in lines[index + 1 : index + 6]:
                if not follow.strip():
                    continue
                if re.match(r"^[A-Z-]+:", follow.strip()):
                    break
                proof.append(_sanitize_proof_line(follow.strip()))
                if len(proof) >= 3:
                    break
            return proof
    return []


def _extract_nuclei_proof(raw_text: str, finding: Finding) -> list[str]:
    for line in raw_text.splitlines():
        compact = line.strip()
        if not compact.startswith("{"):
            continue
        try:
            payload = json.loads(compact)
        except json.JSONDecodeError:
            continue

        info = payload.get("info", {}) if isinstance(payload.get("info"), dict) else {}
        name = _safe_text(info.get("name"))
        matched_at = _safe_text(payload.get("matched-at"))
        curl_command = _safe_text(payload.get("curl-command"))
        cwe_ids = [str(item).lower() for item in ((info.get("classification", {}) or {}).get("cwe-id", []) if isinstance(info.get("classification", {}), dict) else [])]
        if name.lower() != _safe_text(finding.title).lower() and _safe_text(finding.vuln_ref).lower() not in cwe_ids and matched_at != _safe_text(finding.asset_ref):
            continue

        proof = []
        if name:
            proof.append(_sanitize_proof_line(f"Template matched: {name}"))
        if matched_at:
            proof.append(_sanitize_proof_line(f"Matched at: {matched_at}"))
        if curl_command:
            proof.append(_sanitize_proof_line(f"Validation request: {curl_command}"))
        return proof
    return []


def _extract_nikto_proof(raw_text: str, finding: Finding) -> list[str]:
    proof: list[str] = []
    vuln_ref = _safe_text(finding.vuln_ref).lower()
    title = _safe_text(finding.title).lower()
    for line in raw_text.splitlines():
        compact = line.strip()
        if not compact.startswith("+"):
            continue
        lowered = compact.lower()
        if title in lowered or vuln_ref in lowered:
            proof.append(_sanitize_proof_line(compact))
            if len(proof) >= 2:
                break
    return proof


def _extract_gobuster_proof(raw_text: str, finding: Finding) -> list[str]:
    path_hint = _safe_text(finding.title).replace("Discovered web path", "").strip()
    for line in raw_text.splitlines():
        compact = line.strip()
        if not compact or "wildcard response found" in compact.lower():
            continue
        if path_hint and compact.startswith(path_hint):
            return [_sanitize_proof_line(compact)]
    return []


def _extract_structured_proof(event_timeline: list[dict[str, Any]], finding: Finding) -> list[str]:
    tool_family = _infer_tool_family(finding)
    for event in event_timeline:
        if not isinstance(event, dict):
            continue
        if _safe_text(event.get("event_type")) != "tool.output_chunk":
            continue
        if not _chunk_matches_finding(event, finding):
            continue

        raw_text = _safe_text(event.get("data"))
        if not raw_text:
            continue

        if tool_family == "zap":
            proof = _extract_zap_proof(raw_text, finding)
        elif tool_family == "nuclei":
            proof = _extract_nuclei_proof(raw_text, finding)
        elif tool_family == "nikto":
            proof = _extract_nikto_proof(raw_text, finding)
        elif tool_family == "gobuster":
            proof = _extract_gobuster_proof(raw_text, finding)
        else:
            proof = _extract_proof_lines(raw_text, finding)

        if proof:
            return proof
    return []


def _build_finding_insights(
    findings: list[Finding],
    evidence_store: EvidenceStore,
    event_timeline: list[dict[str, Any]],
    reconciliation: dict[str, dict[str, str]],
) -> dict[str, dict[str, Any]]:
    insights: dict[str, dict[str, Any]] = {}
    for finding in findings:
        proof_lines = _extract_structured_proof(event_timeline, finding)
        evidence_artifacts: list[str] = []

        for evidence_id in list(getattr(finding, "evidence_ids", []) or []):
            evidence_artifacts.append(str(evidence_id))
            if proof_lines:
                continue
            try:
                data = evidence_store.read_evidence(UUID(str(evidence_id)))
                decoded = data.decode("utf-8", errors="replace")
                for line in _extract_proof_lines(decoded, finding):
                    proof_lines.append(_sanitize_proof_line(line))
                    if len(proof_lines) >= 4:
                        break
            except Exception:
                continue
            if len(proof_lines) >= 4:
                break

        if not proof_lines:
            status_value = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
            if status_value == FindingStatus.CONFIRMED.value:
                proof_lines = [
                    "Finding reached confirmed status through objective follow-up; direct payload transcript was not persisted for this specific record.",
                ]
            else:
                proof_lines = [
                    "Scanner output indicated this issue; explicit exploit payload evidence is not yet captured for this finding.",
                ]

        insights[str(finding.finding_id)] = {
            "issue_description": _infer_issue_description(finding.title, finding.vuln_ref),
            "exploitation_path": _infer_exploitation_path(finding.title, finding.vuln_ref, finding.asset_ref),
            "proof_lines": proof_lines,
            "evidence_artifacts": evidence_artifacts,
            "status_rationale": _status_rationale(
                reconciliation.get(str(finding.finding_id), {}).get("reason", "")
            ),
        }

    return insights


def _classify_objective_class(text: str) -> str:
    normalized = str(text or "").strip().lower()
    if not normalized:
        return "generic"
    for objective_class, keywords in _OBJECTIVE_CLASS_KEYWORDS.items():
        if any(keyword in normalized for keyword in keywords):
            return objective_class
    return "generic"


def _normalize_asset(asset_ref: str) -> str:
    value = str(asset_ref or "").strip().lower().rstrip("/")
    if not value:
        return ""

    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    return value


def _asset_matches(objective_asset: str, finding_asset: str) -> bool:
    obj_asset = _normalize_asset(objective_asset)
    fd_asset = _normalize_asset(finding_asset)
    if not obj_asset or not fd_asset:
        return False
    if obj_asset == fd_asset:
        return True

    obj_url = urlparse(obj_asset)
    fd_url = urlparse(fd_asset)
    if obj_url.netloc and fd_url.netloc and obj_url.netloc == fd_url.netloc:
        obj_path = obj_url.path or "/"
        fd_path = fd_url.path or "/"
        return fd_path.startswith(obj_path) or obj_path.startswith(fd_path)
    return False


def _objective_matches_finding(objective: dict[str, Any], finding: Finding) -> bool:
    objective_class = str(objective.get("objective_class", "")).strip().lower()
    objective_status = str(objective.get("status", "")).strip().lower()
    if objective_status != "confirmed":
        return False
    if objective_class in {"", "generic"}:
        return False

    finding_class = _classify_objective_class(f"{finding.title} {finding.vuln_ref}")
    if finding_class != objective_class:
        return False

    objective_asset = str(objective.get("asset_ref", "")).strip()
    if not objective_asset:
        return False
    return _asset_matches(objective_asset, finding.asset_ref)


def _objective_supports_finding(objective: dict[str, Any], finding: Finding) -> bool:
    objective_status = str(objective.get("status", "")).strip().lower()
    if objective_status != "confirmed":
        return False

    objective_asset = str(objective.get("asset_ref", "")).strip()
    if not objective_asset or not _asset_matches(objective_asset, finding.asset_ref):
        return False

    objective_text = " ".join(
        [
            _safe_text(objective.get("title")),
            _safe_text(objective.get("description")),
            _safe_text(objective.get("notes")),
        ]
    ).lower()
    if not objective_text:
        return False

    finding_title = _safe_text(finding.title).lower()
    finding_vuln_ref = _safe_text(finding.vuln_ref).lower()
    finding_class = _classify_objective_class(f"{finding.title} {finding.vuln_ref}")
    objective_text_class = _classify_objective_class(objective_text)

    return bool(
        (finding_vuln_ref and finding_vuln_ref in objective_text)
        or (finding_title and finding_title in objective_text)
        or (objective_text_class != "generic" and objective_text_class == finding_class)
    )


def _status_rationale(reason: str) -> str:
    messages = {
        "preserved_existing_status": "Existing finding status was preserved from the store.",
        "confirmed_by_specific_objective_match": "Status was promoted to confirmed because a confirmed objective matched the finding class and asset.",
        "confirmed_by_corroborated_generic_objective": "Status was promoted to confirmed because a confirmed objective on the same asset explicitly referenced this finding.",
        "generic_objective_requires_corroboration": "Confirmed generic objective telemetry existed, but it did not specifically corroborate this finding.",
        "no_confirmed_objective_match": "No confirmed objective specifically matched this finding, so status remained new.",
    }
    return messages.get(reason, "No additional status rationale recorded.")


def _derive_status_counts(findings: list[Finding]) -> dict[str, int]:
    unconfirmed = 0
    confirmed = 0
    for finding in findings:
        status_value = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
        if status_value == FindingStatus.NEW.value:
            unconfirmed += 1
        elif status_value == FindingStatus.CONFIRMED.value:
            confirmed += 1
    remediation_open = unconfirmed + confirmed
    return {
        "unconfirmed_findings": unconfirmed,
        "confirmed_findings": confirmed,
        "active_findings": remediation_open,
        "remediation_open_findings": remediation_open,
        "open_findings": remediation_open,
    }


class ReportGenerator:
    def __init__(
        self,
        finding_store: FindingStore,
        recon_store: ReconStore,
        evidence_store: EvidenceStore,
        audit_store: AuditStore,
        operator_decision_store: "Any | None" = None,
        correlation_engine: "CorrelationEngine | None" = None,
    ) -> None:
        self._findings = finding_store
        self._recon = recon_store
        self._evidence = evidence_store
        self._audit = audit_store
        self._decision_store = operator_decision_store
        self._correlation = correlation_engine
        self._jinja = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=False,
        )

    def build_bundle(
        self,
        engagement_id: UUID,
        output_dir: Path = Path("."),
        signer: "Any | None" = None,
        run_metadata: dict[str, Any] | None = None,
    ) -> tuple[Path, Path]:
        """
        Build and write report bundle + Markdown summary.

        If *signer* is provided (a ``ReportSigner`` instance), the public key
        is embedded in the bundle and the bundle is signed, producing a
        ``<bundle>.sig`` file alongside the JSON.

        Returns (bundle_path, summary_path).
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Run correlation before reading findings so deduplication and
        # exploitability updates are reflected in the report.
        risk_rollup: dict[str, Any] = {}
        if self._correlation is not None:
            try:
                self._correlation.correlate(engagement_id)
            except Exception as _ce:
                log.warning("report.correlation_error", exc=str(_ce))

        reconciliation = self._reconcile_confirmed_objectives(
            engagement_id=engagement_id,
            assessment_objectives=(run_metadata or {}).get("assessment_objectives", []),
        )

        findings = self._findings.findings_for_engagement(engagement_id)

        if self._correlation is not None:
            try:
                risk_rollup = self._correlation.risk_rollup(engagement_id)
            except Exception as _ce:
                log.warning("report.risk_rollup_error", exc=str(_ce))

        if isinstance(risk_rollup, dict) and risk_rollup:
            expected_counts = _derive_status_counts(findings)
            mismatched = {
                key: {
                    "expected": expected_counts[key],
                    "actual": risk_rollup.get(key),
                }
                for key in expected_counts
                if int(risk_rollup.get(key, -1) or 0) != int(expected_counts[key])
            }
            if mismatched:
                log.warning(
                    "report.risk_rollup_status_mismatch",
                    engagement_id=str(engagement_id),
                    mismatched=mismatched,
                )
                # Keep report-internal invariants deterministic for downstream consumers.
                risk_rollup = {**risk_rollup, **expected_counts}

        hosts = self._recon.hosts_for_engagement(engagement_id)
        services = self._recon.services_for_engagement(engagement_id)

        metadata = run_metadata or {}

        # v2 timeline — execution events from audit store
        event_timeline: list[dict[str, Any]] = []
        try:
            event_timeline = list(self._audit.execution_events_for_engagement(engagement_id))
        except Exception:
            pass

        # v2 operator decisions
        operator_decisions: list[dict[str, Any]] = []
        if self._decision_store is not None:
            try:
                operator_decisions = [
                    d.model_dump(mode="json")
                    for d in self._decision_store.decisions_for_engagement(engagement_id)
                ]
            except Exception:
                pass

        bundle = {
            "engagement_id": str(engagement_id),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings_count": len(findings),
            "hosts_count": len(hosts),
            "services_count": len(services),
            "findings": [f.model_dump(mode="json") for f in findings],
            "hosts": hosts,
            "services": services,
            "run_verdict": metadata.get("run_verdict"),
            "readiness_gate_results": metadata.get("readiness_gate_results", {}),
            "degradation_reasons": metadata.get("degradation_reasons", []),
            "termination_reason": _normalize_none_like(metadata.get("termination_reason")),
            "assessment_objectives": metadata.get("assessment_objectives", []),
            "objective_progress": metadata.get("objective_progress", {}),
            "depth_metrics": metadata.get("depth_metrics", {}),
            "event_timeline": event_timeline,
            "operator_decisions": operator_decisions,
            "finding_status_reconciliation": reconciliation,
            "schema_version": "v2",
            "risk_rollup": risk_rollup,
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
        finding_insights = _build_finding_insights(findings, self._evidence, event_timeline, reconciliation)
        try:
            template = self._jinja.get_template(_SUMMARY_TEMPLATE)
            summary_md = template.render(
                engagement_id=str(engagement_id),
                findings=findings,
                finding_insights=finding_insights,
                hosts=hosts,
                services=services,
                generated_at=datetime.now(timezone.utc).isoformat(),
                objective_progress=metadata.get("objective_progress", {}),
                assessment_objectives=metadata.get("assessment_objectives", []),
                depth_metrics=metadata.get("depth_metrics", {}),
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

    def _reconcile_confirmed_objectives(
        self,
        engagement_id: UUID,
        assessment_objectives: list[dict[str, Any]],
    ) -> dict[str, dict[str, str]]:
        reconciliation: dict[str, dict[str, str]] = {}
        if not isinstance(assessment_objectives, list) or not assessment_objectives:
            return reconciliation

        confirmed_objectives = [
            objective
            for objective in assessment_objectives
            if isinstance(objective, dict)
            and str(objective.get("status", "")).strip().lower() == "confirmed"
        ]
        if not confirmed_objectives:
            return reconciliation

        findings = self._findings.findings_for_engagement(engagement_id)
        for finding in findings:
            finding_id = str(finding.finding_id)
            status_value = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
            if status_value != FindingStatus.NEW.value:
                reconciliation[finding_id] = {
                    "status": status_value,
                    "reason": "preserved_existing_status",
                }
                continue

            if any(_objective_matches_finding(obj, finding) for obj in confirmed_objectives):
                self._findings.update_status(finding.finding_id, FindingStatus.CONFIRMED)
                reconciliation[finding_id] = {
                    "status": FindingStatus.CONFIRMED.value,
                    "reason": "confirmed_by_specific_objective_match",
                }
                log.info(
                    "report.finding_status_reconciled",
                    engagement_id=str(engagement_id),
                    finding_id=str(finding.finding_id),
                    status=FindingStatus.CONFIRMED.value,
                )
                continue

            if any(_objective_supports_finding(obj, finding) for obj in confirmed_objectives):
                self._findings.update_status(finding.finding_id, FindingStatus.CONFIRMED)
                reconciliation[finding_id] = {
                    "status": FindingStatus.CONFIRMED.value,
                    "reason": "confirmed_by_corroborated_generic_objective",
                }
                log.info(
                    "report.finding_status_reconciled",
                    engagement_id=str(engagement_id),
                    finding_id=str(finding.finding_id),
                    status=FindingStatus.CONFIRMED.value,
                    path="generic_objective_corroboration",
                )
                continue

            generic_objectives = [
                objective
                for objective in confirmed_objectives
                if _asset_matches(str(objective.get("asset_ref", "")).strip(), finding.asset_ref)
                and str(objective.get("objective_class", "")).strip().lower() in {"", "generic"}
            ]
            reconciliation[finding_id] = {
                "status": FindingStatus.NEW.value,
                "reason": (
                    "generic_objective_requires_corroboration"
                    if generic_objectives
                    else "no_confirmed_objective_match"
                ),
            }

        return reconciliation
