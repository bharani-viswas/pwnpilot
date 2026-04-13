from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def _first_non_empty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _build_fallback_vuln_ref(tool_name: str, finding: dict[str, Any]) -> str:
    fingerprint_parts = [
        tool_name,
        _first_non_empty(
            finding.get("type"),
            finding.get("template_id"),
            finding.get("id"),
            finding.get("name"),
            finding.get("title"),
            finding.get("matched_at"),
            finding.get("url"),
        ),
    ]
    fallback = ":".join(part for part in fingerprint_parts if part)
    return fallback or f"{tool_name}:unknown"


def canonicalize_finding(
    finding: dict[str, Any],
    tool_name: str,
    default_asset_ref: str,
) -> dict[str, Any]:
    title = _first_non_empty(
        finding.get("title"),
        finding.get("name"),
        finding.get("description"),
        finding.get("message"),
        finding.get("template_id"),
        finding.get("url"),
        finding.get("matched_at"),
    )
    description = _first_non_empty(
        finding.get("description"),
        finding.get("details"),
        finding.get("message"),
        title,
    )
    vuln_ref = _first_non_empty(
        finding.get("vuln_ref"),
        finding.get("cve"),
        finding.get("cwe"),
        finding.get("template_id"),
        finding.get("id"),
        _build_fallback_vuln_ref(tool_name, finding),
    )
    asset_ref = _first_non_empty(
        finding.get("asset_ref"),
        finding.get("target"),
        finding.get("matched_at"),
        finding.get("url"),
        default_asset_ref,
    )

    normalized = {
        "title": title or f"{tool_name} finding",
        "description": description or title or f"{tool_name} finding",
        "vuln_ref": vuln_ref,
        "severity": _first_non_empty(finding.get("severity"), "medium").lower(),
        "confidence": float(finding.get("confidence", 0.5) or 0.5),
        "asset_ref": asset_ref,
        "remediation": _first_non_empty(finding.get("remediation")),
    }

    for key in (
        "template_id",
        "matched_at",
        "matcher_name",
        "curl_command",
        "url",
        "method",
        "parameter",
        "context",
        "techniques",
        "classification",
        "tags",
    ):
        if key in finding and finding[key] not in (None, "", []):
            normalized[key] = finding[key]

    return normalized


def normalize_execution_hint(
    code: str,
    message: str,
    severity: str = "info",
    recommended_action: str = "",
) -> dict[str, str]:
    return {
        "code": code.strip().lower(),
        "message": message.strip(),
        "severity": severity.strip().lower() or "info",
        "recommended_action": recommended_action.strip(),
    }


def infer_host_from_service(service: dict[str, Any]) -> dict[str, Any] | None:
    ip_address = _first_non_empty(service.get("ip_address"), service.get("ip"))
    hostname = _first_non_empty(service.get("hostname"))
    url = _first_non_empty(service.get("url"))

    if url:
        parsed = urlparse(url)
        hostname = hostname or (parsed.hostname or "")
        if not ip_address and parsed.hostname and parsed.hostname.replace(".", "").isdigit():
            ip_address = parsed.hostname

    if not ip_address and hostname in {"localhost", "::1"}:
        ip_address = "127.0.0.1"

    if not ip_address and not hostname:
        return None

    return {
        "ip_address": ip_address,
        "hostname": hostname or None,
        "status": _first_non_empty(service.get("status"), "up"),
        "derived_from": _first_non_empty("service", service.get("derived_from")),
    }


def infer_service_port(service: dict[str, Any]) -> int | None:
    if service.get("port") is not None:
        try:
            return int(service["port"])
        except (TypeError, ValueError):
            return None

    url = _first_non_empty(service.get("url"))
    if not url:
        return None

    parsed = urlparse(url)
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None