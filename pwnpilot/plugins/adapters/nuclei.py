"""
Nuclei adapter — template-driven vulnerability scanner.

Risk class: active_scan
Input: target (URL/IP), templates (severity filter), rate_limit
Output: list of findings with severity, CVE ref, and matcher evidence
"""
from __future__ import annotations

import json
import re
from typing import Any

from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

_ALLOWED_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_SAFE_TEMPLATE_RE = re.compile(r"^[a-zA-Z0-9_\-/]+$")


class NucleiAdapter(BaseAdapter):
    """
    Adapter for nuclei template-driven scanner.
    Uses JSONL output format for streaming-friendly parsing.
    """

    _MANIFEST = PluginManifest(
        name="nuclei",
        version="3.x",
        risk_class="active_scan",
        description="Template-driven vulnerability scanner",
        input_schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "default": "medium",
                },
                "rate_limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                "template_tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "findings": {"type": "array"},
            },
        },
    )

    @property
    def manifest(self) -> PluginManifest:
        return self._MANIFEST

    def validate_params(self, params: dict[str, Any]) -> ToolParams:
        target = str(params.get("target", "")).strip()
        if not target:
            raise ValueError("nuclei: 'target' parameter is required.")

        severity = str(params.get("severity", "medium")).strip().lower()
        if severity not in _ALLOWED_SEVERITIES:
            raise ValueError(f"nuclei: invalid severity '{severity}'")

        rate_limit = int(params.get("rate_limit", 50))
        if not 1 <= rate_limit <= 500:
            raise ValueError(f"nuclei: rate_limit must be 1-500, got {rate_limit}")

        # Validate optional template tags (allow-list safe chars only)
        tags: list[str] = params.get("template_tags", [])
        for tag in tags:
            if not _SAFE_TEMPLATE_RE.match(tag):
                raise ValueError(f"nuclei: unsafe template tag: {tag!r}")

        return ToolParams(
            target=target,
            extra={
                "severity": severity,
                "rate_limit": rate_limit,
                "template_tags": tags,
            },
        )

    def build_command(self, params: ToolParams) -> list[str]:
        """Build nuclei subprocess command — list only, no shell (ADR-002)."""
        cmd = [
            "nuclei",
            "-u", params.target,
            "-severity", params.extra["severity"],
            "-rate-limit", str(params.extra["rate_limit"]),
            "-jsonl",        # JSONL output for streaming parse
            "-silent",
            "-no-color",
        ]

        tags = params.extra.get("template_tags", [])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        if exit_code not in (0, 1):
            return ParsedOutput(
                parser_error=f"nuclei exited with code {exit_code}",
                confidence=0.0,
            )

        if not stdout:
            return ParsedOutput(
                findings=[],
                execution_hints=[
                    {
                        "code": "no_matches",
                        "message": "Nuclei completed with no template matches.",
                        "severity": "info",
                        "recommended_action": "Pivot to a different tool family or broader recon strategy instead of repeating identical nuclei scans.",
                    }
                ],
                raw_summary="nuclei completed with no matches",
                new_findings_count=0,
                confidence=0.6,
            )

        findings = []
        lines = stdout.decode(errors="replace").splitlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = entry.get("template-id", "")
            matched_at = entry.get("matched-at", "")
            severity = entry.get("info", {}).get("severity", "info")
            name = entry.get("info", {}).get("name", template_id)
            cve_ids = entry.get("info", {}).get("classification", {}).get("cve-id", [])
            cwe_ids = entry.get("info", {}).get("classification", {}).get("cwe-id", [])

            vuln_ref = cve_ids[0] if cve_ids else (cwe_ids[0] if cwe_ids else template_id)

            findings.append(
                {
                    "template_id": template_id,
                    "title": name,
                    "matched_at": matched_at,
                    "severity": severity,
                    "vuln_ref": vuln_ref,
                    "matcher_name": entry.get("matcher-name", ""),
                    "curl_command": entry.get("curl-command", ""),
                }
            )

        return ParsedOutput(
            findings=findings,
            raw_summary=f"nuclei found {len(findings)} issue(s)",
            new_findings_count=len(findings),
            confidence=0.85 if findings else 0.5,
        )
