"""
sqlmap adapter — automated SQL injection detection.

Risk class: active_scan
Input:  target URL, optional POST data, level (1–3), risk (1–2), forms flag
Output: list of injection point findings with technique details

Capped safety defaults: level ≤ 3, risk ≤ 2, --batch (no interactive prompts).
Exploitation flags (--dump, --os-shell, --file-write) are intentionally absent;
those require a separate REQUIRES_APPROVAL exploit action.

Parses sqlmap's stdout for injection findings; the structured JSON output
requires a writable session directory which does not fit the runner's
stdout-capture model.
"""
from __future__ import annotations

import re
from typing import Any

from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

# Allow valid http(s) URLs only
_SAFE_URL_RE = re.compile(r"^https?://[a-zA-Z0-9.\-:/\[\]_@%?&=#]+$")

# POST data: form-encoded or simple JSON-like values; no shell metacharacters
_SAFE_DATA_RE = re.compile(r"^[a-zA-Z0-9=&%+\[\]{}\"':,._\-\s]*$")

# sqlmap stdout patterns
_INJECTABLE_RE = re.compile(
    r"Parameter:\s+(.+?)\s+\((GET|POST|Cookie|User-Agent|Referer|Host|URI)\)\s+is\s+vulnerable",
    re.IGNORECASE,
)
_INJECTION_TYPE_RE = re.compile(
    r"Type:\s+(.+?)\n\s*Title:\s+(.+?)\n\s*Payload:\s+(.+?)(?:\n|$)",
    re.IGNORECASE,
)


class SqlmapAdapter(BaseAdapter):
    """
    Adapter for sqlmap SQL injection scanner.

    Runs in detection-only mode.  Exploitation capabilities are explicitly
    excluded; use a dedicated exploit-class action for those work flows.
    """

    _MANIFEST = PluginManifest(
        name="sqlmap",
        version="1.x",
        risk_class="active_scan",
        description="Automated SQL injection detection (detection-only mode)",
        input_schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "data": {
                    "type": "string",
                    "default": "",
                    "description": "POST body (form-encoded or JSON)",
                },
                "level": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3,
                    "default": 1,
                    "description": "Test level 1–3 (capped at 3 for safety)",
                },
                "risk": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 2,
                    "default": 1,
                    "description": "Risk level 1–2 (capped at 2 for safety)",
                },
                "forms": {
                    "type": "boolean",
                    "default": False,
                    "description": "Auto-discover and test HTML forms",
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
            raise ValueError("sqlmap: 'target' parameter is required.")
        if not _SAFE_URL_RE.match(target):
            raise ValueError(
                f"sqlmap: target must be a valid http/https URL, got: {target!r}"
            )

        level = int(params.get("level", 1))
        if not 1 <= level <= 3:
            raise ValueError(
                f"sqlmap: level must be 1–3 (capped for safety), got {level}"
            )

        risk = int(params.get("risk", 1))
        if not 1 <= risk <= 2:
            raise ValueError(
                f"sqlmap: risk must be 1–2 (capped for safety), got {risk}"
            )

        data = str(params.get("data", "")).strip()
        if data and not _SAFE_DATA_RE.match(data):
            raise ValueError(
                f"sqlmap: data contains unsafe characters: {data!r}"
            )

        forms = bool(params.get("forms", False))

        return ToolParams(
            target=target,
            extra={
                "level": level,
                "risk": risk,
                "data": data,
                "forms": forms,
            },
        )

    def build_command(self, params: ToolParams) -> list[str]:
        """Build sqlmap command list — no shell interpolation (ADR-002)."""
        cmd = [
            "sqlmap",
            "-u", params.target,
            "--level", str(params.extra["level"]),
            "--risk", str(params.extra["risk"]),
            "--batch",          # never prompt for user input
            "--no-cast",        # reduce false positives in type casting
        ]
        if params.extra.get("data"):
            cmd.extend(["--data", params.extra["data"]])
        if params.extra.get("forms"):
            cmd.append("--forms")
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        if exit_code not in (0, 1) and not stdout:
            return ParsedOutput(
                parser_error=f"sqlmap exited with code {exit_code}",
                confidence=0.0,
            )

        text = (stdout + stderr).decode(errors="replace")
        findings: list[dict[str, Any]] = []

        # Extract injectable parameter findings
        for m in _INJECTABLE_RE.finditer(text):
            param_name = m.group(1).strip()
            context = m.group(2).strip()
            findings.append(
                {
                    "title": f"SQL Injection — parameter '{param_name}' ({context})",
                    "parameter": param_name,
                    "context": context,
                    "severity": "high",
                    "vuln_ref": "CWE-89",
                }
            )

        # Attach injection technique details to the first finding
        techniques: list[dict[str, str]] = []
        for m in _INJECTION_TYPE_RE.finditer(text):
            techniques.append(
                {
                    "type": m.group(1).strip(),
                    "title": m.group(2).strip(),
                    "payload": m.group(3).strip(),
                }
            )
        if techniques and findings:
            findings[0]["techniques"] = techniques

        # Record explicitly negative result for traceability
        if not findings and "not injectable" in text.lower():
            findings.append(
                {
                    "title": "No SQL injection detected",
                    "severity": "info",
                    "vuln_ref": "CWE-89",
                }
            )

        vulnerable = any(
            kw in text.lower()
            for kw in ("is vulnerable", "injectable", "injection point")
        )

        return ParsedOutput(
            findings=findings,
            new_findings_count=sum(
                1 for f in findings if f.get("severity") != "info"
            ),
            confidence=0.85 if vulnerable else 0.6,
            raw_summary=(
                f"sqlmap: {'injectable' if vulnerable else 'no injection'} "
                f"({len(findings)} finding(s))"
            ),
        )
