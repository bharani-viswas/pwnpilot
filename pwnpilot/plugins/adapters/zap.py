"""
ZAP Baseline adapter — passive web application security scanner.

Risk class: active_scan
Input:  target URL, max_duration (minutes), ajax_spider flag, min_level filter
Output: list of web application findings with risk level, alert ID, and count

Parses the text output from zap-baseline.py, which is the most portable
output format across ZAP versions and does not require a writable side-channel.
Alert lines have the form:
    WARN-NEW: Alert Name [ID] x N
    FAIL-NEW: Alert Name [ID] x N
    PASS: Alert Name [ID]
ZAP exits 0 = no alerts, 1 = WARN, 2 = FAIL — all are valid scan completions.
"""
from __future__ import annotations

import re
from typing import Any

from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

# Only allow http/https URLs with safe characters
_SAFE_URL_RE = re.compile(r"^https?://[a-zA-Z0-9.\-:/\[\]_@%?&=#]+$")

# Maps ZAP risk word → unified severity
_RISK_MAP: dict[str, str] = {
    "FAIL": "high",
    "WARN": "medium",
    "INFO": "low",
    "PASS": "info",
}

# Matches alert lines: WARN-NEW: Alert Name [10016] x 3
_ALERT_LINE_RE = re.compile(
    r"^(PASS|WARN|FAIL|INFO)(?:-NEW|-CHANGED|-ABSENT)?\s*:\s+(.+?)\s+\[(\d+)\]"
    r"(?:\s+x\s+(\d+))?",
    re.IGNORECASE,
)


class ZapAdapter(BaseAdapter):
    """
    Adapter for OWASP ZAP baseline scanner.

    Runs ``zap-baseline.py`` which performs a passive crawl + baseline active scan
    against the target URL and reports alerts to stdout/stderr.
    """

    _MANIFEST = PluginManifest(
        name="zap",
        version="2.14",
        risk_class="active_scan",
        description="OWASP ZAP baseline web application security scan",
        input_schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "max_duration": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 60,
                    "default": 5,
                    "description": "Maximum scan duration in minutes",
                },
                "ajax_spider": {"type": "boolean", "default": False},
                "min_level": {
                    "type": "string",
                    "enum": ["PASS", "INFO", "WARN", "FAIL"],
                    "default": "WARN",
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
            raise ValueError("zap: 'target' parameter is required.")
        if not _SAFE_URL_RE.match(target):
            raise ValueError(
                f"zap: target must be a valid http/https URL, got: {target!r}"
            )

        max_duration = int(params.get("max_duration", 5))
        if not 1 <= max_duration <= 60:
            raise ValueError(
                f"zap: max_duration must be 1–60 minutes, got {max_duration}"
            )

        ajax_spider = bool(params.get("ajax_spider", False))

        min_level = str(params.get("min_level", "WARN")).upper()
        if min_level not in _RISK_MAP:
            raise ValueError(f"zap: invalid min_level '{min_level}'")

        return ToolParams(
            target=target,
            extra={
                "max_duration": max_duration,
                "ajax_spider": ajax_spider,
                "min_level": min_level,
            },
        )

    def build_command(self, params: ToolParams) -> list[str]:
        """Build zap-baseline.py command list — no shell interpolation (ADR-002)."""
        cmd = [
            "zap-baseline.py",
            "-t", params.target,
            "-m", str(params.extra["max_duration"]),
            "-l", params.extra["min_level"],
            "-I",   # ignore failure exit codes so we always get output
        ]
        if params.extra.get("ajax_spider"):
            cmd.append("-j")
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        # ZAP baseline exits 0 (clean), 1 (WARN found), 2 (FAIL found) — all valid
        if exit_code > 2 and not stdout and not stderr:
            return ParsedOutput(
                parser_error=(
                    f"zap-baseline.py exited with unexpected code {exit_code}"
                ),
                confidence=0.0,
            )

        # ZAP prints alert lines to stderr; also capture stdout for completeness
        combined = (stdout + b"\n" + stderr).decode(errors="replace")
        findings: list[dict[str, Any]] = []

        for line in combined.splitlines():
            m = _ALERT_LINE_RE.match(line.strip())
            if not m:
                continue

            risk_word, alert_name, alert_id, count_str = m.groups()
            risk_word = risk_word.upper()
            severity = _RISK_MAP.get(risk_word, "info")
            count = int(count_str) if count_str else 1

            findings.append(
                {
                    "alert_id": alert_id,
                    "title": alert_name.strip(),
                    "severity": severity,
                    "risk_level": risk_word,
                    "count": count,
                    "vuln_ref": f"ZAP-{alert_id}",
                }
            )

        return ParsedOutput(
            findings=findings,
            new_findings_count=len(findings),
            confidence=0.8 if findings else 0.5,
            raw_summary=f"ZAP scan complete. {len(findings)} alert(s) found.",
        )
