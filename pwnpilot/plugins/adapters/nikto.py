"""
Nikto adapter — web server vulnerability scanner.

Risk class: active_scan
Input:  target host or URL, port, ssl, maxtime, tuning class
Output: list of findings with OSVDB/CVE references

Parses text output from Nikto (lines starting with '+').
Note: Nikto 2.1.5 does not support -Format json; uses native stderr text output.
"""
from __future__ import annotations

import re
from typing import Any

from pwnpilot.plugins.parsers.contracts import normalize_execution_hint
from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

# Allow hostnames, IPs, and http(s) URLs — reject shell-special chars
_SAFE_HOST_RE = re.compile(r"^[a-zA-Z0-9.\-:/\[\]_@%?&=#]+$")

# Tuning options are single hex/alpha chars from nikto docs
_SAFE_TUNING_RE = re.compile(r"^[0-9abcdeghijklmoprstuvwxy]+$")

# Extract OSVDB reference from text output
_OSVDB_RE = re.compile(r"OSVDB-(\d+)")


class NiktoAdapter(BaseAdapter):
    """
    Adapter for Nikto web server scanner.

    Uses native Nikto text output and deterministic local parsing.
    """

    _MANIFEST = PluginManifest(
        name="nikto",
        version="2.x",
        risk_class="active_scan",
        description="Web server vulnerability scanner with OSVDB/CVE references",
        input_schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "port": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535,
                    "default": 80,
                },
                "ssl": {"type": "boolean", "default": False},
                "maxtime": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": 3600,
                    "default": 300,
                    "description": "Maximum scan time in seconds",
                },
                "tuning": {
                    "type": "string",
                    "default": "x",
                    "description": "Nikto tuning option string (see nikto -list-plugins)",
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
            raise ValueError("nikto: 'target' parameter is required.")
        if not _SAFE_HOST_RE.match(target):
            raise ValueError(
                f"nikto: target contains unsafe characters: {target!r}"
            )

        port = int(params.get("port", 80))
        if not 1 <= port <= 65535:
            raise ValueError(f"nikto: port must be 1–65535, got {port}")

        ssl = bool(params.get("ssl", False))

        maxtime = int(params.get("maxtime", 300))
        if not 10 <= maxtime <= 3600:
            raise ValueError(
                f"nikto: maxtime must be 10–3600 seconds, got {maxtime}"
            )

        tuning = str(params.get("tuning", "x")).lower()
        if not _SAFE_TUNING_RE.match(tuning):
            raise ValueError(f"nikto: invalid tuning options: {tuning!r}")

        return ToolParams(
            target=target,
            extra={
                "port": port,
                "ssl": ssl,
                "maxtime": maxtime,
                "tuning": tuning,
            },
        )

    def build_command(self, params: ToolParams) -> list[str]:
        """Build nikto command list — no shell interpolation (ADR-002).
        
        Note: Nikto 2.1.5 does not support -Format json; use text output (stderr).
        """
        cmd = [
            "nikto",
            "-host", params.target,
            "-port", str(params.extra["port"]),
            "-maxtime", str(params.extra["maxtime"]),
            "-nointeractive",
        ]
        if params.extra.get("ssl"):
            cmd.append("-ssl")
        tuning = params.extra.get("tuning", "x")
        if tuning and tuning != "x":
            cmd.extend(["-Tuning", tuning])
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        """Parse Nikto text output from both stdout and stderr.

        Nikto versions differ in where they emit output, so parse the combined
        stream and classify lines deterministically.
        """
        if not stdout and not stderr:
            return ParsedOutput(
                parser_error="nikto produced no output",
                confidence=0.0,
            )

        findings: list[dict[str, Any]] = []
        execution_hints: list[dict[str, Any]] = []

        combined_text = "\n".join(
            part for part in [stdout.decode(errors="replace"), stderr.decode(errors="replace")] if part
        )

        for line in combined_text.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue

            message = line.lstrip("+ ")
            lower_message = message.lower()

            # Detect tool errors as execution hints, not vulnerabilities
            if "invalid output format" in lower_message:
                execution_hints.append(
                    normalize_execution_hint(
                        code="output_format_invalid",
                        message=message,
                        severity="warning",
                        recommended_action="Nikto does not support the requested output format; use native text parsing.",
                    )
                )
                continue

            if "error" in lower_message:
                execution_hints.append(
                    normalize_execution_hint(
                        code="execution_error",
                        message=message,
                        severity="warning",
                        recommended_action="Review nikto execution; tool may not have completed successfully.",
                    )
                )
                continue

            # Skip informational banner/progress lines to reduce noise.
            if lower_message.startswith((
                "target ip:",
                "target hostname:",
                "target port:",
                "start time:",
                "end time:",
                "server:",
                "no banner retrieved",
                "no cgi directories found",
            )):
                continue

            # Extract OSVDB reference and build finding
            osvdb_match = _OSVDB_RE.search(message)
            ref = (
                f"OSVDB-{osvdb_match.group(1)}" if osvdb_match else "nikto-finding"
            )

            if not any(
                marker in lower_message
                for marker in (
                    "osvdb-",
                    "might be interesting",
                    "contains",
                    "header",
                    "robots.txt",
                    "file/dir",
                    "returned a non-forbidden",
                )
            ):
                continue

            findings.append(
                {
                    "title": message,
                    "vuln_ref": ref,
                    "severity": "medium",
                }
            )

        if not findings and not execution_hints:
            return ParsedOutput(
                parser_error="nikto: no parseable findings or diagnostics in output",
                confidence=0.2,
            )

        return ParsedOutput(
            findings=findings,
            execution_hints=execution_hints,
            new_findings_count=len(findings),
            confidence=0.7 if findings else 0.5,
            raw_summary=f"Nikto: {len(findings)} finding(s), {len(execution_hints)} hint(s)",
        )
