"""
Nikto adapter — web server vulnerability scanner.

Risk class: active_scan
Input:  target host or URL, port, ssl, maxtime, tuning class
Output: list of findings with OSVDB/CVE references

Attempts to parse JSON output from ``nikto -Format json -output /dev/stdout``.
Falls back to text-line parsing (lines starting with '+') for older Nikto builds
that do not support JSON-to-stdout.
"""
from __future__ import annotations

import json
import re
from typing import Any

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

    Uses ``-Format json -output /dev/stdout`` for structured output.
    Falls back to text parsing when JSON is unavailable.
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
        """Build nikto command list — no shell interpolation (ADR-002)."""
        cmd = [
            "nikto",
            "-host", params.target,
            "-port", str(params.extra["port"]),
            "-maxtime", str(params.extra["maxtime"]),
            "-Format", "json",
            "-output", "/dev/stdout",
            "-nointeractive",
        ]
        if params.extra.get("ssl"):
            cmd.append("-ssl")
        tuning = params.extra.get("tuning", "x")
        if tuning and tuning != "x":
            cmd.extend(["-Tuning", tuning])
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        if not stdout and not stderr:
            return ParsedOutput(
                parser_error="nikto produced no output",
                confidence=0.0,
            )

        findings: list[dict[str, Any]] = []
        raw = stdout.decode(errors="replace").strip()

        # --- Attempt JSON parse (nikto -Format json) ---
        try:
            data = json.loads(raw)
            for vuln in data.get("vulnerabilities", []):
                osvdb = str(vuln.get("OSVDB", "0"))
                ref = f"OSVDB-{osvdb}" if osvdb and osvdb != "0" else "nikto-finding"
                findings.append(
                    {
                        "title": vuln.get("msg", ""),
                        "url": vuln.get("url", ""),
                        "method": vuln.get("method", "GET"),
                        "osvdb": osvdb,
                        "vuln_ref": ref,
                        "severity": "medium",
                    }
                )
            return ParsedOutput(
                findings=findings,
                new_findings_count=len(findings),
                confidence=0.85 if findings else 0.6,
                raw_summary=f"Nikto JSON scan: {len(findings)} finding(s)",
            )
        except (json.JSONDecodeError, KeyError):
            pass

        # --- Fallback: text output (lines starting with '+') ---
        for line in (stdout + stderr).decode(errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            osvdb_match = _OSVDB_RE.search(line)
            ref = (
                f"OSVDB-{osvdb_match.group(1)}" if osvdb_match else "nikto-finding"
            )
            findings.append(
                {
                    "title": line.lstrip("+ "),
                    "vuln_ref": ref,
                    "severity": "medium",
                }
            )

        if not findings:
            return ParsedOutput(
                parser_error="nikto: no parseable findings in output",
                confidence=0.3,
            )

        return ParsedOutput(
            findings=findings,
            new_findings_count=len(findings),
            confidence=0.7,
            raw_summary=f"Nikto text parse: {len(findings)} finding(s)",
        )
