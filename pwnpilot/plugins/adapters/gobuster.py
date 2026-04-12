"""
gobuster adapter — directory and DNS enumeration.

Risk class: active_scan
Input: target URL/domain, mode (dir|dns), wordlist and scan controls
Output: list of discovered paths/subdomains
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from pwnpilot.plugins.parsers.contracts import normalize_execution_hint
from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

_SAFE_PATH_RE = re.compile(r"^[a-zA-Z0-9_./\-]+$")
_SAFE_EXT_RE = re.compile(r"^[a-zA-Z0-9,]+$")
_SAFE_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]+$")

_DIR_LINE_RE = re.compile(
    r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d{3})\)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
)
_DNS_LINE_RE = re.compile(r"^Found:\s*(?P<host>[a-zA-Z0-9.-]+)\s*$")


class GobusterAdapter(BaseAdapter):
    """Adapter for gobuster directory and DNS enumeration."""

    _MANIFEST = PluginManifest(
        name="gobuster",
        version="3.x",
        risk_class="active_scan",
        description="Directory and DNS brute-force discovery scanner",
        input_schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "mode": {
                    "type": "string",
                    "enum": ["dir", "dns"],
                    "default": "dir",
                },
                "wordlist": {
                    "type": "string",
                    "default": "/home/viswas/pwnpilot/wordlists/dirb/common.txt",
                },
                "extensions": {
                    "type": "string",
                    "default": "",
                    "description": "Comma-separated extension list, dir mode only",
                },
                "threads": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 20,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 120,
                    "default": 10,
                },
            },
            "x_supported_target_types": ["ip", "domain", "url"],
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
        mode = str(params.get("mode", "dir")).strip().lower()
        if mode not in {"dir", "dns"}:
            raise ValueError("gobuster: mode must be 'dir' or 'dns'.")

        target = str(params.get("target", "")).strip()
        if not target:
            raise ValueError("gobuster: 'target' parameter is required.")

        if mode == "dir":
            parsed = urlparse(target)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(
                    f"gobuster: dir mode requires a valid http/https URL target, got: {target!r}"
                )
        else:
            if "://" in target or not _SAFE_DOMAIN_RE.match(target):
                raise ValueError(
                    f"gobuster: dns mode requires a valid domain target, got: {target!r}"
                )

        wordlist = str(
            params.get("wordlist", "/home/viswas/pwnpilot/wordlists/dirb/common.txt")
        ).strip()
        if not wordlist or not _SAFE_PATH_RE.match(wordlist):
            raise ValueError(f"gobuster: invalid wordlist path: {wordlist!r}")

        extensions = str(params.get("extensions", "")).strip()
        if extensions and not _SAFE_EXT_RE.match(extensions):
            raise ValueError(
                f"gobuster: extensions must be comma-separated alphanumeric values, got: {extensions!r}"
            )

        threads = int(params.get("threads", 20))
        if not 1 <= threads <= 50:
            raise ValueError(f"gobuster: threads must be 1-50, got {threads}")

        timeout_seconds = int(params.get("timeout_seconds", 10))
        if not 1 <= timeout_seconds <= 120:
            raise ValueError(
                f"gobuster: timeout_seconds must be 1-120, got {timeout_seconds}"
            )

        return ToolParams(
            target=target,
            extra={
                "mode": mode,
                "wordlist": wordlist,
                "extensions": extensions,
                "threads": threads,
                "timeout_seconds": timeout_seconds,
            },
        )

    def build_command(self, params: ToolParams) -> list[str]:
        mode = str(params.extra["mode"])
        cmd = [
            "gobuster",
            "-m",
            mode,
            "-w",
            str(params.extra["wordlist"]),
            "-t",
            str(params.extra["threads"]),
            "-to",
            f"{params.extra['timeout_seconds']}s",
            "-q",
            "-np",
        ]

        if mode == "dir":
            cmd.extend(["-u", params.target])
            extensions = str(params.extra.get("extensions", ""))
            if extensions:
                cmd.extend(["-x", extensions])
        else:
            cmd.extend(["-d", params.target])

        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        if exit_code not in (0, 1):
            return ParsedOutput(
                parser_error=f"gobuster exited with code {exit_code}",
                confidence=0.0,
            )

        lines = (stdout + b"\n" + stderr).decode(errors="replace").splitlines()
        findings: list[dict[str, Any]] = []
        execution_hints: list[dict[str, Any]] = []

        for raw in lines:
            line = raw.strip()
            if not line:
                continue

            if "wildcard response found" in line.lower():
                execution_hints.append(
                    normalize_execution_hint(
                        code="wildcard_detected",
                        message=line,
                        severity="warning",
                        recommended_action="Consider enabling gobuster force-wildcard handling when assessment policy permits.",
                    )
                )
                continue

            if "force processing of wildcard responses" in line.lower():
                continue

            m_dir = _DIR_LINE_RE.match(line)
            if m_dir:
                findings.append(
                    {
                        "title": f"Discovered web path {m_dir.group('path')}",
                        "path": m_dir.group("path"),
                        "status": int(m_dir.group("status")),
                        "size": int(m_dir.group("size")) if m_dir.group("size") else None,
                        "vuln_ref": "gobuster:path-discovery",
                        "severity": "info",
                    }
                )
                continue

            m_dns = _DNS_LINE_RE.match(line)
            if m_dns:
                host = m_dns.group("host")
                findings.append(
                    {
                        "title": f"Discovered subdomain {host}",
                        "hostname": host,
                        "vuln_ref": "gobuster:dns-discovery",
                        "severity": "info",
                    }
                )

        return ParsedOutput(
            findings=findings,
            execution_hints=execution_hints,
            new_findings_count=len(findings),
            confidence=0.85 if findings else 0.6,
            raw_summary=f"gobuster discovered {len(findings)} item(s)",
        )
