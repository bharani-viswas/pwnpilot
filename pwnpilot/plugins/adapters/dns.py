"""
DNS adapter — DNS record lookups and zone enumeration.

Risk class: recon_passive
Input:  target (domain name), record_type (A/AAAA/MX/NS/TXT/CNAME/SOA/ANY)
Output: list of DNS records with type, name, and value fields

Uses Python's built-in ``socket`` module for simple A/AAAA queries and
the system ``dig`` binary for all other record types.  ``dig`` output is
parsed in its default text format.

Security note: target is validated against a strict allowlist regex before
being passed to the ``dig`` subprocess argument list (ADR-002).
"""
from __future__ import annotations

import re
import socket
from typing import Any

from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

# Allow only safe target characters for domain names and IPs
_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9.\-_]+$")

_ALLOWED_RECORD_TYPES = frozenset(
    {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "ANY"}
)

# Parse dig ANSWER SECTION lines: name TTL class type value
_DIG_RECORD_RE = re.compile(
    r"^(\S+)\s+(\d+)\s+IN\s+(\w+)\s+(.+)$"
)


class DnsAdapter(BaseAdapter):
    """
    Adapter for DNS lookups using system dig.
    """

    _MANIFEST = PluginManifest(
        name="dns",
        version="1.0",
        risk_class="recon_passive",
        description="DNS record lookup (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV)",
        input_schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain name or IP address",
                },
                "record_type": {
                    "type": "string",
                    "enum": list(_ALLOWED_RECORD_TYPES),
                    "default": "A",
                },
                "resolver": {
                    "type": "string",
                    "description": "Custom DNS resolver IP (optional)",
                    "default": "",
                },
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "records": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name":  {"type": "string"},
                            "ttl":   {"type": "integer"},
                            "type":  {"type": "string"},
                            "value": {"type": "string"},
                        },
                    },
                },
            },
        },
    )

    @property
    def manifest(self) -> PluginManifest:
        return self._MANIFEST

    def validate_params(self, params: dict[str, Any]) -> ToolParams:
        target = str(params.get("target", "")).strip()
        if not target:
            raise ValueError("dns: 'target' parameter is required.")
        if not _SAFE_TARGET_RE.match(target):
            raise ValueError(
                f"dns: target contains unsafe characters: {target!r}. "
                "Only alphanumeric, dots, hyphens, and underscores are allowed."
            )

        record_type = str(params.get("record_type", "A")).upper()
        if record_type not in _ALLOWED_RECORD_TYPES:
            raise ValueError(
                f"dns: record_type {record_type!r} not allowed. "
                f"Allowed: {sorted(_ALLOWED_RECORD_TYPES)}"
            )

        resolver = str(params.get("resolver", "")).strip()
        if resolver and not _SAFE_TARGET_RE.match(resolver):
            raise ValueError(
                f"dns: resolver contains unsafe characters: {resolver!r}"
            )

        return ToolParams(
            target=target,
            extra={"record_type": record_type, "resolver": resolver},
        )

    def build_command(self, params: ToolParams) -> list[str]:
        """Build dig command list — no shell interpolation (ADR-002)."""
        record_type = params.extra.get("record_type", "A")
        resolver = params.extra.get("resolver", "")
        cmd = ["dig", "+noall", "+answer", params.target, record_type]
        if resolver:
            # dig uses @resolver syntax
            cmd = ["dig", "+noall", "+answer", f"@{resolver}", params.target, record_type]
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        """Parse dig ANSWER SECTION output into structured records."""
        raw_stdout = stdout.decode("utf-8", errors="replace")
        records: list[dict[str, Any]] = []

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            match = _DIG_RECORD_RE.match(line)
            if match:
                records.append({
                    "name":  match.group(1).rstrip("."),
                    "ttl":   int(match.group(2)),
                    "type":  match.group(3),
                    "rdata": match.group(4).strip().rstrip("."),
                })

        confidence = 0.9 if records else 0.5
        summary = f"{len(records)} record(s) found"

        return ParsedOutput(
            findings=[{"type": "dns_records", "records": records, "record_count": len(records)}],
            raw_summary=summary,
            confidence=confidence,
        )
