"""
Whois adapter — domain and IP registration lookups.

Risk class: recon_passive
Input:  target (domain name or IP address)
Output: parsed whois fields (registrar, creation_date, expiry_date, name_servers,
        registrant, abuse_contact, raw_text)

Uses the system ``whois`` binary.  Output is text and is parsed with regex
heuristics covering common whois formats (ARIN, RIPE, APNIC, verisign, etc.).
"""
from __future__ import annotations

import re
from typing import Any

from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

# Allow only safe target characters: alphanumeric, dots, hyphens (domain / IPv4 / IPv6)
_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9.\-:\[\]]+$")

# Regex patterns for common whois field extraction
_FIELD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("registrar",       re.compile(r"(?:Registrar|registrar):\s*(.+)", re.IGNORECASE)),
    ("creation_date",   re.compile(r"(?:Creation Date|created|registered):\s*(.+)", re.IGNORECASE)),
    ("expiry_date",     re.compile(r"(?:Expir(?:y|ation) Date|expires|paid-till):\s*(.+)", re.IGNORECASE)),
    ("updated_date",    re.compile(r"(?:Updated Date|last-modified|changed):\s*(.+)", re.IGNORECASE)),
    ("registrant",      re.compile(r"(?:Registrant(?:\s+Name)?|org):\s*(.+)", re.IGNORECASE)),
    ("abuse_contact",   re.compile(r"(?:Abuse Contact Email|OrgAbuse|abuse-mailbox):\s*(.+)", re.IGNORECASE)),
]
_NS_PATTERN = re.compile(r"(?:Name Server|nserver|nameserver):\s*(\S+)", re.IGNORECASE)


class WhoisAdapter(BaseAdapter):
    """
    Adapter for the system whois command.
    """

    _MANIFEST = PluginManifest(
        name="whois",
        version="5.x",
        risk_class="recon_passive",
        description="Domain and IP WHOIS registration lookup",
        input_schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain name or IP address to look up",
                },
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "registrar":      {"type": "string"},
                "creation_date":  {"type": "string"},
                "expiry_date":    {"type": "string"},
                "updated_date":   {"type": "string"},
                "registrant":     {"type": "string"},
                "abuse_contact":  {"type": "string"},
                "name_servers":   {"type": "array", "items": {"type": "string"}},
                "raw":            {"type": "string"},
            },
        },
    )

    @property
    def manifest(self) -> PluginManifest:
        return self._MANIFEST

    def validate_params(self, params: dict[str, Any]) -> ToolParams:
        target = str(params.get("target", "")).strip()
        if not target:
            raise ValueError("whois: 'target' parameter is required.")
        if not _SAFE_TARGET_RE.match(target):
            raise ValueError(
                f"whois: target contains unsafe characters: {target!r}. "
                "Only alphanumeric characters, dots, hyphens, and colons are allowed."
            )
        return ToolParams(target=target)

    def build_command(self, params: ToolParams) -> list[str]:
        """Build whois command list (no shell interpolation)."""
        return ["whois", params.target]

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        """
        Parse whois text output into structured fields.
        Handles multiple common whois server formats via regex heuristics.
        """
        raw_stdout = stdout.decode("utf-8", errors="replace")
        result: dict[str, Any] = {
            "registrar": "",
            "creation_date": "",
            "expiry_date": "",
            "updated_date": "",
            "registrant": "",
            "abuse_contact": "",
            "name_servers": [],
            "raw": raw_stdout[:4096],  # cap raw output at 4 KB
        }

        for field_name, pattern in _FIELD_PATTERNS:
            match = pattern.search(raw_stdout)
            if match:
                result[field_name] = match.group(1).strip()

        # Name servers — can appear multiple times
        ns_matches = _NS_PATTERN.findall(raw_stdout)
        result["name_servers"] = sorted(set(ns.lower() for ns in ns_matches))

        confidence = 0.8 if result["registrar"] or result["creation_date"] else 0.4

        return ParsedOutput(
            findings=[{"type": "whois_record", "data": result}],
            raw_summary=raw_stdout[:512],
            confidence=confidence,
        )
