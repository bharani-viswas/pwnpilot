"""
Searchsploit adapter — ExploitDB CVE / service enrichment.

Risk class: recon_passive
Input:  query string (product + version, or bare CVE ID); optional exact_match flag
Output: list of matching exploits with EDB ID, title, type, and CVE reference

Uses ``searchsploit --json`` which writes JSON to stdout — no temp files required.
This adapter performs offline database lookup only; it does not send any network
traffic to the target.
"""
from __future__ import annotations

import json
import re
from typing import Any

from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

# Allow alphanumeric, hyphens, dots, underscores, spaces — typical CVE IDs and product names
_SAFE_QUERY_RE = re.compile(r"^[a-zA-Z0-9.\-_ /]+$")

# Strict CVE format: CVE-YYYY-NNNNN
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# Extract any CVE references embedded in exploit titles
_CVE_TITLE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


class SearchsploitAdapter(BaseAdapter):
    """
    Adapter for ExploitDB searchsploit tool.

    Performs offline exploit-DB lookups against the local ExploitDB copy installed
    with ``apt install exploitdb``.  No network traffic is generated to the target.
    """

    _MANIFEST = PluginManifest(
        name="searchsploit",
        version="4.x",
        risk_class="recon_passive",
        description="ExploitDB exploit search and CVE enrichment (offline lookup)",
        input_schema={
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Product name + version, keyword, or CVE ID",
                },
                "exact_match": {
                    "type": "boolean",
                    "default": False,
                    "description": "Require exact keyword match",
                },
                "cve": {
                    "type": "string",
                    "default": "",
                    "description": "Optional CVE identifier to look up directly",
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
        # Accept 'query' or 'target' for ActionRequest compatibility
        query = str(params.get("query", params.get("target", ""))).strip()
        if not query:
            raise ValueError("searchsploit: 'query' parameter is required.")
        if not _SAFE_QUERY_RE.match(query):
            raise ValueError(
                f"searchsploit: query contains unsafe characters: {query!r}"
            )

        cve = str(params.get("cve", "")).strip()
        if cve and not _CVE_RE.match(cve):
            raise ValueError(
                f"searchsploit: invalid CVE identifier format: {cve!r}"
            )

        exact_match = bool(params.get("exact_match", False))

        return ToolParams(
            target=query,
            extra={
                "query": query,
                "cve": cve,
                "exact_match": exact_match,
            },
        )

    def build_command(self, params: ToolParams) -> list[str]:
        """Build searchsploit command list — no shell interpolation (ADR-002)."""
        cmd = ["searchsploit", "--json", "--disable-colour"]
        if params.extra.get("exact_match"):
            cmd.append("--exact")
        if params.extra.get("cve"):
            cmd.extend(["--cve", params.extra["cve"]])
        # Split query into tokens; searchsploit ANDs multiple keywords
        cmd.extend(params.extra["query"].split())
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        if exit_code not in (0, 1) or not stdout:
            return ParsedOutput(
                parser_error=f"searchsploit exited with code {exit_code}",
                confidence=0.0,
            )

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            return ParsedOutput(
                parser_error=f"searchsploit: JSON parse error: {exc}",
                confidence=0.0,
            )

        exploits: list[dict[str, Any]] = data.get("RESULTS_EXPLOIT", [])
        shellcodes: list[dict[str, Any]] = data.get("RESULTS_SHELLCODE", [])

        findings: list[dict[str, Any]] = []
        for entry in exploits + shellcodes:
            edb_id = str(entry.get("EDB-ID", ""))
            title = entry.get("Title", "")
            path = entry.get("Path", "")
            date = entry.get("Date", "")
            entry_type = entry.get("Type", "")

            # Prefer CVE ref from title; fall back to EDB ID
            cve_refs = _CVE_TITLE_RE.findall(title)
            vuln_ref = (
                cve_refs[0].upper()
                if cve_refs
                else (f"EDB-{edb_id}" if edb_id else "EDB")
            )

            findings.append(
                {
                    "title": title,
                    "edb_id": edb_id,
                    "path": path,
                    "date": date,
                    "type": entry_type,
                    "vuln_ref": vuln_ref,
                    # Public exploit available → high severity by default
                    "severity": "high",
                }
            )

        return ParsedOutput(
            findings=findings,
            new_findings_count=len(findings),
            confidence=0.9 if findings else 0.7,
            raw_summary=(
                f"searchsploit: {len(exploits)} exploit(s), "
                f"{len(shellcodes)} shellcode(s) found"
            ),
        )
