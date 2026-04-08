"""
CVE Enrichment adapter — live NVD/CVE API lookup.

Risk class: recon_passive
Input:  cve_id (CVE-YYYY-NNNNN format)
Output: CVSS score, severity, description, CWE references, CPE list

Queries the NVD REST API v2 (https://services.nvd.nist.gov/rest/json/cves/2.0).
No traffic is sent to the engagement target — all requests go to NVD.

An optional ``NVD_API_KEY`` environment variable or ``nvd_api_key`` config field
increases the rate limit from 5 req/30s (unauthenticated) to 50 req/30s.

Security note:
- CVE ID is validated against a strict regex before being embedded in the URL.
- The URL is constructed from a fixed base with only the CVE ID appended.
- All network I/O uses the standard `urllib.request` (no third-party HTTP library
  required); TLS verification is always enabled.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

# Strict CVE identifier validation — CVE-YYYY-NNNNN (4–7 digits)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_TIMEOUT_SECONDS = 15


class CveEnrichAdapter(BaseAdapter):
    """
    Adapter for live NVD CVE enrichment lookups.

    ``build_command`` is intentionally unused (no subprocess invoked); the adapter
    performs its own HTTP call inside ``parse``.  This follows the same pattern used
    by adapters that wrap APIs rather than CLI tools.
    """

    _MANIFEST = PluginManifest(
        name="cve_enrich",
        version="nvd-api-v2",
        risk_class="recon_passive",
        description="Live CVE enrichment via NVD REST API v2 (no target traffic)",
        input_schema={
            "type": "object",
            "required": ["cve_id"],
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier (CVE-YYYY-NNNNN)",
                },
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "cve_id":      {"type": "string"},
                "description": {"type": "string"},
                "cvss_score":  {"type": "number"},
                "cvss_vector": {"type": "string"},
                "severity":    {"type": "string"},
                "cwe_ids":     {"type": "array", "items": {"type": "string"}},
                "cpe_list":    {"type": "array", "items": {"type": "string"}},
                "published":   {"type": "string"},
                "modified":    {"type": "string"},
            },
        },
    )

    @property
    def manifest(self) -> PluginManifest:
        return self._MANIFEST

    def validate_params(self, params: dict[str, Any]) -> ToolParams:
        cve_id = str(params.get("cve_id", "")).strip().upper()
        if not cve_id:
            raise ValueError("cve_enrich: 'cve_id' parameter is required.")
        if not _CVE_RE.match(cve_id):
            raise ValueError(
                f"cve_enrich: '{cve_id}' is not a valid CVE identifier. "
                "Expected format: CVE-YYYY-NNNNN"
            )
        return ToolParams(target=cve_id)

    def build_command(self, params: ToolParams) -> list[str]:
        """
        This adapter does not invoke a subprocess.  Return an empty list so the
        runner skips subprocess execution and calls ``parse`` with empty bytes.
        The actual HTTP call is performed inside ``parse``.
        """
        return []

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        """
        Fetch CVE details from the NVD API and return structured enrichment data.

        ``stdout``/``stderr``/``exit_code`` are ignored — this adapter talks directly
        to the NVD API rather than a subprocess.
        """
        # The CVE ID was stored in stdout by the runner framework; fall back to
        # inspecting the params stored during validate_params.  Since BaseAdapter
        # does not carry params across methods, we accept an empty stdout gracefully
        # and return a parser_error.
        cve_id = stdout.decode("utf-8", errors="replace").strip()
        if not cve_id or not _CVE_RE.match(cve_id):
            return ParsedOutput(
                parser_error="cve_enrich: no valid CVE ID available for lookup",
            )
        return self._fetch(cve_id)

    # ------------------------------------------------------------------
    # Internal fetch helper (separated so it can be called with a known CVE ID)
    # ------------------------------------------------------------------

    def enrich(self, cve_id: str) -> ParsedOutput:
        """
        Public entry point for direct enrichment calls (e.g. from the executor or
        correlation engine) without going through the subprocess runner.
        """
        cve_id = cve_id.strip().upper()
        if not _CVE_RE.match(cve_id):
            raise ValueError(f"cve_enrich: invalid CVE ID: {cve_id!r}")
        return self._fetch(cve_id)

    def _fetch(self, cve_id: str) -> ParsedOutput:
        url = f"{_NVD_BASE_URL}?cveId={cve_id}"
        headers: dict[str, str] = {"Accept": "application/json"}
        api_key = os.environ.get("NVD_API_KEY", "")
        if api_key:
            headers["apiKey"] = api_key

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:  # noqa: S310
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return ParsedOutput(parser_error=f"NVD API HTTP {exc.code}: {exc.reason}")
        except Exception as exc:
            return ParsedOutput(parser_error=f"NVD API error: {exc}")

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return ParsedOutput(
                findings=[],
                raw_summary=f"No NVD entry found for {cve_id}",
                confidence=0.0,
            )

        cve_data = vulns[0].get("cve", {})
        return self._parse_cve(cve_id, cve_data)

    @staticmethod
    def _parse_cve(cve_id: str, cve_data: dict[str, Any]) -> ParsedOutput:
        # Description (English preferred)
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            next((d.get("value", "") for d in descriptions), ""),
        )

        # CVSS score + vector (prefer v3.1, fall back to v3.0, then v2)
        metrics = cve_data.get("metrics", {})
        cvss_score: float | None = None
        cvss_vector: str = ""
        severity: str = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                entry = entries[0].get("cvssData", {})
                cvss_score = entry.get("baseScore")
                cvss_vector = entry.get("vectorString", "")
                severity = entry.get("baseSeverity", entries[0].get("baseSeverity", ""))
                break

        # CWE IDs
        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids: list[str] = []
        for w in weaknesses:
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # CPE list (affected products)
        configs = cve_data.get("configurations", [])
        cpe_list: list[str] = []
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    uri = match.get("criteria", "")
                    if uri:
                        cpe_list.append(uri)

        published = cve_data.get("published", "")
        modified = cve_data.get("lastModified", "")

        result = {
            "cve_id":      cve_id,
            "description": description,
            "cvss_score":  cvss_score,
            "cvss_vector": cvss_vector,
            "severity":    severity.lower() if severity else "",
            "cwe_ids":     list(dict.fromkeys(cwe_ids)),
            "cpe_list":    cpe_list[:20],  # cap to 20 CPEs
            "published":   published,
            "modified":    modified,
        }

        confidence = 0.95 if cvss_score is not None else 0.5
        return ParsedOutput(
            findings=[{"type": "cve_enrichment", "data": result}],
            raw_summary=f"{cve_id}: {severity} (CVSS {cvss_score})" if cvss_score else cve_id,
            confidence=confidence,
        )
