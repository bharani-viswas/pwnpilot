"""
WhatWeb adapter — web application technology fingerprinting.

Risk class: recon_passive
Input:  target URL, aggression level (1=stealthy, 3=aggressive)
Output: list of detected technologies with name, version, and confidence score

Uses ``--log-json=-`` which writes JSONL directly to stdout — no temp files required.
"""
from __future__ import annotations

import json
import re
from typing import Any

from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

# Allow http/https URLs only
_SAFE_URL_RE = re.compile(r"^https?://[a-zA-Z0-9.\-:/\[\]_@%?&=#]+$")

_ALLOWED_AGGRESSION = frozenset({1, 2, 3})


class WhatWebAdapter(BaseAdapter):
    """
    Adapter for WhatWeb technology fingerprinting.

    Aggression levels:
        1 — stealthy (one request per URL, recommended)
        2 — unaggressive (follow interesting links)
        3 — aggressive (follow all links)
    """

    _MANIFEST = PluginManifest(
        name="whatweb",
        version="0.5.x",
        risk_class="recon_passive",
        description="Web application technology fingerprinting",
        input_schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string"},
                "aggression": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3,
                    "default": 1,
                    "description": "Aggression level: 1=stealthy, 2=unaggressive, 3=aggressive",
                },
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "services": {"type": "array"},
            },
        },
    )

    @property
    def manifest(self) -> PluginManifest:
        return self._MANIFEST

    def validate_params(self, params: dict[str, Any]) -> ToolParams:
        target = str(params.get("target", "")).strip()
        if not target:
            raise ValueError("whatweb: 'target' parameter is required.")
        if not _SAFE_URL_RE.match(target):
            raise ValueError(
                f"whatweb: target must be a valid http/https URL, got: {target!r}"
            )

        aggression = int(params.get("aggression", 1))
        if aggression not in _ALLOWED_AGGRESSION:
            raise ValueError(
                f"whatweb: aggression must be 1, 2, or 3; got {aggression}"
            )

        return ToolParams(
            target=target,
            extra={"aggression": aggression},
        )

    def build_command(self, params: ToolParams) -> list[str]:
        """Build whatweb command list — no shell interpolation (ADR-002)."""
        return [
            "whatweb",
            f"--aggression={params.extra['aggression']}",
            "--log-json=-",     # write JSONL to stdout
            "--no-errors",
            "--quiet",
            params.target,
        ]

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        if exit_code not in (0, 1) or not stdout:
            return ParsedOutput(
                parser_error=(
                    f"whatweb exited with code {exit_code} with no output"
                ),
                confidence=0.0,
            )

        services: list[dict[str, Any]] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            target_url = entry.get("target", "")
            http_status = entry.get("http_status", 0)
            plugins = entry.get("plugins", {})

            techs: list[dict[str, Any]] = []
            for plugin_name, plugin_data in plugins.items():
                raw_conf = plugin_data.get("confidence", [50])
                if isinstance(raw_conf, list):
                    conf = max(raw_conf) if raw_conf else 50
                else:
                    conf = int(raw_conf)

                version_list = plugin_data.get("version", [])
                version_str = (
                    ", ".join(str(v) for v in version_list) if version_list else ""
                )
                techs.append(
                    {
                        "name": plugin_name,
                        "version": version_str,
                        "confidence": round(conf / 100.0, 2),
                    }
                )

            services.append(
                {
                    "url": target_url,
                    "http_status": http_status,
                    "technologies": techs,
                    "service_name": "http",
                }
            )

        tech_count = sum(len(s["technologies"]) for s in services)
        return ParsedOutput(
            services=services,
            # Fingerprinting does not produce vulnerability findings by itself
            new_findings_count=0,
            confidence=0.9 if services else 0.4,
            raw_summary=(
                f"WhatWeb: {tech_count} technology signature(s) across "
                f"{len(services)} target(s)"
            ),
        )
