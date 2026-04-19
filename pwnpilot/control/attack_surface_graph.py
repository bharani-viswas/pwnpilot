"""
Attack-surface graph model (Phase 6D).

Lightweight in-memory graph keyed by engagement_id.
Tracks assets/interfaces/findings/hypotheses for specialist routing.
"""
from __future__ import annotations

import threading
from typing import Any


class AttackSurfaceGraphStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._graphs: dict[str, dict[str, Any]] = {}

    def _ensure(self, engagement_id: str) -> dict[str, Any]:
        g = self._graphs.get(engagement_id)
        if g is None:
            g = {
                "assets": set(),
                "interfaces": set(),
                "parameters": set(),
                "identities": set(),
                "findings": [],
                "hypotheses": [],
            }
            self._graphs[engagement_id] = g
        return g

    def update_from_execution(
        self,
        engagement_id: str,
        parsed_output: dict[str, Any] | None,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        with self._lock:
            g = self._ensure(engagement_id)
            data = parsed_output or {}
            for host in data.get("hosts", []) if isinstance(data, dict) else []:
                ip = str(host.get("ip", "")).strip()
                if ip:
                    g["assets"].add(ip)
                hostname = str(host.get("hostname", "")).strip()
                if hostname:
                    g["assets"].add(hostname)
            for endpoint in data.get("endpoints", []) if isinstance(data, dict) else []:
                g["interfaces"].add(str(endpoint).strip())
            for finding in (findings or []):
                title = str(finding.get("title", "")).strip()
                if title:
                    g["findings"].append({
                        "title": title,
                        "severity": str(finding.get("severity", "")).strip(),
                        "asset_ref": str(finding.get("asset_ref", "")).strip(),
                    })

    def add_hypothesis(self, engagement_id: str, hypothesis: str, confidence: float = 0.5) -> None:
        with self._lock:
            g = self._ensure(engagement_id)
            g["hypotheses"].append({
                "hypothesis": str(hypothesis).strip(),
                "confidence": max(0.0, min(1.0, float(confidence))),
            })

    def snapshot(self, engagement_id: str) -> dict[str, Any]:
        with self._lock:
            g = self._ensure(engagement_id)
            return {
                "asset_count": len(g["assets"]),
                "interface_count": len(g["interfaces"]),
                "finding_count": len(g["findings"]),
                "hypothesis_count": len(g["hypotheses"]),
                "assets": sorted(g["assets"]),
                "interfaces": sorted(g["interfaces"]),
                "findings": list(g["findings"][-20:]),
                "hypotheses": list(g["hypotheses"][-20:]),
            }
