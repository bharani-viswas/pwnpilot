"""
Dynamic specialist router (Phase 6D).
"""
from __future__ import annotations

from typing import Any


_SPECIALISTS = {"recon", "injection", "auth_session"}


class SpecialistRouter:
    def select_profile(
        self,
        graph_snapshot: dict[str, Any],
        objective_focus: dict[str, Any] | None,
        rag_context: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        objective = objective_focus or {}
        rag = rag_context or []
        obj_text = f"{objective.get('title', '')} {objective.get('description', '')}".lower()

        if any("credential" in str(item.get("tactic", "")) for item in rag) or "auth" in obj_text:
            return {
                "specialist_profile": "auth_session",
                "confidence": 0.72,
                "rationale": "Objective and retrieval context indicate auth/session pathway.",
            }

        if any(
            kw in obj_text
            for kw in ["sqli", "sql injection", "xss", "injection", "deserialization"]
        ) or any(
            "injection" in str(item.get("name", "")).lower() for item in rag
        ):
            return {
                "specialist_profile": "injection",
                "confidence": 0.78,
                "rationale": "Objective/retrieval context prioritizes injection exploitation path.",
            }

        if int(graph_snapshot.get("finding_count", 0) or 0) == 0:
            return {
                "specialist_profile": "recon",
                "confidence": 0.8,
                "rationale": "Low evidence state favors recon specialist to expand attack surface.",
            }

        return {
            "specialist_profile": "recon",
            "confidence": 0.6,
            "rationale": "Defaulting to recon specialist due to mixed signals.",
        }
