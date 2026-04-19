"""
Tests for Phase 6A RAG foundation:
  - attack_knowledge.py  (ATT&CK STIX ingestion + lexical index)
  - rag_retriever.py     (dual-mode retrieval, hybrid merge, result schema)
  - RAGConfig in config  (defaults, env overrides, planner injection)
"""
from __future__ import annotations

import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _minimal_stix_bundle(techniques: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Build a minimal valid ATT&CK STIX 2.1 bundle for tests."""
    default_techniques = [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--001",
            "name": "Exploit Public-Facing Application",
            "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            "x_mitre_platforms": ["Windows", "Linux", "macOS"],
            "x_mitre_is_subtechnique": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1190"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--002",
            "name": "SQL Injection",
            "description": "SQL injection allows attackers to manipulate database queries.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            "x_mitre_platforms": ["Windows", "Linux"],
            "x_mitre_is_subtechnique": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1190.001"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--003",
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques to gain access to accounts.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "x_mitre_platforms": ["Windows", "Linux", "macOS"],
            "x_mitre_is_subtechnique": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110"}
            ],
        },
    ]
    objs = techniques if techniques is not None else default_techniques
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "x-mitre-collection",
                "id": "collection--test",
                "x_mitre_version": "16.0",
            },
            *objs,
        ],
    }


@pytest.fixture()
def stix_file(tmp_path: Path) -> Path:
    bundle = _minimal_stix_bundle()
    p = tmp_path / "attack_test.json"
    p.write_text(json.dumps(bundle))
    return p


# ===========================================================================
# test_attack_knowledge.py
# ===========================================================================


class TestLoadAttackKnowledge:
    def test_loads_techniques_from_stix(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        assert "T1190" in kb.techniques
        assert "T1110" in kb.techniques
        assert kb.bundle_version == "16.0"
        assert len(kb.checksum) == 64  # SHA-256 hex

    def test_subtechnique_has_parent_id(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        assert "T1190.001" in kb.techniques
        tech = kb.techniques["T1190.001"]
        assert tech.is_subtechnique is True
        assert tech.parent_id == "T1190"

    def test_returns_empty_kb_when_file_missing(self, tmp_path: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        kb = load_attack_knowledge(tmp_path / "nonexistent.json")
        assert len(kb.techniques) == 0
        assert kb.bundle_version == "unknown"

    def test_returns_empty_kb_on_corrupt_json(self, tmp_path: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ not valid json")
        kb = load_attack_knowledge(bad_file)
        assert len(kb.techniques) == 0

    def test_skips_revoked_techniques(self, tmp_path: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        bundle = _minimal_stix_bundle([
            {
                "type": "attack-pattern",
                "id": "attack-pattern--rev",
                "name": "Old Technique",
                "description": "Revoked",
                "revoked": True,
                "kill_chain_phases": [],
                "x_mitre_platforms": [],
                "x_mitre_is_subtechnique": False,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
            }
        ])
        p = tmp_path / "revoked.json"
        p.write_text(json.dumps(bundle))
        kb = load_attack_knowledge(p)
        assert "T9999" not in kb.techniques

    def test_cache_returns_same_object(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        kb1 = load_attack_knowledge(stix_file)
        kb2 = load_attack_knowledge(stix_file)
        assert kb1 is kb2

    def test_clear_cache_reloads(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        kb1 = load_attack_knowledge(stix_file)
        clear_cache()
        kb2 = load_attack_knowledge(stix_file)
        assert kb1 is not kb2
        assert set(kb1.techniques) == set(kb2.techniques)


class TestAttackKnowledgeBaseQuery:
    def test_query_returns_relevant_technique(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        results = kb.query("SQL injection database exploit")
        tech_ids = [r["technique_id"] for r in results]
        assert "T1190.001" in tech_ids or "T1190" in tech_ids

    def test_query_result_schema(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        results = kb.query("brute force password")
        assert len(results) >= 1
        r = results[0]
        for key in ("technique_id", "name", "tactic", "tactics", "description", "platforms", "score", "url"):
            assert key in r, f"Missing key: {key}"
        assert r["url"].startswith("https://attack.mitre.org/techniques/")

    def test_query_empty_returns_empty(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        assert kb.query("") == []

    def test_query_tactic_filter(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        results = kb.query("brute force", tactic_filter=["credential-access"])
        # All results should be credential-access tactic
        for r in results:
            assert "credential-access" in r["tactics"]

    def test_query_top_k_respected(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        results = kb.query("exploit attack access", top_k=1)
        assert len(results) <= 1

    def test_empty_kb_query_returns_empty(self) -> None:
        from pwnpilot.control.attack_knowledge import AttackKnowledgeBase

        kb = AttackKnowledgeBase(techniques={}, bundle_version="0", checksum="", source_path="")
        kb.build_index()
        assert kb.query("anything") == []


# ===========================================================================
# test_rag_retriever.py
# ===========================================================================


class TestRagRetrieverLexical:
    def test_lexical_returns_attack_kb_results(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge
        from pwnpilot.control.rag_retriever import RagRetriever

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        retriever = RagRetriever(attack_kb=kb, mode="lexical")
        results = retriever.retrieve("SQL injection database")
        assert isinstance(results, list)
        # At least one result expected for a relevant query
        assert len(results) >= 1

    def test_result_schema_complete(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge
        from pwnpilot.control.rag_retriever import RagRetriever

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        retriever = RagRetriever(attack_kb=kb, mode="lexical")
        results = retriever.retrieve("exploit web application")
        assert len(results) >= 1
        for r in results:
            for key in ("technique_id", "tactic", "name", "description", "confidence", "source", "rationale_excerpt"):
                assert key in r, f"Missing key: {key}"
            assert r["source"] == "attack_kb"
            assert 0.0 <= r["confidence"] <= 1.0

    def test_returns_empty_list_on_error(self) -> None:
        from pwnpilot.control.rag_retriever import RagRetriever

        retriever = RagRetriever(attack_kb=None, mode="lexical")
        results = retriever.retrieve("anything")
        assert results == []

    def test_no_exception_on_bad_engagement_id(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge
        from pwnpilot.control.rag_retriever import RagRetriever

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        retriever = RagRetriever(attack_kb=kb, mode="lexical", enable_internal_history=True)
        # Passing a bad engagement_id should not raise
        results = retriever.retrieve("exploit", engagement_id=None)
        assert isinstance(results, list)

    def test_top_k_limits_results(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge
        from pwnpilot.control.rag_retriever import RagRetriever

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        retriever = RagRetriever(attack_kb=kb, mode="lexical", top_k=1)
        results = retriever.retrieve("exploit access attack brute force SQL injection")
        assert len(results) <= 1


class TestRagRetrieverEmbeddingDegradation:
    def test_embedding_mode_degrades_to_lexical_without_router(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge
        from pwnpilot.control.rag_retriever import RagRetriever

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        # No embedding_router → should degrade to lexical silently
        retriever = RagRetriever(attack_kb=kb, mode="embedding", embedding_router=None)
        assert retriever._mode == "lexical"
        results = retriever.retrieve("SQL injection")
        assert isinstance(results, list)

    def test_hybrid_mode_degrades_to_lexical_without_router(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge
        from pwnpilot.control.rag_retriever import RagRetriever

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        retriever = RagRetriever(attack_kb=kb, mode="hybrid", embedding_router=None)
        assert retriever._mode == "lexical"

    def test_embedding_mode_with_mock_router(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge
        from pwnpilot.control.rag_retriever import RagRetriever

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        mock_router = MagicMock()
        # embed() returns a fixed vector
        mock_router.embed.return_value = [0.1] * 8
        # embed_many() returns a list of vectors (one per text)
        mock_router.embed_many.return_value = [[0.1] * 8, [0.2] * 8, [0.3] * 8]

        retriever = RagRetriever(attack_kb=kb, mode="embedding", embedding_router=mock_router)
        assert retriever._mode == "embedding"
        results = retriever.retrieve("SQL injection")
        assert isinstance(results, list)


class TestRagRetrieverWithHistory:
    def test_history_results_included(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge
        from pwnpilot.control.rag_retriever import RagRetriever

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        mock_store = MagicMock()
        mock_store.query.return_value = [
            {"title": "Found SQLi", "body": "SQLi at /login endpoint", "score": 0.9}
        ]
        retriever = RagRetriever(
            retrieval_store=mock_store,
            attack_kb=kb,
            mode="lexical",
            enable_internal_history=True,
        )
        engagement_id = UUID("12345678-1234-5678-1234-567812345678")
        results = retriever.retrieve("SQL injection", engagement_id=engagement_id)
        assert any(r["source"] == "engagement_history" for r in results)

    def test_history_disabled(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache, load_attack_knowledge
        from pwnpilot.control.rag_retriever import RagRetriever

        clear_cache()
        kb = load_attack_knowledge(stix_file)
        mock_store = MagicMock()
        retriever = RagRetriever(
            retrieval_store=mock_store,
            attack_kb=kb,
            mode="lexical",
            enable_internal_history=False,
        )
        engagement_id = UUID("12345678-1234-5678-1234-567812345678")
        retriever.retrieve("SQL injection", engagement_id=engagement_id)
        mock_store.query.assert_not_called()


class TestBuildRagRetriever:
    def test_disabled_rag_returns_empty_retriever(self, stix_file: Path) -> None:
        from pwnpilot.control.rag_retriever import RagRetriever, build_rag_retriever

        class FakeCfg:
            enabled = False
            mode = "lexical"
            top_k = 5
            min_confidence = 0.01
            attack_stix_path = str(stix_file)
            enable_internal_history = True

        retriever = build_rag_retriever(FakeCfg())
        assert isinstance(retriever, RagRetriever)
        # Should return empty results
        results = retriever.retrieve("SQL injection")
        assert results == []

    def test_enabled_rag_builds_retriever(self, stix_file: Path) -> None:
        from pwnpilot.control.attack_knowledge import clear_cache
        from pwnpilot.control.rag_retriever import RagRetriever, build_rag_retriever

        clear_cache()

        class FakeCfg:
            enabled = True
            mode = "lexical"
            top_k = 3
            min_confidence = 0.01
            attack_stix_path = str(stix_file)
            enable_internal_history = False

        retriever = build_rag_retriever(FakeCfg())
        assert isinstance(retriever, RagRetriever)
        assert retriever._top_k == 3
        assert retriever._mode == "lexical"


# ===========================================================================
# RAGConfig in PwnpilotConfig
# ===========================================================================


class TestRAGConfig:
    def test_rag_config_defaults(self) -> None:
        from pwnpilot.config import PwnpilotConfig

        cfg = PwnpilotConfig()
        assert cfg.rag.enabled is True
        assert cfg.rag.mode == "lexical"
        assert cfg.rag.top_k == 5
        assert cfg.rag.min_confidence == 0.01
        assert cfg.rag.attack_stix_path == ""
        assert cfg.rag.enable_internal_history is True

    def test_rag_config_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from pwnpilot.config import PwnpilotConfig, _apply_env_overrides

        monkeypatch.setenv("PWNPILOT_RAG__ENABLED", "false")
        monkeypatch.setenv("PWNPILOT_RAG__MODE", "hybrid")
        monkeypatch.setenv("PWNPILOT_RAG__TOP_K", "10")

        raw = _apply_env_overrides({})
        cfg = PwnpilotConfig(**raw)
        assert cfg.rag.enabled is False
        assert cfg.rag.mode == "hybrid"
        assert cfg.rag.top_k == 10

    def test_rag_config_from_yaml(self, tmp_path: Path) -> None:
        import yaml
        from pwnpilot.config import load_config

        data = {
            "rag": {
                "enabled": True,
                "mode": "embedding",
                "top_k": 8,
                "min_confidence": 0.05,
                "attack_stix_path": "/opt/attack.json",
                "enable_internal_history": False,
            }
        }
        f = tmp_path / "config.yaml"
        f.write_text(yaml.dump(data))
        cfg = load_config(config_path=f)
        assert cfg.rag.mode == "embedding"
        assert cfg.rag.top_k == 8
        assert cfg.rag.attack_stix_path == "/opt/attack.json"
        assert cfg.rag.enable_internal_history is False


# ===========================================================================
# Planner rag_context injection
# ===========================================================================


class TestPlannerRagContextInjection:
    def _make_planner(self, rag_retriever=None, retrieval_store=None):
        from pwnpilot.agent.planner import PlannerNode

        mock_llm = MagicMock()
        mock_llm.complete.return_value = json.dumps({
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "target": "http://localhost",
            "params": {},
            "rationale": "Initial recon",
            "estimated_risk": "low",
        })
        return PlannerNode(
            llm_router=mock_llm,
            engagement_summary={"engagement_id": "12345678-1234-5678-1234-567812345678"},
            rag_retriever=rag_retriever,
            retrieval_store=retrieval_store,
        )

    def test_rag_retriever_is_called_by_planner(self) -> None:
        """RagRetriever.retrieve() should be invoked each planning iteration."""
        mock_rag = MagicMock()
        mock_rag.retrieve.return_value = [
            {
                "technique_id": "T1190",
                "tactic": "initial-access",
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries exploit weaknesses",
                "confidence": 0.85,
                "source": "attack_kb",
                "rationale_excerpt": "Adversaries exploit weaknesses",
            }
        ]
        planner = self._make_planner(rag_retriever=mock_rag)

        state = {
            "engagement_id": "12345678-1234-5678-1234-567812345678",
            "iteration_count": 1,
            "recon_summary": "Web application running on port 80 with SQL database",
            "previous_actions": [],
            "kill_switch": False,
        }
        planner(state)
        mock_rag.retrieve.assert_called_once()

    def test_no_rag_retriever_does_not_crash(self) -> None:
        planner = self._make_planner(rag_retriever=None)

        state = {
            "engagement_id": "12345678-1234-5678-1234-567812345678",
            "iteration_count": 1,
            "recon_summary": "Port 80 open",
            "previous_actions": [],
            "kill_switch": False,
        }
        # Should not raise
        result = planner(state)
        assert result is not None
