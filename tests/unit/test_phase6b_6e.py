from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

from pwnpilot.control.payload_engine import (
    classify_reflection_outcome,
    generate_payload_candidates,
    mutate_payload,
    preflight_validate_payload,
)
from pwnpilot.control.policy_prior import PolicyPriorScorer
from pwnpilot.control.specialist_router import SpecialistRouter
from pwnpilot.data.task_tree_store import TaskTreeStore


class _StubLLM:
    def plan(self, context: dict[str, Any]) -> dict[str, Any]:
        return {
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "target": "http://localhost",
            "params": {},
            "rationale": "plan",
            "estimated_risk": "low",
        }


class _StubRagRetriever:
    def retrieve(self, query_text: str, engagement_id: UUID | None = None) -> list[dict[str, Any]]:
        return [
            {
                "technique_id": "T1190",
                "tactic": "initial-access",
                "name": "Exploit Public-Facing Application",
                "description": "desc",
                "confidence": 0.88,
                "source": "attack_kb",
                "rationale_excerpt": "desc",
            }
        ]


def test_task_tree_store_lifecycle(tmp_path: Path) -> None:
    from pwnpilot.runtime import get_db_session

    # Dedicated sqlite file for this test
    db_path = tmp_path / "phase6b_test.db"
    db_cfg = tmp_path / "cfg.yaml"
    db_cfg.write_text(f"database:\n  url: sqlite:///{db_path}\n")
    session = get_db_session(config_path=db_cfg)
    store = TaskTreeStore(session)
    eng = UUID("12345678-1234-5678-1234-567812345678")

    node_id = store.create_node(
        engagement_id=eng,
        objective_id="obj-1",
        tactic="initial-access",
        target_asset="http://localhost",
        current_hypothesis="Try web exploit",
        confidence=0.6,
    )
    assert node_id

    assert store.advance_node(node_id, "in_progress", confidence=0.75) is True
    summary = store.summarize_for_planner(eng)
    assert summary["in_progress_count"] >= 1

    assert store.invalidate_node(node_id, "no_attack_surface") is True


def test_payload_engine_generation_and_reflection() -> None:
    candidates = generate_payload_candidates("sqli", target="http://localhost/login", max_candidates=3)
    assert len(candidates) >= 1
    payload = candidates[0]["payload"]

    ok, reason = preflight_validate_payload(payload, "sqli", roe_disallow_patterns=["drop table"])
    assert ok is True
    assert reason == "ok"

    outcome = classify_reflection_outcome(
        stdout="WAF blocked request with 403",
        stderr="",
        exit_code=0,
    )
    assert outcome == "likely_blocked_by_waf"

    mutated = mutate_payload(payload, round_idx=1)
    assert mutated
    assert mutated != payload


def test_specialist_router_selection() -> None:
    router = SpecialistRouter()
    decision = router.select_profile(
        graph_snapshot={"finding_count": 0},
        objective_focus={"title": "Test SQL injection path"},
        rag_context=[{"name": "SQL injection", "tactic": "initial-access"}],
    )
    assert decision["specialist_profile"] == "injection"
    assert 0.0 <= decision["confidence"] <= 1.0


def test_policy_prior_scorer(tmp_path: Path) -> None:
    stats_file = tmp_path / "policy_stats.json"
    stats_file.write_text(json.dumps({"tool_success_rate": {"nmap": 0.9}}))

    scorer = PolicyPriorScorer(enabled=True, policy_file=str(stats_file))
    score = scorer.score({"tool_name": "nmap", "action_type": "recon_passive"}, {})
    assert score >= 0.85


def test_planner_enriches_proposal_with_phase_metadata() -> None:
    from pwnpilot.agent.planner import PlannerNode

    class _StubTaskTree:
        def summarize_for_planner(self, engagement_id: UUID, limit: int = 8) -> dict[str, Any]:
            return {"open_nodes": [{"node_id": "n1", "node_state": "open"}], "open_count": 1}

    class _StubSpecialist:
        def select_profile(self, graph_snapshot: dict[str, Any], objective_focus: dict[str, Any] | None, rag_context: list[dict[str, Any]] | None) -> dict[str, Any]:
            return {
                "specialist_profile": "injection",
                "confidence": 0.77,
                "rationale": "injection pathway",
            }

    class _StubPolicyPrior:
        def score(self, proposal: dict[str, Any], state: dict[str, Any]) -> float:
            return 0.66

    planner = PlannerNode(
        llm_router=_StubLLM(),
        engagement_summary={"engagement_id": "12345678-1234-5678-1234-567812345678"},
        rag_retriever=_StubRagRetriever(),
        task_tree_store=_StubTaskTree(),
        specialist_router=_StubSpecialist(),
        policy_prior=_StubPolicyPrior(),
        retrieval_store=None,
    )

    state = {
        "engagement_id": "12345678-1234-5678-1234-567812345678",
        "iteration_count": 0,
        "recon_summary": "web target",
        "previous_actions": [],
        "kill_switch": False,
    }
    out = planner(state)
    proposal = out.get("proposed_action") or {}
    assert proposal.get("attack_technique_ids") == ["T1190"]
    assert proposal.get("retrieval_sources") == ["attack_kb"]
    assert proposal.get("specialist_profile") == "injection"
    assert proposal.get("policy_prior_score") == 0.66


def test_specialist_profile_pivots_tool_behavior() -> None:
    from pwnpilot.agent.planner import PlannerNode

    class _LLMProposesReconTool:
        def plan(self, context: dict[str, Any]) -> dict[str, Any]:
            return {
                "action_type": "active_scan",
                "tool_name": "whatweb",
                "target": "http://localhost",
                "params": {},
                "rationale": "baseline recon",
                "estimated_risk": "low",
            }

    class _InjectionSpecialist:
        def select_profile(self, graph_snapshot: dict[str, Any], objective_focus: dict[str, Any] | None, rag_context: list[dict[str, Any]] | None) -> dict[str, Any]:
            return {
                "specialist_profile": "injection",
                "confidence": 0.9,
                "rationale": "injection route preferred",
            }

    planner = PlannerNode(
        llm_router=_LLMProposesReconTool(),
        engagement_summary={"engagement_id": "12345678-1234-5678-1234-567812345678"},
        available_tools=["whatweb", "sqlmap", "nuclei", "zap"],
        specialist_router=_InjectionSpecialist(),
    )

    state = {
        "engagement_id": "12345678-1234-5678-1234-567812345678",
        "iteration_count": 0,
        "recon_summary": "Likely SQL injection target",
        "previous_actions": [],
        "kill_switch": False,
    }

    out = planner(state)
    proposal = out.get("proposed_action") or {}
    assert proposal.get("specialist_profile") == "injection"
    assert proposal.get("tool_name") in {"sqlmap", "zap", "nuclei"}
