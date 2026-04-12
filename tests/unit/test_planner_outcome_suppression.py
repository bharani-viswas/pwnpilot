from __future__ import annotations

from uuid import uuid4

from pwnpilot.agent.planner import PlannerNode


def _base_state() -> dict:
    return {
        "engagement_id": str(uuid4()),
        "kill_switch": False,
        "iteration_count": 1,
        "previous_actions": [],
        "recon_summary": {},
        "temporarily_unavailable_tools": {},
    }


class _RepeatSqlmapLLM:
    def plan(self, context: dict) -> dict:
        return {
            "action_type": "active_scan",
            "tool_name": "sqlmap",
            "target": "http://localhost:3000",
            "params": {"forms": True},
            "rationale": "Try sqlmap again",
            "estimated_risk": "medium",
        }


class _RepeatDnsLLM:
    def plan(self, context: dict) -> dict:
        return {
            "action_type": "active_scan",
            "tool_name": "dns",
            "target": "http://localhost:3000",
            "params": {},
            "rationale": "Try dns again",
            "estimated_risk": "medium",
        }


def test_planner_avoids_recent_low_value_tool_outcome() -> None:
    planner = PlannerNode(
        llm_router=_RepeatSqlmapLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["sqlmap", "nuclei"],
        tools_catalog=[],
    )

    state = {
        **_base_state(),
        "previous_actions": [
            {
                "tool_name": "sqlmap",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["no_forms_detected"],
            }
        ],
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] == "nuclei"


def test_planner_fallback_skips_tools_with_extra_required_params() -> None:
    planner = PlannerNode(
        llm_router=_RepeatSqlmapLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["sqlmap", "cve_enrich", "nuclei"],
        tools_catalog=[
            {
                "tool_name": "cve_enrich",
                "required_params": ["target", "cve_id"],
            },
            {
                "tool_name": "nuclei",
                "required_params": ["target"],
            },
        ],
    )

    state = {
        **_base_state(),
        "previous_actions": [
            {
                "tool_name": "sqlmap",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["no_forms_detected"],
            }
        ],
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] == "nuclei"


def test_planner_fallback_avoids_incompatible_target_types() -> None:
    planner = PlannerNode(
        llm_router=_RepeatSqlmapLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["sqlmap", "dns", "nmap"],
        tools_catalog=[
            {
                "tool_name": "dns",
                "required_params": ["target"],
                "supported_target_types": ["domain"],
            },
            {
                "tool_name": "nmap",
                "required_params": ["target"],
                "supported_target_types": ["ip", "domain", "url", "cidr"],
            },
        ],
    )

    state = {
        **_base_state(),
        "previous_actions": [
            {
                "tool_name": "sqlmap",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["no_forms_detected"],
            }
        ],
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] == "nmap"


def test_validator_reject_adds_tool_cooldown_and_pivots() -> None:
    planner = PlannerNode(
        llm_router=_RepeatDnsLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["dns", "nmap"],
        tools_catalog=[
            {
                "tool_name": "dns",
                "required_params": ["target"],
                "supported_target_types": ["domain"],
            },
            {
                "tool_name": "nmap",
                "required_params": ["target"],
                "supported_target_types": ["ip", "domain", "url", "cidr"],
            },
        ],
    )

    state = {
        **_base_state(),
        "proposed_action": {
            "tool_name": "dns",
            "target": "http://localhost:3000",
            "action_type": "active_scan",
            "params": {},
            "rationale": "previous attempt",
            "estimated_risk": "medium",
        },
        "validation_result": {
            "verdict": "reject",
            "rationale": "Target type 'url' is not supported by tool 'dns'.",
            "risk_override": None,
        },
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] == "nmap"
    assert result["temporarily_unavailable_tools"].get("dns", 0) >= 1
