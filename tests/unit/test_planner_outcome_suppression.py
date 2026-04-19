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


def test_planner_keeps_sqlmap_params_and_defers_mode_enforcement() -> None:
    planner = PlannerNode(
        llm_router=_RepeatSqlmapLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["sqlmap"],
        tools_catalog=[],
    )

    state = {
        **_base_state(),
        "previous_actions": [
            {
                "tool_name": "sqlmap",
                "target": "http://localhost:3000/login",
                "action_type": "active_scan",
                "execution_hint_codes": ["no_forms_detected"],
            }
        ],
    }

    # LLM proposes root target and forms mode; planner now defers mode enforcement
    # to invocation compilation/executor policy.
    state["proposed_action"] = None
    result = planner(state)
    params = result["proposed_action"].get("params", {})
    assert result["proposed_action"]["tool_name"] == "sqlmap"
    assert params.get("forms") is True


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
                "risk_class": "recon_passive",
                "required_params": ["target"],
                "supported_target_types": ["domain"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "record_type": {"type": "string", "enum": ["A", "AAAA"]},
                },
            },
            {
                "tool_name": "nmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["ip", "domain", "url", "cidr"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "ports": {"type": "string"},
                    "scan_type": {"type": "string"},
                    "timing": {"type": "integer"},
                },
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
    assert result["proposed_action"]["params"] == {}


def test_planner_fallback_skips_risk_class_mismatch_candidates() -> None:
    planner = PlannerNode(
        llm_router=_RepeatSqlmapLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["sqlmap", "whatweb", "nmap"],
        tools_catalog=[
            {
                "tool_name": "whatweb",
                "risk_class": "recon_passive",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "aggression": {"type": "integer"},
                },
            },
            {
                "tool_name": "nmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["ip", "domain", "url", "cidr"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "ports": {"type": "string"},
                },
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
                "risk_class": "recon_passive",
                "required_params": ["target"],
                "supported_target_types": ["domain"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "record_type": {"type": "string", "enum": ["A", "AAAA"]},
                },
            },
            {
                "tool_name": "nmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["ip", "domain", "url", "cidr"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "ports": {"type": "string"},
                },
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


class _JumpAheadLLM:
    def plan(self, context: dict) -> dict:
        return {
            "action_type": "active_scan",
            "tool_name": "nmap",
            "target": "http://localhost:3000",
            "params": {"ports": "1-1000"},
            "rationale": "Jump ahead to broad network scanning",
            "estimated_risk": "medium",
        }


def test_planner_no_longer_forces_step_recovery_candidates() -> None:
    planner = PlannerNode(
        llm_router=_JumpAheadLLM(),
        engagement_summary={
            "engagement_id": str(uuid4()),
            "strategy_plan": {
                "sequence": [
                    {
                        "step_id": "web_discovery",
                        "preferred_tools": ["zap", "gobuster"],
                        "fallback_tools": ["shell"],
                        "recovery_rules": [
                            {
                                "hint_codes": ["wildcard_detected"],
                                "preferred_tools": ["zap"],
                            }
                        ],
                    },
                    {
                        "step_id": "web_vuln_scan",
                        "preferred_tools": ["nuclei"],
                        "fallback_tools": ["nikto"],
                    },
                ]
            },
        },
        available_tools=["zap", "gobuster", "nmap"],
        tools_catalog=[
            {
                "tool_name": "zap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {"target": {"type": "string"}},
            },
            {
                "tool_name": "gobuster",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {"target": {"type": "string"}},
            },
            {
                "tool_name": "nmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["ip", "domain", "url", "cidr"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "ports": {"type": "string"},
                },
            },
        ],
    )

    state = {
        **_base_state(),
        "previous_actions": [
            {
                "tool_name": "gobuster",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["wildcard_detected"],
            }
        ],
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] == "nmap"


class _RepeatGobusterLLM:
    def plan(self, context: dict) -> dict:
        return {
            "action_type": "active_scan",
            "tool_name": "gobuster",
            "target": "http://localhost:3000",
            "params": {"mode": "dir", "extensions": "js,json"},
            "rationale": "Retry route discovery",
            "estimated_risk": "medium",
        }


def test_planner_uses_dynamic_fallback_instead_of_recovery_param_overrides() -> None:
    planner = PlannerNode(
        llm_router=_RepeatGobusterLLM(),
        engagement_summary={
            "engagement_id": str(uuid4()),
            "strategy_plan": {
                "sequence": [
                    {
                        "step_id": "web_discovery",
                        "preferred_tools": ["gobuster"],
                        "fallback_tools": ["zap"],
                        "recovery_rules": [
                            {
                                "hint_codes": ["wildcard_detected"],
                                "preferred_tools": ["gobuster"],
                                "param_overrides": {
                                    "gobuster": {
                                        "force_wildcard": True,
                                    }
                                },
                            }
                        ],
                    }
                ]
            },
        },
        available_tools=["gobuster", "zap"],
        tools_catalog=[
            {
                "tool_name": "gobuster",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "mode": {"type": "string"},
                    "extensions": {"type": "string"},
                    "force_wildcard": {"type": "boolean"},
                },
            },
            {
                "tool_name": "zap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {"target": {"type": "string"}},
            },
        ],
    )

    state = {
        **_base_state(),
        "previous_actions": [
            {
                "tool_name": "gobuster",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["wildcard_detected"],
            }
        ],
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] == "zap"


def test_planner_ignores_recovery_override_param_without_step_gating() -> None:
    planner = PlannerNode(
        llm_router=_RepeatGobusterLLM(),
        engagement_summary={
            "engagement_id": str(uuid4()),
            "strategy_plan": {
                "sequence": [
                    {
                        "step_id": "web_discovery",
                        "preferred_tools": ["gobuster"],
                        "recovery_rules": [
                            {
                                "hint_codes": ["wildcard_detected"],
                                "preferred_tools": ["gobuster"],
                                "param_overrides": {
                                    "gobuster": {
                                        "exclude_length": 0,
                                    }
                                },
                            }
                        ],
                    }
                ]
            },
        },
        available_tools=["gobuster"],
        tools_catalog=[
            {
                "tool_name": "gobuster",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "exclude_length": {"type": "integer"},
                },
            }
        ],
    )

    state = {
        **_base_state(),
        "previous_actions": [
            {
                "tool_name": "gobuster",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["wildcard_detected"],
            }
        ],
    }

    result = planner(state)
    assert "exclude_length" not in result["proposed_action"].get("params", {})


def test_planner_forces_pivot_after_reject_streak() -> None:
    planner = PlannerNode(
        llm_router=_RepeatSqlmapLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["sqlmap", "dns", "nmap"],
        tools_catalog=[
            {
                "tool_name": "sqlmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "forms": {"type": "boolean"},
                },
            },
            {
                "tool_name": "dns",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["domain"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "record_type": {"type": "string"},
                },
            },
            {
                "tool_name": "nmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url", "ip", "domain", "cidr"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "ports": {"type": "string"},
                },
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
            "risk_override": None,
            "rationale": "Target type 'url' is not supported by tool 'dns'.",
        },
        "nonproductive_cycle_streak": 6,
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] == "nmap"


class _RepeatDnsOnlyLLM:
    def plan(self, context: dict) -> dict:
        return {
            "action_type": "active_scan",
            "tool_name": "dns",
            "target": "example.com",
            "params": {},
            "rationale": "Keep using dns",
            "estimated_risk": "medium",
        }


def test_planner_tracks_rejection_repeat_metadata() -> None:
    planner = PlannerNode(
        llm_router=_RepeatDnsLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["dns", "nmap"],
        tools_catalog=[
            {
                "tool_name": "dns",
                "risk_class": "active_scan",
                "categories": ["dns"],
                "required_params": ["target"],
                "supported_target_types": ["domain", "url"],
                "parameter_schema": {"target": {"type": "string"}},
            },
            {
                "tool_name": "nmap",
                "risk_class": "active_scan",
                "categories": ["network"],
                "required_params": ["target"],
                "supported_target_types": ["url", "ip", "domain", "cidr"],
                "parameter_schema": {"target": {"type": "string"}},
            },
        ],
    )

    state = {
        **_base_state(),
        "proposed_action": {
            "tool_name": "dns",
            "target": "example.com",
            "action_type": "active_scan",
            "params": {},
            "rationale": "previous attempt",
            "estimated_risk": "medium",
        },
        "validation_result": {
            "verdict": "reject",
            "risk_override": None,
            "rationale": "Target not supported",
            "rejection_reason_code": "TARGET_TYPE_NOT_SUPPORTED",
            "rejection_class": "target",
        },
        "last_rejection_code": "TARGET_TYPE_NOT_SUPPORTED",
        "last_rejection_class": "target",
        "rejection_repeat_count": 1,
        "reject_reason_streak_count": 6,
        "nonproductive_cycle_streak": 6,
    }

    result = planner(state)
    assert result["rejection_repeat_count"] == 2
    assert result["last_rejection_code"] == "TARGET_TYPE_NOT_SUPPORTED"
    assert result["last_rejection_class"] == "target"


def test_planner_sets_kill_switch_when_reject_loop_has_no_viable_pivot() -> None:
    planner = PlannerNode(
        llm_router=_RepeatDnsOnlyLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["dns"],
        tools_catalog=[
            {
                "tool_name": "dns",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["domain"],
                "parameter_schema": {
                    "target": {"type": "string"},
                },
            },
        ],
    )

    state = {
        **_base_state(),
        "proposed_action": {
            "tool_name": "dns",
            "target": "example.com",
            "action_type": "active_scan",
            "params": {},
            "rationale": "previous attempt",
            "estimated_risk": "medium",
        },
        "validation_result": {
            "verdict": "reject",
            "risk_override": None,
            "rationale": "No progress.",
        },
        "reject_reason_streak_count": 12,
        "nonproductive_cycle_streak": 12,
    }

    result = planner(state)
    assert result.get("force_report") is True
    assert result.get("termination_reason") == "reflector_terminate"
    assert "Reject reason streak exceeded reflector terminate threshold" in str(result.get("error", ""))


class _BaseTargetSqlmapLLM:
    def plan(self, context: dict) -> dict:
        return {
            "action_type": "active_scan",
            "tool_name": "sqlmap",
            "target": "http://localhost:3000",
            "params": {"forms": False},
            "rationale": "Run targeted injection checks",
            "estimated_risk": "medium",
        }


def test_planner_prioritizes_attack_surface_endpoint_target() -> None:
    planner = PlannerNode(
        llm_router=_BaseTargetSqlmapLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["sqlmap"],
        tools_catalog=[
            {
                "tool_name": "sqlmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "forms": {"type": "boolean"},
                },
            }
        ],
    )

    state = {
        **_base_state(),
        "recon_summary": {
            "attack_surface": {
                "web_targets": ["http://localhost:3000"],
                "endpoints": [
                    "http://localhost:3000/rest/user/login?email=test@example.com",
                    "http://localhost:3000/profile",
                ],
                "routes": ["/rest/user/login", "/profile"],
                "parameters": ["email"],
                "auth_paths": ["/rest/user/login"],
            }
        },
    }

    result = planner(state)
    assert result["proposed_action"]["target"] == "http://localhost:3000/rest/user/login?email=test@example.com"
    assert "attack_surface" in result["proposed_action"]["rationale"]


def test_planner_parameterizes_sqlmap_target_from_attack_surface_fields() -> None:
    planner = PlannerNode(
        llm_router=_BaseTargetSqlmapLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["sqlmap"],
        tools_catalog=[
            {
                "tool_name": "sqlmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "forms": {"type": "boolean"},
                    "data": {"type": "string"},
                },
            }
        ],
    )

    state = {
        **_base_state(),
        "recon_summary": {
            "attack_surface": {
                "web_targets": ["http://localhost:3000"],
                "endpoints": [
                    "http://localhost:3000/rest/products/search",
                ],
                "routes": ["/rest/products/search"],
                "parameters": ["q"],
                "auth_paths": [],
            }
        },
    }

    result = planner(state)
    assert result["proposed_action"]["target"].endswith("/rest/products/search?q=1")
    assert result["proposed_action"]["params"]["forms"] is False
    assert result["proposed_action"]["params"]["data"] == "q=1"
    assert result["proposed_action"]["params"]["mode_selection_reason"] == "attack_surface_parameterized"


def test_planner_does_not_set_strategy_step_id_without_strategy_gating() -> None:
    planner = PlannerNode(
        llm_router=_RepeatGobusterLLM(),
        engagement_summary={
            "engagement_id": str(uuid4()),
            "strategy_plan": {
                "sequence": [
                    {
                        "step_id": "web_discovery",
                        "preferred_tools": ["gobuster"],
                        "fallback_tools": ["zap"],
                    },
                    {
                        "step_id": "web_vuln_scan",
                        "preferred_tools": ["nuclei"],
                        "fallback_tools": ["nikto"],
                    },
                ]
            },
        },
        available_tools=["gobuster", "nuclei"],
        tools_catalog=[
            {
                "tool_name": "gobuster",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {"target": {"type": "string"}},
            },
            {
                "tool_name": "nuclei",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "severity": {"type": "string"},
                },
            },
        ],
        per_step_budget=1,
    )

    state = {
        **_base_state(),
        "previous_actions": [
            {
                "tool_name": "gobuster",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "strategy_step_id": "web_discovery",
                "execution_hint_codes": ["wildcard_detected"],
                "new_findings_count": 0,
            }
        ],
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] in {"gobuster", "nuclei"}
    assert result["proposed_action"].get("strategy_step_id") is None


def test_planner_adaptive_cooldown_avoids_repeat_low_yield_tool() -> None:
    planner = PlannerNode(
        llm_router=_RepeatSqlmapLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["sqlmap", "nuclei"],
        tools_catalog=[
            {
                "tool_name": "sqlmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "forms": {"type": "boolean"},
                },
            },
            {
                "tool_name": "nuclei",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {"target": {"type": "string"}},
            },
        ],
        adaptive_cooldown_enabled=True,
        adaptive_cooldown_max=4,
    )

    state = {
        **_base_state(),
        "previous_actions": [
            {
                "tool_name": "sqlmap",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["no_forms_detected"],
                "new_findings_count": 0,
            },
            {
                "tool_name": "sqlmap",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["no_matches"],
                "new_findings_count": 0,
            },
        ],
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] == "nuclei"
    assert result["temporarily_unavailable_tools"].get("sqlmap", 0) >= 2


class _RepeatNucleiLLM:
    def plan(self, context: dict) -> dict:
        return {
            "action_type": "active_scan",
            "tool_name": "nuclei",
            "target": "http://localhost:3000",
            "params": {"severity": "high"},
            "rationale": "Run a broad scan",
            "estimated_risk": "medium",
        }


def test_planner_objective_focus_overrides_to_injection_tooling() -> None:
    planner = PlannerNode(
        llm_router=_RepeatNucleiLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["nuclei", "sqlmap"],
        tools_catalog=[
            {
                "tool_name": "nuclei",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {"target": {"type": "string"}},
            },
            {
                "tool_name": "sqlmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "forms": {"type": "boolean"},
                },
            },
        ],
    )

    state = {
        **_base_state(),
        "nonproductive_cycle_streak": 2,
        "assessment_objectives": [
            {
                "objective_id": "injection:http://localhost:3000/rest/products/search?q=1",
                "objective_class": "injection",
                "title": "Potential SQL injection",
                "asset_ref": "http://localhost:3000/rest/products/search?q=1",
                "severity": "high",
                "status": "open",
            }
        ],
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] == "sqlmap"
    assert result["proposed_action"]["target"] == "http://localhost:3000/rest/products/search?q=1"
    assert "Objective focus" in result["proposed_action"]["rationale"]


def test_planner_detects_scan_churn_and_pivots_to_objective_followup() -> None:
    planner = PlannerNode(
        llm_router=_RepeatNucleiLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["nuclei", "sqlmap"],
        tools_catalog=[
            {
                "tool_name": "nuclei",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {"target": {"type": "string"}},
            },
            {
                "tool_name": "sqlmap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {
                    "target": {"type": "string"},
                    "forms": {"type": "boolean"},
                },
            },
        ],
    )

    state = {
        **_base_state(),
        "assessment_objectives": [
            {
                "objective_id": "injection:http://localhost:3000/rest/products/search?q=1",
                "objective_class": "injection",
                "title": "Potential SQL injection",
                "asset_ref": "http://localhost:3000/rest/products/search?q=1",
                "severity": "high",
                "status": "in_progress",
            }
        ],
        "previous_actions": [
            {
                "tool_name": "nuclei",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["no_matches"],
                "failure_reasons": ["NoActionableOutput"],
            },
            {
                "tool_name": "nuclei",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["no_matches"],
                "failure_reasons": ["NoActionableOutput"],
            },
            {
                "tool_name": "nuclei",
                "target": "http://localhost:3000",
                "action_type": "active_scan",
                "execution_hint_codes": ["execution_error"],
                "failure_reasons": ["NoActionableOutput"],
            },
        ],
    }

    result = planner(state)
    assert result["proposed_action"]["tool_name"] == "sqlmap"
    assert "scan churn" in result["proposed_action"]["rationale"].lower()


def test_planner_rebuild_fallback_rationale_matches_selected_tool() -> None:
    planner = PlannerNode(
        llm_router=_RepeatNucleiLLM(),
        engagement_summary={"engagement_id": str(uuid4())},
        available_tools=["zap", "nikto"],
        tools_catalog=[
            {
                "tool_name": "zap",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {"target": {"type": "string"}},
            },
            {
                "tool_name": "nikto",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "supported_target_types": ["url"],
                "parameter_schema": {"target": {"type": "string"}},
            },
        ],
    )

    rebuilt = planner._rebuild_fallback_proposal(
        {
            "tool_name": "zap",
            "action_type": "active_scan",
            "target": "http://localhost:3000",
            "params": {"target": "http://localhost:3000", "ajax_spider": True},
            "rationale": "Moving to web_discovery with ZAP and ajax spider capabilities.",
            "estimated_risk": "medium",
        },
        "nikto",
        "Stayed within current strategy step.",
    )

    assert rebuilt["tool_name"] == "nikto"
    assert "Planner fallback selected 'nikto'" in rebuilt["rationale"]
    assert "web_discovery with ZAP" not in rebuilt["rationale"]
