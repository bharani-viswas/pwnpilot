from __future__ import annotations

import time

from pwnpilot.agent.supervisor import _route_after_execution, _route_after_validation


def _base_state() -> dict:
    return {
        "kill_switch": False,
        "error": None,
        "iteration_count": 1,
        "max_iterations": 50,
        "no_new_findings_streak": 0,
        "nonproductive_cycle_streak": 0,
        "planner_validator_cycle_streak": 0,
        "reject_reason_streak_count": 0,
        "last_reject_reason_fingerprint": None,
        "max_pv_cycles_without_executor": 40,
        "max_consecutive_rejects_per_reason": 12,
        "max_autonomous_runtime_seconds": 3600,
        "run_started_at_epoch": time.time(),
        "previous_actions": [],
        "operator_mode": "autonomous",
    }


def test_convergence_not_triggered_before_minimum_actions() -> None:
    state = {
        **_base_state(),
        "no_new_findings_streak": 10,
        "previous_actions": [{"tool_name": "whatweb"}, {"tool_name": "nuclei"}],
    }

    assert _route_after_execution(state) == "continue"


def test_convergence_triggered_after_threshold_and_minimum_actions() -> None:
    state = {
        **_base_state(),
        "no_new_findings_streak": 5,
        "previous_actions": [
            {"tool_name": "whatweb"},
            {"tool_name": "nuclei"},
            {"tool_name": "gobuster"},
            {"tool_name": "nikto"},
            {"tool_name": "sqlmap"},
        ],
    }

    assert _route_after_execution(state) == "report"


def test_validation_reject_reports_when_max_iterations_reached() -> None:
    state = {
        **_base_state(),
        "iteration_count": 50,
        "validation_result": {"verdict": "reject"},
    }

    assert _route_after_validation(state) == "report"


def test_validation_reject_reports_when_nonproductive_limit_reached() -> None:
    state = {
        **_base_state(),
        "nonproductive_cycle_streak": 5,
        "validation_result": {"verdict": "reject"},
    }

    assert _route_after_validation(state) == "report"
    assert state.get("operator_mode") == "guided"
    assert state.get("operator_directives", {}).get("supervisor_escalation", {}).get("reason") == "nonproductive_cycle_limit"


def test_validation_reject_reports_when_planner_validator_churn_limit_reached() -> None:
    state = {
        **_base_state(),
        "planner_validator_cycle_streak": 39,
        "max_pv_cycles_without_executor": 40,
        "validation_result": {
            "verdict": "reject",
            "rejection_reason_code": "TOOL_NOT_ENABLED",
            "rejection_class": "capability",
        },
    }

    assert _route_after_validation(state) == "report"
    assert state.get("termination_reason") == "planner_validator_churn"
    assert state.get("operator_directives", {}).get("supervisor_escalation", {}).get("reason") == "planner_validator_churn_limit"


def test_validation_reject_reports_when_same_reason_limit_reached() -> None:
    state = {
        **_base_state(),
        "reject_reason_streak_count": 11,
        "last_reject_reason_fingerprint": "TOOL_NOT_ENABLED:capability",
        "max_consecutive_rejects_per_reason": 12,
        "validation_result": {
            "verdict": "reject",
            "rejection_reason_code": "TOOL_NOT_ENABLED",
            "rejection_class": "capability",
        },
    }

    assert _route_after_validation(state) == "report"
    assert state.get("report_trigger_reason") == "reject_reason_limit"
    assert state.get("operator_directives", {}).get("supervisor_escalation", {}).get("reason") == "reject_reason_limit"


def test_execution_resets_planner_validator_watchdog_state() -> None:
    state = {
        **_base_state(),
        "planner_validator_cycle_streak": 8,
        "reject_reason_streak_count": 4,
        "last_reject_reason_fingerprint": "VALIDATOR_REJECT:policy",
    }

    assert _route_after_execution(state) == "continue"
    assert state.get("planner_validator_cycle_streak") == 0
    assert state.get("reject_reason_streak_count") == 0
    assert state.get("last_reject_reason_fingerprint") is None


def test_route_reports_when_runtime_budget_exceeded() -> None:
    state = {
        **_base_state(),
        "run_started_at_epoch": time.time() - 11,
        "max_autonomous_runtime_seconds": 10,
    }

    assert _route_after_execution(state) == "report"
    assert state.get("termination_reason") == "runtime_budget_exceeded"
    assert state.get("operator_directives", {}).get("supervisor_escalation", {}).get("reason") == "runtime_budget_limit"


def test_force_report_routes_immediately() -> None:
    state = {
        **_base_state(),
        "force_report": True,
        "report_trigger_reason": "reflector_terminate",
        "validation_result": {"verdict": "reject"},
    }

    assert _route_after_validation(state) == "report"


def test_validation_warning_escalates_to_guided_before_limit() -> None:
    state = {
        **_base_state(),
        "planner_validator_cycle_streak": 39,
        "max_pv_cycles_without_executor": 40,
        "validation_result": {
            "verdict": "approve",
        },
    }

    assert _route_after_validation(state) == "execute"
    assert state.get("operator_mode") == "guided"
    assert state.get("operator_directives", {}).get("supervisor_escalation", {}).get("reason") == "planner_validator_churn_warning"
