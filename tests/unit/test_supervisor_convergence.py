from __future__ import annotations

from pwnpilot.agent.supervisor import _route_after_execution, _route_after_validation


def _base_state() -> dict:
    return {
        "kill_switch": False,
        "error": None,
        "iteration_count": 1,
        "max_iterations": 50,
        "no_new_findings_streak": 0,
        "nonproductive_cycle_streak": 0,
        "previous_actions": [],
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
