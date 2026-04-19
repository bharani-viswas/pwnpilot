from __future__ import annotations

from pwnpilot.reporting.readiness_policy import ReportReadinessPolicy


def test_readiness_requires_depth_when_findings_exist() -> None:
    policy = ReportReadinessPolicy()
    state = {
        "previous_actions": [
            {
                "tool_name": "nuclei",
                "outcome_status": "success",
                "failure_reasons": [],
                "action_type": "active_scan",
                "requires_followup_validation": False,
                "confirmation_candidate_count": 0,
            }
        ],
        "evidence_ids": ["a", "b"],
        "recon_summary": {
            "findings_summary": {
                "total_findings": 2,
            }
        },
    }

    result = policy.evaluate(state)
    assert result["gates"]["min_exploit_validation_actions"] is False
    assert result["gates"]["min_confirmation_candidates"] is False
    assert "min_exploit_validation_actions" in result["failed_gates"]
    assert "min_confirmation_candidates" in result["failed_gates"]


def test_readiness_depth_gate_passes_with_validation_progress() -> None:
    policy = ReportReadinessPolicy()
    state = {
        "previous_actions": [
            {
                "tool_name": "sqlmap",
                "outcome_status": "success",
                "failure_reasons": [],
                "action_type": "active_scan",
                "requires_followup_validation": True,
                "confirmation_candidate_count": 1,
            }
        ],
        "evidence_ids": ["a", "b"],
        "recon_summary": {
            "findings_summary": {
                "total_findings": 1,
            }
        },
    }

    result = policy.evaluate(state)
    assert result["gates"]["min_exploit_validation_actions"] is True
    assert result["gates"]["min_confirmation_candidates"] is True
    assert "min_exploit_validation_actions" not in result["failed_gates"]
    assert "min_confirmation_candidates" not in result["failed_gates"]
