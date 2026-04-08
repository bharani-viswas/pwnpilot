"""Unit tests for agent nodes: planner, validator, executor, reporter, supervisor."""
from __future__ import annotations

import json
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.agent.executor import ExecutorNode
from pwnpilot.agent.planner import PlannerNode
from pwnpilot.agent.reporter import ReporterNode
from pwnpilot.agent.state import AgentState
from pwnpilot.agent.supervisor import CONVERGENCE_THRESHOLD, _route_after_execution, _route_after_validation
from pwnpilot.agent.validator import ValidatorNode
from pwnpilot.control.approval import ApprovalService
from pwnpilot.control.engagement import EngagementService
from pwnpilot.control.policy import PolicyEngine
from pwnpilot.data.audit_store import AuditStore
from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.data.finding_store import FindingStore
from pwnpilot.data.models import Engagement, EngagementScope, RiskLevel
from pwnpilot.data.recon_store import ReconStore
from pwnpilot.governance.kill_switch import KillSwitch
from pwnpilot.governance.simulation import SimulationEngine


def _session():
    engine = create_engine("sqlite:///:memory:")
    return sessionmaker(bind=engine)()


def _base_state(max_iter=10) -> AgentState:
    return {
        "engagement_id": str(uuid4()),
        "iteration_count": 0,
        "max_iterations": max_iter,
        "no_new_findings_streak": 0,
        "recon_summary": {},
        "previous_actions": [],
        "proposed_action": None,
        "validation_result": None,
        "last_result": None,
        "evidence_ids": [],
        "kill_switch": False,
        "report_complete": False,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Routing functions
# ---------------------------------------------------------------------------


class TestRouting:
    def test_route_after_validation_approve(self):
        state = {**_base_state(), "validation_result": {"verdict": "approve"}}
        assert _route_after_validation(state) == "execute"

    def test_route_after_validation_escalate(self):
        state = {**_base_state(), "validation_result": {"verdict": "escalate"}}
        assert _route_after_validation(state) == "execute"

    def test_route_after_validation_reject(self):
        state = {**_base_state(), "validation_result": {"verdict": "reject"}}
        assert _route_after_validation(state) == "replan"

    def test_route_after_validation_kill_switch(self):
        state = {**_base_state(), "kill_switch": True, "validation_result": {"verdict": "approve"}}
        assert _route_after_validation(state) == "halt"

    def test_route_after_execution_continue(self):
        state = _base_state(max_iter=50)
        assert _route_after_execution(state) == "continue"

    def test_route_after_execution_max_iter(self):
        state = {**_base_state(max_iter=5), "iteration_count": 5}
        assert _route_after_execution(state) == "report"

    def test_route_after_execution_convergence(self):
        state = {**_base_state(), "no_new_findings_streak": CONVERGENCE_THRESHOLD}
        assert _route_after_execution(state) == "report"

    def test_route_after_execution_kill_switch(self):
        state = {**_base_state(), "kill_switch": True}
        assert _route_after_execution(state) == "halt"

    def test_route_after_execution_error(self):
        state = {**_base_state(), "error": "something broke"}
        assert _route_after_execution(state) == "halt"


# ---------------------------------------------------------------------------
# Planner node
# ---------------------------------------------------------------------------


class MockLLMRouter:
    def __init__(self, proposal: dict = None, validation: dict = None):
        self._proposal = proposal or {
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "target": "10.0.0.1",
            "params": {},
            "rationale": "Initial recon",
            "estimated_risk": "low",
        }
        self._validation = validation or {
            "verdict": "approve",
            "risk_override": None,
            "rationale": "Looks fine",
        }

    def plan(self, context: dict) -> dict:
        return self._proposal

    def validate(self, context: dict) -> dict:
        return self._validation


class TestPlannerNode:
    def test_produces_proposal(self):
        planner = PlannerNode(
            llm_router=MockLLMRouter(),
            engagement_summary={"engagement_id": str(uuid4())},
        )
        state = _base_state()
        result = planner(state)
        assert result["proposed_action"] is not None
        assert result["iteration_count"] == 1

    def test_kill_switch_returns_unchanged(self):
        planner = PlannerNode(
            llm_router=MockLLMRouter(),
            engagement_summary={},
        )
        state = {**_base_state(), "kill_switch": True}
        result = planner(state)
        assert result.get("proposed_action") is None

    def test_llm_error_sets_error_state(self):
        class ErrLLM:
            def plan(self, ctx):
                raise RuntimeError("LLM offline")
        planner = PlannerNode(llm_router=ErrLLM(), engagement_summary={})
        result = planner(_base_state())
        assert result.get("error") is not None

    def test_repeated_state_circuit_breaker(self):
        router = MockLLMRouter()
        planner = PlannerNode(llm_router=router, engagement_summary={})

        # Feed same proposals to fill breaker
        state = _base_state()
        for _ in range(3):
            # Mark the proposal as already done
            state = {**state, "previous_actions": [
                {"action_id": str(uuid4()), "tool_name": "nmap",
                 "action_type": "recon_passive", "target": "10.0.0.1"}
            ]}
            state = planner(state)

        # After 3 consecutive repeats, kill_switch should be set
        assert state.get("kill_switch") is True


# ---------------------------------------------------------------------------
# Validator node
# ---------------------------------------------------------------------------


class TestValidatorNode:
    def test_approve_verdict(self):
        validator = ValidatorNode(
            llm_router=MockLLMRouter(),
            policy_context={},
        )
        state = {**_base_state(), "proposed_action": {
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "target": "10.0.0.1",
            "rationale": "test",
            "estimated_risk": "low",
        }}
        result = validator(state)
        assert result["validation_result"]["verdict"] == "approve"

    def test_no_proposal_rejects(self):
        validator = ValidatorNode(llm_router=MockLLMRouter(), policy_context={})
        result = validator(_base_state())
        assert result["validation_result"]["verdict"] == "reject"

    def test_downgrade_rejected_by_no_downgrade_rule(self):
        router = MockLLMRouter(
            validation={"verdict": "escalate", "risk_override": "low", "rationale": "x"}
        )
        validator = ValidatorNode(llm_router=router, policy_context={})
        state = {**_base_state(), "proposed_action": {
            "action_type": "active_scan",
            "tool_name": "nmap",
            "target": "10.0.0.1",
            "rationale": "test",
            "estimated_risk": "high",  # proposal says high
        }}
        result = validator(state)
        # risk_override "low" is a downgrade from "high"; should be overridden to "high"
        assert result["validation_result"]["risk_override"] == "high"


# ---------------------------------------------------------------------------
# Simulation engine
# ---------------------------------------------------------------------------


class TestSimulationEngine:
    def _make_eng_svc(self) -> EngagementService:
        now = datetime.now(timezone.utc)
        eng = Engagement(
            name="sim",
            operator_id="op",
            scope=EngagementScope(scope_cidrs=["10.0.0.0/8"]),
            roe_document_hash="e" * 64,
            authoriser_identity="Eve",
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(hours=1),
        )
        return EngagementService(eng)

    def test_simulate_allow(self):
        from pwnpilot.data.models import ActionRequest, ActionType
        sim = SimulationEngine(self._make_eng_svc())
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.RECON_PASSIVE,
            tool_name="nmap",
            params={"target": "10.1.1.1"},
            risk_level=RiskLevel.LOW,
        )
        decision = sim.simulate(action)
        from pwnpilot.data.models import PolicyVerdict
        assert decision.verdict == PolicyVerdict.ALLOW

    def test_summary_includes_results(self):
        from pwnpilot.data.models import ActionRequest, ActionType
        sim = SimulationEngine(self._make_eng_svc())
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.DATA_EXFIL,
            tool_name="wget",
            params={"target": "10.1.1.1"},
            risk_level=RiskLevel.CRITICAL,
        )
        sim.simulate(action)
        summary = sim.summary()
        assert summary["total"] == 1
        assert "deny" in summary["verdicts"]


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------


class TestReportGenerator:
    def test_build_bundle_empty_engagement(self, tmp_path):
        from pwnpilot.reporting.generator import ReportGenerator

        session = _session()
        eng_id = uuid4()
        generator = ReportGenerator(
            finding_store=FindingStore(session),
            recon_store=ReconStore(session),
            evidence_store=EvidenceStore(base_dir=tmp_path / "evidence", session=session),
            audit_store=AuditStore(session),
        )
        bundle_path, summary_path = generator.build_bundle(
            engagement_id=eng_id,
            output_dir=tmp_path,
        )
        assert bundle_path.exists()
        assert summary_path.exists()
        bundle = json.loads(bundle_path.read_text())
        assert bundle["engagement_id"] == str(eng_id)
        assert bundle["findings_count"] == 0


# ---------------------------------------------------------------------------
# ExecutorNode
# ---------------------------------------------------------------------------


class TestExecutorNode:
    def _make_executor(self):
        from unittest.mock import MagicMock
        from datetime import datetime, timedelta, timezone
        from pwnpilot.data.models import Engagement, EngagementScope

        now = datetime.now(timezone.utc)
        eng = Engagement(
            name="exec-test",
            operator_id="op",
            scope=EngagementScope(scope_cidrs=["10.0.0.0/8"]),
            roe_document_hash="a" * 64,
            authoriser_identity="Alice",
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(hours=2),
        )
        eng_svc = EngagementService(eng)
        session = _session()
        audit = AuditStore(session)
        policy = PolicyEngine(eng_svc)
        approval = ApprovalService()
        runner = MagicMock()
        return ExecutorNode(
            policy_engine=policy,
            tool_runner=runner,
            approval_service=approval,
            audit_store=audit,
        ), runner, eng.engagement_id

    def _proposal_dict(self, eng_id):
        return {
            "engagement_id": str(eng_id),
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "target": "10.0.0.1",
            "params": {},
            "estimated_risk": "low",
            "rationale": "basic recon",
            "rejection_reason": None,
        }

    def test_kill_switch_passes_through(self):
        executor, _, eng_id = self._make_executor()
        state = {**_base_state(), "engagement_id": str(eng_id), "kill_switch": True}
        result = executor(state)
        assert result["kill_switch"] is True

    def test_missing_proposal_returns_error(self):
        executor, _, eng_id = self._make_executor()
        state = {**_base_state(), "engagement_id": str(eng_id)}
        result = executor(state)
        assert result.get("error")

    def test_deny_injects_rejection_reason(self):
        """DATA_EXFIL actions should be DENY"""
        executor, _, eng_id = self._make_executor()
        proposal = self._proposal_dict(eng_id)
        proposal["action_type"] = "data_exfil"
        proposal["estimated_risk"] = "critical"
        validation = {
            "verdict": "approve",
            "risk_override": None,
            "rejection_reason": None,
            "rationale": "looks safe",
        }
        state = {
            **_base_state(),
            "engagement_id": str(eng_id),
            "proposed_action": proposal,
            "validation_result": validation,
        }
        result = executor(state)
        # Should inject rejection_reason into proposal
        assert result["proposed_action"]["rejection_reason"] is not None
        assert result.get("validation_result") is None

    def test_successful_execution_updates_state(self):
        from unittest.mock import MagicMock
        from pwnpilot.data.models import ToolExecutionResult

        executor, runner, eng_id = self._make_executor()
        mock_result = MagicMock()
        mock_result.exit_code = 0
        mock_result.parsed_output = {"new_findings_count": 2}
        mock_result.model_dump.return_value = {"exit_code": 0, "parsed_output": {}}
        runner.execute.return_value = mock_result

        proposal = self._proposal_dict(eng_id)
        validation = {
            "verdict": "approve",
            "risk_override": None,
            "rejection_reason": None,
            "rationale": "looks safe",
        }
        state = {
            **_base_state(),
            "engagement_id": str(eng_id),
            "proposed_action": proposal,
            "validation_result": validation,
        }
        result = executor(state)
        assert result["error"] is None
        assert result["no_new_findings_streak"] == 0  # reset due to new_findings_count=2
        assert result["proposed_action"] is None
        assert len(result["previous_actions"]) == 1

    def test_tool_error_returns_error_state(self):
        executor, runner, eng_id = self._make_executor()
        runner.execute.side_effect = RuntimeError("tool crashed")

        proposal = self._proposal_dict(eng_id)
        validation = {
            "verdict": "approve",
            "risk_override": None,
            "rejection_reason": None,
            "rationale": "looks safe",
        }
        state = {
            **_base_state(),
            "engagement_id": str(eng_id),
            "proposed_action": proposal,
            "validation_result": validation,
        }
        result = executor(state)
        assert "Tool execution failed" in result["error"]

    def test_requires_approval_sets_kill_switch(self):
        """EXPLOIT actions require approval"""
        executor, _, eng_id = self._make_executor()
        proposal = self._proposal_dict(eng_id)
        proposal["action_type"] = "exploit"
        proposal["estimated_risk"] = "critical"
        validation = {
            "verdict": "approve",
            "risk_override": "critical",
            "rejection_reason": None,
            "rationale": "validated exploit",
        }
        state = {
            **_base_state(),
            "engagement_id": str(eng_id),
            "proposed_action": proposal,
            "validation_result": validation,
        }
        result = executor(state)
        assert result["kill_switch"] is True

    def test_no_new_findings_increments_streak(self):
        from unittest.mock import MagicMock

        executor, runner, eng_id = self._make_executor()
        mock_result = MagicMock()
        mock_result.exit_code = 0
        mock_result.parsed_output = {"new_findings_count": 0}
        mock_result.model_dump.return_value = {"exit_code": 0}
        runner.execute.return_value = mock_result

        proposal = self._proposal_dict(eng_id)
        validation = {
            "verdict": "approve",
            "risk_override": None,
            "rejection_reason": None,
            "rationale": "looks safe",
        }
        state = {
            **_base_state(),
            "engagement_id": str(eng_id),
            "proposed_action": proposal,
            "validation_result": validation,
            "no_new_findings_streak": 1,
        }
        result = executor(state)
        assert result["no_new_findings_streak"] == 2


# ---------------------------------------------------------------------------
# ReporterNode
# ---------------------------------------------------------------------------


class TestReporterNode:
    def test_reporter_success(self, tmp_path):
        from unittest.mock import MagicMock
        from pwnpilot.reporting.generator import ReportGenerator

        session = _session()
        eng_id = uuid4()
        generator = ReportGenerator(
            finding_store=FindingStore(session),
            recon_store=ReconStore(session),
            evidence_store=EvidenceStore(base_dir=tmp_path / "evidence", session=session),
            audit_store=AuditStore(session),
        )
        audit = AuditStore(session)
        reporter = ReporterNode(
            report_generator=generator,
            audit_store=audit,
            output_dir=tmp_path,
        )
        state = {**_base_state(), "engagement_id": str(eng_id)}
        result = reporter(state)
        assert result["report_complete"] is True
        assert result.get("error") is None

    def test_reporter_generator_failure(self, tmp_path):
        from unittest.mock import MagicMock

        session = _session()
        eng_id = uuid4()
        mock_gen = MagicMock()
        mock_gen.build_bundle.side_effect = RuntimeError("disk full")
        audit = AuditStore(session)
        reporter = ReporterNode(
            report_generator=mock_gen,
            audit_store=audit,
            output_dir=tmp_path,
        )
        state = {**_base_state(), "engagement_id": str(eng_id)}
        result = reporter(state)
        assert "Report generation failed" in result.get("error", "")


# ---------------------------------------------------------------------------
# Supervisor graph compilation
# ---------------------------------------------------------------------------


class TestSupervisorBuild:
    def test_build_graph_compiles(self):
        """Verify build_graph() produces a compiled StateGraph without error."""
        from unittest.mock import MagicMock
        from pwnpilot.agent.supervisor import build_graph

        graph = build_graph(
            planner_fn=MagicMock(),
            validator_fn=MagicMock(),
            executor_fn=MagicMock(),
            reporter_fn=MagicMock(),
        )
        # compiled graph has an invoke method
        assert hasattr(graph, "invoke")
