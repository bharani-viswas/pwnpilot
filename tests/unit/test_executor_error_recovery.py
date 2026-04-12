"""
Tests for Executor ValueError handling and recovery.
"""
import pytest
from unittest.mock import MagicMock, patch
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from pwnpilot.agent.executor import ExecutorNode
from pwnpilot.agent.state import AgentState
from pwnpilot.control.policy import PolicyEngine, PolicyDecision, PolicyVerdict, GateType
from pwnpilot.control.approval import ApprovalService
from pwnpilot.data.audit_store import AuditStore
from pwnpilot.data.models import RiskLevel


def _make_session() -> Session:
    """Create an in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:")
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


@pytest.fixture
def executor_setup():
    """Setup executor with mocked dependencies."""
    db_session = _make_session()
    
    policy_engine = MagicMock(spec=PolicyEngine)
    policy_engine.evaluate.return_value = PolicyDecision(
        verdict=PolicyVerdict.ALLOW,
        reason="Test approval",
        gate_type=GateType.ALLOW,
    )
    
    tool_runner = MagicMock()
    
    approval_service = MagicMock(spec=ApprovalService)
    approval_service.create_ticket.return_value = MagicMock(ticket_id=uuid4())
    
    audit_store = AuditStore(db_session)
    
    executor = ExecutorNode(
        policy_engine=policy_engine,
        tool_runner=tool_runner,
        approval_service=approval_service,
        audit_store=audit_store,
    )
    
    return {
        "executor": executor,
        "policy_engine": policy_engine,
        "tool_runner": tool_runner,
        "approval_service": approval_service,
        "audit_store": audit_store,
    }


class TestExecutorValueErrorRecovery:
    """Test cases for executor ValueError handling."""

    def test_generic_parameter_validation_error_creates_rejection_reason(self, executor_setup):
        """Test that generic ValueError creates rejection_reason for planner retry."""
        executor = executor_setup["executor"]
        tool_runner = executor_setup["tool_runner"]
        
        # Make tool_runner raise ValueError for invalid params
        tool_runner.execute.side_effect = ValueError("invalid scan_type value")
        
        state = {
            "engagement_id": str(uuid4()),
            "kill_switch": False,
            "proposed_action": {
                "action_type": "recon_passive",
                "tool_name": "nmap",
                "target": "192.168.1.1",
                "params": {"scan_type": "invalid"},
                "rationale": "Test",
                "estimated_risk": "medium",
            },
            "validation_result": {
                "verdict": "approve",
                "risk_override": None,
                "rationale": "Test",
            },
            "previous_actions": [],
        }
        
        result = executor(state)
        
        # Should have rejection_reason for planner
        assert "rejection_reason" in result["proposed_action"]
        assert "invalid scan_type value" in result["proposed_action"]["rejection_reason"]
        assert result["error"] is None
        assert "param_validation_failed" in str(result["previous_actions"])

    def test_shell_permission_error_creates_approval_ticket(self, executor_setup):
        """Test that shell permission errors create approval tickets."""
        executor = executor_setup["executor"]
        tool_runner = executor_setup["tool_runner"]
        approval_service = executor_setup["approval_service"]
        
        # Make tool_runner raise ValueError for not allow-listed command
        tool_runner.execute.side_effect = ValueError(
            "shell: command 'nmap' is not allow-listed. Allowed: ['ls', 'pwd', ...]"
        )
        
        state = {
            "engagement_id": str(uuid4()),
            "kill_switch": False,
            "proposed_action": {
                "action_type": "recon_passive",
                "tool_name": "shell",
                "target": "localhost",
                "params": {"command": "nmap"},
                "rationale": "Scan network",
                "estimated_risk": "high",
            },
            "validation_result": {
                "verdict": "approve",
                "risk_override": None,
                "rationale": "Test",
            },
            "previous_actions": [],
        }
        
        result = executor(state)
        
        # Should create approval ticket and set kill_switch
        assert approval_service.create_ticket.called
        assert result["kill_switch"] is True
        assert result["error"] is None

    def test_toolavailable_error_suggests_alternatives(self, executor_setup):
        """Test that tool not available errors suggest alternatives."""
        executor = executor_setup["executor"]
        tool_runner = executor_setup["tool_runner"]
        tool_runner.available_tools = ["ls", "pwd", "grep"]
        
        # Make tool_runner raise KeyError for missing tool
        tool_runner.execute.side_effect = KeyError("nmap")
        
        state = {
            "engagement_id": str(uuid4()),
            "kill_switch": False,
            "proposed_action": {
                "action_type": "recon_passive",
                "tool_name": "nmap",
                "target": "192.168.1.1",
                "params": {},
                "rationale": "Test",
                "estimated_risk": "medium",
            },
            "validation_result": {
                "verdict": "approve",
                "risk_override": None,
                "rationale": "Test",
            },
            "previous_actions": [],
        }
        
        result = executor(state)
        
        # Should inject rejection_reason with available alternatives
        assert "rejection_reason" in result["proposed_action"]
        assert "available tools" in result["proposed_action"]["rejection_reason"].lower()
        assert "ls" in result["proposed_action"]["rejection_reason"]

    def test_permission_ticket_includes_context(self, executor_setup):
        """Test that permission tickets include proper context."""
        executor = executor_setup["executor"]
        tool_runner = executor_setup["tool_runner"]
        approval_service = executor_setup["approval_service"]
        
        tool_runner.execute.side_effect = ValueError(
            "shell: command 'nmap' is not allow-listed. Allowed: ['ls', 'pwd']"
        )
        
        state = {
            "engagement_id": str(uuid4()),
            "kill_switch": False,
            "proposed_action": {
                "action_type": "recon_passive",
                "tool_name": "shell",
                "target": "localhost",
                "params": {"command": "nmap"},
                "rationale": "Network scan",
                "estimated_risk": "high",
            },
            "validation_result": {
                "verdict": "approve",
                "risk_override": None,
                "rationale": "Test",
            },
            "previous_actions": [],
        }
        
        executor(state)
        
        # Check that create_ticket was called with action containing command
        assert approval_service.create_ticket.called
        call_args = approval_service.create_ticket.call_args
        
        # Action should have the command in params
        action = call_args[0][0]  # First positional argument
        assert action.tool_name == "shell"

    def test_param_validation_error_added_to_previous_actions(self, executor_setup):
        """Test that param validation errors are added to previous_actions."""
        executor = executor_setup["executor"]
        tool_runner = executor_setup["tool_runner"]
        
        tool_runner.execute.side_effect = ValueError("bad param")
        
        state = {
            "engagement_id": str(uuid4()),
            "kill_switch": False,
            "proposed_action": {
                "action_type": "recon_passive",
                "tool_name": "nmap",
                "target": "192.168.1.1",
                "params": {},
                "rationale": "Test",
                "estimated_risk": "medium",
            },
            "validation_result": {
                "verdict": "approve",
                "risk_override": None,
                "rationale": "Test",  
            },
            "previous_actions": [],
        }
        
        result = executor(state)
        
        assert len(result["previous_actions"]) == 1
        action = result["previous_actions"][0]
        assert action["error"] == "param_validation_failed"
        assert action["tool_name"] == "nmap"

    def test_hard_error_still_surfaces(self, executor_setup):
        """Test that non-ValueError exceptions still cause hard errors."""
        executor = executor_setup["executor"]
        tool_runner = executor_setup["tool_runner"]
        
        tool_runner.execute.side_effect = RuntimeError("catastrophic failure")
        
        state = {
            "engagement_id": str(uuid4()),
            "kill_switch": False,
            "proposed_action": {
                "action_type": "recon_passive",
                "tool_name": "nmap",
                "target": "192.168.1.1",
                "params": {},
                "rationale": "Test",
                "estimated_risk": "medium",
            },
            "validation_result": {
                "verdict": "approve",
                "risk_override": None,
                "rationale": "Test",
            },
            "previous_actions": [],
        }
        
        result = executor(state)
        
        # Hard errors should still cause errors
        assert result["error"] is not None
        assert "catastrophic failure" in result["error"]
