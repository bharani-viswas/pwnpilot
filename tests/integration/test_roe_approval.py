"""
Integration tests for ROE Approval Workflow.

These tests verify the complete approval workflow including:
- Session lifecycle management
- Sudo password verification (mocked)
- User approval prompts
- Audit logging
- Session timeout handling
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch
from uuid import UUID, uuid4

import pytest

from pwnpilot.agent.roe_interpreter import ExtractedPolicy, InterpretationResult
from pwnpilot.control.roe_approval import (
    ApprovalDeniedError,
    ApprovalRecord,
    ApprovalSession,
    ApprovalWorkflow,
    SessionExpiredError,
    SudoVerificationError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engagement_id():
    return uuid4()


@pytest.fixture
def sample_extracted_policy():
    """Create a sample extracted policy for testing."""
    return ExtractedPolicy(
        scope_cidrs=["192.168.1.0/24", "10.0.0.0/8"],
        scope_domains=["example.com"],
        scope_urls=[],
        excluded_ips=["192.168.1.1"],
        restricted_actions=["MODIFY_DATA", "DELETE_DATA"],
        max_iterations=5,
        max_retries=3,
        timeout_seconds=300,
        cloud_allowed=False,
    )


@pytest.fixture
def sample_interpretation_result(sample_extracted_policy):
    """Create a sample interpretation result."""
    return InterpretationResult(
        is_valid=True,
        extracted_policy=sample_extracted_policy,
        confidence_score=0.95,
        warnings=["High risk actions enabled"],
        concerns=[],
        hallucination_risks=[],
        injection_detected=False,
    )


@pytest.fixture
def audit_callback():
    """Create a mock audit callback."""
    return MagicMock()


@pytest.fixture
def approval_workflow(audit_callback):
    """Create an ApprovalWorkflow instance."""
    return ApprovalWorkflow(audit_fn=audit_callback, session_ttl_seconds=900)


# ---------------------------------------------------------------------------
# Test ApprovalSession
# ---------------------------------------------------------------------------


class TestApprovalSession:
    """Test ApprovalSession lifecycle and security features."""

    def test_session_creation(self, engagement_id):
        """Test creating a new session generates unique ID and nonce."""
        session = ApprovalSession(
            user="testuser",
            engagement_id=engagement_id,
            ttl_seconds=900,
        )

        assert session.user == "testuser"
        assert session.engagement_id == engagement_id
        assert session.session_id  # Non-empty
        assert len(session.nonce_token) > 0
        assert session.is_valid is True
        assert session.approval_status is None
        assert session.password_verified is False

    def test_session_nonce_is_unique(self, engagement_id):
        """Test that each session gets a unique nonce token."""
        session1 = ApprovalSession("user1", engagement_id=engagement_id, ttl_seconds=900)
        session2 = ApprovalSession("user2", engagement_id=engagement_id, ttl_seconds=900)

        assert session1.nonce_token != session2.nonce_token
        assert len(session1.nonce_token) == len(session2.nonce_token)

    def test_session_timeout_detection(self, engagement_id):
        """Test that session timeout is detected correctly."""
        session = ApprovalSession(
            user="testuser",
            engagement_id=engagement_id,
            ttl_seconds=1,  # 1 second TTL
        )

        # Session should not be expired immediately
        assert session.is_expired() is False
        assert session.is_valid is True

        # Move time forward past TTL
        session.created_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        session.expires_at = session.created_at + timedelta(seconds=1)

        # Now session should be expired
        assert session.is_expired() is True
        assert session.is_valid is False
        assert session.approval_status == "expired"

    def test_session_to_dict(self, engagement_id):
        """Test session serialization to dict."""
        session = ApprovalSession(
            user="testuser",
            engagement_id=engagement_id,
            ttl_seconds=900,
        )
        session_dict = session.to_dict()

        assert "session_id" in session_dict
        assert "user" in session_dict
        assert "engagement_id" in session_dict
        assert "created_at" in session_dict
        assert "expires_at" in session_dict
        assert session_dict["user"] == "testuser"


# ---------------------------------------------------------------------------
# Test ApprovalWorkflow
# ---------------------------------------------------------------------------


class TestApprovalWorkflowSessions:
    """Test ApprovalWorkflow session management."""

    def test_create_session(self, approval_workflow, engagement_id, audit_callback):
        """Test creating a new approval session."""
        session = approval_workflow.create_session(
            user="testuser",
            engagement_id=engagement_id,
        )

        assert session.user == "testuser"
        assert session.engagement_id == engagement_id
        assert audit_callback.called  # Audit event created

    def test_get_session_exists(self, approval_workflow, engagement_id):
        """Test retrieving an existing session."""
        session1 = approval_workflow.create_session("testuser", engagement_id)
        session2 = approval_workflow.get_session(session1.session_id)

        assert session1.session_id == session2.session_id
        assert session1.user == session2.user

    def test_get_session_not_found(self, approval_workflow):
        """Test getting non-existent session raises error."""
        with pytest.raises(ValueError, match="not found"):
            approval_workflow.get_session("nonexistent-id")

    def test_get_session_expired(self, approval_workflow, engagement_id):
        """Test that expired sessions raise SessionExpiredError."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Manually expire the session
        session.created_at = datetime.now(timezone.utc) - timedelta(seconds=1000)
        session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=100)

        with pytest.raises(SessionExpiredError):
            approval_workflow.get_session(session.session_id)

    def test_cleanup_sessions(self, approval_workflow, engagement_id):
        """Test cleanup removes expired sessions."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Manually expire the session
        session.created_at = datetime.now(timezone.utc) - timedelta(seconds=1000)
        session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=100)

        # Cleanup should mark as expired
        approval_workflow.cleanup_sessions()
        assert session.approval_status == "expired"


class TestApprovalWorkflowDisplay:
    """Test display_policies output formatting."""

    def test_display_policies_basic(
        self,
        approval_workflow,
        engagement_id,
        sample_interpretation_result,
        audit_callback,
        capsys,
    ):
        """Test displayPolicies outputs formatted policy information."""
        session = approval_workflow.create_session("testuser", engagement_id)

        approval_workflow.display_policies(session.session_id, sample_interpretation_result)

        captured = capsys.readouterr()
        output = captured.out

        # Check for key sections
        assert "ROE APPROVAL WORKFLOW" in output
        assert "SCOPE (Targets" in output
        assert "ALLOWED ACTIONS" in output
        assert "EXECUTION LIMITS" in output
        assert "CONFIDENCE ANALYSIS" in output

        # Check for actual policy data
        assert "192.168.1.0/24" in output
        assert "example.com" in output
        assert "MODIFY_DATA" in output
        assert "Max iterations: 5" in output

        # Verify audit was called
        assert audit_callback.called

    def test_display_policies_with_warnings(
        self,
        approval_workflow,
        engagement_id,
        sample_interpretation_result,
        capsys,
    ):
        """Test display includes warnings section."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Add warnings
        sample_interpretation_result.warnings.extend([
            "Warning 1",
            "Warning 2",
        ])

        approval_workflow.display_policies(session.session_id, sample_interpretation_result)

        captured = capsys.readouterr()
        assert "WARNINGS" in captured.out
        assert "Warning 1" in captured.out
        assert "Warning 2" in captured.out

    def test_display_policies_with_concerns(
        self,
        approval_workflow,
        engagement_id,
        sample_interpretation_result,
        capsys,
    ):
        """Test display includes concerns section."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Add concerns
        sample_interpretation_result.concerns.extend([
            "Concern 1: Database deletion allowed",
            "Concern 2: High iteration count",
        ])

        approval_workflow.display_policies(session.session_id, sample_interpretation_result)

        captured = capsys.readouterr()
        assert "CONCERNS" in captured.out
        assert "Concern 1" in captured.out


class TestApprovalWorkflowUserApproval:
    """Test user approval prompting."""

    def test_request_approval_yes(
        self,
        approval_workflow,
        engagement_id,
        audit_callback,
        monkeypatch,
    ):
        """Test user approval with 'yes' response."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Mock user input to 'yes'
        monkeypatch.setattr("builtins.input", lambda _: "yes")

        result = approval_workflow.request_approval(session.session_id)

        assert result is True
        assert session.approval_status == "approved"
        assert audit_callback.called

    def test_request_approval_no(
        self,
        approval_workflow,
        engagement_id,
        audit_callback,
        monkeypatch,
    ):
        """Test user approval with 'no' response raises error."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Mock user input to 'no'
        monkeypatch.setattr("builtins.input", lambda _: "no")

        with pytest.raises(ApprovalDeniedError):
            approval_workflow.request_approval(session.session_id)

        assert session.approval_status == "denied"

    def test_request_approval_y_shorthand(
        self,
        approval_workflow,
        engagement_id,
        monkeypatch,
    ):
        """Test user approval with 'y' shorthand."""
        session = approval_workflow.create_session("testuser", engagement_id)

        monkeypatch.setattr("builtins.input", lambda _: "y")

        result = approval_workflow.request_approval(session.session_id)

        assert result is True
        assert session.approval_status == "approved"

    def test_request_approval_n_shorthand(
        self,
        approval_workflow,
        engagement_id,
        monkeypatch,
    ):
        """Test user approval with 'n' shorthand."""
        session = approval_workflow.create_session("testuser", engagement_id)

        monkeypatch.setattr("builtins.input", lambda _: "n")

        with pytest.raises(ApprovalDeniedError):
            approval_workflow.request_approval(session.session_id)

    def test_request_approval_invalid_then_yes(
        self,
        approval_workflow,
        engagement_id,
        monkeypatch,
    ):
        """Test user approval retries on invalid input."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Mock input to return invalid, then valid
        responses = iter(["maybe", "YES"])
        monkeypatch.setattr("builtins.input", lambda _: next(responses))

        result = approval_workflow.request_approval(session.session_id)

        assert result is True


class TestApprovalWorkflowSudoVerification:
    """Test sudo password verification."""

    def test_sudo_verification_success(
        self,
        approval_workflow,
        engagement_id,
        audit_callback,
    ):
        """Test successful sudo password verification."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Mock successful sudo verification
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr=b"")

            result = approval_workflow.verify_sudo_password(
                session.session_id,
                "correct_password",
            )

            assert result is True
            assert session.password_verified is True
            assert session.verification_timestamp is not None
            assert audit_callback.called

    def test_sudo_verification_failed(
        self,
        approval_workflow,
        engagement_id,
        audit_callback,
    ):
        """Test failed sudo password verification."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Mock failed sudo verification
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stderr=b"sudo: 1 incorrect password attempt",
            )

            with pytest.raises(SudoVerificationError):
                approval_workflow.verify_sudo_password(
                    session.session_id,
                    "wrong_password",
                )

            assert session.password_verified is False

    def test_sudo_verification_timeout(
        self,
        approval_workflow,
        engagement_id,
        audit_callback,
    ):
        """Test sudo verification timeout."""
        import subprocess
        session = approval_workflow.create_session("testuser", engagement_id)

        # Mock timeout
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("sudo", 5)

            with pytest.raises(SudoVerificationError):
                approval_workflow.verify_sudo_password(
                    session.session_id,
                    "password",
                )

    def test_sudo_verification_not_found(
        self,
        approval_workflow,
        engagement_id,
    ):
        """Test sudo command not found."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Mock FileNotFoundError
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("sudo not found")

            with pytest.raises(SudoVerificationError, match="not found"):
                approval_workflow.verify_sudo_password(
                    session.session_id,
                    "password",
                )


class TestApprovalWorkflowIntegration:
    """Test end-to-end approval workflow."""

    def test_approve_policies_complete_workflow(
        self,
        approval_workflow,
        engagement_id,
        sample_interpretation_result,
        audit_callback,
    ):
        """Test complete approval workflow: session -> display -> approve -> verify."""
        # Step 1: Create session
        session = approval_workflow.create_session("testuser", engagement_id)

        # Step 2: Request approval
        with patch("builtins.input", return_value="yes"):
            approval_workflow.request_approval(session.session_id)

        # Step 3: Approve policies with password verification
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr=b"")

            record = approval_workflow.approve_policies(
                session.session_id,
                sample_interpretation_result,
                "test_password",
            )

        assert isinstance(record, ApprovalRecord)
        assert record.user == "testuser"
        assert record.engagement_id == engagement_id
        assert record.password_verified is True
        assert record.confidence_score == 0.95

        # Verify audit was called
        assert audit_callback.called

    def test_approve_policies_session_expired(
        self,
        approval_workflow,
        engagement_id,
        sample_interpretation_result,
    ):
        """Test approval fails if session has expired."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Expire session
        session.created_at = datetime.now(timezone.utc) - timedelta(seconds=1000)
        session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=100)

        with pytest.raises(SessionExpiredError):
            approval_workflow.approve_policies(
                session.session_id,
                sample_interpretation_result,
                "password",
            )


class TestApprovalRecord:
    """Test ApprovalRecord creation and serialization."""

    def test_approval_record_creation(self, sample_extracted_policy, engagement_id):
        """Test creating an approval record."""
        record = ApprovalRecord(
            approval_id=uuid4(),
            session_id="test-session-id",
            engagement_id=engagement_id,
            user="testuser",
            extracted_policy=sample_extracted_policy,
            confidence_score=0.95,
            password_verified=True,
            approved_at=datetime.now(timezone.utc),
        )

        assert record.user == "testuser"
        assert record.confidence_score == 0.95
        assert record.password_verified is True

    def test_approval_record_to_dict(
        self,
        sample_extracted_policy,
        engagement_id,
    ):
        """Test approval record serialization."""
        now = datetime.now(timezone.utc)
        approval_id = uuid4()

        record = ApprovalRecord(
            approval_id=approval_id,
            session_id="test-session-id",
            engagement_id=engagement_id,
            user="testuser",
            extracted_policy=sample_extracted_policy,
            confidence_score=0.95,
            password_verified=True,
            approved_at=now,
        )

        record_dict = record.to_dict()

        assert record_dict["user"] == "testuser"
        assert record_dict["confidence_score"] == 0.95
        assert record_dict["password_verified"] is True
        assert str(approval_id) in record_dict["approval_id"]
        assert "extracted_policy" in record_dict


class TestApprovalWorkflowEdgeCases:
    """Test edge cases and error conditions."""

    def test_display_policies_with_empty_scope(
        self,
        approval_workflow,
        engagement_id,
        sample_interpretation_result,
        capsys,
    ):
        """Test display with empty scope lists."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Clear scope
        sample_interpretation_result.extracted_policy.scope_cidrs = []
        sample_interpretation_result.extracted_policy.scope_domains = []
        sample_interpretation_result.extracted_policy.scope_urls = []

        approval_workflow.display_policies(session.session_id, sample_interpretation_result)

        captured = capsys.readouterr()
        assert "ROE APPROVAL WORKFLOW" in captured.out

    def test_display_policies_with_low_confidence(
        self,
        approval_workflow,
        engagement_id,
        sample_interpretation_result,
        capsys,
    ):
        """Test display with low confidence score warnings."""
        session = approval_workflow.create_session("testuser", engagement_id)

        # Set low confidence
        sample_interpretation_result.confidence_score = 0.45

        approval_workflow.display_policies(session.session_id, sample_interpretation_result)

        captured = capsys.readouterr()
        assert "45.0%" in captured.out

    def test_multiple_concurrent_sessions(self, approval_workflow):
        """Test handling multiple concurrent approval sessions."""
        session1 = approval_workflow.create_session("user1")
        session2 = approval_workflow.create_session("user2")
        session3 = approval_workflow.create_session("user3")

        # All sessions should be retrievable
        assert approval_workflow.get_session(session1.session_id).user == "user1"
        assert approval_workflow.get_session(session2.session_id).user == "user2"
        assert approval_workflow.get_session(session3.session_id).user == "user3"

        # Sessions should have unique IDs
        assert session1.session_id != session2.session_id
        assert session2.session_id != session3.session_id
