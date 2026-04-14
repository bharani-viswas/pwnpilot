from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest

from pwnpilot.agent.roe_interpreter import ExtractedPolicy, InterpretationResult
from pwnpilot.control.roe_approval import (
    ApprovalDeniedError,
    ApprovalWorkflow,
    SessionExpiredError,
    SudoVerificationError,
)


def _policy() -> ExtractedPolicy:
    return ExtractedPolicy(
        scope_cidrs=["10.0.0.0/24"],
        scope_domains=["example.com"],
        scope_urls=["https://example.com"],
        excluded_ips=["10.0.0.5"],
        restricted_actions=["DELETE_DATA"],
        max_iterations=20,
        max_retries=3,
        cloud_allowed=False,
    )


def _result() -> InterpretationResult:
    return InterpretationResult(
        is_valid=True,
        extracted_policy=_policy(),
        confidence_score=0.93,
        warnings=[],
        concerns=[],
        hallucination_risks=[],
        injection_detected=False,
        error_message=None,
    )


def test_create_and_get_session_round_trip() -> None:
    wf = ApprovalWorkflow()
    engagement_id = uuid4()
    session = wf.create_session(user="operator", engagement_id=engagement_id)

    loaded = wf.get_session(session.session_id)
    assert loaded.session_id == session.session_id
    assert loaded.user == "operator"
    assert loaded.engagement_id == engagement_id
    assert loaded.is_valid is True


def test_get_session_raises_when_expired() -> None:
    wf = ApprovalWorkflow(session_ttl_seconds=1)
    session = wf.create_session(user="operator")
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    with pytest.raises(SessionExpiredError):
        wf.get_session(session.session_id)


def test_request_approval_accepts_yes() -> None:
    wf = ApprovalWorkflow()
    session = wf.create_session(user="operator")

    with patch("builtins.input", return_value="yes"):
        approved = wf.request_approval(session.session_id)

    assert approved is True
    assert session.approval_status == "approved"


def test_request_approval_rejects_no() -> None:
    wf = ApprovalWorkflow()
    session = wf.create_session(user="operator")

    with patch("builtins.input", return_value="no"):
        with pytest.raises(ApprovalDeniedError):
            wf.request_approval(session.session_id)

    assert session.approval_status == "denied"


def test_request_approval_reprompts_on_invalid_input() -> None:
    wf = ApprovalWorkflow()
    session = wf.create_session(user="operator")

    with patch("builtins.input", side_effect=["maybe", "y"]):
        approved = wf.request_approval(session.session_id)

    assert approved is True
    assert session.approval_status == "approved"


def test_verify_sudo_password_success_sets_flags() -> None:
    wf = ApprovalWorkflow()
    session = wf.create_session(user="operator")

    class _OK:
        returncode = 0
        stderr = b""

    with patch("subprocess.run", return_value=_OK()):
        verified = wf.verify_sudo_password(session.session_id, "secret")

    assert verified is True
    assert session.password_verified is True
    assert session.verification_timestamp is not None


def test_verify_sudo_password_failure_raises() -> None:
    wf = ApprovalWorkflow()
    session = wf.create_session(user="operator")

    class _Fail:
        returncode = 1
        stderr = b"incorrect password"

    with patch("subprocess.run", return_value=_Fail()):
        with pytest.raises(SudoVerificationError):
            wf.verify_sudo_password(session.session_id, "bad")


def test_verify_sudo_password_timeout_and_notfound_raise() -> None:
    wf = ApprovalWorkflow()
    session = wf.create_session(user="operator")

    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["sudo", "-S", "-v"], timeout=5),
    ):
        with pytest.raises(SudoVerificationError):
            wf.verify_sudo_password(session.session_id, "secret")

    with patch("subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(SudoVerificationError):
            wf.verify_sudo_password(session.session_id, "secret")


def test_approve_policies_returns_record_after_verification() -> None:
    wf = ApprovalWorkflow()
    session = wf.create_session(user="operator")

    class _OK:
        returncode = 0
        stderr = b""

    with patch("subprocess.run", return_value=_OK()):
        record = wf.approve_policies(
            session_id=session.session_id,
            interpretation_result=_result(),
            password="secret",
        )

    payload = record.to_dict()
    assert payload["session_id"] == session.session_id
    assert payload["user"] == "operator"
    assert payload["password_verified"] is True
    assert payload["confidence_score"] == 0.93


def test_cleanup_sessions_marks_expired_sessions() -> None:
    wf = ApprovalWorkflow()
    session = wf.create_session(user="operator")
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    wf.cleanup_sessions()

    assert session.approval_status == "expired"


def test_display_policies_covers_warnings_concerns_and_hallucination() -> None:
    events = []
    wf = ApprovalWorkflow(audit_fn=lambda e: events.append(e))
    session = wf.create_session(user="operator")

    result = InterpretationResult(
        is_valid=True,
        extracted_policy=_policy(),
        confidence_score=0.87,
        warnings=["low confidence in section"],
        concerns=["scope conflict"],
        hallucination_risks=["possible invented URL"],
        injection_detected=True,
        error_message=None,
    )

    with patch("builtins.print") as p:
        wf.display_policies(session.session_id, result)

    assert p.called
    assert any(e.event_type == "roe.approval.policies_displayed" for e in events)


def test_verify_sudo_password_called_process_error_branch() -> None:
    wf = ApprovalWorkflow()
    session = wf.create_session(user="operator")

    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, ["sudo"])):
        with pytest.raises(SudoVerificationError):
            wf.verify_sudo_password(session.session_id, "secret")


def test_audit_callback_failure_is_swallowed() -> None:
    def _broken(_event):
        raise RuntimeError("audit backend down")

    wf = ApprovalWorkflow(audit_fn=_broken)

    # create_session triggers _audit internally; should not raise
    session = wf.create_session(user="operator")
    assert session.user == "operator"
