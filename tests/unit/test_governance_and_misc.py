"""Unit tests for kill switch, authorization, simulation, redactor, action envelope."""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from pwnpilot.agent.action_envelope import ActionEnvelopeError, parse_action_envelope
from pwnpilot.agent.action_validator import ActionValidationError, ActionValidator
from pwnpilot.data.models import ActionRequest, ActionType, RiskLevel
from pwnpilot.governance.authorization import (
    AuthorizationArtifact,
    AuthorizationError,
    assert_authorized,
)
from pwnpilot.governance.kill_switch import KillSwitch
from pwnpilot.plugins.generic_adapter import GenericCLIAdapter
from pwnpilot.plugins.manifest_loader import load_manifest_file
from pwnpilot.secrets.redactor import Redactor


def _nmap_adapter() -> GenericCLIAdapter:
    manifest_path = Path(__file__).resolve().parents[2] / "pwnpilot" / "plugins" / "manifests" / "nmap.yaml"
    return GenericCLIAdapter(load_manifest_file(manifest_path))


class TestKillSwitch:
    def test_initially_not_set(self):
        ks = KillSwitch()
        assert ks.is_set() is False

    def test_trigger_sets(self):
        ks = KillSwitch()
        ks.trigger("test")
        assert ks.is_set() is True
        assert ks.reason == "test"

    def test_idempotent_trigger(self):
        ks = KillSwitch()
        ks.trigger("first")
        ks.trigger("second")
        assert ks.reason == "first"  # first trigger wins

    def test_audit_fn_called_on_trigger(self):
        calls = []
        ks = KillSwitch(audit_fn=lambda r: calls.append(r))
        ks.trigger("halt!")
        assert calls == ["halt!"]

    def test_clear_resets(self):
        ks = KillSwitch()
        ks.trigger("x")
        ks.clear()
        assert ks.is_set() is False


class TestAuthorization:
    def _make_artifact(self, **overrides) -> AuthorizationArtifact:
        now = datetime.now(timezone.utc)
        defaults = dict(
            engagement_id=uuid4(),
            approver_identity="Alice",
            ticket_reference="TICKET-001",
            roe_document_hash="d" * 64,
            valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(hours=4),
            signed_at=now,
        )
        defaults.update(overrides)
        return AuthorizationArtifact(**defaults)

    def test_valid_artifact_passes(self):
        artifact = self._make_artifact()
        assert_authorized(artifact)  # should not raise

    def test_expired_artifact_raises(self):
        now = datetime.now(timezone.utc)
        artifact = self._make_artifact(
            valid_from=now - timedelta(hours=4),
            valid_until=now - timedelta(hours=1),
        )
        with pytest.raises(AuthorizationError):
            assert_authorized(artifact)

    def test_future_artifact_raises(self):
        now = datetime.now(timezone.utc)
        artifact = self._make_artifact(
            valid_from=now + timedelta(hours=2),
            valid_until=now + timedelta(hours=4),
        )
        with pytest.raises(AuthorizationError):
            assert_authorized(artifact)

    def test_missing_roe_hash_raises(self):
        artifact = self._make_artifact(roe_document_hash="")
        with pytest.raises(AuthorizationError):
            assert_authorized(artifact)


class TestRedactor:
    def setup_method(self):
        self.r = Redactor()

    def test_scrubs_private_ip(self):
        result = self.r.scrub("Connect to 192.168.1.50 for auth")
        assert "192.168.1.50" not in result
        assert "[REDACTED]" in result

    def test_scrubs_api_key_pattern(self):
        result = self.r.scrub("api_key=supersecrettoken123")
        assert "supersecrettoken123" not in result

    def test_plain_text_preserved(self):
        result = self.r.scrub("The vulnerability is a buffer overflow")
        assert "buffer overflow" in result

    def test_scrub_dict_recurses(self):
        data = {"target": "192.168.1.1", "nested": {"key": "api_key=abc"}}
        result = self.r.scrub_dict(data)
        assert "192.168.1.1" not in str(result)


class TestActionEnvelope:
    def test_valid_envelope_parses(self):
        import json
        payload = json.dumps({
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "target": "10.0.0.1",
            "rationale": "Initial recon",
            "estimated_risk": "low",
        })
        env = parse_action_envelope(payload)
        assert env.tool_name == "nmap"

    def test_markdown_fenced_json_parsed(self):
        import json
        payload = "```json\n" + json.dumps({
            "action_type": "active_scan",
            "tool_name": "nuclei",
            "target": "http://10.0.0.1",
            "rationale": "Scan",
            "estimated_risk": "medium",
        }) + "\n```"
        env = parse_action_envelope(payload)
        assert env.tool_name == "nuclei"

    def test_to_action_request_succeeds(self):
        import json
        payload = json.dumps({
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "target": "10.0.0.1",
            "rationale": "Test",
            "estimated_risk": "low",
        })
        env = parse_action_envelope(payload)
        ar = env.to_action_request(uuid4())
        assert ar.action_type == ActionType.RECON_PASSIVE
        assert ar.risk_level == RiskLevel.LOW


class TestActionValidator:
    def setup_method(self):
        self.validator = ActionValidator({"nmap": _nmap_adapter()})

    def test_valid_action_passes(self):
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )
        result = self.validator.validate(action)
        assert result is action

    def test_unknown_tool_raises(self):
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="unknown_tool",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )
        with pytest.raises(ActionValidationError):
            self.validator.validate(action)

    def test_invalid_params_raises(self):
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": ""},  # empty target
            risk_level=RiskLevel.MEDIUM,
        )
        with pytest.raises(ActionValidationError):
            self.validator.validate(action)
