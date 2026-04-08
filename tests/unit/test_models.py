"""Unit tests for data models (Sprint 1)."""
from __future__ import annotations

import pytest
from uuid import uuid4

from pwnpilot.data.models import (
    ActionRequest,
    ActionType,
    AuditEvent,
    Exploitability,
    Finding,
    FindingStatus,
    PlannerProposal,
    PolicyDecision,
    PolicyVerdict,
    GateType,
    RiskLevel,
    Severity,
    ValidationResult,
)


class TestActionRequest:
    def test_constructs_with_defaults(self):
        ar = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.RECON_PASSIVE,
            tool_name="nmap",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.LOW,
        )
        assert ar.schema_version == "v1"
        assert ar.requires_approval is False

    def test_payload_hash_is_deterministic(self):
        eid = uuid4()
        ar1 = ActionRequest(
            engagement_id=eid,
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )
        # Same fields, different action_id → different hash (action_id is in payload)
        assert len(ar1.payload_hash()) == 64


class TestAuditEvent:
    def test_payload_hash_auto_computed(self):
        ev = AuditEvent(
            engagement_id=uuid4(),
            actor="system",
            event_type="TestEvent",
            payload={"foo": "bar"},
        )
        assert len(ev.payload_hash) == 64

    def test_prev_event_hash_default_empty(self):
        ev = AuditEvent(
            engagement_id=uuid4(),
            actor="system",
            event_type="TestEvent",
        )
        assert ev.prev_event_hash == ""


class TestFinding:
    def test_default_status_is_new(self):
        f = Finding(
            engagement_id=uuid4(),
            asset_ref="10.0.0.1:80",
            title="Test vuln",
            vuln_ref="CVE-2024-0001",
            severity=Severity.HIGH,
        )
        assert f.status == FindingStatus.NEW
        assert f.exploitability == Exploitability.NONE


class TestValidationResult:
    def test_valid_verdicts(self):
        for v in ("approve", "reject", "escalate"):
            vr = ValidationResult(verdict=v, rationale="test")
            assert vr.verdict == v

    def test_invalid_verdict_raises(self):
        with pytest.raises(Exception):
            ValidationResult(verdict="allow", rationale="test")


class TestPolicyDecision:
    def test_deny_decision(self):
        d = PolicyDecision(
            verdict=PolicyVerdict.DENY,
            reason="out of scope",
            gate_type=GateType.SCOPE_VIOLATION,
        )
        assert d.verdict == PolicyVerdict.DENY
