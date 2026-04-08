"""Unit tests for PolicyEngine (Sprint 2)."""
from __future__ import annotations

import time
import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from pwnpilot.control.engagement import EngagementService
from pwnpilot.control.policy import PolicyEngine, _HARD_RATE_LIMIT
from pwnpilot.data.models import (
    ActionRequest,
    ActionType,
    GateType,
    PolicyVerdict,
    RiskLevel,
    Engagement,
    EngagementScope,
)


def _make_svc() -> EngagementService:
    now = datetime.now(timezone.utc)
    eng = Engagement(
        name="policy-test",
        operator_id="op",
        scope=EngagementScope(
            scope_cidrs=["10.0.0.0/8"],
            scope_domains=["target.local"],
        ),
        roe_document_hash="b" * 64,
        authoriser_identity="Bob",
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=4),
    )
    return EngagementService(eng)


def _make_action(
    action_type: ActionType = ActionType.RECON_PASSIVE,
    target: str = "10.1.1.1",
    tool: str = "nmap",
    risk: RiskLevel = RiskLevel.LOW,
    engagement_id=None,
) -> ActionRequest:
    svc = _make_svc()
    return ActionRequest(
        engagement_id=engagement_id or uuid4(),
        action_type=action_type,
        tool_name=tool,
        params={"target": target},
        risk_level=risk,
    )


class TestPolicyGates:
    def setup_method(self):
        self.svc = _make_svc()
        self.engine = PolicyEngine(self.svc)

    def test_recon_passive_allowed(self):
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.RECON_PASSIVE,
            tool_name="nmap",
            params={"target": "10.1.2.3"},
            risk_level=RiskLevel.LOW,
        )
        d = self.engine.evaluate(action)
        assert d.verdict == PolicyVerdict.ALLOW

    def test_active_scan_allowed_within_limit(self):
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": "10.1.2.3"},
            risk_level=RiskLevel.MEDIUM,
        )
        d = self.engine.evaluate(action)
        assert d.verdict == PolicyVerdict.ALLOW

    def test_exploit_requires_approval(self):
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.EXPLOIT,
            tool_name="metasploit",
            params={"target": "10.1.2.3"},
            risk_level=RiskLevel.HIGH,
        )
        d = self.engine.evaluate(action)
        assert d.verdict == PolicyVerdict.REQUIRES_APPROVAL

    def test_post_exploit_requires_approval(self):
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.POST_EXPLOIT,
            tool_name="mimikatz",
            params={"target": "10.1.2.3"},
            risk_level=RiskLevel.CRITICAL,
        )
        d = self.engine.evaluate(action)
        assert d.verdict == PolicyVerdict.REQUIRES_APPROVAL

    def test_data_exfil_denied(self):
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.DATA_EXFIL,
            tool_name="wget",
            params={"target": "10.1.2.3"},
            risk_level=RiskLevel.CRITICAL,
        )
        d = self.engine.evaluate(action)
        assert d.verdict == PolicyVerdict.DENY

    def test_out_of_scope_target_denied(self):
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.RECON_PASSIVE,
            tool_name="nmap",
            params={"target": "8.8.8.8"},  # not in scope
            risk_level=RiskLevel.LOW,
        )
        d = self.engine.evaluate(action)
        assert d.verdict == PolicyVerdict.DENY
        assert d.gate_type == GateType.SCOPE_VIOLATION


class TestRateLimiting:
    def test_active_scan_hard_limit_blocks(self):
        svc = _make_svc()
        engine = PolicyEngine(svc)
        eng_id = uuid4()

        # Fill the bucket
        for _ in range(_HARD_RATE_LIMIT):
            action = ActionRequest(
                engagement_id=eng_id,
                action_type=ActionType.ACTIVE_SCAN,
                tool_name="nmap",
                params={"target": "10.1.2.3"},
                risk_level=RiskLevel.MEDIUM,
            )
            d = engine.evaluate(action)
            assert d.verdict == PolicyVerdict.ALLOW

        # Next should be blocked
        action = ActionRequest(
            engagement_id=eng_id,
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": "10.1.2.3"},
            risk_level=RiskLevel.MEDIUM,
        )
        d = engine.evaluate(action)
        assert d.verdict == PolicyVerdict.DENY
        assert d.gate_type == GateType.RATE_LIMIT
