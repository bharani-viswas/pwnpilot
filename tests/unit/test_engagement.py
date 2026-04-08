"""Unit tests for EngagementService scope validator (Sprint 1)."""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from pwnpilot.control.engagement import (
    EngagementAuthorizationError,
    EngagementExpiredError,
    EngagementService,
    ScopeViolationError,
)
from pwnpilot.data.models import Engagement, EngagementScope


def _make_engagement(**overrides) -> Engagement:
    now = datetime.now(timezone.utc)
    defaults = dict(
        name="test",
        operator_id="op1",
        scope=EngagementScope(
            scope_cidrs=["192.168.1.0/24"],
            scope_domains=["example.com"],
            scope_urls=["https://app.example.com/api"],
        ),
        roe_document_hash="a" * 64,
        authoriser_identity="Alice",
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=1),
    )
    defaults.update(overrides)
    return Engagement(**defaults)


class TestEngagementServiceCreation:
    def test_valid_engagement_creates_ok(self):
        eng = _make_engagement()
        svc = EngagementService(eng)
        assert svc.engagement.name == "test"

    def test_missing_roe_hash_raises(self):
        eng = _make_engagement(roe_document_hash="")
        with pytest.raises(EngagementAuthorizationError):
            EngagementService(eng)

    def test_missing_authoriser_raises(self):
        eng = _make_engagement(authoriser_identity="")
        with pytest.raises(EngagementAuthorizationError):
            EngagementService(eng)

    def test_invalid_time_window_raises(self):
        now = datetime.now(timezone.utc)
        eng = _make_engagement(valid_from=now + timedelta(hours=1), valid_until=now)
        with pytest.raises(EngagementAuthorizationError):
            EngagementService(eng)


class TestScopeChecking:
    def setup_method(self):
        self.svc = EngagementService(_make_engagement())

    def test_ip_in_cidr_is_in_scope(self):
        assert self.svc.is_in_scope("192.168.1.50") is True

    def test_ip_outside_cidr_not_in_scope(self):
        assert self.svc.is_in_scope("10.0.0.1") is False

    def test_apex_domain_in_scope(self):
        assert self.svc.is_in_scope("example.com") is True

    def test_subdomain_in_scope(self):
        assert self.svc.is_in_scope("sub.example.com") is True

    def test_different_domain_not_in_scope(self):
        assert self.svc.is_in_scope("attacker.com") is False

    def test_url_prefix_in_scope(self):
        assert self.svc.is_in_scope("https://app.example.com/api/v1/resource") is True

    def test_url_outside_prefix_checked_via_domain(self):
        # The domain check kicks in even if URL prefix doesn't match
        assert self.svc.is_in_scope("https://sub.example.com/other") is True

    def test_require_in_scope_raises_on_oos(self):
        with pytest.raises(ScopeViolationError):
            self.svc.require_in_scope("evil.com")


class TestExpiry:
    def test_expired_engagement_raises(self):
        now = datetime.now(timezone.utc)
        eng = _make_engagement(
            valid_from=now - timedelta(hours=4),
            valid_until=now - timedelta(hours=1),
        )
        svc = EngagementService(eng)
        with pytest.raises(EngagementExpiredError):
            svc.assert_valid()

    def test_future_engagement_raises(self):
        now = datetime.now(timezone.utc)
        eng = _make_engagement(
            valid_from=now + timedelta(hours=2),
            valid_until=now + timedelta(hours=4),
        )
        svc = EngagementService(eng)
        with pytest.raises(EngagementExpiredError):
            svc.assert_valid()

    def test_is_in_scope_raises_on_expired(self):
        now = datetime.now(timezone.utc)
        eng = _make_engagement(
            valid_from=now - timedelta(hours=4),
            valid_until=now - timedelta(hours=1),
        )
        svc = EngagementService(eng)
        with pytest.raises(EngagementExpiredError):
            svc.is_in_scope("192.168.1.1")
