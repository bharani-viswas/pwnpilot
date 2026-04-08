"""Unit tests for ApprovalService (Sprint 2)."""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from pwnpilot.control.approval import (
    ApprovalService,
    TicketAlreadyResolvedError,
    TicketNotFoundError,
)
from pwnpilot.data.models import ActionRequest, ActionType, ApprovalStatus, RiskLevel


def _make_action() -> ActionRequest:
    return ActionRequest(
        engagement_id=uuid4(),
        action_type=ActionType.EXPLOIT,
        tool_name="metasploit",
        params={"target": "10.1.2.3"},
        risk_level=RiskLevel.HIGH,
    )


class TestApprovalService:
    def setup_method(self):
        self.svc = ApprovalService(ttl_seconds=60)

    def test_create_ticket(self):
        action = _make_action()
        ticket = self.svc.create_ticket(action, rationale="Test exploitation")
        assert ticket.status == ApprovalStatus.PENDING
        assert ticket.action_id == action.action_id

    def test_approve_ticket(self):
        action = _make_action()
        ticket = self.svc.create_ticket(action)
        approved = self.svc.approve(ticket.ticket_id, resolved_by="Alice", reason="OK")
        assert approved.status == ApprovalStatus.APPROVED
        assert approved.resolved_by == "Alice"

    def test_deny_ticket(self):
        action = _make_action()
        ticket = self.svc.create_ticket(action)
        denied = self.svc.deny(ticket.ticket_id, resolved_by="Bob")
        assert denied.status == ApprovalStatus.DENIED

    def test_defer_ticket(self):
        action = _make_action()
        ticket = self.svc.create_ticket(action)
        deferred = self.svc.defer(ticket.ticket_id, resolved_by="Carol")
        assert deferred.status == ApprovalStatus.DEFERRED

    def test_double_resolve_raises(self):
        action = _make_action()
        ticket = self.svc.create_ticket(action)
        self.svc.approve(ticket.ticket_id, resolved_by="Alice")
        with pytest.raises(TicketAlreadyResolvedError):
            self.svc.deny(ticket.ticket_id, resolved_by="Bob")

    def test_unknown_ticket_raises(self):
        with pytest.raises(TicketNotFoundError):
            self.svc.approve(uuid4(), resolved_by="Alice")

    def test_pending_tickets_list(self):
        svc = ApprovalService(ttl_seconds=60)
        for _ in range(3):
            svc.create_ticket(_make_action())
        assert len(svc.pending_tickets()) == 3

    def test_ticket_expires(self):
        svc = ApprovalService(ttl_seconds=0)  # immediate expiry
        action = _make_action()
        ticket = svc.create_ticket(action)
        # Force expire by calling pending_tickets (triggers _expire_stale)
        import time
        time.sleep(0.01)
        pending = svc.pending_tickets()
        assert ticket not in pending
