"""
Quality benchmark gate: Approval audit integrity.

Validates that operator decisions are:
  - Persisted with correct types (approve/deny/defer/roe_approval)
  - Queryable and idempotent (duplicate records ignored)
  - Correctly linked to actions, ROE IDs, and ticket IDs
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.data.models import OperatorDecision, OperatorDecisionType
from pwnpilot.data.operator_decision_store import OperatorDecisionStore


def _make_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Session = sessionmaker(bind=engine)
    return Session()


class TestApprovalAuditIntegrityGate:
    """Pass/fail gates for approval audit integrity."""

    def test_record_and_retrieve_approve_decision(self) -> None:
        session = _make_session()
        store = OperatorDecisionStore(session)
        eid = uuid4()
        action_id = uuid4()

        decision = OperatorDecision(
            engagement_id=eid,
            decision_type=OperatorDecisionType.APPROVE,
            scope=f"action:{action_id}",
            rationale="Low-risk recon approved by operator",
            actor="operator@example.com",
            action_id=action_id,
        )

        store.record(decision)
        results = list(store.decisions_for_engagement(eid))
        assert len(results) == 1
        assert results[0].decision_type == OperatorDecisionType.APPROVE
        assert results[0].actor == "operator@example.com"

    def test_record_roe_approval_decision(self) -> None:
        session = _make_session()
        store = OperatorDecisionStore(session)
        eid = uuid4()
        roe_id = uuid4()

        decision = OperatorDecision(
            engagement_id=eid,
            decision_type=OperatorDecisionType.ROE_APPROVAL,
            scope=f"roe:{roe_id}",
            rationale="ROE approved after sudo verification",
            actor="admin",
            roe_id=roe_id,
        )

        store.record(decision)
        roe_decisions = list(
            store.decisions_by_type(eid, OperatorDecisionType.ROE_APPROVAL)
        )
        assert len(roe_decisions) == 1
        assert roe_decisions[0].roe_id == roe_id

    def test_idempotent_record(self) -> None:
        """Recording the same decision twice should not duplicate it."""
        session = _make_session()
        store = OperatorDecisionStore(session)
        eid = uuid4()

        decision = OperatorDecision(
            engagement_id=eid,
            decision_type=OperatorDecisionType.DENY,
            scope="action:test",
            rationale="Out of scope",
            actor="operator",
        )

        store.record(decision)
        store.record(decision)  # idempotent

        count = store.decision_count(eid)
        assert count == 1

    def test_decisions_ordered_by_time(self) -> None:
        """Decisions are returned in chronological order."""
        from datetime import timedelta
        session = _make_session()
        store = OperatorDecisionStore(session)
        eid = uuid4()

        now = datetime.now(timezone.utc)
        for i in range(3):
            d = OperatorDecision(
                engagement_id=eid,
                decision_type=OperatorDecisionType.APPROVE,
                scope=f"action:{i}",
                rationale=f"Decision {i}",
                actor="operator",
                decided_at=now + timedelta(seconds=i),
            )
            store.record(d)

        decisions = list(store.decisions_for_engagement(eid))
        assert len(decisions) == 3
        times = [d.decided_at for d in decisions]
        assert times == sorted(times)

    def test_multiple_engagements_isolated(self) -> None:
        """Decisions for different engagements are not mixed."""
        session = _make_session()
        store = OperatorDecisionStore(session)
        eid_a = uuid4()
        eid_b = uuid4()

        for eid in [eid_a, eid_b]:
            store.record(OperatorDecision(
                engagement_id=eid,
                decision_type=OperatorDecisionType.DEFER,
                scope="action:x",
                rationale="Deferred pending review",
                actor="operator",
            ))

        assert store.decision_count(eid_a) == 1
        assert store.decision_count(eid_b) == 1

    def test_get_by_id(self) -> None:
        """A recorded decision can be retrieved by its ID."""
        session = _make_session()
        store = OperatorDecisionStore(session)
        eid = uuid4()

        decision = OperatorDecision(
            engagement_id=eid,
            decision_type=OperatorDecisionType.POLICY_EXCEPTION,
            scope="tool_family:exploit",
            rationale="Approved for red-team exercise",
            actor="red-team-lead",
        )
        store.record(decision)

        retrieved = store.get(decision.decision_id)
        assert retrieved is not None
        assert retrieved.decision_id == decision.decision_id
        assert retrieved.decision_type == OperatorDecisionType.POLICY_EXCEPTION

    def test_get_unknown_id_returns_none(self) -> None:
        session = _make_session()
        store = OperatorDecisionStore(session)
        assert store.get(uuid4()) is None
