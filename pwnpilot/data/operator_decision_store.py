"""
OperatorDecisionStore v2 — persists unified OperatorDecision records.

Replaces the parallel ApprovalTicket-only and ROEApprovalRecord-only stores
for all operator-facing decision flows.

v2 decisions cover:
  - Runtime action approvals (was: ApprovalTicket)
  - ROE approvals (was: ROEApprovalRecord)
  - Policy exceptions
  - Deferred decisions

Usage::

    store = OperatorDecisionStore(session)
    store.record(decision)
    decisions = store.decisions_for_engagement(engagement_id)
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Iterator
from uuid import UUID

import structlog
from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.orm import DeclarativeBase, Session

from pwnpilot.data.models import OperatorDecision, OperatorDecisionType

log = structlog.get_logger(__name__)


class _Base(DeclarativeBase):
    pass


class OperatorDecisionRow(_Base):
    """ORM row for a single operator decision."""

    __tablename__ = "operator_decisions"

    decision_id = Column(String(36), primary_key=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    decision_type = Column(String(64), nullable=False)
    scope = Column(Text, nullable=False)
    rationale = Column(Text, nullable=False)
    actor = Column(String(255), nullable=False)
    decided_at = Column(DateTime(timezone=True), nullable=False)
    expiry = Column(DateTime(timezone=True), nullable=True)
    downstream_effect_json = Column(Text, nullable=False, default="{}")
    action_id = Column(String(36), nullable=True)
    roe_id = Column(String(36), nullable=True)
    ticket_id = Column(String(36), nullable=True)
    schema_version = Column(String(16), nullable=False, default="v2")


class OperatorDecisionStore:
    """
    Persistence for unified operator decisions.

    Thread-safe — writes serialised under a threading.Lock.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._lock = threading.Lock()
        _Base.metadata.create_all(bind=session.get_bind())

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(self, decision: OperatorDecision) -> None:
        """Persist an OperatorDecision.  Idempotent (upsert by decision_id)."""
        with self._lock:
            existing = self._session.get(OperatorDecisionRow, str(decision.decision_id))
            if existing:
                return  # Already recorded — decisions are immutable

            row = OperatorDecisionRow(
                decision_id=str(decision.decision_id),
                engagement_id=str(decision.engagement_id),
                decision_type=decision.decision_type.value,
                scope=decision.scope,
                rationale=decision.rationale,
                actor=decision.actor,
                decided_at=decision.decided_at,
                expiry=decision.expiry,
                downstream_effect_json=json.dumps(decision.downstream_effect, default=str),
                action_id=str(decision.action_id) if decision.action_id else None,
                roe_id=str(decision.roe_id) if decision.roe_id else None,
                ticket_id=str(decision.ticket_id) if decision.ticket_id else None,
            )
            self._session.add(row)
            self._session.commit()

        log.debug(
            "operator_decision.recorded",
            decision_id=str(decision.decision_id),
            decision_type=decision.decision_type.value,
            engagement_id=str(decision.engagement_id),
        )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def decisions_for_engagement(
        self, engagement_id: UUID
    ) -> Iterator[OperatorDecision]:
        """Yield OperatorDecision objects for an engagement in chronological order."""
        rows = (
            self._session.query(OperatorDecisionRow)
            .filter(OperatorDecisionRow.engagement_id == str(engagement_id))
            .order_by(OperatorDecisionRow.decided_at)
            .all()
        )
        for row in rows:
            yield self._row_to_model(row)

    def decisions_by_type(
        self, engagement_id: UUID, decision_type: OperatorDecisionType
    ) -> Iterator[OperatorDecision]:
        """Yield decisions of a specific type for an engagement."""
        rows = (
            self._session.query(OperatorDecisionRow)
            .filter(
                OperatorDecisionRow.engagement_id == str(engagement_id),
                OperatorDecisionRow.decision_type == decision_type.value,
            )
            .order_by(OperatorDecisionRow.decided_at)
            .all()
        )
        for row in rows:
            yield self._row_to_model(row)

    def get(self, decision_id: UUID) -> OperatorDecision | None:
        """Return a single decision by ID, or None."""
        row = self._session.get(OperatorDecisionRow, str(decision_id))
        if row is None:
            return None
        return self._row_to_model(row)

    def decision_count(self, engagement_id: UUID) -> int:
        return (
            self._session.query(OperatorDecisionRow)
            .filter(OperatorDecisionRow.engagement_id == str(engagement_id))
            .count()
        )

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_model(row: OperatorDecisionRow) -> OperatorDecision:
        try:
            downstream = json.loads(row.downstream_effect_json)
        except Exception:
            downstream = {}
        return OperatorDecision(
            decision_id=UUID(row.decision_id),
            engagement_id=UUID(row.engagement_id),
            decision_type=OperatorDecisionType(row.decision_type),
            scope=row.scope,
            rationale=row.rationale,
            actor=row.actor,
            decided_at=row.decided_at,
            expiry=row.expiry,
            downstream_effect=downstream,
            action_id=UUID(row.action_id) if row.action_id else None,
            roe_id=UUID(row.roe_id) if row.roe_id else None,
            ticket_id=UUID(row.ticket_id) if row.ticket_id else None,
        )
