"""
Approval persistence store — SQLAlchemy-backed storage for approval tickets.

Creates and manages the ``approval_tickets`` database table.  Provides
``upsert`` and ``load_pending`` callables compatible with ``ApprovalService``.

Usage::

    from pwnpilot.data.approval_store import ApprovalStore

    store = ApprovalStore(session)
    service = ApprovalService(
        persist_fn=store.upsert,
        load_fn=store.load_pending,
    )
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import structlog
from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.orm import DeclarativeBase, Session

from pwnpilot.data.models import (
    ActionType,
    ApprovalStatus,
    ApprovalTicket,
    RiskLevel,
)

log = structlog.get_logger(__name__)


class _Base(DeclarativeBase):
    pass


class ApprovalTicketRow(_Base):
    """ORM row for a single approval ticket."""

    __tablename__ = "approval_tickets"

    ticket_id = Column(String(36), primary_key=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    action_id = Column(String(36), nullable=False, index=True)
    action_type = Column(String(64), nullable=False)
    tool_name = Column(String(128), nullable=False)
    risk_level = Column(String(32), nullable=False)
    rationale = Column(Text, nullable=False, default="")
    impact_preview = Column(Text, nullable=False, default="")
    status = Column(String(32), nullable=False, default="PENDING")
    resolved_by = Column(String(255), nullable=True)
    resolution_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)


class ApprovalStore:
    """
    SQLAlchemy-backed persistence for ApprovalService tickets.

    Creates the ``approval_tickets`` table on first use if it doesn't exist.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        _Base.metadata.create_all(bind=session.get_bind())

    # ------------------------------------------------------------------
    # persist_fn — upsert an ApprovalTicket row
    # ------------------------------------------------------------------

    def upsert(self, ticket: ApprovalTicket) -> None:
        """Persist or update an ApprovalTicket row.  Called by ApprovalService."""
        existing = self._session.get(ApprovalTicketRow, str(ticket.ticket_id))
        if existing:
            existing.status = ticket.status.value
            existing.resolved_by = ticket.resolved_by
            existing.resolution_reason = ticket.resolution_reason
            existing.resolved_at = ticket.resolved_at
        else:
            row = ApprovalTicketRow(
                ticket_id=str(ticket.ticket_id),
                engagement_id=str(ticket.engagement_id),
                action_id=str(ticket.action_id),
                action_type=ticket.action_type.value,
                tool_name=ticket.tool_name,
                risk_level=ticket.risk_level.value,
                rationale=ticket.rationale,
                impact_preview=ticket.impact_preview,
                status=ticket.status.value,
                resolved_by=ticket.resolved_by,
                resolution_reason=ticket.resolution_reason,
                created_at=ticket.created_at,
                expires_at=ticket.expires_at,
                resolved_at=ticket.resolved_at,
            )
            self._session.add(row)
        self._session.commit()

    # ------------------------------------------------------------------
    # load_fn — reload pending tickets from DB on startup
    # ------------------------------------------------------------------

    def load_pending(self) -> list[ApprovalTicket]:
        """Return all PENDING tickets so ApprovalService can reload them."""
        rows = (
            self._session.query(ApprovalTicketRow)
            .filter(ApprovalTicketRow.status == ApprovalStatus.PENDING.value)
            .all()
        )
        tickets: list[ApprovalTicket] = []
        for row in rows:
            try:
                ticket = ApprovalTicket(
                    ticket_id=UUID(row.ticket_id),
                    action_id=UUID(row.action_id),
                    engagement_id=UUID(row.engagement_id),
                    action_type=ActionType(row.action_type),
                    tool_name=row.tool_name,
                    rationale=row.rationale,
                    impact_preview=row.impact_preview,
                    risk_level=RiskLevel(row.risk_level),
                    status=ApprovalStatus(row.status),
                    resolved_by=row.resolved_by,
                    resolution_reason=row.resolution_reason,
                    created_at=row.created_at,
                    expires_at=row.expires_at,
                    resolved_at=row.resolved_at,
                )
                tickets.append(ticket)
            except Exception as exc:
                log.warning(
                    "approval_store.reload_failed",
                    ticket_id=row.ticket_id,
                    exc=str(exc),
                )
        return tickets
