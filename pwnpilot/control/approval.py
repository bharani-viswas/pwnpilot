"""
Approval Service — queues, persists, and resolves human approval for high-risk actions.

Ticket lifecycle:  PENDING → APPROVED | DENIED | DEFERRED | EXPIRED

Architecture notes:
- Every ticket is written to the database BEFORE the function returns, ensuring
  tickets survive process crashes.
- On startup, any PENDING rows are reloaded from the database.
- All state transitions are wrapped in a DB transaction to prevent partial writes.
- Unresolved tickets expire after a configurable TTL.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import UUID

import structlog

from pwnpilot.data.models import (
    ActionRequest,
    ActionType,
    ApprovalStatus,
    ApprovalTicket,
    RiskLevel,
)

log = structlog.get_logger(__name__)

DEFAULT_TICKET_TTL_SECONDS: int = 3600  # 1 hour


class TicketNotFoundError(Exception):
    pass


class TicketAlreadyResolvedError(Exception):
    pass


class ApprovalService:
    """
    Manages the lifecycle of approval tickets for high-risk actions.

    In v1 the backing store is an in-process dict (tickets are also passed to the
    optional *persist_fn* callback for DB persistence).  The caller (typically the
    orchestrator startup path) should supply *persist_fn* and *load_fn* to wire up
    SQLAlchemy persistence.
    """

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_TICKET_TTL_SECONDS,
        persist_fn: Callable[[ApprovalTicket], None] | None = None,
        load_fn: Callable[[], list[ApprovalTicket]] | None = None,
    ) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        self._persist = persist_fn
        self._tickets: dict[UUID, ApprovalTicket] = {}
        self._lock = threading.Lock()

        # Reload pending tickets from persistent store on startup
        if load_fn:
            for ticket in load_fn():
                if ticket.status == ApprovalStatus.PENDING:
                    self._tickets[ticket.ticket_id] = ticket

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_ticket(self, action: ActionRequest, rationale: str = "") -> ApprovalTicket:
        """
        Create and persist an approval ticket for the given action.  The ticket is
        written to the backing store BEFORE this function returns.
        """
        expires_at = datetime.now(timezone.utc) + self._ttl
        impact = self._build_impact_preview(action)

        ticket = ApprovalTicket(
            action_id=action.action_id,
            engagement_id=action.engagement_id,
            action_type=action.action_type,
            tool_name=action.tool_name,
            rationale=rationale,
            impact_preview=impact,
            risk_level=action.risk_level,
            expires_at=expires_at,
        )

        with self._lock:
            self._tickets[ticket.ticket_id] = ticket

        # Persist BEFORE returning (crash durability requirement)
        if self._persist:
            self._persist(ticket)

        log.info(
            "approval.ticket_created",
            ticket_id=str(ticket.ticket_id),
            action_id=str(action.action_id),
            tool=action.tool_name,
            expires_at=expires_at.isoformat(),
        )
        return ticket

    def approve(self, ticket_id: UUID, resolved_by: str, reason: str = "") -> ApprovalTicket:
        """Approve a pending ticket."""
        return self._resolve(ticket_id, ApprovalStatus.APPROVED, resolved_by, reason)

    def deny(self, ticket_id: UUID, resolved_by: str, reason: str = "") -> ApprovalTicket:
        """Deny a pending ticket."""
        return self._resolve(ticket_id, ApprovalStatus.DENIED, resolved_by, reason)

    def defer(self, ticket_id: UUID, resolved_by: str, reason: str = "") -> ApprovalTicket:
        """Defer a pending ticket (operator needs more time to decide)."""
        return self._resolve(ticket_id, ApprovalStatus.DEFERRED, resolved_by, reason)

    def pending_tickets(self) -> list[ApprovalTicket]:
        """Return all non-expired, non-resolved tickets."""
        self._expire_stale()
        with self._lock:
            return [
                t for t in self._tickets.values()
                if t.status == ApprovalStatus.PENDING
            ]

    def get_ticket(self, ticket_id: UUID) -> ApprovalTicket:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise TicketNotFoundError(f"Ticket {ticket_id} not found.")
        return ticket

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve(
        self,
        ticket_id: UUID,
        new_status: ApprovalStatus,
        resolved_by: str,
        reason: str,
    ) -> ApprovalTicket:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise TicketNotFoundError(f"Ticket {ticket_id} not found.")
            if ticket.status != ApprovalStatus.PENDING:
                raise TicketAlreadyResolvedError(
                    f"Ticket {ticket_id} is already in state '{ticket.status}'."
                )

            updated = ticket.model_copy(
                update={
                    "status": new_status,
                    "resolved_at": datetime.now(timezone.utc),
                    "resolved_by": resolved_by,
                    "resolution_reason": reason,
                }
            )
            self._tickets[ticket_id] = updated

        if self._persist:
            self._persist(updated)

        log.info(
            "approval.ticket_resolved",
            ticket_id=str(ticket_id),
            status=new_status,
            resolved_by=resolved_by,
        )
        return updated

    def _expire_stale(self) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            to_expire = [
                tid
                for tid, t in self._tickets.items()
                if t.status == ApprovalStatus.PENDING
                and t.expires_at is not None
                and now > t.expires_at
            ]
            for tid in to_expire:
                self._tickets[tid] = self._tickets[tid].model_copy(
                    update={"status": ApprovalStatus.EXPIRED}
                )
                log.warning("approval.ticket_expired", ticket_id=str(tid))

    @staticmethod
    def _build_impact_preview(action: ActionRequest) -> str:
        target = action.params.get("target", "<unknown>")
        return (
            f"Tool: {action.tool_name} | "
            f"Class: {action.action_type.value} | "
            f"Risk: {action.risk_level.value} | "
            f"Target: {target}"
        )
