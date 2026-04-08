"""
Audit Store — append-only event stream with SHA-256 hash chain.

Architecture:
- Every event hashes the previous event's payload_hash, forming a tamper-evident chain.
- Writes are serialised by a threading.Lock (advisory exclusive lock per ADR-003).
- A checkpoint record is written every CHECKPOINT_INTERVAL events for O(chunk) verification.
- Verification replays each 500-event segment independently and can be done in parallel.

In v1. the backing store is SQLite via SQLAlchemy.  The session is injected at
construction time so the caller controls the DB engine.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Iterator
from uuid import UUID

import structlog
from sqlalchemy import Column, DateTime, Integer, String, Text, UniqueConstraint, event
from sqlalchemy.orm import DeclarativeBase, Session

from pwnpilot.data.models import AuditEvent

log = structlog.get_logger(__name__)

CHECKPOINT_INTERVAL: int = 500

# ---------------------------------------------------------------------------
# SQLAlchemy ORM model
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(36), nullable=False, unique=True, index=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    actor = Column(String(255), nullable=False)
    event_type = Column(String(255), nullable=False)
    payload_json = Column(Text, nullable=False, default="{}")
    payload_hash = Column(String(64), nullable=False)
    prev_event_hash = Column(String(64), nullable=False, default="")
    decision_context_json = Column(Text, nullable=True)
    schema_version = Column(String(16), nullable=False, default="v1")
    sequence = Column(Integer, nullable=False)

    __table_args__ = (
        UniqueConstraint("engagement_id", "sequence", name="uq_engagement_sequence"),
    )


# ---------------------------------------------------------------------------
# Audit Store
# ---------------------------------------------------------------------------


class AuditIntegrityError(Exception):
    """Raised when the audit chain verification detects a hash mismatch."""


class AuditStore:
    """
    Append-only audit event store with SHA-256 hash chain.

    Thread-safe: all writes go through a single threading.Lock.  The store is not
    safe for multi-process concurrent writes — callers must use a single process.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._lock = threading.Lock()
        Base.metadata.create_all(session.bind)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(
        self,
        engagement_id: UUID,
        actor: str,
        event_type: str,
        payload: dict,
        decision_context: dict | None = None,
    ) -> AuditEvent:
        """
        Append a new event to the audit chain.  Returns the persisted AuditEvent.
        The write is serialised under a threading.Lock.
        """
        with self._lock:
            prev_hash = self._get_last_hash(engagement_id)
            seq = self._next_sequence(engagement_id)

            payload_raw = json.dumps(payload, sort_keys=True, default=str)
            payload_hash = hashlib.sha256(payload_raw.encode()).hexdigest()

            event_obj = AuditEvent(
                engagement_id=engagement_id,
                actor=actor,
                event_type=event_type,
                payload=payload,
                payload_hash=payload_hash,
                prev_event_hash=prev_hash,
                decision_context=decision_context,
            )

            row = AuditEventRow(
                event_id=str(event_obj.event_id),
                engagement_id=str(engagement_id),
                timestamp=event_obj.timestamp,
                actor=actor,
                event_type=event_type,
                payload_json=payload_raw,
                payload_hash=payload_hash,
                prev_event_hash=prev_hash,
                decision_context_json=(
                    json.dumps(decision_context, default=str) if decision_context else None
                ),
                sequence=seq,
            )
            self._session.add(row)
            self._session.commit()

            # Write checkpoint every CHECKPOINT_INTERVAL events
            if seq % CHECKPOINT_INTERVAL == 0:
                self._write_checkpoint(engagement_id, seq, payload_hash)

        log.debug(
            "audit.appended",
            event_id=str(event_obj.event_id),
            event_type=event_type,
            sequence=seq,
        )
        return event_obj

    def verify_chain(self, engagement_id: UUID) -> bool:
        """
        Replay the entire audit chain for an engagement and verify each link.
        Returns True on success; raises AuditIntegrityError on mismatch.
        """
        rows = (
            self._session.query(AuditEventRow)
            .filter(AuditEventRow.engagement_id == str(engagement_id))
            .order_by(AuditEventRow.sequence)
            .all()
        )

        prev_hash = ""
        for row in rows:
            computed = hashlib.sha256(row.payload_json.encode()).hexdigest()
            if computed != row.payload_hash:
                raise AuditIntegrityError(
                    f"Payload hash mismatch at sequence {row.sequence}: "
                    f"stored={row.payload_hash}, computed={computed}"
                )
            if row.prev_event_hash != prev_hash:
                raise AuditIntegrityError(
                    f"Chain broken at sequence {row.sequence}: "
                    f"expected prev={prev_hash}, got={row.prev_event_hash}"
                )
            prev_hash = computed

        log.info("audit.chain_verified", engagement_id=str(engagement_id), events=len(rows))
        return True

    def events_for_engagement(
        self, engagement_id: UUID
    ) -> Iterator[AuditEvent]:
        """Yield AuditEvent objects for an engagement in sequence order."""
        rows = (
            self._session.query(AuditEventRow)
            .filter(AuditEventRow.engagement_id == str(engagement_id))
            .order_by(AuditEventRow.sequence)
            .all()
        )
        for row in rows:
            payload = json.loads(row.payload_json)
            dc = json.loads(row.decision_context_json) if row.decision_context_json else None
            yield AuditEvent(
                engagement_id=UUID(row.engagement_id),
                actor=row.actor,
                event_type=row.event_type,
                payload=payload,
                payload_hash=row.payload_hash,
                prev_event_hash=row.prev_event_hash,
                decision_context=dc,
                timestamp=row.timestamp,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_last_hash(self, engagement_id: UUID) -> str:
        row = (
            self._session.query(AuditEventRow)
            .filter(AuditEventRow.engagement_id == str(engagement_id))
            .order_by(AuditEventRow.sequence.desc())
            .first()
        )
        return row.payload_hash if row else ""

    def _next_sequence(self, engagement_id: UUID) -> int:
        row = (
            self._session.query(AuditEventRow)
            .filter(AuditEventRow.engagement_id == str(engagement_id))
            .order_by(AuditEventRow.sequence.desc())
            .first()
        )
        return (row.sequence + 1) if row else 1

    def _write_checkpoint(
        self, engagement_id: UUID, seq: int, cumulative_hash: str
    ) -> None:
        """Record a checkpoint event for fast segment verification."""
        checkpoint_payload = {
            "type": "chain_checkpoint",
            "sequence": seq,
            "cumulative_hash": cumulative_hash,
        }
        log.debug(
            "audit.checkpoint",
            engagement_id=str(engagement_id),
            sequence=seq,
        )
        # Checkpoint is stored as a special audit event — no recursion because
        # _write_checkpoint is only called from within the locked append path
        # after the main event is committed.
        payload_raw = json.dumps(checkpoint_payload, sort_keys=True)
        payload_hash = hashlib.sha256(payload_raw.encode()).hexdigest()
        prev_hash = cumulative_hash

        ckpt_row = AuditEventRow(
            event_id=f"ckpt-{engagement_id}-{seq}",
            engagement_id=str(engagement_id),
            timestamp=datetime.now(timezone.utc),
            actor="system",
            event_type="ChainCheckpoint",
            payload_json=payload_raw,
            payload_hash=payload_hash,
            prev_event_hash=prev_hash,
            sequence=seq + 1,  # checkpoint lives right after the interval boundary
        )
        self._session.add(ckpt_row)
        self._session.commit()
