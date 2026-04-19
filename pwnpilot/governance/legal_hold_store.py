"""
Legal hold store — SQLite-backed persistence for legal holds.

Legal holds prevent engagement data from being deleted, even after TTL expiry.
They must survive process restarts.

H-3: Persist legal holds to the database.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import structlog
from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.orm import DeclarativeBase, Session

log = structlog.get_logger(__name__)


class _Base(DeclarativeBase):
    pass


class LegalHoldRecord(_Base):
    """ORM row for a single legal hold."""

    __tablename__ = "legal_holds"

    id = Column(String(36), primary_key=True)
    engagement_id = Column(String(36), nullable=False, unique=True, index=True)
    holder = Column(String(256), nullable=False)
    reason = Column(Text, nullable=False)
    placed_at = Column(DateTime(timezone=True), nullable=False)
    released_at = Column(DateTime(timezone=True), nullable=True)
    released_by = Column(String(256), nullable=True)


class LegalHoldStore:
    """Thread-safe SQLite-backed legal hold storage."""

    def __init__(self, session_factory: callable) -> None:
        """
        Initialize with a session factory (e.g., SessionLocal from database.py).
        
        Args:
            session_factory: A callable that returns a new DB session.
        """
        self._session_factory = session_factory

    def place_hold(
        self,
        engagement_id: UUID | str,
        holder: str,
        reason: str,
    ) -> None:
        """Place a legal hold on an engagement."""
        try:
            from uuid import uuid4
            
            eng_id = str(engagement_id)
            now = datetime.now(timezone.utc)
            
            session = self._session_factory()
            try:
                # Check if hold already exists
                existing = session.query(LegalHoldRecord).filter(
                    LegalHoldRecord.engagement_id == eng_id,
                ).first()
                
                if existing:
                    # Update existing hold if it was previously released
                    if existing.released_at:
                        existing.released_at = None
                        existing.released_by = None
                    existing.holder = holder
                    existing.reason = reason
                    session.commit()
                    log.info("legal_hold_store.hold_reactivated", engagement_id=eng_id)
                else:
                    # Create new hold
                    record = LegalHoldRecord(
                        id=str(uuid4()),
                        engagement_id=eng_id,
                        holder=holder,
                        reason=reason,
                        placed_at=now,
                        released_at=None,
                        released_by=None,
                    )
                    session.add(record)
                    session.commit()
                    log.info("legal_hold_store.hold_placed", engagement_id=eng_id, holder=holder)
            finally:
                session.close()
        except Exception as exc:
            log.warning("legal_hold_store.place_error", engagement_id=str(engagement_id), exc=str(exc))

    def release_hold(self, engagement_id: UUID | str, released_by: str) -> None:
        """Release an active legal hold."""
        try:
            eng_id = str(engagement_id)
            now = datetime.now(timezone.utc)
            
            session = self._session_factory()
            try:
                record = session.query(LegalHoldRecord).filter(
                    LegalHoldRecord.engagement_id == eng_id,
                ).first()
                
                if record:
                    if not record.released_at:
                        record.released_at = now
                        record.released_by = released_by
                        session.commit()
                        log.info("legal_hold_store.hold_released", engagement_id=eng_id)
                else:
                    log.warning("legal_hold_store.no_hold_found", engagement_id=eng_id)
            finally:
                session.close()
        except Exception as exc:
            log.warning("legal_hold_store.release_error", engagement_id=str(engagement_id), exc=str(exc))

    def has_active_hold(self, engagement_id: UUID | str) -> bool:
        """Check if an engagement has an active legal hold."""
        try:
            eng_id = str(engagement_id)
            
            session = self._session_factory()
            try:
                record = session.query(LegalHoldRecord).filter(
                    LegalHoldRecord.engagement_id == eng_id,
                    LegalHoldRecord.released_at.is_(None),
                ).first()
                return record is not None
            finally:
                session.close()
        except Exception as exc:
            log.warning("legal_hold_store.check_error", engagement_id=str(engagement_id), exc=str(exc))
            return False

    def get_hold(self, engagement_id: UUID | str) -> dict[str, object] | None:
        """Get hold details if an active hold exists."""
        try:
            eng_id = str(engagement_id)
            
            session = self._session_factory()
            try:
                record = session.query(LegalHoldRecord).filter(
                    LegalHoldRecord.engagement_id == eng_id,
                ).first()
                
                if record:
                    return {
                        "engagement_id": record.engagement_id,
                        "holder": record.holder,
                        "reason": record.reason,
                        "placed_at": record.placed_at.isoformat() if record.placed_at else None,
                        "released_at": record.released_at.isoformat() if record.released_at else None,
                        "released_by": record.released_by,
                        "is_active": record.released_at is None,
                    }
                return None
            finally:
                session.close()
        except Exception as exc:
            log.warning("legal_hold_store.get_error", engagement_id=str(engagement_id), exc=str(exc))
            return None
