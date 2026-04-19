"""
Rate-limit store — SQLite-backed persistence for policy engine rate-limit counters.

Provides sliding-window rate-limit tracking that survives process restarts.
Implements the same semantics as in-memory TokenBucket but persists to database.

ADR-014: Rate-limit storage is SQLite-backed for resume persistence.
"""
from __future__ import annotations

import threading
import time
from uuid import UUID

import structlog
from sqlalchemy import Column, DateTime, Float, String
from sqlalchemy.orm import DeclarativeBase, Session

log = structlog.get_logger(__name__)

_WINDOW_SECONDS: int = 60


class _Base(DeclarativeBase):
    pass


class RateLimitRecord(_Base):
    """ORM row for a single rate-limit record."""

    __tablename__ = "rate_limit_records"

    id = Column(String(36), primary_key=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    action_class = Column(String(64), nullable=False, index=True)
    timestamp = Column(Float, nullable=False, index=True)


class RateLimitStore:
    """Thread-safe SQLite-backed rate-limit counter storage."""

    def __init__(self, session_factory: callable) -> None:
        """
        Initialize with a session factory (e.g., SessionLocal from database.py).
        
        Args:
            session_factory: A callable that returns a new DB session.
        """
        self._session_factory = session_factory
        self._lock = threading.Lock()

    def record_action(self, engagement_id: UUID | str, action_class: str) -> None:
        """Record an action timestamp for rate-limiting."""
        try:
            from uuid import uuid4
            
            eng_id = str(engagement_id)
            now = time.time()
            
            session = self._session_factory()
            try:
                record = RateLimitRecord(
                    id=str(uuid4()),
                    engagement_id=eng_id,
                    action_class=action_class,
                    timestamp=now,
                )
                session.add(record)
                session.commit()
            finally:
                session.close()
        except Exception as exc:
            log.warning("rate_limit_store.record_error", action_class=action_class, exc=str(exc))

    def count_recent(self, engagement_id: UUID | str, action_class: str) -> int:
        """Count actions in the current window for the given engagement and action class."""
        try:
            eng_id = str(engagement_id)
            cutoff = time.time() - _WINDOW_SECONDS
            
            session = self._session_factory()
            try:
                count = session.query(RateLimitRecord).filter(
                    RateLimitRecord.engagement_id == eng_id,
                    RateLimitRecord.action_class == action_class,
                    RateLimitRecord.timestamp > cutoff,
                ).count()
                return count
            finally:
                session.close()
        except Exception as exc:
            log.warning("rate_limit_store.count_error", action_class=action_class, exc=str(exc))
            return 0

    def reset_engagement(self, engagement_id: UUID | str) -> None:
        """Clear all rate-limit records for an engagement (called on completion)."""
        try:
            eng_id = str(engagement_id)
            
            session = self._session_factory()
            try:
                session.query(RateLimitRecord).filter(
                    RateLimitRecord.engagement_id == eng_id,
                ).delete()
                session.commit()
            finally:
                session.close()
        except Exception as exc:
            log.warning("rate_limit_store.reset_error", engagement_id=eng_id, exc=str(exc))

    def cleanup_old_records(self, older_than_hours: int = 24) -> int:
        """Clean up old rate-limit records (retention management)."""
        try:
            cutoff = time.time() - (older_than_hours * 3600)
            
            session = self._session_factory()
            try:
                count = session.query(RateLimitRecord).filter(
                    RateLimitRecord.timestamp < cutoff,
                ).delete()
                session.commit()
                return count
            finally:
                session.close()
        except Exception as exc:
            log.warning("rate_limit_store.cleanup_error", exc=str(exc))
            return 0
