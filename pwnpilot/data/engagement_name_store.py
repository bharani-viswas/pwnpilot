"""EngagementNameStore maps user-friendly names to canonical engagement UUIDs."""
from __future__ import annotations

import re
import threading
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import DeclarativeBase, Session


class _Base(DeclarativeBase):
    pass


class EngagementNameRow(_Base):
    __tablename__ = "engagement_names"

    name_key = Column(String(255), primary_key=True)
    display_name = Column(String(255), nullable=False)
    engagement_id = Column(String(36), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)


class EngagementNameStore:
    """Persist and resolve engagement names.

    The table is intentionally simple: one normalized name maps to one
    engagement UUID at any point in time.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._lock = threading.Lock()
        _Base.metadata.create_all(bind=session.get_bind())

    @staticmethod
    def normalize_name(name: str) -> str:
        key = (name or "").strip().lower()
        key = re.sub(r"\s+", "-", key)
        key = re.sub(r"[^a-z0-9._-]", "", key)
        key = re.sub(r"-+", "-", key).strip("-")
        if not key:
            raise ValueError("Engagement name must contain at least one alphanumeric character.")
        return key

    def bind(self, name: str, engagement_id: UUID) -> str:
        """Create or update the name -> engagement mapping."""
        now = datetime.now(timezone.utc)
        name_key = self.normalize_name(name)

        with self._lock:
            row = self._session.get(EngagementNameRow, name_key)
            if row is None:
                row = EngagementNameRow(
                    name_key=name_key,
                    display_name=name,
                    engagement_id=str(engagement_id),
                    created_at=now,
                    updated_at=now,
                )
                self._session.add(row)
            else:
                row.display_name = name
                row.engagement_id = str(engagement_id)
                row.updated_at = now
            self._session.commit()

        return name_key

    def resolve(self, reference: str) -> UUID | None:
        """Resolve an engagement name to UUID. Returns None if unknown."""
        try:
            return UUID(reference)
        except Exception:
            pass

        name_key = self.normalize_name(reference)
        row = self._session.get(EngagementNameRow, name_key)
        if row is None:
            return None
        return UUID(str(row.engagement_id))
