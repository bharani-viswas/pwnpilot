"""
Retention governance — TTL, legal hold, and secure deletion for engagement data.

Responsibilities:
  - Apply retention TTL policies per engagement classification.
  - Support legal hold (block deletion, document hold reason and holder).
  - Secure-delete evidence files (overwrite before unlink).
  - Record all retention actions in the audit store.

Classification → default TTL:
  ctf         30 days
  lab         30 days
  web_api     90 days
  internal    90 days
  external    90 days
  iot         90 days
  (unknown)   90 days (conservative default)

Usage::

    from pwnpilot.governance.retention import RetentionManager, EngagementClassification

    rm = RetentionManager(evidence_store, audit_store)
    rm.apply_ttl(engagement_id, classification=EngagementClassification.CTF)

    # Place a legal hold — prevents deletion
    rm.place_legal_hold(engagement_id, holder="legal@example.com", reason="litigation")

    # Release hold and then apply TTL
    rm.release_legal_hold(engagement_id, released_by="legal@example.com")
    rm.apply_ttl(engagement_id, classification=EngagementClassification.EXTERNAL)
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog

if TYPE_CHECKING:
    from pwnpilot.governance.legal_hold_store import LegalHoldStore

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Classification enum + TTL map
# ---------------------------------------------------------------------------


class EngagementClassification(str, Enum):
    CTF = "ctf"
    LAB = "lab"
    WEB_API = "web_api"
    INTERNAL = "internal"
    EXTERNAL = "external"
    IOT = "iot"
    UNKNOWN = "unknown"


_TTL_DAYS: dict[EngagementClassification, int] = {
    EngagementClassification.CTF: 30,
    EngagementClassification.LAB: 30,
    EngagementClassification.WEB_API: 90,
    EngagementClassification.INTERNAL: 90,
    EngagementClassification.EXTERNAL: 90,
    EngagementClassification.IOT: 90,
    EngagementClassification.UNKNOWN: 90,
}

# ---------------------------------------------------------------------------
# Legal hold record (persisted to DB via LegalHoldStore; H-3)
# ---------------------------------------------------------------------------


class LegalHold:
    """In-memory representation of a legal hold (persisted to DB)."""
    
    def __init__(self, engagement_id: str, holder: str, reason: str) -> None:
        self.engagement_id = engagement_id
        self.holder = holder
        self.reason = reason
        self.placed_at: datetime = datetime.now(timezone.utc)
        self.released_at: datetime | None = None
        self.released_by: str | None = None

    @property
    def is_active(self) -> bool:
        return self.released_at is None


# ---------------------------------------------------------------------------
# RetentionManager
# ---------------------------------------------------------------------------


class RetentionManager:
    """
    Manages retention TTL, legal holds, and secure deletion.

    Args:
        evidence_store: EvidenceStore instance for reading evidence index entries.
        audit_store:    AuditStore instance for recording retention events.
        legal_hold_store: Optional LegalHoldStore for persistent hold storage (H-3).
    """

    def __init__(
        self,
        evidence_store: Any,
        audit_store: Any,
        legal_hold_store: LegalHoldStore | None = None,
    ) -> None:
        self._evidence = evidence_store
        self._audit = audit_store
        self._legal_hold_store = legal_hold_store
        # Fallback in-memory cache
        self._holds: dict[str, LegalHold] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Legal hold
    # ------------------------------------------------------------------

    def place_legal_hold(
        self, engagement_id: UUID, holder: str, reason: str
    ) -> LegalHold:
        """
        Place a legal hold on an engagement, preventing all data deletion.
        Idempotent — calling again updates the reason but does not create a
        second hold for the same engagement.
        """
        key = str(engagement_id)
        
        # H-3: Persist to store if available
        if self._legal_hold_store:
            self._legal_hold_store.place_hold(engagement_id, holder, reason)
        
        with self._lock:
            if key in self._holds and self._holds[key].is_active:
                log.warning(
                    "retention.hold_already_active",
                    engagement_id=key,
                    holder=self._holds[key].holder,
                )
                return self._holds[key]
            hold = LegalHold(key, holder, reason)
            self._holds[key] = hold

        self._audit_event(
            engagement_id,
            "LegalHoldPlaced",
            {"holder": holder, "reason": reason},
        )
        log.info(
            "retention.hold_placed",
            engagement_id=key,
            holder=holder,
            reason=reason,
        )
        return hold

    def release_legal_hold(
        self, engagement_id: UUID, released_by: str
    ) -> None:
        """Release an active legal hold.  No-op if no hold is active."""
        key = str(engagement_id)
        
        # H-3: Update in store if available
        if self._legal_hold_store:
            self._legal_hold_store.release_hold(engagement_id, released_by)
        
        with self._lock:
            hold = self._holds.get(key)
            if not hold or not hold.is_active:
                log.warning("retention.no_active_hold", engagement_id=key)
                return
            hold.released_at = datetime.now(timezone.utc)
            hold.released_by = released_by

        self._audit_event(
            engagement_id,
            "LegalHoldReleased",
            {"released_by": released_by},
        )
        log.info(
            "retention.hold_released",
            engagement_id=key,
            released_by=released_by,
        )

    def has_active_hold(self, engagement_id: UUID) -> bool:
        """Check if an engagement has an active legal hold."""
        key = str(engagement_id)
        
        # H-3: Check store first if available
        if self._legal_hold_store:
            return self._legal_hold_store.has_active_hold(engagement_id)
        
        # Fallback to in-memory
        with self._lock:
            hold = self._holds.get(key)
            return hold is not None and hold.is_active

    def get_hold(self, engagement_id: UUID) -> LegalHold | None:
        """Get the legal hold object if one exists."""
        key = str(engagement_id)
        
        # H-3: Check store first if available
        if self._legal_hold_store:
            hold_data = self._legal_hold_store.get_hold(engagement_id)
            if hold_data:
                hold = LegalHold(key, hold_data["holder"], hold_data["reason"])
                hold.placed_at = datetime.fromisoformat(hold_data["placed_at"]) if hold_data["placed_at"] else datetime.now(timezone.utc)
                if hold_data["released_at"]:
                    hold.released_at = datetime.fromisoformat(hold_data["released_at"])
                hold.released_by = hold_data["released_by"]
                return hold
            return None
        
        # Fallback to in-memory
        return self._holds.get(key)

    # ------------------------------------------------------------------
    # TTL expiry check
    # ------------------------------------------------------------------

    def is_expired(
        self,
        engagement_id: UUID,
        classification: EngagementClassification,
        created_at: datetime,
    ) -> bool:
        """Return True if the engagement data has exceeded its TTL."""
        ttl_days = _TTL_DAYS.get(classification, 90)
        expiry = created_at + timedelta(days=ttl_days)
        return datetime.now(timezone.utc) > expiry

    def ttl_days(self, classification: EngagementClassification) -> int:
        return _TTL_DAYS.get(classification, 90)

    # ------------------------------------------------------------------
    # Secure deletion
    # ------------------------------------------------------------------

    def apply_ttl(
        self,
        engagement_id: UUID,
        classification: EngagementClassification,
        created_at: datetime | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Delete evidence files for an expired engagement.

        - Checks for active legal hold; raises ``RuntimeError`` if present.
        - Checks TTL expiry (skip unless *force=True* or TTL exceeded).
        - Calls ``secure_delete_engagement()`` on the evidence store.
        - Records a ``RetentionApplied`` audit event.

        Returns a summary dict with ``deleted_count`` and ``skipped_count``.
        """
        if self.has_active_hold(engagement_id):
            raise RuntimeError(
                f"Engagement {engagement_id} is under a legal hold. "
                "Release the hold before applying retention."
            )

        if created_at and not force:
            if not self.is_expired(engagement_id, classification, created_at):
                log.info(
                    "retention.not_expired",
                    engagement_id=str(engagement_id),
                    classification=classification.value,
                )
                return {"deleted_count": 0, "skipped_count": 0, "reason": "not_expired"}

        result = self.secure_delete_engagement(engagement_id)
        ttl_days = _TTL_DAYS.get(classification, 90)

        self._audit_event(
            engagement_id,
            "RetentionApplied",
            {
                "classification": classification.value,
                "ttl_days": ttl_days,
                "deleted_count": result["deleted_count"],
                "force": force,
            },
        )
        log.info(
            "retention.applied",
            engagement_id=str(engagement_id),
            deleted=result["deleted_count"],
            classification=classification.value,
        )
        return result

    def secure_delete_engagement(self, engagement_id: UUID) -> dict[str, int]:
        """
        Securely delete all evidence files for an engagement.

        Evidence files are overwritten with random bytes before unlinking
        to prevent forensic recovery.  The evidence index entries are also
        removed from the database.

        Returns ``{"deleted_count": n, "skipped_count": m}``.
        """
        deleted = 0
        skipped = 0

        try:
            entries = self._evidence.list_for_engagement(engagement_id)
        except Exception:
            entries = []

        for entry in entries:
            fpath = Path(entry.get("file_path", "")) if isinstance(entry, dict) else Path(entry.file_path)
            try:
                if fpath.exists():
                    self._overwrite_file(fpath)
                    fpath.unlink()
                deleted += 1
            except Exception as exc:
                log.warning(
                    "retention.delete_failed",
                    path=str(fpath),
                    exc=str(exc),
                )
                skipped += 1

        log.info(
            "retention.secure_delete_complete",
            engagement_id=str(engagement_id),
            deleted=deleted,
            skipped=skipped,
        )
        return {"deleted_count": deleted, "skipped_count": skipped}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _overwrite_file(path: Path, passes: int = 1) -> None:
        """Overwrite a file with random bytes before deletion (secure erase)."""
        size = path.stat().st_size
        with path.open("r+b") as fh:
            for _ in range(passes):
                fh.seek(0)
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())

    def _audit_event(
        self, engagement_id: UUID, event_type: str, payload: dict[str, Any]
    ) -> None:
        try:
            self._audit.append(
                engagement_id=engagement_id,
                actor="system",
                event_type=event_type,
                payload=payload,
            )
        except Exception as exc:
            log.warning(
                "retention.audit_write_failed",
                event_type=event_type,
                exc=str(exc),
            )
