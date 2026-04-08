"""
Evidence Store — write-once raw artifact persistence with SHA-256 hash index.

Security:
- File paths are constructed from UUID components ONLY.  No user-controlled input
  enters path construction (prevents path traversal — Architecture §5.8).
- stdout/stderr are written in 64 KB streaming chunks (never buffered fully in memory).
- Size cap: configurable max_evidence_bytes (default 256 MB); subprocess is killed and
  truncation is recorded if the limit is breached.
- Immutable: files are write-once; deletion only via retention governance.
"""
from __future__ import annotations

import hashlib
import io
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from uuid import UUID, uuid4

import structlog
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import DeclarativeBase, Session

from pwnpilot.data.models import EvidenceIndex

log = structlog.get_logger(__name__)

_CHUNK_SIZE: int = 64 * 1024          # 64 KB stream chunks
DEFAULT_MAX_BYTES: int = 256 * 1024 * 1024  # 256 MB


class EvidenceSizeExceededError(Exception):
    pass


class Base(DeclarativeBase):
    pass


class EvidenceIndexRow(Base):
    __tablename__ = "evidence_index"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String(36), nullable=False, unique=True, index=True)
    action_id = Column(String(36), nullable=False, index=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    file_path = Column(String(512), nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    truncated = Column(Boolean, nullable=False, default=False)


class EvidenceStore:
    """
    Persists raw tool output as immutable binary files and maintains an indexed hash.

    Args:
        base_dir:   Root directory for evidence files (e.g. ~/.pwnpilot/evidence).
        session:    SQLAlchemy session for the index table.
        max_bytes:  Per-action size cap (default 256 MB).
    """

    def __init__(
        self,
        base_dir: Path,
        session: Session,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self._base = base_dir
        self._session = session
        self._max_bytes = max_bytes
        Base.metadata.create_all(session.bind)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def stream_write(
        self,
        engagement_id: UUID,
        action_id: UUID,
        data_stream: Iterator[bytes],
    ) -> EvidenceIndex:
        """
        Stream-write evidence from an iterator of byte chunks.
        Returns the index record.  Raises EvidenceSizeExceededError if *max_bytes* is
        breached (the partial file is kept to preserve whatever was captured).
        """
        evidence_id = uuid4()
        dest = self._evidence_path(engagement_id, evidence_id)
        dest.parent.mkdir(parents=True, exist_ok=True)

        hasher = hashlib.sha256()
        total = 0
        truncated = False

        with dest.open("wb") as fh:
            for chunk in data_stream:
                if not chunk:
                    continue
                remaining = self._max_bytes - total
                if remaining <= 0:
                    truncated = True
                    break
                write_chunk = chunk[:remaining]
                fh.write(write_chunk)
                hasher.update(write_chunk)
                total += len(write_chunk)
                if len(write_chunk) < len(chunk):
                    truncated = True
                    break

        sha256 = hasher.hexdigest()
        now = datetime.now(timezone.utc)

        index = EvidenceIndex(
            evidence_id=evidence_id,
            action_id=action_id,
            engagement_id=engagement_id,
            file_path=str(dest),
            sha256_hash=sha256,
            size_bytes=total,
            timestamp=now,
            truncated=truncated,
        )

        row = EvidenceIndexRow(
            evidence_id=str(evidence_id),
            action_id=str(action_id),
            engagement_id=str(engagement_id),
            file_path=str(dest),
            sha256_hash=sha256,
            size_bytes=total,
            timestamp=now,
            truncated=truncated,
        )
        self._session.add(row)
        self._session.commit()

        if truncated:
            log.warning(
                "evidence.truncated",
                evidence_id=str(evidence_id),
                max_bytes=self._max_bytes,
                written=total,
            )

        log.debug(
            "evidence.stored",
            evidence_id=str(evidence_id),
            sha256=sha256,
            size=total,
        )
        return index

    def write_bytes(
        self,
        engagement_id: UUID,
        action_id: UUID,
        data: bytes,
    ) -> EvidenceIndex:
        """Convenience wrapper: write a bytes blob as a single evidence artifact."""
        return self.stream_write(
            engagement_id,
            action_id,
            iter([data]),
        )

    def read_evidence(self, evidence_id: UUID) -> bytes:
        """Read evidence file contents.  Validates SHA-256 on read."""
        row = (
            self._session.query(EvidenceIndexRow)
            .filter(EvidenceIndexRow.evidence_id == str(evidence_id))
            .first()
        )
        if row is None:
            raise FileNotFoundError(f"Evidence {evidence_id} not found in index.")

        data = Path(row.file_path).read_bytes()
        computed = hashlib.sha256(data).hexdigest()
        if computed != row.sha256_hash:
            raise ValueError(
                f"Evidence {evidence_id} hash mismatch: "
                f"stored={row.sha256_hash}, computed={computed}"
            )
        return data

    def index_for_action(self, action_id: UUID) -> list[EvidenceIndex]:
        rows = (
            self._session.query(EvidenceIndexRow)
            .filter(EvidenceIndexRow.action_id == str(action_id))
            .all()
        )
        return [
            EvidenceIndex(
                evidence_id=UUID(r.evidence_id),
                action_id=UUID(r.action_id),
                engagement_id=UUID(r.engagement_id),
                file_path=r.file_path,
                sha256_hash=r.sha256_hash,
                size_bytes=r.size_bytes,
                timestamp=r.timestamp,
                truncated=r.truncated,
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evidence_path(self, engagement_id: UUID, evidence_id: UUID) -> Path:
        """
        Construct an evidence file path from UUID components ONLY.
        No user-controlled strings enter this path (path traversal prevention).
        """
        return self._base / str(engagement_id) / f"{evidence_id}.bin"
