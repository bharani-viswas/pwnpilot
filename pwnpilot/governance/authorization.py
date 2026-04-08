"""
Engagement Authorization — persists and validates operator authorization artifacts.

An AuthorizationArtifact must be present and unexpired for every engagement before
the orchestrator may run.  This check is performed on every Orchestrator.run() call.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel

import structlog

log = structlog.get_logger(__name__)


class AuthorizationArtifact(BaseModel):
    artifact_id: UUID = UUID("00000000-0000-0000-0000-000000000000")
    engagement_id: UUID
    approver_identity: str
    ticket_reference: str
    roe_document_hash: str
    valid_from: datetime
    valid_until: datetime
    signed_at: datetime
    notes: str = ""
    schema_version: str = "v1"

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.valid_until

    def is_pending(self) -> bool:
        return datetime.now(timezone.utc) < self.valid_from


class AuthorizationError(Exception):
    pass


def assert_authorized(artifact: AuthorizationArtifact) -> None:
    """
    Raise AuthorizationError if the artifact is missing, expired, or not yet valid.
    Called by the orchestrator before every run loop.
    """
    now = datetime.now(timezone.utc)

    if artifact.is_pending():
        raise AuthorizationError(
            f"Authorization for engagement {artifact.engagement_id} "
            f"is not yet valid (valid_from={artifact.valid_from.isoformat()})."
        )
    if artifact.is_expired():
        raise AuthorizationError(
            f"Authorization for engagement {artifact.engagement_id} "
            f"has expired (valid_until={artifact.valid_until.isoformat()})."
        )
    if not artifact.roe_document_hash:
        raise AuthorizationError(
            f"ROE document hash is missing for engagement {artifact.engagement_id}."
        )

    log.debug(
        "authorization.valid",
        engagement_id=str(artifact.engagement_id),
        valid_until=artifact.valid_until.isoformat(),
    )
