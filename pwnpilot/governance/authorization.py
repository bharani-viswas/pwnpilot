"""
Engagement Authorization — persists and validates operator authorization artifacts.

An AuthorizationArtifact must be present and unexpired for every engagement before
the orchestrator may run.  This check is performed on every Orchestrator.run() call.
"""
from __future__ import annotations

import hashlib
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


def verify_roe_document(artifact: AuthorizationArtifact, roe_yaml_bytes: bytes) -> None:
    """
    Verify that the ROE document has not been modified since authorization.
    
    Raises AuthorizationError if the computed hash does not match the stored hash.
    """
    computed_hash = hashlib.sha256(roe_yaml_bytes).hexdigest()
    stored_hash = artifact.roe_document_hash.strip().lower()
    computed_hash_lower = computed_hash.lower()
    
    if computed_hash_lower != stored_hash:
        log.error(
            "authorization.roe_integrity_violation",
            engagement_id=str(artifact.engagement_id),
            stored_hash=stored_hash,
            computed_hash=computed_hash_lower,
        )
        raise AuthorizationError(
            f"ROE document integrity check failed for engagement {artifact.engagement_id}. "
            f"The ROE YAML has been modified since authorization. "
            f"(stored: {stored_hash[:16]}..., computed: {computed_hash_lower[:16]}...)"
        )


def assert_authorized(
    artifact: AuthorizationArtifact,
    roe_yaml_bytes: bytes | None = None,
) -> None:
    """
    Raise AuthorizationError if the artifact is missing, expired, not yet valid, or if
    the ROE document hash does not match (if roe_yaml_bytes is provided).
    
    Called by the orchestrator before every run loop.
    
    Args:
        artifact: The authorization artifact to validate.
        roe_yaml_bytes: Optional ROE YAML bytes for integrity verification (H-2).
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

    # H-2: Verify ROE document integrity if bytes are provided
    if roe_yaml_bytes is not None:
        verify_roe_document(artifact, roe_yaml_bytes)

    log.debug(
        "authorization.valid",
        engagement_id=str(artifact.engagement_id),
        valid_until=artifact.valid_until.isoformat(),
    )
