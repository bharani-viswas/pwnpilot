"""
Permission Store — tracks runtime-approved operations not in default allow-lists.

Provides an audit trail of operator decisions to allow operations that deviate
from strict allow-lists. Useful for shell commands, custom parameters, etc.

Usage::

    from pwnpilot.data.permission_store import PermissionStore
    
    store = PermissionStore(session)
    
    # Grant permission interactively
    store.grant_permission(
        engagement_id=eng_uuid,
        resource_type="shell_command",
        resource_identifier="nmap",
        requested_by="operator",
        decision_context={"reason": "needed for service scanning"}
    )
    
    # Check if already approved
    if store.has_permission(eng_uuid, "shell_command", "nmap"):
        # it's allowed
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import structlog
from sqlalchemy import Column, DateTime, String, Text, Boolean
from sqlalchemy.orm import DeclarativeBase, Session

from pwnpilot.data.models import AuditEvent

log = structlog.get_logger(__name__)


class _Base(DeclarativeBase):
    pass


class PermissionRow(_Base):
    """ORM row for a single runtime permission grant."""

    __tablename__ = "runtime_permissions"

    permission_id = Column(String(36), primary_key=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    resource_type = Column(String(128), nullable=False)  # "shell_command", "parameter_alias", etc.
    resource_identifier = Column(String(512), nullable=False)  # command name, parameter alias, etc.
    granted_by = Column(String(255), nullable=False)  # operator ID or name
    decision_context_json = Column(Text, nullable=True)  # JSON-serialized context
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)


class PermissionStore:
    """
    Tracks operator approvals for operations not in default allow-lists.

    Thread-safe storage of runtime permissions. Useful for:
    - Approving shell commands not in _ALLOWED_COMMANDS
    - Recording operator decisions for audit trail
    - Supporting future parameter normalization with operator consent
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        _Base.metadata.create_all(bind=session.get_bind())

    def grant_permission(
        self,
        engagement_id: UUID,
        resource_type: str,
        resource_identifier: str,
        granted_by: str,
        decision_context: dict | None = None,
    ) -> str:
        """
        Grant a permission and persist it. Returns permission_id.
        
        Args:
            engagement_id: UUID of engagement
            resource_type: Category (e.g., "shell_command", "parameter_alias")
            resource_identifier: Specific resource (e.g., "nmap", "service_detection")
            granted_by: Operator identifier
            decision_context: Optional metadata about the decision
        """
        import json
        from uuid import uuid4
        
        permission_id = str(uuid4())
        
        # Check if permission already exists
        existing = self._session.query(PermissionRow).filter(
            PermissionRow.engagement_id == str(engagement_id),
            PermissionRow.resource_type == resource_type,
            PermissionRow.resource_identifier == resource_identifier,
            PermissionRow.is_active == True,
        ).first()
        
        if existing:
            log.debug(
                "permission_store.already_granted",
                resource_type=resource_type,
                resource_id=resource_identifier,
            )
            return str(existing.permission_id)
        
        row = PermissionRow(
            permission_id=permission_id,
            engagement_id=str(engagement_id),
            resource_type=resource_type,
            resource_identifier=resource_identifier,
            granted_by=granted_by,
            decision_context_json=json.dumps(decision_context) if decision_context else None,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        
        self._session.add(row)
        self._session.commit()
        
        log.info(
            "permission_store.granted",
            permission_id=permission_id,
            resource_type=resource_type,
            resource_id=resource_identifier,
            granted_by=granted_by,
        )
        
        return permission_id

    def has_permission(
        self,
        engagement_id: UUID,
        resource_type: str,
        resource_identifier: str,
    ) -> bool:
        """
        Check if a permission for this resource has been granted in this engagement.
        
        Returns True if an active, non-expired permission exists.
        """
        row = self._session.query(PermissionRow).filter(
            PermissionRow.engagement_id == str(engagement_id),
            PermissionRow.resource_type == resource_type,
            PermissionRow.resource_identifier == resource_identifier,
            PermissionRow.is_active == True,
        ).first()
        
        if not row:
            return False
        
        # Check expiration if any (ensure both are timezone-aware for comparison)
        if row.expires_at:
            now = datetime.now(timezone.utc)
            expires_at = row.expires_at
            
            # Ensure expires_at is timezone-aware for comparison
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            
            if expires_at < now:
                log.debug("permission_store.expired", resource_id=resource_identifier)
                return False
        
        return True

    def revoke_permission(
        self,
        engagement_id: UUID,
        resource_type: str,
        resource_identifier: str,
    ) -> bool:
        """
        Revoke an active permission. Returns True if it was revoked, False if not found.
        """
        row = self._session.query(PermissionRow).filter(
            PermissionRow.engagement_id == str(engagement_id),
            PermissionRow.resource_type == resource_type,
            PermissionRow.resource_identifier == resource_identifier,
            PermissionRow.is_active == True,
        ).first()
        
        if not row:
            return False
        
        row.is_active = False
        self._session.commit()
        
        log.info(
            "permission_store.revoked",
            resource_type=resource_type,
            resource_id=resource_identifier,
        )
        
        return True

    def list_permissions(
        self,
        engagement_id: UUID,
        resource_type: str | None = None,
    ) -> list[dict]:
        """
        List all active permissions for an engagement, optionally filtered by type.
        
        Returns list of dicts with: permission_id, resource_type, resource_identifier, granted_by, created_at
        """
        query = self._session.query(PermissionRow).filter(
            PermissionRow.engagement_id == str(engagement_id),
            PermissionRow.is_active == True,
        )
        
        if resource_type:
            query = query.filter(PermissionRow.resource_type == resource_type)
        
        rows = query.all()
        
        return [
            {
                "permission_id": row.permission_id,
                "resource_type": row.resource_type,
                "resource_identifier": row.resource_identifier,
                "granted_by": row.granted_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]
