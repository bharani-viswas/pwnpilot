"""
Tests for PermissionStore — runtime permission tracking and grant management.
"""
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from pwnpilot.data.permission_store import PermissionStore, PermissionRow


def _make_session() -> Session:
    """Create an in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:")
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


@pytest.fixture
def db_session() -> Session:
    """Fixture providing a fresh in-memory database session."""
    return _make_session()


@pytest.fixture
def permission_store(db_session: Session) -> PermissionStore:
    """Fixture providing a fresh PermissionStore."""
    return PermissionStore(db_session)


class TestPermissionStore:
    """Test cases for runtime permission grants and revocations."""

    def test_grant_permission(self, permission_store: PermissionStore):
        """Test granting a new permission."""
        eng_id = uuid4()
        perm_id = permission_store.grant_permission(
            engagement_id=eng_id,
            resource_type="shell_command",
            resource_identifier="nmap",
            granted_by="operator@example.com",
            decision_context={"reason": "needed for service scan"},
        )
        
        assert perm_id is not None
        assert isinstance(perm_id, str)

    def test_has_permission_after_grant(self, permission_store: PermissionStore):
        """Test checking that permission exists after grant."""
        eng_id = uuid4()
        permission_store.grant_permission(
            engagement_id=eng_id,
            resource_type="shell_command",
            resource_identifier="nmap",
            granted_by="operator@example.com",
        )
        
        assert permission_store.has_permission(eng_id, "shell_command", "nmap")

    def test_does_not_have_permission_before_grant(self, permission_store: PermissionStore):
        """Test that permission is not granted before being granted."""
        eng_id = uuid4()
        assert not permission_store.has_permission(eng_id, "shell_command", "nmap")

    def test_permission_per_engagement(self, permission_store: PermissionStore):
        """Test that permissions are scoped per engagement."""
        eng_id_1 = uuid4()
        eng_id_2 = uuid4()
        
        permission_store.grant_permission(
            engagement_id=eng_id_1,
            resource_type="shell_command",
            resource_identifier="nmap",
            granted_by="operator@example.com",
        )
        
        # Should be available in eng_id_1 but not eng_id_2
        assert permission_store.has_permission(eng_id_1, "shell_command", "nmap")
        assert not permission_store.has_permission(eng_id_2, "shell_command", "nmap")

    def test_revoke_permission(self, permission_store: PermissionStore):
        """Test revoking a permission."""
        eng_id = uuid4()
        permission_store.grant_permission(
            engagement_id=eng_id,
            resource_type="shell_command",
            resource_identifier="nmap",
            granted_by="operator@example.com",
        )
        
        assert permission_store.has_permission(eng_id, "shell_command", "nmap")
        
        revoked = permission_store.revoke_permission(eng_id, "shell_command", "nmap")
        assert revoked
        assert not permission_store.has_permission(eng_id, "shell_command", "nmap")

    def test_revoke_nonexistent_permission(self, permission_store: PermissionStore):
        """Test revoking a permission that doesn't exist."""
        eng_id = uuid4()
        revoked = permission_store.revoke_permission(eng_id, "shell_command", "nmap")
        assert not revoked

    def test_list_permissions(self, permission_store: PermissionStore):
        """Test listing permissions for an engagement."""
        eng_id = uuid4()
        
        permission_store.grant_permission(
            engagement_id=eng_id,
            resource_type="shell_command",
            resource_identifier="nmap",
            granted_by="operator@example.com",
        )
        permission_store.grant_permission(
            engagement_id=eng_id,
            resource_type="shell_command",
            resource_identifier="curl",
            granted_by="operator@example.com",
        )
        
        perms = permission_store.list_permissions(eng_id)
        assert len(perms) == 2
        
        identifiers = {p["resource_identifier"] for p in perms}
        assert identifiers == {"nmap", "curl"}

    def test_list_permissions_filtered_by_type(self, permission_store: PermissionStore):
        """Test listing permissions filtered by resource type."""
        eng_id = uuid4()
        
        permission_store.grant_permission(
            engagement_id=eng_id,
            resource_type="shell_command",
            resource_identifier="nmap",
            granted_by="operator@example.com",
        )
        permission_store.grant_permission(
            engagement_id=eng_id,
            resource_type="parameter_alias",
            resource_identifier="service_detection",
            granted_by="operator@example.com",
        )
        
        shell_perms = permission_store.list_permissions(eng_id, "shell_command")
        assert len(shell_perms) == 1
        assert shell_perms[0]["resource_identifier"] == "nmap"
        
        param_perms = permission_store.list_permissions(eng_id, "parameter_alias")
        assert len(param_perms) == 1
        assert param_perms[0]["resource_identifier"] == "service_detection"

    def test_duplicate_permission_grant(self, permission_store: PermissionStore):
        """Test that granting the same permission twice returns same ID."""
        eng_id = uuid4()
        
        perm_id_1 = permission_store.grant_permission(
            engagement_id=eng_id,
            resource_type="shell_command",
            resource_identifier="nmap",
            granted_by="operator@example.com",
        )
        
        perm_id_2 = permission_store.grant_permission(
            engagement_id=eng_id,
            resource_type="shell_command",
            resource_identifier="nmap",
            granted_by="operator@example.com",
        )
        
        # Should return the same ID (not create duplicate)
        assert perm_id_1 == perm_id_2

    def test_permission_expiration(self, permission_store: PermissionStore, db_session: Session):
        """Test that expired permissions are not granted."""
        eng_id = uuid4()
        
        # Grant a permission with expired date
        perm_id = permission_store.grant_permission(
            engagement_id=eng_id,
            resource_type="shell_command",
            resource_identifier="nmap",
            granted_by="operator@example.com",
        )
        
        # Manually expire the permission
        row = db_session.query(PermissionRow).filter(
            PermissionRow.permission_id == perm_id
        ).first()
        
        assert row is not None
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db_session.commit()
        
        # Should not have permission after expiration
        assert not permission_store.has_permission(eng_id, "shell_command", "nmap")
