"""
Tests for ShellAdapter permission-aware parameter validation.
"""
import pytest
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from pwnpilot.plugins.adapters.shell import ShellAdapter
from pwnpilot.data.permission_store import PermissionStore


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
def shell_adapter() -> ShellAdapter:
    """Fixture providing a fresh ShellAdapter."""
    return ShellAdapter()


@pytest.fixture
def shell_adapter_with_perms(db_session: Session) -> tuple[ShellAdapter, PermissionStore]:
    """Fixture providing ShellAdapter and PermissionStore."""
    perm_store = PermissionStore(db_session)
    adapter = ShellAdapter(
        permission_context={
            "permission_store": perm_store,
            "engagement_id": uuid4(),
        }
    )
    return adapter, perm_store


class TestShellAdapterValidation:
    """Test cases for shell adapter parameter validation."""

    def test_allowed_command_passes(self, shell_adapter: ShellAdapter):
        """Test that allow-listed commands pass validation."""
        params = {
            "target": "localhost",
            "command": "pwd",
            "args": [],
        }
        
        result = shell_adapter.validate_params(params)
        
        assert result.target == "localhost"
        assert result.extra["command"] == "pwd"
        assert result.extra["args"] == []

    def test_disallowed_command_fails(self, shell_adapter: ShellAdapter):
        """Test that non-allow-listed commands fail validation."""
        params = {
            "target": "localhost",
            "command": "nmap",
            "args": [],
        }
        
        with pytest.raises(ValueError) as exc_info:
            shell_adapter.validate_params(params)
        
        assert "not allow-listed" in str(exc_info.value).lower()

    def test_disallowed_command_with_permission_passes(self, shell_adapter_with_perms):
        """Test that disallowed commands pass if permission is granted."""
        adapter, perm_store = shell_adapter_with_perms
        eng_id = adapter._permission_context["engagement_id"]
        
        # Grant permission for nmap
        perm_store.grant_permission(
            engagement_id=eng_id,
            resource_type="shell_command",
            resource_identifier="nmap",
            granted_by="test",
        )
        
        params = {
            "target": "localhost",
            "command": "nmap",
            "args": [],
        }
        
        result = adapter.validate_params(params)
        assert result.extra["command"] == "nmap"

    def test_unsafe_mode_requires_enabled_env(self, shell_adapter: ShellAdapter):
        """Test that unsafe mode requires the env var to be set."""
        params = {
            "target": "localhost",
            "command": "whoami",
            "unsafe": True,
        }
        
        with pytest.raises(ValueError) as exc_info:
            shell_adapter.validate_params(params)
        
        assert "unsafe mode" in str(exc_info.value).lower()

    def test_target_required(self, shell_adapter: ShellAdapter):
        """Test that target parameter is required."""
        params = {
            "command": "pwd",
        }
        
        with pytest.raises(ValueError) as exc_info:
            shell_adapter.validate_params(params)
        
        assert "target" in str(exc_info.value).lower()

    def test_command_required(self, shell_adapter: ShellAdapter):
        """Test that command parameter is required."""
        params = {
            "target": "localhost",
        }
        
        with pytest.raises(ValueError) as exc_info:
            shell_adapter.validate_params(params)
        
        assert "command" in str(exc_info.value).lower()

    def test_args_validation(self, shell_adapter: ShellAdapter):
        """Test that args are properly validated."""
        params = {
            "target": "localhost",
            "command": "ls",
            "args": ["-la", "/tmp"],
        }
        
        result = shell_adapter.validate_params(params)
        assert result.extra["args"] == ["-la", "/tmp"]

    def test_args_not_a_list_fails(self, shell_adapter: ShellAdapter):
        """Test that non-list args fail."""
        params = {
            "target": "localhost",
            "command": "ls",
            "args": "not a list",
        }
        
        with pytest.raises(ValueError) as exc_info:
            shell_adapter.validate_params(params)
        
        assert "array" in str(exc_info.value).lower()

    def test_too_many_args_fails(self, shell_adapter: ShellAdapter):
        """Test that too many args fail."""
        params = {
            "target": "localhost",
            "command": "ls",
            "args": [f"arg{i}" for i in range(20)],  # More than _MAX_ARGS
        }
        
        with pytest.raises(ValueError) as exc_info:
            shell_adapter.validate_params(params)
        
        assert "too many" in str(exc_info.value).lower()

    def test_unsafe_argument_rejected_in_safe_mode(self, shell_adapter: ShellAdapter):
        """Test that unsafe arguments are rejected in safe mode."""
        params = {
            "target": "localhost",
            "command": "grep",
            "args": ["'$(whoami)'"],  # Contains unsafe characters
        }
        
        with pytest.raises(ValueError) as exc_info:
            shell_adapter.validate_params(params)
        
        assert "unsafe argument" in str(exc_info.value).lower()

    def test_target_with_unsafe_characters_fails(self, shell_adapter: ShellAdapter):
        """Test that targets with unsafe characters fail."""
        params = {
            "target": "localhost'; DROP TABLE",
            "command": "pwd",
        }
        
        with pytest.raises(ValueError) as exc_info:
            shell_adapter.validate_params(params)
        
        assert "unsafe characters" in str(exc_info.value).lower()

    def test_manifest_properties_present(self, shell_adapter: ShellAdapter):
        """Test that shell adapter manifest has expected properties."""
        manifest = shell_adapter.manifest
        
        assert manifest.name == "shell"
        assert manifest.version == "1.0"
        assert manifest.risk_class == "recon_passive"
        assert "allow-listed" in manifest.description.lower() or "controlled" in manifest.description.lower()

    def test_adapter_without_permission_context(self):
        """Test that adapter works without permission context."""
        adapter = ShellAdapter(permission_context=None)
        
        params = {
            "target": "localhost",
            "command": "pwd",
        }
        
        result = adapter.validate_params(params)
        assert result.target == "localhost"

    def test_adapter_with_empty_permission_context(self):
        """Test that adapter works with empty permission context."""
        adapter = ShellAdapter(permission_context={})
        
        params = {
            "target": "localhost",
            "command": "pwd",
        }
        
        result = adapter.validate_params(params)
        assert result.target == "localhost"
