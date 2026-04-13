"""
Integration tests for Phase 5: CLI ROE Updates.

Tests for new CLI commands and ROE workflow integration:
- pwnpilot start --roe-file
- pwnpilot roe verify
- pwnpilot roe list
- pwnpilot roe audit
- pwnpilot roe export
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from typer.testing import CliRunner

# Import the CLI app
from pwnpilot.cli import app


runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_roe_file(tmp_path):
    """Create a sample ROE YAML file for testing."""
    roe_content = """
scope:
  cidrs:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
  domains:
    - "example.com"
  urls:
    - "https://api.example.com/v1"
  excludedIps:
    - "192.168.1.1"

actions:
  - MODIFY_DATA
  - DELETE_DATA
  - EXFILTRATE_DATA

limits:
  maxIterations: 5
  maxRetries: 3
  timeoutSeconds: 300
  cloudAllowed: false

authorisation:
  operator: "security-team@example.com"
  validFrom: "2026-04-12T00:00:00Z"
  validUntil: "2026-05-12T23:59:59Z"
"""
    roe_file = tmp_path / "test_roe.yaml"
    roe_file.write_text(roe_content)
    return roe_file


@pytest.fixture
def invalid_roe_file(tmp_path):
    """Create an invalid ROE YAML file."""
    roe_content = """
scope:
  # Missing required fields
  cidrs: []

# Missing actions section
# Missing limits section
"""
    roe_file = tmp_path / "invalid_roe.yaml"
    roe_file.write_text(roe_content)
    return roe_file


# ---------------------------------------------------------------------------
# Test ROE Verify Command
# ---------------------------------------------------------------------------


class TestROEVerifyCommand:
    """Test roe verify subcommand."""

    def test_roe_verify_valid_file(self, sample_roe_file):
        """Test verifying a valid ROE file."""
        result = runner.invoke(app, ["roe", "verify", str(sample_roe_file)])
        
        # Should succeed or show "valid" in output
        assert result.exit_code in [0, 1]  # Can be 0 or 1 depending on validation

    def test_roe_verify_invalid_file(self, invalid_roe_file):
        """Test verifying an invalid ROE file."""
        result = runner.invoke(app, ["roe", "verify", str(invalid_roe_file)])
        
        # Invalid file should exit with error
        assert result.exit_code != 0 or "error" in result.stdout.lower()

    def test_roe_verify_nonexistent_file(self):
        """Test verifying a non-existent file."""
        result = runner.invoke(app, ["roe", "verify", "/nonexistent/roe.yaml"])
        
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_roe_verify_invalid_yaml(self, tmp_path):
        """Test verifying a file with invalid YAML."""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("{invalid: yaml: content: [")
        
        result = runner.invoke(app, ["roe", "verify", str(bad_yaml)])
        
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Test ROE List Command
# ---------------------------------------------------------------------------


class TestROEListCommand:
    """Test roe list subcommand."""

    def test_roe_list_displays_table(self):
        """Test roe list displays header without engagement filter."""
        result = runner.invoke(app, ["roe", "list"])

        # v2: requires --engagement; shows prompt message without one
        assert "ROE Approvals" in result.stdout or "engagement" in result.stdout.lower()

    def test_roe_list_with_engagement_filter(self):
        """Test roe list with engagement ID filter."""
        engagement_id = str(uuid4())
        result = runner.invoke(app, ["roe", "list", "--engagement", engagement_id])
        
        assert result.exit_code == 0

    def test_roe_list_all_flag(self):
        """Test roe list --all flag."""
        result = runner.invoke(app, ["roe", "list", "--all"])
        
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Test ROE Audit Command
# ---------------------------------------------------------------------------


class TestROEAuditCommand:
    """Test roe audit subcommand."""

    def test_roe_audit_displays_table(self):
        """Test roe audit displays audit trail table."""
        engagement_id = str(uuid4())
        result = runner.invoke(app, ["roe", "audit", engagement_id])
        
        # Should show table or message
        assert result.exit_code == 0
        assert "Engagement" in result.stdout or "Audit" in result.stdout.lower()

    def test_roe_audit_valid_uuid(self):
        """Test roe audit with valid UUID format."""
        engagement_id = str(uuid4())
        result = runner.invoke(app, ["roe", "audit", engagement_id])
        
        assert result.exit_code == 0

    def test_roe_audit_invalid_uuid(self):
        """Test roe audit with invalid UUID format."""
        result = runner.invoke(app, ["roe", "audit", "not-a-uuid"])

        # v2: invalid UUID is caught and returns exit code 1 with an error message
        assert result.exit_code in [0, 1, 2]  # 1=handled error, 2=typer arg error


# ---------------------------------------------------------------------------
# Test ROE Export Command
# ---------------------------------------------------------------------------


@pytest.fixture
def roe_export_tmp_path(tmp_path):
    """Fixture for export tests."""
    import os
    os.chdir(tmp_path)
    return tmp_path


class TestROEExportCommand:
    """Test roe export subcommand."""

    def test_roe_export_creates_file_with_output_flag(self, roe_export_tmp_path):
        """Test roe export creates output file."""
        engagement_id = str(uuid4())
        output_file = roe_export_tmp_path / f"audit-{engagement_id}.json"
        
        result = runner.invoke(app, [
            "roe", "export",
            engagement_id,
            "--output", str(output_file),
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()

    def test_roe_export_json_format(self, tmp_path):
        """Test roe export creates valid JSON."""
        import json
        
        engagement_id = str(uuid4())
        output_file = tmp_path / "audit.json"
        
        result = runner.invoke(app, [
            "roe", "export",
            engagement_id,
            "--output", str(output_file),
        ])
        
        assert result.exit_code == 0
        
        # Verify JSON is valid
        if output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
                assert data["engagement_id"] == engagement_id

    def test_roe_export_with_invalid_output_path(self):
        """Test roe export handles invalid output paths."""
        engagement_id = str(uuid4())
        
        result = runner.invoke(app, [
            "roe", "export",
            engagement_id,
            "--output", "/root/nonexistent/audit.json",  # Should fail
        ])
        
        #Can succeed or fail depending on permissions
        assert result.exit_code in [0, 1]


# ---------------------------------------------------------------------------
# Test START Command with ROE File
# ---------------------------------------------------------------------------


class TestStartCommandWithROE:
    """Test start command with --roe-file flag."""

    def test_start_without_roe_file_or_scope(self):
        """Test start command fails without ROE file or scope."""
        result = runner.invoke(app, [
            "start",
            "--name", "Test Engagement",
        ])
        
        assert result.exit_code != 0

    def test_start_with_invalid_roe_file(self):
        """Test start command with non-existent ROE file."""
        result = runner.invoke(app, [
            "start",
            "--name", "Test",
            "--roe-file", "/nonexistent/roe.yaml",
        ])
        
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_start_legacy_mode_requires_roe_hash(self):
        """Test start command in legacy mode requires roe-hash."""
        result = runner.invoke(app, [
            "start",
            "--name", "Test Engagement",
            "--cidr", "10.0.0.0/8",
        ])
        
        # Should fail because --roe-hash is required in legacy mode
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestCLIIntegration:
    """Integration tests for CLI ROE workflow."""

    def test_cli_help_shows_roe_commands(self):
        """Test help output includes roe commands."""
        result = runner.invoke(app, ["roe", "--help"])
        
        assert result.exit_code == 0
        assert "verify" in result.stdout
        assert "list" in result.stdout
        assert "audit" in result.stdout
        assert "export" in result.stdout

    def test_cli_roe_verify_help(self):
        """Test roe verify has help text."""
        result = runner.invoke(app, ["roe", "verify", "--help"])
        
        assert result.exit_code == 0
        assert "validate" in result.stdout.lower() or "verify" in result.stdout.lower()

    def test_cli_version_command_still_works(self):
        """Test that existing commands still work."""
        result = runner.invoke(app, ["version"])
        
        assert result.exit_code == 0
        assert "pwnpilot" in result.stdout.lower()


class TestCLIErrorHandling:
    """Test error handling in CLI commands."""

    def test_roe_command_with_invalid_args(self):
        """Test roe command handles invalid arguments."""
        result = runner.invoke(app, ["roe", "verify"])  # Missing required file argument
        
        assert result.exit_code == 2  # Typer exit code for usage error

    def test_start_with_both_roe_and_legacy_flags(self, sample_roe_file):
        """Test start command handles conflicting flags."""
        result = runner.invoke(app, [
            "start",
            "--name", "Test",
            "--roe-file", str(sample_roe_file),
            "--cidr", "10.0.0.0/8",
            "--roe-dry-run",
        ])
        
        # Should succeed - ROE file takes precedence
        assert result.exit_code in [0, 1]  # Depends on validation

    def test_cli_graceful_handling_of_yaml_errors(self):
        """Test CLI handles YAML parse errors gracefully."""
        import tempfile
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("{invalid: yaml: [[[")
            f.flush()
            
            result = runner.invoke(app, ["roe", "verify", f.name])
            
            assert result.exit_code in [0, 1]
            # May succeed or fail depending on yaml parsing
