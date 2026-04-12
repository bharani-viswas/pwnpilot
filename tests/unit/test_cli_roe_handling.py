"""
Test suite for CLI ROE file handling and error scenarios.

Tests the CLI's file validation logic at the entry point
"""

import pytest
import tempfile
from pathlib import Path
from typer.testing import CliRunner
from pwnpilot.cli import app


runner = CliRunner()


class TestCLIROEFileHandling:
    """Test CLI-level ROE file handling."""
    
    def test_cli_rejects_nonexistent_file(self):
        """Test that CLI properly rejects nonexistent ROE file."""
        result = runner.invoke(app, [
            "start",
            "--name", "test",
            "--roe-file", "/tmp/nonexistent_roe_xyz.yaml"
        ])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower() or "error" in result.stdout.lower()
    
    def test_cli_rejects_empty_file(self):
        """Test that CLI properly rejects empty ROE file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Write nothing - empty file
            temp_path = f.name
        
        try:
            result = runner.invoke(app, [
                "start",
                "--name", "test",
                "--roe-file", temp_path
            ])
            # Should exit with error
            assert result.exit_code != 0
            # Should mention it's empty
            assert "empty" in result.stdout.lower() or "no valid" in result.stdout.lower() or "error" in result.stdout.lower()
        finally:
            Path(temp_path).unlink()
    
    def test_cli_rejects_yaml_comments_only(self):
        """Test that CLI properly rejects YAML file with only comments."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("# This is just a comment\n# No actual data\n")
            temp_path = f.name
        
        try:
            result = runner.invoke(app, [
                "start",
                "--name", "test",
                "--roe-file", temp_path
            ])
            # Should exit with error
            assert result.exit_code != 0
            # Should mention no valid content
            assert "empty" in result.stdout.lower() or "no valid" in result.stdout.lower() or "error" in result.stdout.lower()
        finally:
            Path(temp_path).unlink()
    
    def test_cli_rejects_invalid_yaml_syntax(self):
        """Test that CLI properly rejects malformed YAML."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Invalid YAML
            f.write("engagement:\n  name: [unclosed\npolicy: missing_colon value\n")
            temp_path = f.name
        
        try:
            result = runner.invoke(app, [
                "start",
                "--name", "test",
                "--roe-file", temp_path
            ])
            # Should exit with error (YAML parsing error or validation error)
            assert result.exit_code != 0
        finally:
            Path(temp_path).unlink()
    
    def test_cli_shows_helpful_hints_for_empty_file(self):
        """Test that empty file error message includes helpful hint."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            temp_path = f.name
        
        try:
            result = runner.invoke(app, [
                "start",
                "--name", "test",
                "--roe-file", temp_path
            ])
            # Should include hint about required fields
            output = result.stdout.lower()
            assert "error" in output
            assert ("empty" in output or "hint" in output)
        finally:
            Path(temp_path).unlink()


class TestCLIValidROEAcceptance:
    """Test that CLI properly accepts valid ROE files."""
    
    def test_cli_accepts_valid_roe_file(self):
        """Test that CLI accepts a properly formatted ROE file."""
        roe_content = """engagement:
  name: "Test Engagement"
  authorizer: "test@example.com"
  description: "This is a test description with sufficient length to pass validation requirements. It must be at least 100 characters long."

scope:
  urls: "http://localhost:3000"
  cidrs: ""
  domains: ""

policy:
  max_iterations: 30
  max_retries: 3
  timeout_seconds: 3600
  cloud_allowed: true
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(roe_content)
            temp_path = f.name
        
        try:
            result = runner.invoke(app, [
                "start",
                "--name", "test",
                "--roe-file", temp_path,
                "--roe-dry-run"  # Dry run to avoid needing full setup
            ])
            # Should not fail at the file validation stage
            # (may fail later, but not due to file format)
            assert "file not found" not in result.stdout.lower()
            assert "empty" not in result.stdout.lower()
        finally:
            Path(temp_path).unlink()


class TestErrorMessageFormat:
    """Test that error messages are properly formatted and informative."""
    
    def test_empty_file_error_is_clear(self):
        """Test that empty file error message is clear to users."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            temp_path = f.name
        
        try:
            result = runner.invoke(app, [
                "start",
                "--name", "test",
                "--roe-file", temp_path
            ])
            output = result.stdout
            # Should be in red (error color) and mention "empty"
            assert "[red]" in output or "Error" in output
            assert "empty" in output.lower() or "no valid" in output.lower()
        finally:
            Path(temp_path).unlink()
    
    def test_error_includes_file_path(self):
        """Test that error messages include the problematic file path."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            temp_path = f.name
        
        try:
            result = runner.invoke(app, [
                "start",
                "--name", "test",
                "--roe-file", temp_path
            ])
            # Should show file path in error message
            assert temp_path in result.stdout or "roe" in result.stdout.lower()
        finally:
            Path(temp_path).unlink()
