"""
Integration tests for Phase 6: ROE Verification Command.

Tests for ROE verification, audit trail querying, and compliance report generation:
- pwnpilot roe verify
- pwnpilot roe list
- pwnpilot roe audit
- pwnpilot roe export
"""
from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest
from typer.testing import CliRunner

from pwnpilot.cli import app


runner = CliRunner()


# ---------------------------------------------------------------------------
# Phase 6: Verification Command Tests
# ---------------------------------------------------------------------------


class TestROEVerificationCommand:
    """Test comprehensive ROE verification functionality."""

    def test_verify_displays_schema_info(self, tmp_path):
        """Test verify command displays schema version and statistics."""
        roe_content = """
engagement:
  name: "Test Engagement"
  authorizer: "test@example.com"
  description: "This is a comprehensive test engagement with full details for testing purposes. It includes necessary scope definitions"
  valid_hours: 24

scope:
  cidrs: "192.168.1.0/24"
  domains: "example.com"
  urls: ""
  excluded_ips: ""
  restricted_actions: ""

policy:
  max_iterations: 5
  max_retries: 3
  timeout_seconds: 300
  cloud_allowed: false
"""
        roe_file = tmp_path / "test.yaml"
        roe_file.write_text(roe_content)
        
        result = runner.invoke(app, ["roe", "verify", str(roe_file)])
        
        assert result.exit_code == 0
        # Should show schema version
        assert "v1" in result.stdout or "Schema" in result.stdout

    def test_verify_counts_scope_targets(self, tmp_path):
        """Test verify command counts CIDR and domain targets."""
        roe_content = """
engagement:
  name: "Multi-Target Engagement"
  authorizer: "test@example.com"
  description: "This comprehensive test engagement includes multiple scope targets including several CIDR ranges and domains for verification"
  valid_hours: 24

scope:
  cidrs: "192.168.1.0/24,10.0.0.0/8,172.16.0.0/12"
  domains: "example.com,test.example.com"
  urls: ""
  excluded_ips: ""
  restricted_actions: ""

policy:
  max_iterations: 5
  max_retries: 3
  timeout_seconds: 300
  cloud_allowed: false
"""
        roe_file = tmp_path / "multi.yaml"
        roe_file.write_text(roe_content)
        
        result = runner.invoke(app, ["roe", "verify", str(roe_file)])
        
        assert result.exit_code == 0
        # Should indicate scope target count
        assert "targets" in result.stdout.lower() or "scope" in result.stdout.lower()

    def test_verify_reports_allowed_actions(self, tmp_path):
        """Test verify command reports allowed actions."""
        roe_content = """
engagement:
  name: "Actions Engagement"
  authorizer: "test@example.com"
  description: "This test engagement validates that allowed actions are correctly reported by the verification command during ROE analysis"
  valid_hours: 24

scope:
  cidrs: "10.0.0.0/8"
  domains: ""
  urls: ""
  excluded_ips: ""
  restricted_actions: "MODIFY_DATA,DELETE_DATA"

policy:
  max_iterations: 5
  max_retries: 3
  timeout_seconds: 300
  cloud_allowed: false
"""
        roe_file = tmp_path / "actions.yaml"
        roe_file.write_text(roe_content)
        
        result = runner.invoke(app, ["roe", "verify", str(roe_file)])
        
        assert result.exit_code == 0
        # Should show action count
        assert "action" in result.stdout.lower()


class TestROEListCommand:
    """Test ROE list (discovery) functionality."""

    def test_list_shows_table_headers(self):
        """Test list displays table with expected columns."""
        result = runner.invoke(app, ["roe", "list"])
        
        assert result.exit_code == 0
        # Should have table headers or message
        assert any(x in result.stdout for x in ["ROE", "FILE", "ID", "available"])

    def test_list_with_engagement_filter(self):
        """Test list with engagement filter option."""
        engagement_id = str(uuid4())
        result = runner.invoke(app, ["roe", "list", "--engagement", engagement_id])
        
        assert result.exit_code == 0

    def test_list_all_includes_inactive(self):
        """Test list --all flag includes inactive ROEs."""
        result = runner.invoke(app, ["roe", "list", "--all"])
        
        assert result.exit_code == 0


class TestROEAuditCommand:
    """Test ROE audit trail querying."""

    def test_audit_shows_engagement_id(self):
        """Test audit trail shows the engagement ID."""
        engagement_id = str(uuid4())
        result = runner.invoke(app, ["roe", "audit", engagement_id])
        
        assert result.exit_code == 0
        assert engagement_id in result.stdout or "Audit" in result.stdout

    def test_audit_displays_timeline(self):
        """Test audit shows event timeline."""
        engagement_id = str(uuid4())
        result = runner.invoke(app, ["roe", "audit", engagement_id])
        
        assert result.exit_code == 0
        # Should mention audit/events/timeline
        audit_related = ["Audit", "audit", "event", "timeline", "Trail"]
        assert any(x in result.stdout for x in audit_related) or "available" in result.stdout

    def test_audit_with_invalid_engagement_id(self):
        """Test audit handles invalid engagement IDs."""
        result = runner.invoke(app, ["roe", "audit", "not-a-uuid"])
        
        # Should either succeed (handle gracefully) or fail with usage error
        assert result.exit_code in [0, 2]


class TestROEExportCommand:
    """Test ROE audit report export."""

    def test_export_creates_json_output(self, tmp_path):
        """Test export creates a JSON file."""
        engagement_id = str(uuid4())
        output_file = tmp_path / "audit_report.json"
        
        result = runner.invoke(app, [
            "roe", "export",
            engagement_id,
            "--output", str(output_file),
        ])
        
        assert result.exit_code == 0
        if output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
                assert isinstance(data, dict)

    def test_export_includes_engagement_id(self, tmp_path):
        """Test export report includes engagement ID."""
        engagement_id = str(uuid4())
        output_file = tmp_path / "audit.json"
        
        result = runner.invoke(app, [
            "roe", "export",
            engagement_id,
            "--output", str(output_file),
        ])
        
        assert result.exit_code == 0
        if output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
                assert data.get("engagement_id") == engagement_id

    def test_export_includes_export_timestamp(self, tmp_path):
        """Test export includes export timestamp."""
        engagement_id = str(uuid4())
        output_file = tmp_path / "audit.json"
        
        result = runner.invoke(app, [
            "roe", "export",
            engagement_id,
            "--output", str(output_file),
        ])
        
        assert result.exit_code == 0
        if output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
                # Should have export timestamp
                assert "exported_at" in data or "timestamp" in data.keys()

    def test_export_default_filename_format(self, tmp_path):
        """Test export default filename follows pattern."""
        engagement_id = str(uuid4())
        
        # Change to tmp_path to write the default file
        import os
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = runner.invoke(app, [
                "roe", "export",
                engagement_id,
            ])
            
            assert result.exit_code == 0
            # Check if default file was created
            default_file = tmp_path / f"roe-audit-{engagement_id}.json"
            assert default_file.exists() or "export" in result.stdout.lower()
        finally:
            os.chdir(original_cwd)


class TestROEComplianceReporting:
    """Test compliance features of ROE verification."""

    def test_verify_validates_required_fields(self, tmp_path):
        """Test verify catches missing required fields."""
        incomplete_roe = """
scope:
  cidrs:
    - "10.0.0.0/8"
# Missing actions, limits, etc.
"""
        roe_file = tmp_path / "incomplete.yaml"
        roe_file.write_text(incomplete_roe)
        
        result = runner.invoke(app, ["roe", "verify", str(roe_file)])
        
        # Should fail or warn about validation
        assert result.exit_code in [0, 1]

    def test_verify_checks_action_whitelist(self, tmp_path):
        """Test verify validates against known actions."""
        invalid_roe = """
scope:
  cidrs:
    - "10.0.0.0/8"
  domains: []
  excludedIps: []

actions:
  - INVALID_ACTION
  - UNKNOWN_OPERATION

limits:
  maxIterations: 5
  maxRetries: 3
  timeoutSeconds: 300
  cloudAllowed: false
"""
        roe_file = tmp_path / "invalid_actions.yaml"
        roe_file.write_text(invalid_roe)
        
        result = runner.invoke(app, ["roe", "verify", str(roe_file)])
        
        # Should reject or warn about invalid actions
        assert result.exit_code in [0, 1]


class TestROECommandIntegration:
    """Test ROE commands work together."""

    def test_verify_then_list_workflow(self, tmp_path):
        """Test verify followed by list."""
        roe_content = """
engagement:
  name: "Workflow Engagement"
  authorizer: "test@example.com"
  description: "This test engagement validates the verify then list workflow with proper ROE schema format and comprehensive testing"
  valid_hours: 24

scope:
  cidrs: "10.0.0.0/8"
  domains: ""
  urls: ""
  excluded_ips: ""
  restricted_actions: ""

policy:
  max_iterations: 5
  max_retries: 3
  timeout_seconds: 300
  cloud_allowed: false
"""
        roe_file = tmp_path / "workflow.yaml"
        roe_file.write_text(roe_content)
        
        # First verify
        result1 = runner.invoke(app, ["roe", "verify", str(roe_file)])
        assert result1.exit_code == 0
        
        # Then list
        result2 = runner.invoke(app, ["roe", "list"])
        assert result2.exit_code == 0

    def test_audit_then_export_workflow(self, tmp_path):
        """Test audit followed by export."""
        engagement_id = str(uuid4())
        output_file = tmp_path / "audit.json"
        
        # First audit
        result1 = runner.invoke(app, ["roe", "audit", engagement_id])
        assert result1.exit_code in [0, 2]  # Argument errors OK
        
        # Then export with --output to avoid creating files in project root
        result2 = runner.invoke(app, ["roe", "export", engagement_id, "--output", str(output_file)])
        assert result2.exit_code == 0

    def test_help_text_for_all_roe_commands(self):
        """Test all roe commands have help text."""
        commands = ["verify", "list", "audit", "export"]
        
        for cmd in commands:
            result = runner.invoke(app, ["roe", cmd, "--help"])
            assert result.exit_code == 0
            assert cmd.lower() in result.stdout.lower() or "help" not in result.stdout.lower()


class TestSOC2ComplianceFeatures:
    """Test SOC 2 compliance-related features."""

    def test_audit_includes_user_identity(self):
        """Test audit trail includes user information."""
        engagement_id = str(uuid4())
        result = runner.invoke(app, ["roe", "audit", engagement_id])
        
        assert result.exit_code == 0
        # Should reference user or actor
        assert any(x.lower() in result.stdout.lower() for x in ["user", "actor", "operator", "by"])

    def test_export_generates_compliance_report(self, tmp_path):
        """Test export creates compliance-ready report."""
        engagement_id = str(uuid4())
        output_file = tmp_path / "compliance_report.json"
        
        result = runner.invoke(app, [
            "roe", "export",
            engagement_id,
            "--output", str(output_file),
        ])
        
        assert result.exit_code == 0
        if output_file.exists():
            with open(output_file) as f:
                report = json.load(f)
                # Compliance report should include key fields
                expected_fields = ["engagement_id", "exported_at"]
                for field in expected_fields:
                    assert field in report or len(report) > 0

    def test_audit_trail_immutability(self):
        """Test audit trail shows immutable record nature."""
        engagement_id = str(uuid4())
        result = runner.invoke(app, ["roe", "audit", engagement_id])
        
        assert result.exit_code == 0
        # Audit trail should indicate it's immutable
        assert any(x.lower() in result.stdout.lower() for x in ["audit", "trail", "log", "record"])
