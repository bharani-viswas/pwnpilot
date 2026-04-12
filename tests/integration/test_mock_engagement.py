"""
Integration tests for the pwnpilot agent pipeline.

These tests wire together real components (SQLite, in-process stores) but mock
the LLM and all external network calls (tools / NVD API).  They exercise the
end-to-end engagement lifecycle without requiring any running services.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4
from uuid import UUID

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_config(tmp_path: Path) -> dict[str, Any]:
    """Return a fake YAML-equivalent config dict understood by _load_config."""
    return {
        "database": {"url": f"sqlite:///{tmp_path}/integration.db"},
        "storage": {
            "evidence_dir": str(tmp_path / "evidence"),
            "report_dir": str(tmp_path / "reports"),
        },
        "llm": {
            "local_url": "http://localhost:11434",
            "local_model": "llama3",
        },
    }


def _minimal_typed_config(tmp_path: Path):
    """Return a MagicMock with attributes matching PwnpilotConfig."""
    return MagicMock(
        llm=MagicMock(
            local_url="http://localhost:11434",
            local_model="llama3",
            model_name="ollama/llama3",
            api_key="",
            api_base_url="",
            fallback_model_name="gpt-4o-mini",
            fallback_api_key="",
            fallback_api_base_url="",
            cloud_allowed=False,
            timeout_seconds=30,
            max_retries=3,
        ),
        storage=MagicMock(
            evidence_dir=str(tmp_path / "evidence"),
            report_dir=str(tmp_path / "reports"),
        ),
        database=MagicMock(url=f"sqlite:///{tmp_path}/integration.db"),
        tools=MagicMock(
            trust_mode="first_party_only",
            allow_unsigned_first_party=True,
            plugin_package="pwnpilot.plugins.adapters",
            entrypoint_group="pwnpilot.plugins",
            discovery_mode="package",
            enabled_tools=[],
            disabled_tools=[],
            static_fallback_when_empty=False,
        ),
    )


# ---------------------------------------------------------------------------
# Integration: startup checks pass on a fresh SQLite DB
# ---------------------------------------------------------------------------


class TestStartupCheckIntegration:
    def test_startup_checks_return_list(self, tmp_path, monkeypatch):
        """run_startup_checks() returns a list regardless of environment."""
        monkeypatch.setenv("PWNPILOT_DB_URL", f"sqlite:///{tmp_path}/sc.db")

        with patch("pwnpilot.runtime._load_config",
                   return_value=_minimal_config(tmp_path)):
            with patch("pwnpilot.runtime._load_typed_config",
                       return_value=_minimal_typed_config(tmp_path)):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(
                        returncode=0,
                        stdout="abc123 (head)\n",
                        stderr="",
                    )
                    from pwnpilot.runtime import run_startup_checks
                    issues = run_startup_checks()

        assert isinstance(issues, list)
        # Should not have DB connectivity issues (SQLite always accessible)
        db_issues = [i for i in issues if "DATABASE" in i]
        assert len(db_issues) == 0

    def test_startup_checks_detect_alembic_behind_head(self, tmp_path, monkeypatch):
        """When alembic current does not report (head), a MIGRATIONS warning appears."""
        monkeypatch.setenv("PWNPILOT_DB_URL", f"sqlite:///{tmp_path}/sc2.db")

        with patch("pwnpilot.runtime._load_config",
                   return_value=_minimal_config(tmp_path)):
            with patch("pwnpilot.runtime._load_typed_config",
                       return_value=_minimal_typed_config(tmp_path)):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(
                        returncode=0,
                        stdout="abc123\n",  # no "(head)"
                        stderr="",
                    )
                    from pwnpilot.runtime import run_startup_checks
                    issues = run_startup_checks()

        mig_issues = [i for i in issues if "MIGRATIONS" in i]
        assert len(mig_issues) > 0


# ---------------------------------------------------------------------------
# Integration: policy simulation end-to-end
# ---------------------------------------------------------------------------


class TestPolicySimulationIntegration:
    def test_simulation_returns_results_for_each_action(self, tmp_path, monkeypatch):
        """run_policy_simulation() produces one result per input action."""
        monkeypatch.setenv("PWNPILOT_DB_URL", f"sqlite:///{tmp_path}/sim.db")
        eid = uuid4()

        actions = [
            {
                "engagement_id": str(eid),
                "action_type": "recon_passive",
                "tool_name": "nmap",
                "rationale": "discover hosts",
                "estimated_risk": "low",
                "risk_level": "low",
            },
            {
                "engagement_id": str(eid),
                "action_type": "active_scan",
                "tool_name": "nikto",
                "rationale": "web scan",
                "estimated_risk": "medium",
                "risk_level": "medium",
            },
        ]

        with patch("pwnpilot.runtime._load_config",
                   return_value=_minimal_config(tmp_path)):
            with patch("pwnpilot.runtime._load_typed_config",
                       return_value=_minimal_typed_config(tmp_path)):
                from pwnpilot.runtime import run_policy_simulation
                results = run_policy_simulation(actions, engagement_id=eid)

        assert len(results) == len(actions)
        for r in results:
            assert "verdict" in r
            assert r["verdict"] in ("allow", "deny", "escalate")


# ---------------------------------------------------------------------------
# Integration: audit trail written by KillSwitch trigger
# ---------------------------------------------------------------------------


class TestKillSwitchAuditIntegration:
    def test_kill_switch_trigger_sets_state(self, tmp_path, monkeypatch):
        """Triggering the kill switch sets its internal flag without raising."""
        monkeypatch.setenv("PWNPILOT_DB_URL", f"sqlite:///{tmp_path}/ks.db")
        (tmp_path / "evidence").mkdir()

        with patch("pwnpilot.runtime._load_config",
                   return_value=_minimal_config(tmp_path)):
            with patch("pwnpilot.runtime._load_typed_config",
                       return_value=_minimal_typed_config(tmp_path)):
                from pwnpilot.runtime import _build_runtime
                rt = _build_runtime()

        kill_switch = rt["kill_switch"]
        audit_store = rt["audit_store"]

        assert not kill_switch.is_set()
        # trigger() must not raise even when audit store is live
        kill_switch.trigger(reason="integration-test-stop")
        assert kill_switch.is_set()

        # Verify audit store is functional (can query by engagement_id)
        events = list(audit_store.events_for_engagement(uuid4()))
        assert isinstance(events, list)  # empty list for unknown ID

    def test_runtime_emits_plugin_load_audit_events(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PWNPILOT_DB_URL", f"sqlite:///{tmp_path}/pl.db")
        (tmp_path / "evidence").mkdir()

        with patch("pwnpilot.runtime._load_config", return_value=_minimal_config(tmp_path)):
            with patch("pwnpilot.runtime._load_typed_config", return_value=_minimal_typed_config(tmp_path)):
                from pwnpilot.runtime import _build_runtime
                rt = _build_runtime()

        events = list(rt["audit_store"].events_for_engagement(UUID(int=0)))
        assert any(e.event_type == "PluginLoad" for e in events)

    def test_static_fallback_when_registry_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PWNPILOT_DB_URL", f"sqlite:///{tmp_path}/pl2.db")
        (tmp_path / "evidence").mkdir()

        typed = _minimal_typed_config(tmp_path)
        typed.tools.trust_mode = "strict_signed_all"
        typed.tools.allow_unsigned_first_party = False
        typed.tools.static_fallback_when_empty = True

        with patch("pwnpilot.runtime._load_config", return_value=_minimal_config(tmp_path)):
            with patch("pwnpilot.runtime._load_typed_config", return_value=typed):
                from pwnpilot.runtime import _build_runtime
                rt = _build_runtime()

        assert "nmap" in rt["adapters"]
        assert "gobuster" in rt["adapters"]


# ---------------------------------------------------------------------------
# Integration: ApprovalStore round-trip
# ---------------------------------------------------------------------------


class TestApprovalStoreIntegration:
    def test_approval_round_trip(self, tmp_path, monkeypatch):
        """Create a ticket, retrieve it, then approve it — all against SQLite."""
        from pwnpilot.data.models import ActionRequest, ActionType, RiskLevel
        monkeypatch.setenv("PWNPILOT_DB_URL", f"sqlite:///{tmp_path}/ap.db")
        (tmp_path / "evidence").mkdir()

        with patch("pwnpilot.runtime._load_config",
                   return_value=_minimal_config(tmp_path)):
            with patch("pwnpilot.runtime._load_typed_config",
                       return_value=_minimal_typed_config(tmp_path)):
                from pwnpilot.runtime import _build_runtime
                rt = _build_runtime()

        approval_svc = rt["approval_service"]
        eid = uuid4()

        action = ActionRequest(
            engagement_id=eid,
            action_type=ActionType.RECON_PASSIVE,
            tool_name="nmap",
            risk_level=RiskLevel.LOW,
            requires_approval=True,
        )

        # Create ticket
        ticket = approval_svc.create_ticket(action, rationale="integration test scan")
        assert ticket.status == "pending"

        # Retrieve the ticket
        loaded = approval_svc.get_ticket(ticket.ticket_id)
        assert loaded is not None
        assert loaded.tool_name == "nmap"

        # Approve the ticket
        approved = approval_svc.approve(ticket.ticket_id, resolved_by="operator")
        assert approved.status == "approved"

        # Deny a second scenario
        action2 = ActionRequest(
            engagement_id=eid,
            action_type=ActionType.EXPLOIT,
            tool_name="sqlmap",
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
        )
        ticket2 = approval_svc.create_ticket(action2, rationale="test denial path")
        denied = approval_svc.deny(
            ticket2.ticket_id,
            resolved_by="operator",
            reason="outside ROE",
        )
        assert denied.status == "denied"


# ---------------------------------------------------------------------------
# Integration: dry-run engagement creation
# ---------------------------------------------------------------------------


class TestDryRunEngagementIntegration:
    def test_dry_run_returns_engagement_id(self, tmp_path, monkeypatch):
        """dry_run=True bypasses agent graph execution and returns an ID string."""
        monkeypatch.setenv("PWNPILOT_DB_URL", f"sqlite:///{tmp_path}/dr.db")
        (tmp_path / "evidence").mkdir()

        with patch("pwnpilot.runtime._load_config",
                   return_value=_minimal_config(tmp_path)):
            with patch("pwnpilot.runtime._load_typed_config",
                       return_value=_minimal_typed_config(tmp_path)):
                from pwnpilot.runtime import create_and_run_engagement
                eid = create_and_run_engagement(
                    name="integration-dry",
                    scope_cidrs=["192.0.2.0/24"],
                    scope_domains=[],
                    scope_urls=[],
                    roe_document_hash="a" * 64,
                    authoriser_identity="test-operator",
                    dry_run=True,
                )

        # Should be a valid UUID string
        from uuid import UUID
        UUID(eid)  # raises ValueError if not a valid UUID


# ---------------------------------------------------------------------------
# Integration: RetentionManager round-trip
# ---------------------------------------------------------------------------


class TestRetentionIntegration:
    def test_apply_ttl_deletes_expired_evidence(self, tmp_path, monkeypatch):
        """apply_ttl with force=True deletes evidence files."""
        from datetime import datetime, timedelta, timezone
        from pwnpilot.governance.retention import RetentionManager, EngagementClassification

        evidence_file = tmp_path / "evidence.bin"
        evidence_file.write_bytes(b"secret evidence " * 50)

        entry = MagicMock()
        entry.file_path = str(evidence_file)

        ev_store = MagicMock()
        ev_store.list_for_engagement.return_value = [entry]
        audit_store = MagicMock()

        mgr = RetentionManager(evidence_store=ev_store, audit_store=audit_store)
        eid = uuid4()
        three_months_ago = datetime.now(timezone.utc) - timedelta(days=100)

        result = mgr.apply_ttl(eid, EngagementClassification.EXTERNAL,
                               three_months_ago, force=True)

        assert result["deleted_count"] == 1
        assert not evidence_file.exists()

    def test_legal_hold_prevents_deletion(self, tmp_path):
        """apply_ttl raises RuntimeError when engagement is under a legal hold."""
        from datetime import datetime, timedelta, timezone
        from pwnpilot.governance.retention import RetentionManager, EngagementClassification

        evidence_file = tmp_path / "held.bin"
        evidence_file.write_bytes(b"protected " * 50)

        ev_store = MagicMock()
        audit_store = MagicMock()
        mgr = RetentionManager(evidence_store=ev_store, audit_store=audit_store)

        eid = uuid4()
        mgr.place_legal_hold(eid, holder="counsel", reason="ongoing litigation")

        far_past = datetime.now(timezone.utc) - timedelta(days=365 * 2)
        with pytest.raises(RuntimeError, match="legal hold"):
            mgr.apply_ttl(eid, EngagementClassification.EXTERNAL, far_past)

        # File must be untouched since deletion was blocked
        assert evidence_file.exists()
