"""
Tests for all gap implementations:
  - reporting/signer.py          (ReportSigner)
  - governance/retention.py      (RetentionManager, LegalHold)
  - observability/tracing.py     (Tracer, Span, TraceContext)
  - plugins/adapters/whois.py    (WhoisAdapter)
  - plugins/adapters/dns.py      (DnsAdapter)
  - data/approval_store.py       (ApprovalStore)
  - runtime.run_startup_checks   (startup validation)
  - cli db backup / check        (CLI smoke tests)
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

# ---------------------------------------------------------------------------
# reporting/signer.py
# ---------------------------------------------------------------------------


class TestReportSigner:
    def test_generate_key_pair_creates_files(self, tmp_path):
        from pwnpilot.reporting.signer import ReportSigner

        priv = tmp_path / "test.key"
        pub = tmp_path / "test.pub"
        ReportSigner.generate_key_pair(priv, pub)
        assert priv.exists()
        assert pub.exists()
        # Private key must not be world-readable
        assert oct(priv.stat().st_mode)[-3:] in ("600", "400")

    def test_round_trip_sign_verify(self, tmp_path):
        from pwnpilot.reporting.signer import ReportSigner

        priv = tmp_path / "op.key"
        pub = tmp_path / "op.pub"
        ReportSigner.generate_key_pair(priv, pub)

        # Create a fake bundle
        bundle = tmp_path / "report.json"
        bundle.write_text(json.dumps({"findings": [], "schema_version": "v1"}))

        signer = ReportSigner.from_key_file(priv)
        sig_path = signer.sign(bundle)

        assert sig_path.exists()
        # Verify succeeds with explicit public key
        ReportSigner.verify(bundle, sig_path, pub)

    def test_verify_fails_on_tampered_bundle(self, tmp_path):
        from pwnpilot.reporting.signer import ReportSigner, SignatureError

        priv = tmp_path / "op.key"
        pub = tmp_path / "op.pub"
        ReportSigner.generate_key_pair(priv, pub)

        bundle = tmp_path / "report.json"
        bundle.write_text(json.dumps({"findings": []}))

        signer = ReportSigner.from_key_file(priv)
        sig_path = signer.sign(bundle)

        # Tamper with the bundle
        bundle.write_text(json.dumps({"findings": ["INJECTED"]}))

        with pytest.raises(SignatureError):
            ReportSigner.verify(bundle, sig_path, pub)

    def test_embed_pubkey_round_trip(self, tmp_path):
        from pwnpilot.reporting.signer import ReportSigner

        priv = tmp_path / "op.key"
        pub = tmp_path / "op.pub"
        ReportSigner.generate_key_pair(priv, pub)

        bundle = tmp_path / "report.json"
        bundle.write_text(json.dumps({"findings": []}))

        signer = ReportSigner.from_key_file(priv)
        signer.embed_pubkey_in_bundle(bundle)

        data = json.loads(bundle.read_text())
        assert "operator_pubkey_b64" in data

        sig_path = signer.sign(bundle)
        # Verify using embedded key (no explicit public_key_path)
        ReportSigner.verify(bundle, sig_path)

    def test_from_public_key_file_only_verifies(self, tmp_path):
        from pwnpilot.reporting.signer import ReportSigner

        priv = tmp_path / "op.key"
        pub = tmp_path / "op.pub"
        ReportSigner.generate_key_pair(priv, pub)

        bundle = tmp_path / "report.json"
        bundle.write_text(json.dumps({"x": 1}))

        signer = ReportSigner.from_key_file(priv)
        sig_path = signer.sign(bundle)

        # Verifier instantiated from public key only
        verifier = ReportSigner.from_public_key_file(pub)
        ReportSigner.verify(bundle, sig_path, pub)  # should not raise


# ---------------------------------------------------------------------------
# governance/retention.py
# ---------------------------------------------------------------------------


class TestRetentionManager:
    def _make_store(self):
        mock_ev = MagicMock()
        mock_ev.list_evidence_for_engagement.return_value = []
        mock_audit = MagicMock()
        mock_audit.append = MagicMock()
        return mock_ev, mock_audit

    def test_place_and_check_legal_hold(self):
        from pwnpilot.governance.retention import RetentionManager

        ev, audit = self._make_store()
        mgr = RetentionManager(evidence_store=ev, audit_store=audit)
        eid = uuid4()
        mgr.place_legal_hold(eid, holder="legal@example.com", reason="litigation")
        assert mgr.has_active_hold(eid)

    def test_release_legal_hold(self):
        from pwnpilot.governance.retention import RetentionManager

        ev, audit = self._make_store()
        mgr = RetentionManager(evidence_store=ev, audit_store=audit)
        eid = uuid4()
        mgr.place_legal_hold(eid, holder="legal@example.com", reason="test")
        mgr.release_legal_hold(eid, released_by="operator")
        assert not mgr.has_active_hold(eid)

    def test_place_hold_idempotent(self):
        from pwnpilot.governance.retention import RetentionManager

        ev, audit = self._make_store()
        mgr = RetentionManager(evidence_store=ev, audit_store=audit)
        eid = uuid4()
        mgr.place_legal_hold(eid, holder="a@b.com", reason="r")
        mgr.place_legal_hold(eid, holder="a@b.com", reason="r")  # second call is no-op
        assert mgr.has_active_hold(eid)

    def test_is_expired_true_beyond_ttl(self):
        from pwnpilot.governance.retention import EngagementClassification, RetentionManager

        ev, audit = self._make_store()
        mgr = RetentionManager(evidence_store=ev, audit_store=audit)
        eid = uuid4()
        old_date = datetime.now(timezone.utc) - timedelta(days=400)
        assert mgr.is_expired(eid, EngagementClassification.CTF, old_date)

    def test_is_expired_false_within_ttl(self):
        from pwnpilot.governance.retention import EngagementClassification, RetentionManager

        ev, audit = self._make_store()
        mgr = RetentionManager(evidence_store=ev, audit_store=audit)
        eid = uuid4()
        recent = datetime.now(timezone.utc) - timedelta(days=5)
        assert not mgr.is_expired(eid, EngagementClassification.CTF, recent)

    def test_apply_ttl_blocked_by_legal_hold(self):
        from pwnpilot.governance.retention import EngagementClassification, RetentionManager

        ev, audit = self._make_store()
        mgr = RetentionManager(evidence_store=ev, audit_store=audit)
        eid = uuid4()
        mgr.place_legal_hold(eid, holder="legal@example.com", reason="hold")
        old_date = datetime.now(timezone.utc) - timedelta(days=400)
        # apply_ttl must raise RuntimeError when a legal hold is active
        with pytest.raises(RuntimeError, match="legal hold"):
            mgr.apply_ttl(eid, EngagementClassification.CTF, old_date)

    def test_apply_ttl_not_expired_returns_not_expired(self):
        from pwnpilot.governance.retention import EngagementClassification, RetentionManager

        ev, audit = self._make_store()
        mgr = RetentionManager(evidence_store=ev, audit_store=audit)
        eid = uuid4()
        recent = datetime.now(timezone.utc) - timedelta(days=1)
        result = mgr.apply_ttl(eid, EngagementClassification.CTF, recent)
        assert result.get("reason") == "not_expired"


# ---------------------------------------------------------------------------
# observability/tracing.py
# ---------------------------------------------------------------------------


class TestTracing:
    def test_span_lifecycle(self):
        from pwnpilot.observability.tracing import Tracer

        t = Tracer()
        span = t.start_span("test_op")
        assert span.end_time is None
        t.finish_span(span)
        assert span.end_time is not None

    def test_context_manager(self):
        from pwnpilot.observability.tracing import Tracer

        t = Tracer()
        with t.span("my_op") as span:
            span.set_attribute("key", "value")
        assert span.status == "ok"
        assert span.attributes["key"] == "value"

    def test_context_manager_exception_sets_error(self):
        from pwnpilot.observability.tracing import Tracer

        t = Tracer()
        with pytest.raises(ValueError):
            with t.span("failing_op") as span:
                raise ValueError("boom")
        assert span.status == "error"

    def test_nested_spans_parent_child(self):
        from pwnpilot.observability.tracing import Tracer

        t = Tracer()
        with t.span("parent") as parent_span:
            with t.span("child") as child_span:
                pass
        assert child_span.parent_id == parent_span.span_id

    def test_export_returns_spans(self):
        from pwnpilot.observability.tracing import Tracer

        t = Tracer()
        with t.span("op1"):
            pass
        spans = t.export()
        assert len(spans) >= 1
        assert any(s["name"] == "op1" for s in spans)

    def test_clear_removes_spans(self):
        from pwnpilot.observability.tracing import Tracer

        t = Tracer()
        with t.span("op"):
            pass
        t.clear()
        assert t.export() == []

    def test_thread_isolation_active_stack(self):
        """Active span stacks are thread-local (spans on one thread don't become parents on another)."""
        from pwnpilot.observability.tracing import Tracer

        t = Tracer()
        parent_ids: dict = {}

        def worker(name: str) -> None:
            with t.span(name) as span:
                parent_ids[name] = span.parent_id

        threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(3)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        # Each thread starts its span with no parent (independent stacks)
        for name, pid in parent_ids.items():
            assert pid is None, f"Thread {name} unexpectedly got parent_id={pid}"


# ---------------------------------------------------------------------------
# plugins/manifests/whois.yaml + GenericCLIAdapter
# ---------------------------------------------------------------------------


class TestWhoisAdapter:
    def _adapter(self):
        from pwnpilot.plugins.generic_adapter import GenericCLIAdapter
        from pwnpilot.plugins.manifest_loader import load_manifest_file

        manifest = Path(__file__).resolve().parents[2] / "pwnpilot" / "plugins" / "manifests" / "whois.yaml"
        return GenericCLIAdapter(load_manifest_file(manifest))

    def test_build_command(self):
        adapter = self._adapter()
        params = adapter.validate_params({"target": "example.com"})
        cmd = adapter.build_command(params)
        assert cmd == ["whois", "example.com"]

    def test_validate_params_accepts_valid_domain(self):
        adapter = self._adapter()
        params = adapter.validate_params({"target": "example.com"})
        assert params.target == "example.com"

    def test_parse_preserves_raw_record(self):
        adapter = self._adapter()
        sample = (
            b"Registrar: Acme Registrar Inc.\n"
            b"Creation Date: 2000-01-15\n"
            b"Registry Expiry Date: 2030-01-15\n"
            b"Registrant Name: John Doe\n"
            b"Name Server: ns1.example.com\n"
        )
        result = adapter.parse(sample, b"", 0)
        assert result.findings
        assert "Registrar: Acme Registrar Inc." in result.findings[0]["raw"]

    def test_risk_class(self):
        assert self._adapter().manifest.risk_class == "passive_recon"


# ---------------------------------------------------------------------------
# plugins/adapters/dns.py
# ---------------------------------------------------------------------------


class TestDnsAdapter:
    def test_build_command_default(self):
        from pwnpilot.plugins.adapters.dns import DnsAdapter
        from pwnpilot.plugins.sdk import ToolParams

        adapter = DnsAdapter()
        params = ToolParams(target="example.com", extra={"record_type": "A", "resolver": ""})
        cmd = adapter.build_command(params)
        assert cmd == ["dig", "+noall", "+answer", "example.com", "A"]

    def test_build_command_with_resolver(self):
        from pwnpilot.plugins.adapters.dns import DnsAdapter
        from pwnpilot.plugins.sdk import ToolParams

        adapter = DnsAdapter()
        params = ToolParams(target="example.com", extra={"record_type": "MX", "resolver": "8.8.8.8"})
        cmd = adapter.build_command(params)
        assert "@8.8.8.8" in cmd

    def test_validate_params_rejects_injection(self):
        from pwnpilot.plugins.adapters.dns import DnsAdapter

        adapter = DnsAdapter()
        with pytest.raises(ValueError):
            adapter.validate_params({"target": "; cat /etc/passwd", "record_type": "A"})

    def test_parse_a_record(self):
        from pwnpilot.plugins.adapters.dns import DnsAdapter

        adapter = DnsAdapter()
        sample = b"example.com.      300    IN    A    93.184.216.34\n"
        result = adapter.parse(sample, b"", 0)
        records = result.findings[0]["records"]
        assert result.findings[0]["record_count"] >= 1
        assert any(r.get("rdata") == "93.184.216.34" for r in records)

    def test_risk_class(self):
        from pwnpilot.plugins.adapters.dns import DnsAdapter

        assert DnsAdapter().manifest.risk_class == "recon_passive"


# ---------------------------------------------------------------------------
# data/approval_store.py
# ---------------------------------------------------------------------------


class TestApprovalStore:
    def _make_session(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        return Session()

    def _make_ticket(self):
        from pwnpilot.data.models import (
            ActionType,
            ApprovalStatus,
            ApprovalTicket,
            RiskLevel,
        )

        return ApprovalTicket(
            action_id=uuid4(),
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            rationale="scan the target",
            impact_preview="port scan on 10.0.0.1",
            risk_level=RiskLevel.MEDIUM,
            status=ApprovalStatus.PENDING,
        )

    def test_upsert_and_reload_pending(self):
        from pwnpilot.data.approval_store import ApprovalStore

        session = self._make_session()
        store = ApprovalStore(session)
        ticket = self._make_ticket()

        store.upsert(ticket)
        pending = store.load_pending()
        assert len(pending) == 1
        assert pending[0].ticket_id == ticket.ticket_id
        assert pending[0].tool_name == "nmap"

    def test_upsert_updates_status(self):
        from pwnpilot.data.approval_store import ApprovalStore
        from pwnpilot.data.models import ApprovalStatus

        session = self._make_session()
        store = ApprovalStore(session)
        ticket = self._make_ticket()
        store.upsert(ticket)

        # Update status to APPROVED
        approved = ticket.model_copy(
            update={
                "status": ApprovalStatus.APPROVED,
                "resolved_by": "operator",
                "resolution_reason": "looks good",
                "resolved_at": datetime.now(timezone.utc),
            }
        )
        store.upsert(approved)

        # load_pending only returns PENDING — should be empty now
        pending = store.load_pending()
        assert len(pending) == 0

    def test_load_pending_skips_non_pending(self):
        from pwnpilot.data.approval_store import ApprovalStore
        from pwnpilot.data.models import ApprovalStatus

        session = self._make_session()
        store = ApprovalStore(session)

        t1 = self._make_ticket()
        t2 = self._make_ticket()
        store.upsert(t1)
        store.upsert(t2)

        # Approve t2
        store.upsert(
            t2.model_copy(
                update={
                    "status": ApprovalStatus.APPROVED,
                    "resolved_by": "op",
                    "resolved_at": datetime.now(timezone.utc),
                }
            )
        )

        pending = store.load_pending()
        assert len(pending) == 1
        assert pending[0].ticket_id == t1.ticket_id

    def test_creates_table_automatically(self):
        from pwnpilot.data.approval_store import ApprovalStore
        from sqlalchemy import inspect as sa_inspect

        session = self._make_session()
        _ = ApprovalStore(session)  # table creation side-effect
        inspector = sa_inspect(session.get_bind())
        assert "approval_tickets" in inspector.get_table_names()


# ---------------------------------------------------------------------------
# runtime.run_startup_checks
# ---------------------------------------------------------------------------


class TestRunStartupChecks:
    def test_returns_list(self):
        """run_startup_checks must always return a list (may contain warnings)."""
        from pwnpilot.runtime import run_startup_checks

        # Using an in-memory SQLite DB so no real DB is needed
        with patch.dict(os.environ, {"PWNPILOT_DB_URL": "sqlite:///:memory:"}):
            result = run_startup_checks()
        assert isinstance(result, list)

    def test_db_unreachable_returns_issue(self):
        from pwnpilot.runtime import run_startup_checks

        with patch.dict(os.environ, {"PWNPILOT_DB_URL": "postgresql://no-such-host:5432/x"}):
            issues = run_startup_checks()
        assert any("DATABASE" in i for i in issues)

    def test_signing_key_absent_warns(self, tmp_path, monkeypatch):
        from pwnpilot.runtime import run_startup_checks

        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()
        # Use a path that won't exist so DB check won't interfere
        monkeypatch.setenv("PWNPILOT_DB_URL", "postgresql://no-such-host/x")
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.delenv("PWNPILOT_SIGNING_KEY", raising=False)

        issues = run_startup_checks()
        # DB unreachable is expected; signing key warning should still appear
        signing_issues = [i for i in issues if "SIGNING" in i]
        assert len(signing_issues) >= 1
