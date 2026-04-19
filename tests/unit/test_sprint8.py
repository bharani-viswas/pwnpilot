"""Unit tests for Sprint 8: SqliteCheckpointer, CorrelationEngine."""
from __future__ import annotations

import pytest
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.data.audit_store import AuditStore
from pwnpilot.data.correlation import CorrelationEngine
from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.data.finding_store import FindingStore
from pwnpilot.data.models import Exploitability, Severity
from pwnpilot.data.recon_store import ReconStore


def _session():
    engine = create_engine("sqlite:///:memory:")
    return sessionmaker(bind=engine)()


# ---------------------------------------------------------------------------
# SqliteCheckpointer
# ---------------------------------------------------------------------------


class TestSqliteCheckpointer:
    def test_import_ok(self):
        from pwnpilot.agent.checkpointer import SqliteCheckpointer
        assert SqliteCheckpointer is not None

    def test_init_creates_tables(self, tmp_path):
        from pwnpilot.agent.checkpointer import SqliteCheckpointer
        db = tmp_path / "cp.db"
        cp = SqliteCheckpointer.from_path(db)
        assert db.exists()
        cp.__exit__(None, None, None)

    def test_context_manager(self, tmp_path):
        from pwnpilot.agent.checkpointer import SqliteCheckpointer
        db = tmp_path / "cp.db"
        with SqliteCheckpointer.from_path(db) as cp:
            assert cp is not None

    def test_put_and_get_tuple(self, tmp_path):
        """A checkpoint written with put should be retrievable via get_tuple."""
        from pwnpilot.agent.checkpointer import SqliteCheckpointer
        from langgraph.checkpoint.memory import MemorySaver

        db = tmp_path / "cp.db"
        with SqliteCheckpointer.from_path(db) as cp:
            config = {"configurable": {"thread_id": "t1", "checkpoint_ns": ""}}
            # create a minimal checkpoint dict
            checkpoint = {
                "v": 1,
                "id": "cp-001",
                "ts": "2026-04-07T00:00:00+00:00",
                "channel_values": {},
                "channel_versions": {},
                "versions_seen": {},
                "pending_sends": [],
            }
            metadata = {"source": "loop", "step": 0, "writes": {}, "parents": {}}
            new_config = cp.put(config, checkpoint, metadata, {})
            assert new_config["configurable"]["checkpoint_id"] == "cp-001"

            t = cp.get_tuple(
                {"configurable": {"thread_id": "t1", "checkpoint_ns": "",
                                  "checkpoint_id": "cp-001"}}
            )
            assert t is not None
            assert t.checkpoint["id"] == "cp-001"

    def test_reload_from_db(self, tmp_path):
        """Checkpoints written in one instance persist to SQLite tables."""
        from pwnpilot.agent.checkpointer import SqliteCheckpointer
        import sqlite3

        db = tmp_path / "reload.db"
        with SqliteCheckpointer.from_path(db) as cp1:
            config = {"configurable": {"thread_id": "t2", "checkpoint_ns": ""}}
            checkpoint = {
                "v": 1, "id": "cp-reload", "ts": "2026-04-07T01:00:00+00:00",
                "channel_values": {}, "channel_versions": {},
                "versions_seen": {}, "pending_sends": [],
            }
            metadata = {"source": "loop", "step": 0, "writes": {}, "parents": {}}
            cp1.put(config, checkpoint, metadata, {})

        # Verify the row exists in SQLite directly (bypassing serde)
        conn = sqlite3.connect(db)
        rows = conn.execute(
            "SELECT checkpoint_id FROM lg_checkpoints WHERE thread_id='t2'"
        ).fetchall()
        conn.close()
        assert len(rows) == 1
        assert rows[0][0] == "cp-reload"

    def test_delete_thread(self, tmp_path):
        from pwnpilot.agent.checkpointer import SqliteCheckpointer

        db = tmp_path / "del.db"
        config = {"configurable": {"thread_id": "to-delete", "checkpoint_ns": ""}}
        checkpoint = {
            "v": 1, "id": "cp-del", "ts": "2026-04-07T02:00:00+00:00",
            "channel_values": {}, "channel_versions": {},
            "versions_seen": {}, "pending_sends": [],
        }
        metadata = {"source": "loop", "step": 0, "writes": {}, "parents": {}}

        with SqliteCheckpointer.from_path(db) as cp:
            cp.put(config, checkpoint, metadata, {})
            cp.delete_thread("to-delete")
            t = cp.get_tuple(
                {"configurable": {"thread_id": "to-delete", "checkpoint_ns": "",
                                  "checkpoint_id": "cp-del"}}
            )
            assert t is None

    def test_put_writes(self, tmp_path):
        """put_writes should not raise."""
        from pwnpilot.agent.checkpointer import SqliteCheckpointer

        db = tmp_path / "writes.db"
        with SqliteCheckpointer.from_path(db) as cp:
            config = {
                "configurable": {
                    "thread_id": "tw", "checkpoint_ns": "", "checkpoint_id": "cp-w1"
                }
            }
            cp.put_writes(config, [("channel_a", "value_a")], task_id="task-1")


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------


class TestCorrelationEngine:
    def _setup(self, tmp_path):
        session = _session()
        fs = FindingStore(session)
        rs = ReconStore(session)
        return CorrelationEngine(fs, rs), fs, rs, session

    def test_risk_rollup_empty_engagement(self, tmp_path):
        engine, _, _, _ = self._setup(tmp_path)
        eng_id = uuid4()
        summary = engine.risk_rollup(eng_id)
        assert summary["total_findings"] == 0
        assert summary["overall_risk"] == "info"
        assert summary["severity_distribution"]["critical"] == 0

    def test_risk_rollup_with_findings(self, tmp_path):
        engine, fs, _, _ = self._setup(tmp_path)
        eng_id = uuid4()

        fs.upsert(
            engagement_id=eng_id,
            asset_ref="10.0.0.1:80",
            title="SQL Injection",
            vuln_ref="CWE-89",
            tool_name="sqlmap",
            severity=Severity.HIGH,
            confidence=0.9,
        )
        fs.upsert(
            engagement_id=eng_id,
            asset_ref="10.0.0.1:80",
            title="Open Port",
            vuln_ref="info-open-port",
            tool_name="nmap",
            severity=Severity.INFO,
            confidence=1.0,
        )

        summary = engine.risk_rollup(eng_id)
        assert summary["total_findings"] == 2
        assert summary["overall_risk"] == "high"
        assert summary["severity_distribution"]["high"] == 1
        assert summary["unconfirmed_findings"] == 2
        assert summary["confirmed_findings"] == 0
        assert summary["remediation_open_findings"] == 2
        assert "sqlmap" in summary["tool_coverage"]
        assert len(summary["top_findings"]) <= 5

    def test_correlate_exploits_escalates_exploitability(self, tmp_path):
        engine, fs, _, _ = self._setup(tmp_path)
        eng_id = uuid4()

        # A vulnerability finding
        fs.upsert(
            engagement_id=eng_id,
            asset_ref="10.0.0.1",
            title="Apache Path Traversal",
            vuln_ref="CVE-2021-41773",
            tool_name="nuclei",
            severity=Severity.HIGH,
            confidence=0.8,
            exploitability=Exploitability.NONE,
        )

        # A searchsploit finding referencing the same CVE
        fs.upsert(
            engagement_id=eng_id,
            asset_ref="10.0.0.1",
            title="Apache 2.4.49 CVE-2021-41773 PoC",
            vuln_ref="CVE-2021-41773",
            tool_name="searchsploit",
            severity=Severity.HIGH,
            confidence=0.9,
        )

        escalated = engine.correlate(eng_id)
        assert escalated >= 1

        # Verify the nuclei finding's exploitability was escalated
        from pwnpilot.data.finding_store import FindingRow
        row = (
            engine._findings._session.query(FindingRow)
            .filter(
                FindingRow.engagement_id == str(eng_id),
                FindingRow.tool_name == "nuclei",
            )
            .first()
        )
        assert row is not None
        assert row.exploitability != "none"

    def test_correlate_no_exploits_returns_zero(self, tmp_path):
        engine, fs, _, _ = self._setup(tmp_path)
        eng_id = uuid4()

        fs.upsert(
            engagement_id=eng_id,
            asset_ref="10.0.0.1",
            title="Some finding",
            vuln_ref="CWE-79",
            tool_name="zap",
            severity=Severity.MEDIUM,
            confidence=0.7,
        )

        escalated = engine.correlate(eng_id)
        assert escalated == 0

    def test_correlate_service_versions(self, tmp_path):
        engine, fs, rs, _ = self._setup(tmp_path)
        eng_id = uuid4()

        # Insert a host and service in recon store
        host_id = rs.upsert_host(
            engagement_id=eng_id,
            ip_address="10.0.0.2",
            hostname="web.local",
        )
        rs.upsert_service(
            host_id=host_id,
            engagement_id=eng_id,
            port=80,
            protocol="tcp",
            service_name="http",
            product="Apache",
            version="2.4.49",
        )

        # A finding on that IP
        fs.upsert(
            engagement_id=eng_id,
            asset_ref="10.0.0.2:80",
            title="XSS vulnerability",
            vuln_ref="CWE-79",
            tool_name="zap",
            severity=Severity.MEDIUM,
            confidence=0.7,
        )

        engine.correlate(eng_id)

        from pwnpilot.data.finding_store import FindingRow
        row = (
            engine._findings._session.query(FindingRow)
            .filter(FindingRow.engagement_id == str(eng_id))
            .first()
        )
        # Title should now include the product name
        assert "Apache" in row.title

    def test_services_for_engagement(self, tmp_path):
        session = _session()
        rs = ReconStore(session)
        eng_id = uuid4()

        host_id = rs.upsert_host(engagement_id=eng_id, ip_address="192.168.1.1")
        rs.upsert_service(
            host_id=host_id,
            engagement_id=eng_id,
            port=443, protocol="tcp",
            service_name="https", product="nginx", version="1.24",
        )

        svcs = rs.services_for_engagement(eng_id)
        assert len(svcs) == 1
        assert svcs[0]["ip"] == "192.168.1.1"
        assert svcs[0]["port"] == 443
