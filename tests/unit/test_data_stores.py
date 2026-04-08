"""Unit tests for EvidenceStore, FindingStore, ReconStore (Sprint 2)."""
from __future__ import annotations

import pytest
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.data.finding_store import FindingStore
from pwnpilot.data.models import Exploitability, FindingStatus, Severity
from pwnpilot.data.recon_store import ReconStore


def _session():
    engine = create_engine("sqlite:///:memory:")
    return sessionmaker(bind=engine)()


class TestEvidenceStore:
    def setup_method(self, tmp_path=None):
        self.session = _session()
        self.dir = Path("/tmp") / f"pwnpilot_test_{uuid4().hex[:8]}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.store = EvidenceStore(base_dir=self.dir, session=self.session)
        self.eng_id = uuid4()
        self.action_id = uuid4()

    def test_write_bytes_stores_evidence(self):
        idx = self.store.write_bytes(self.eng_id, self.action_id, b"test output")
        assert idx.size_bytes == 11
        assert len(idx.sha256_hash) == 64
        assert not idx.truncated

    def test_read_back_matches(self):
        data = b"hello evidence"
        idx = self.store.write_bytes(self.eng_id, self.action_id, data)
        recovered = self.store.read_evidence(idx.evidence_id)
        assert recovered == data

    def test_size_cap_truncates(self):
        store = EvidenceStore(
            base_dir=self.dir / "capped",
            session=self.session,
            max_bytes=5,
        )
        store._base.mkdir(parents=True, exist_ok=True)
        idx = store.write_bytes(self.eng_id, self.action_id, b"abcdefghij")
        assert idx.size_bytes == 5
        assert idx.truncated is True

    def test_path_has_no_user_input(self):
        idx = self.store.write_bytes(self.eng_id, self.action_id, b"x")
        # Path should only contain UUID components
        p = Path(idx.file_path)
        assert str(self.eng_id) in str(p)
        assert str(idx.evidence_id) in str(p)

    def test_unknown_evidence_raises(self):
        with pytest.raises(FileNotFoundError):
            self.store.read_evidence(uuid4())

    def test_index_for_action_returns_records(self):
        self.store.write_bytes(self.eng_id, self.action_id, b"a")
        self.store.write_bytes(self.eng_id, self.action_id, b"b")
        records = self.store.index_for_action(self.action_id)
        assert len(records) == 2


class TestFindingStore:
    def setup_method(self):
        self.session = _session()
        self.store = FindingStore(self.session)
        self.eng_id = uuid4()

    def test_upsert_creates_finding(self):
        f = self.store.upsert(
            engagement_id=self.eng_id,
            asset_ref="10.0.0.1:80",
            title="Test vuln",
            vuln_ref="CVE-2024-0001",
            tool_name="nmap",
            severity=Severity.HIGH,
        )
        assert f.finding_id is not None
        assert f.severity == Severity.HIGH

    def test_duplicate_upsert_merges(self):
        for _ in range(2):
            self.store.upsert(
                engagement_id=self.eng_id,
                asset_ref="10.0.0.1:80",
                title="Test",
                vuln_ref="CVE-2024-0001",
                tool_name="nmap",
                severity=Severity.MEDIUM,
            )
        findings = self.store.findings_for_engagement(self.eng_id)
        assert len(findings) == 1  # deduplicated

    def test_different_vuln_ref_creates_separate(self):
        self.store.upsert(self.eng_id, "10.0.0.1", "A", "CVE-1", "nmap", Severity.LOW)
        self.store.upsert(self.eng_id, "10.0.0.1", "B", "CVE-2", "nmap", Severity.LOW)
        findings = self.store.findings_for_engagement(self.eng_id)
        assert len(findings) == 2

    def test_risk_score_computed(self):
        f = self.store.upsert(
            self.eng_id,
            "10.0.0.1",
            "Test",
            "CVE-2024-0002",
            "nuclei",
            Severity.CRITICAL,
            exploitability=Exploitability.WEAPONIZED,
            confidence=1.0,
        )
        # Should be close to max; critical (9.5) * weaponized (1.25) * confidence (1.0) = 11.875 → clamped to 10.0
        findings = self.store.findings_for_engagement(self.eng_id)
        assert findings[0].severity == Severity.CRITICAL

    def test_update_status(self):
        f = self.store.upsert(self.eng_id, "h", "T", "CVE-X", "t", Severity.LOW)
        self.store.update_status(f.finding_id, FindingStatus.CONFIRMED)
        findings = self.store.findings_for_engagement(self.eng_id)
        assert findings[0].status == FindingStatus.CONFIRMED


class TestReconStore:
    def setup_method(self):
        self.session = _session()
        self.store = ReconStore(self.session)
        self.eng_id = uuid4()

    def test_upsert_host(self):
        host_id = self.store.upsert_host(
            self.eng_id, "10.0.0.1", hostname="target.local", status="up"
        )
        assert host_id

    def test_upsert_host_idempotent(self):
        id1 = self.store.upsert_host(self.eng_id, "10.0.0.1")
        id2 = self.store.upsert_host(self.eng_id, "10.0.0.1", status="up")
        assert id1 == id2

    def test_upsert_service(self):
        host_id = self.store.upsert_host(self.eng_id, "10.0.0.2")
        svc_id = self.store.upsert_service(
            host_id, self.eng_id, port=80, protocol="tcp", service_name="http"
        )
        assert svc_id

    def test_hosts_for_engagement(self):
        self.store.upsert_host(self.eng_id, "10.0.0.1")
        self.store.upsert_host(self.eng_id, "10.0.0.2")
        hosts = self.store.hosts_for_engagement(self.eng_id)
        assert len(hosts) == 2

    def test_services_for_host(self):
        host_id = self.store.upsert_host(self.eng_id, "10.0.0.3")
        self.store.upsert_service(host_id, self.eng_id, port=22)
        self.store.upsert_service(host_id, self.eng_id, port=443)
        services = self.store.services_for_host(host_id)
        assert len(services) == 2
