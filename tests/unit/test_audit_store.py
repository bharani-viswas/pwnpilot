"""Unit tests for audit store hash chain (Sprint 2)."""
from __future__ import annotations

import pytest
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.data.audit_store import AuditIntegrityError, AuditStore


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=engine)
    return Session()


class TestAuditStore:
    def setup_method(self):
        self.session = _make_session()
        self.store = AuditStore(self.session)
        self.eng_id = uuid4()

    def test_append_creates_event(self):
        ev = self.store.append(
            engagement_id=self.eng_id,
            actor="tester",
            event_type="TestEvent",
            payload={"key": "value"},
        )
        assert ev.event_type == "TestEvent"
        assert ev.actor == "tester"

    def test_chain_links_correctly(self):
        e1 = self.store.append(self.eng_id, "a", "E1", {"n": 1})
        e2 = self.store.append(self.eng_id, "a", "E2", {"n": 2})
        assert e2.prev_event_hash == e1.payload_hash

    def test_verify_chain_passes(self):
        for i in range(5):
            self.store.append(self.eng_id, "sys", "Event", {"i": i})
        assert self.store.verify_chain(self.eng_id) is True

    def test_verify_chain_detects_tampering(self):
        self.store.append(self.eng_id, "sys", "Event", {"x": 1})
        # Tamper with the stored row
        from pwnpilot.data.audit_store import AuditEventRow
        row = self.session.query(AuditEventRow).first()
        row.payload_json = '{"x": 999}'  # tampered
        self.session.commit()

        with pytest.raises(AuditIntegrityError):
            self.store.verify_chain(self.eng_id)

    def test_events_iterator(self):
        for i in range(3):
            self.store.append(self.eng_id, "sys", f"E{i}", {})
        events = list(self.store.events_for_engagement(self.eng_id))
        # Filter out checkpoint events
        real = [e for e in events if e.event_type != "ChainCheckpoint"]
        assert len(real) == 3
