"""
Quality benchmark gate: Memory recall quality.

Validates that the RetrievalStore:
  - Indexes findings with relevant terms
  - Returns relevant results for targeted queries
  - Handles empty queries gracefully
  - Returns most relevant findings first
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.data.retrieval_store import RetrievalStore


def _make_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Session = sessionmaker(bind=engine)
    return Session()


class TestMemoryRecallQualityGate:
    """Pass/fail gates for memory (retrieval) quality."""

    def test_indexed_finding_is_retrievable(self) -> None:
        session = _make_session()
        store = RetrievalStore(session)
        eid = uuid4()

        store.index_finding(
            engagement_id=eid,
            title="SQL Injection",
            body="SQL injection vulnerability found in /login endpoint using sqlmap",
        )

        results = store.query(engagement_id=eid, query_text="SQL injection")
        assert len(results) > 0
        assert any("sql" in r.get("body", "").lower() or "sql" in r.get("title", "").lower() for r in results)

    def test_irrelevant_query_returns_empty_or_low(self) -> None:
        session = _make_session()
        store = RetrievalStore(session)
        eid = uuid4()

        store.index_finding(
            engagement_id=eid,
            title="Open SSH Port",
            body="Open port 22 SSH detected via nmap",
        )

        results = store.query(engagement_id=eid, query_text="XSS cross-site scripting javascript")
        # May return 0; must not crash
        assert isinstance(results, list)

    def test_empty_query_returns_empty(self) -> None:
        session = _make_session()
        store = RetrievalStore(session)
        eid = uuid4()

        store.index_finding(
            engagement_id=eid,
            title="SMB Enumeration",
            body="SMB enumeration completed via crackmapexec",
        )

        results = store.query(engagement_id=eid, query_text="")
        assert results == []

    def test_multiple_findings_ranked_by_relevance(self) -> None:
        session = _make_session()
        store = RetrievalStore(session)
        eid = uuid4()

        store.index_finding(
            engagement_id=eid,
            title="Remote Code Execution",
            body="Remote code execution via Java deserialization vulnerability confirmed",
        )
        store.index_finding(
            engagement_id=eid,
            title="Open HTTP Port",
            body="Open HTTP port 80 detected during port scan",
        )

        results = store.query(engagement_id=eid, query_text="remote code execution deserialization")
        assert len(results) >= 1
        # First result should be the RCE finding
        top = results[0]
        assert "remote" in top.get("body", "").lower() or "remote" in top.get("title", "").lower()

    def test_engagements_are_isolated(self) -> None:
        session = _make_session()
        store = RetrievalStore(session)
        eid_a = uuid4()
        eid_b = uuid4()

        store.index_finding(
            engagement_id=eid_a,
            title="XSS Vulnerability",
            body="XSS in search parameter query field",
        )

        results_b = store.query(engagement_id=eid_b, query_text="XSS")
        assert results_b == [], "Engagement B must not see engagement A's findings"

    def test_playbook_indexing_and_retrieval(self) -> None:
        session = _make_session()
        store = RetrievalStore(session)
        eid = uuid4()

        store.index_playbook(
            engagement_id=eid,
            title="SQLmap Deep Scan",
            body="Use sqlmap with --level=5 --risk=3 for thorough SQL injection testing",
        )

        results = store.query(engagement_id=eid, query_text="sqlmap SQL injection")
        assert len(results) > 0
        assert any("sqlmap" in r.get("body", "").lower() for r in results)
