"""
RetrievalStore v2 — lightweight semantic retrieval over persisted findings summaries.

Architecture:
- Maintains a per-engagement index of finding/strategy documents.
- Uses simple TF-IDF-style keyword matching (no external vector DB required).
- Documents are compact text representations of findings, services, and playbooks.
- Provides a ``query`` method returning the top-k most relevant documents.
- Designed to be injected into PlannerNode to replace prompt-only prior-state recall.

Usage::

    store = RetrievalStore(session)
    store.index_finding(engagement_id, "nmap port scan", "Host 10.0.0.1 has port 22 open")
    results = store.query(engagement_id, "SSH login vulnerability", top_k=3)
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterator
from uuid import UUID

import structlog
from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Session

log = structlog.get_logger(__name__)

_STOP_WORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for",
    "if", "in", "into", "is", "it", "no", "not", "of", "on", "or",
    "such", "that", "the", "their", "then", "there", "these", "they",
    "this", "to", "was", "will", "with",
})


def _tokenize(text: str) -> list[str]:
    """Lower-case, split on non-alphanumeric, remove stop words."""
    tokens = re.findall(r"[a-zA-Z0-9_\-\.]+", text.lower())
    return [t for t in tokens if t not in _STOP_WORDS and len(t) > 1]


class _Base(DeclarativeBase):
    pass


class RetrievalDocumentRow(_Base):
    __tablename__ = "retrieval_documents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    engagement_id = Column(String(36), nullable=False, index=True)
    doc_id = Column(String(64), nullable=False, unique=True, index=True)
    category = Column(String(64), nullable=False)  # finding | service | playbook | strategy
    title = Column(Text, nullable=False)
    body = Column(Text, nullable=False)
    tokens_json = Column(Text, nullable=False, default="[]")
    created_at = Column(DateTime(timezone=True), nullable=False)
    schema_version = Column(String(16), nullable=False, default="v2")


class RetrievalStore:
    """
    SQLite-backed lightweight retrieval store.

    Thread-safe — all writes go through a single threading.Lock.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._lock = threading.Lock()
        _Base.metadata.create_all(bind=session.get_bind())

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def index_document(
        self,
        engagement_id: UUID,
        category: str,
        title: str,
        body: str,
    ) -> str:
        """
        Index a document for retrieval.  Returns the doc_id.
        If the same title+body already exists (same hash), skips indexing (idempotent).
        """
        content = f"{title} {body}"
        doc_id = hashlib.sha256(
            f"{engagement_id}:{content}".encode()
        ).hexdigest()[:32]

        with self._lock:
            existing = self._session.get(RetrievalDocumentRow, doc_id)
            if existing:
                return doc_id

            tokens = _tokenize(content)
            row = RetrievalDocumentRow(
                engagement_id=str(engagement_id),
                doc_id=doc_id,
                category=category,
                title=title,
                body=body,
                tokens_json=json.dumps(tokens),
                created_at=datetime.now(timezone.utc),
            )
            self._session.add(row)
            self._session.commit()

        log.debug("retrieval.indexed", engagement_id=str(engagement_id), category=category, doc_id=doc_id)
        return doc_id

    def index_finding(
        self,
        engagement_id: UUID,
        title: str,
        body: str,
    ) -> str:
        return self.index_document(engagement_id, "finding", title, body)

    def index_service(
        self,
        engagement_id: UUID,
        title: str,
        body: str,
    ) -> str:
        return self.index_document(engagement_id, "service", title, body)

    def index_playbook(
        self,
        engagement_id: UUID,
        title: str,
        body: str,
    ) -> str:
        return self.index_document(engagement_id, "playbook", title, body)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def query(
        self,
        engagement_id: UUID,
        query_text: str,
        top_k: int = 5,
        categories: list[str] | None = None,
    ) -> list[dict]:
        """
        Return up to *top_k* documents most relevant to *query_text*.

        Uses BM25-like token overlap scoring (no external ML dependency).
        Returns list of dicts with keys: doc_id, category, title, body, score.
        """
        query_tokens = set(_tokenize(query_text))
        if not query_tokens:
            return []

        rows = (
            self._session.query(RetrievalDocumentRow)
            .filter(RetrievalDocumentRow.engagement_id == str(engagement_id))
        )
        if categories:
            rows = rows.filter(RetrievalDocumentRow.category.in_(categories))
        rows = rows.all()

        if not rows:
            return []

        # Compute IDF weights from corpus
        df: dict[str, int] = defaultdict(int)
        doc_tokens: list[list[str]] = []
        for row in rows:
            try:
                tokens = json.loads(row.tokens_json)
            except Exception:
                tokens = _tokenize(f"{row.title} {row.body}")
            doc_tokens.append(tokens)
            for token in set(tokens):
                df[token] += 1

        N = len(rows)
        scored: list[tuple[float, RetrievalDocumentRow]] = []

        for i, row in enumerate(rows):
            tokens = doc_tokens[i]
            if not tokens:
                continue
            tf: dict[str, float] = defaultdict(float)
            for token in tokens:
                tf[token] += 1.0
            doc_len = len(tokens)

            score = 0.0
            for qt in query_tokens:
                if qt not in tf:
                    continue
                idf = math.log((N + 1) / (df[qt] + 1)) + 1.0
                score += (tf[qt] / doc_len) * idf

            if score > 0:
                scored.append((score, row))

        scored.sort(key=lambda x: -x[0])
        return [
            {
                "doc_id": row.doc_id,
                "category": row.category,
                "title": row.title,
                "body": row.body,
                "score": round(score, 4),
            }
            for score, row in scored[:top_k]
        ]

    def documents_for_engagement(
        self,
        engagement_id: UUID,
        category: str | None = None,
    ) -> Iterator[dict]:
        """Yield all documents for an engagement, optionally filtered by category."""
        rows = (
            self._session.query(RetrievalDocumentRow)
            .filter(RetrievalDocumentRow.engagement_id == str(engagement_id))
        )
        if category:
            rows = rows.filter(RetrievalDocumentRow.category == category)
        for row in rows:
            yield {
                "doc_id": row.doc_id,
                "category": row.category,
                "title": row.title,
                "body": row.body,
            }

    def document_count(self, engagement_id: UUID) -> int:
        return (
            self._session.query(RetrievalDocumentRow)
            .filter(RetrievalDocumentRow.engagement_id == str(engagement_id))
            .count()
        )
