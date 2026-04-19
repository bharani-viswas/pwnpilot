"""
RAG Retriever — dual-mode retrieval abstraction over RetrievalStore + ATT&CK knowledge.

Retrieval modes:
- ``lexical``  (default): TF-IDF BM25-like over the in-session RetrievalStore
  findings + ATT&CK technique keyword matching.
- ``embedding``: Cosine similarity over vectors produced by EmbeddingRouter.
  Gated behind ``rag.mode = embedding|hybrid`` config flag.
- ``hybrid``: Merges lexical and embedding results, de-duplicates, re-ranks
  by combined score.

Return schema (every result has these keys):
    technique_id    str | None   — ATT&CK technique ID if sourced from ATT&CK KB
    tactic          str          — primary tactic or "engagement_history"
    name            str          — technique name or finding title
    description     str          — truncated body text
    confidence      float        — normalised 0-1 score
    source          str          — "attack_kb" | "engagement_history"
    rationale_excerpt str        — first 200 chars of description

Error policy: any retrieval failure returns an empty list and logs at DEBUG —
never propagates exceptions to callers.
"""
from __future__ import annotations

import math
from typing import Any
from uuid import UUID

import structlog

from pwnpilot.control.attack_knowledge import AttackKnowledgeBase, load_attack_knowledge
from pwnpilot.data.retrieval_store import RetrievalStore

log = structlog.get_logger(__name__)

_MAX_COMBINED_RESULTS = 20
_EMBEDDING_BATCH_SIZE = 64


def _norm_score(scores: list[float]) -> list[float]:
    """Min-max normalise a list of scores to [0, 1]."""
    if not scores:
        return scores
    lo, hi = min(scores), max(scores)
    if hi == lo:
        return [1.0 for _ in scores]
    return [(s - lo) / (hi - lo) for s in scores]


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


class RagRetriever:
    """
    Unified retrieval interface for the planner.

    Parameters
    ----------
    retrieval_store:
        Per-engagement TF-IDF store (may be None — treated as empty).
    attack_kb:
        Loaded ATT&CK knowledge base (pre-built index).  If None, ATT&CK
        results are skipped.
    embedding_router:
        Optional EmbeddingRouter instance.  Required for ``embedding`` /
        ``hybrid`` modes; if absent those modes fall back to ``lexical``.
    mode:
        "lexical" | "embedding" | "hybrid"
    top_k:
        Maximum results to return per source before merging.
    min_confidence:
        Minimum normalised confidence to include in results.
    enable_internal_history:
        When True, also searches the per-engagement RetrievalStore for
        relevant past findings.
    """

    def __init__(
        self,
        retrieval_store: RetrievalStore | None = None,
        attack_kb: AttackKnowledgeBase | None = None,
        embedding_router: Any | None = None,
        mode: str = "lexical",
        top_k: int = 5,
        min_confidence: float = 0.01,
        enable_internal_history: bool = True,
    ) -> None:
        self._retrieval_store = retrieval_store
        self._attack_kb = attack_kb
        self._embedding_router = embedding_router
        self._mode = mode.lower() if mode else "lexical"
        self._top_k = max(1, int(top_k))
        self._min_confidence = float(min_confidence)
        self._enable_internal_history = enable_internal_history

        # Degrade to lexical if embedding router is unavailable
        if self._mode in {"embedding", "hybrid"} and self._embedding_router is None:
            log.warning(
                "rag_retriever.embedding_mode_degraded",
                reason="no embedding_router provided",
                fallback="lexical",
            )
            self._mode = "lexical"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def retrieve(
        self,
        query_text: str,
        engagement_id: UUID | None = None,
        tactic_filter: list[str] | None = None,
        platform_filter: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return enriched retrieval results for *query_text*.

        Always returns a list (empty on error).  Each element conforms to the
        standard RAG result schema documented in the module docstring.
        """
        try:
            return self._retrieve_inner(
                query_text=query_text,
                engagement_id=engagement_id,
                tactic_filter=tactic_filter,
                platform_filter=platform_filter,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("rag_retriever.error", query=query_text[:100], exc=str(exc))
            return []

    # ------------------------------------------------------------------
    # Internal retrieval paths
    # ------------------------------------------------------------------

    def _retrieve_inner(
        self,
        query_text: str,
        engagement_id: UUID | None,
        tactic_filter: list[str] | None,
        platform_filter: list[str] | None,
    ) -> list[dict[str, Any]]:
        if self._mode == "lexical":
            return self._merge(
                self._lexical_attack_results(query_text, tactic_filter, platform_filter),
                self._lexical_history_results(query_text, engagement_id),
            )
        if self._mode == "embedding":
            return self._merge(
                self._embedding_attack_results(query_text, tactic_filter, platform_filter),
                self._embedding_history_results(query_text, engagement_id),
            )
        # hybrid
        lexical = self._merge(
            self._lexical_attack_results(query_text, tactic_filter, platform_filter),
            self._lexical_history_results(query_text, engagement_id),
        )
        embedding = self._merge(
            self._embedding_attack_results(query_text, tactic_filter, platform_filter),
            self._embedding_history_results(query_text, engagement_id),
        )
        return self._hybrid_merge(lexical, embedding)

    # ---- lexical ----

    def _lexical_attack_results(
        self,
        query_text: str,
        tactic_filter: list[str] | None,
        platform_filter: list[str] | None,
    ) -> list[dict[str, Any]]:
        if self._attack_kb is None:
            return []
        raw = self._attack_kb.query(
            query_text,
            top_k=self._top_k,
            min_score=self._min_confidence,
            tactic_filter=tactic_filter,
            platform_filter=platform_filter,
        )
        return [_attack_result_to_rag(r) for r in raw]

    def _lexical_history_results(
        self,
        query_text: str,
        engagement_id: UUID | None,
    ) -> list[dict[str, Any]]:
        if not self._enable_internal_history or self._retrieval_store is None or engagement_id is None:
            return []
        try:
            rows = self._retrieval_store.query(engagement_id, query_text=query_text, top_k=self._top_k)
            return [_history_result_to_rag(r) for r in (rows or [])]
        except Exception as exc:
            log.debug("rag_retriever.history_query_error", exc=str(exc))
            return []

    # ---- embedding ----

    def _embedding_attack_results(
        self,
        query_text: str,
        tactic_filter: list[str] | None,
        platform_filter: list[str] | None,
    ) -> list[dict[str, Any]]:
        if self._attack_kb is None or self._embedding_router is None:
            return []
        try:
            q_vec = self._embedding_router.embed(query_text)
        except Exception as exc:
            log.debug("rag_retriever.query_embed_error", exc=str(exc))
            return self._lexical_attack_results(query_text, tactic_filter, platform_filter)

        # Embed all technique combined texts in batches, score by cosine
        tech_ids = list(self._attack_kb.techniques.keys())
        if not tech_ids:
            return []

        techs = self._attack_kb.techniques
        texts = [
            f"{techs[tid].name} {techs[tid].description[:300]}"
            for tid in tech_ids
        ]

        try:
            vecs = self._embedding_router.embed_many(texts[:_EMBEDDING_BATCH_SIZE])
        except Exception as exc:
            log.debug("rag_retriever.bulk_embed_error", exc=str(exc))
            return self._lexical_attack_results(query_text, tactic_filter, platform_filter)

        scored = []
        for i, vec in enumerate(vecs):
            if i >= len(tech_ids):
                break
            tid = tech_ids[i]
            tech = techs[tid]
            if tactic_filter and not any(t in tech.tactics for t in tactic_filter):
                continue
            if platform_filter and not any(p.lower() in [pl.lower() for pl in tech.platforms] for p in platform_filter):
                continue
            score = _cosine(q_vec, vec)
            if score >= self._min_confidence:
                scored.append((tid, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        results = []
        for tid, score in scored[: self._top_k]:
            tech = techs[tid]
            results.append({
                "technique_id": tech.technique_id,
                "tactic": tech.tactic,
                "name": tech.name,
                "description": tech.description[:500],
                "confidence": round(min(score, 1.0), 4),
                "source": "attack_kb",
                "rationale_excerpt": tech.description[:200],
            })
        return results

    def _embedding_history_results(
        self,
        query_text: str,
        engagement_id: UUID | None,
    ) -> list[dict[str, Any]]:
        # Embedding over session history not yet implemented — fall back to lexical.
        return self._lexical_history_results(query_text, engagement_id)

    # ---- merge helpers ----

    def _merge(
        self,
        attack_results: list[dict[str, Any]],
        history_results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        combined = attack_results + history_results
        # Normalise confidence across combined set
        scores = [r.get("confidence", 0.0) for r in combined]
        normed = _norm_score(scores)
        for r, s in zip(combined, normed):
            r["confidence"] = round(s, 4)
        # Filter by min_confidence (post-normalisation), take top_k
        filtered = [r for r in combined if r["confidence"] >= self._min_confidence]
        filtered.sort(key=lambda x: x.get("confidence", 0.0), reverse=True)
        return filtered[: self._top_k]

    def _hybrid_merge(
        self,
        lexical: list[dict[str, Any]],
        embedding: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """RRF (Reciprocal Rank Fusion) merge of lexical + embedding ranked lists."""
        k_rrf = 60
        scores: dict[str, float] = {}
        key_to_result: dict[str, dict[str, Any]] = {}

        for rank, r in enumerate(lexical):
            uid = _result_uid(r)
            scores[uid] = scores.get(uid, 0.0) + 1.0 / (k_rrf + rank + 1)
            key_to_result[uid] = r

        for rank, r in enumerate(embedding):
            uid = _result_uid(r)
            scores[uid] = scores.get(uid, 0.0) + 1.0 / (k_rrf + rank + 1)
            key_to_result.setdefault(uid, r)

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)[: self._top_k]
        normed = _norm_score([s for _, s in ranked])
        return [
            {**key_to_result[uid], "confidence": round(n, 4)}
            for (uid, _), n in zip(ranked, normed)
        ]


# ---------------------------------------------------------------------------
# Result normalisation helpers
# ---------------------------------------------------------------------------


def _attack_result_to_rag(r: dict[str, Any]) -> dict[str, Any]:
    desc = str(r.get("description", ""))
    return {
        "technique_id": r.get("technique_id"),
        "tactic": r.get("tactic", "unknown"),
        "name": r.get("name", ""),
        "description": desc[:500],
        "confidence": round(float(r.get("score", 0.0)), 4),
        "source": "attack_kb",
        "rationale_excerpt": desc[:200],
    }


def _history_result_to_rag(r: Any) -> dict[str, Any]:
    if isinstance(r, dict):
        title = str(r.get("title", r.get("name", "")))
        body = str(r.get("body", r.get("description", "")))
        score = float(r.get("score", r.get("confidence", 0.0)))
    else:
        title = str(getattr(r, "title", ""))
        body = str(getattr(r, "body", ""))
        score = float(getattr(r, "score", 0.0))
    return {
        "technique_id": None,
        "tactic": "engagement_history",
        "name": title,
        "description": body[:500],
        "confidence": round(score, 4),
        "source": "engagement_history",
        "rationale_excerpt": body[:200],
    }


def _result_uid(r: dict[str, Any]) -> str:
    tid = r.get("technique_id") or ""
    name = r.get("name", "")
    source = r.get("source", "")
    return f"{source}:{tid}:{name}"


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------


def build_rag_retriever(
    rag_cfg: Any,
    retrieval_store: RetrievalStore | None = None,
    embedding_router: Any | None = None,
) -> RagRetriever:
    """
    Instantiate a RagRetriever from a RAGConfig instance.

    ``rag_cfg`` is expected to have: enabled, mode, top_k, min_confidence,
    attack_stix_path, enable_internal_history.
    Returns a no-op retriever (empty results, no side effects) when
    ``rag_cfg.enabled`` is False.
    """
    enabled = bool(getattr(rag_cfg, "enabled", True))
    if not enabled:
        return RagRetriever()  # empty — all retrieval methods return []

    stix_path = getattr(rag_cfg, "attack_stix_path", None) or None
    attack_kb = load_attack_knowledge(stix_path)

    return RagRetriever(
        retrieval_store=retrieval_store,
        attack_kb=attack_kb,
        embedding_router=embedding_router,
        mode=str(getattr(rag_cfg, "mode", "lexical")),
        top_k=int(getattr(rag_cfg, "top_k", 5)),
        min_confidence=float(getattr(rag_cfg, "min_confidence", 0.01)),
        enable_internal_history=bool(getattr(rag_cfg, "enable_internal_history", True)),
    )
