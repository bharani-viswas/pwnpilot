"""
ATT&CK Knowledge Base — MITRE ATT&CK STIX 2.1 ingestion and lookup.

Loads the MITRE ATT&CK Enterprise STIX bundle (JSON) from a local path or the
bundled default, normalises each technique/sub-technique into a flat
``AttackTechnique`` record, and exposes fast keyword-based lookup for the
RAG retriever.

Design decisions:
- Pure in-memory index; no DB dependency.  Loaded once at startup and reused.
- Thread-safe read-only after build().
- Graceful degradation: if the STIX file is missing/corrupt, returns an empty
  knowledge base and logs a warning (never crashes the engagement).
- Version pin: records the ATT&CK bundle version and a SHA-256 checksum of
  the loaded file so operators can audit which version was active.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Bundled default STIX path — shipped with pwnpilot for offline operation.
# Operators can override via RAGConfig.attack_stix_path.
# ---------------------------------------------------------------------------
_DEFAULT_STIX_PATH = Path(__file__).parent.parent / "data" / "attack_enterprise_v16.json"

_STOP_WORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for",
    "if", "in", "into", "is", "it", "no", "not", "of", "on", "or",
    "such", "that", "the", "their", "then", "there", "these", "they",
    "this", "to", "was", "will", "with", "used", "using", "can", "may",
    "allows", "via", "through", "which", "where", "when",
})


def _tokenize(text: str) -> list[str]:
    tokens = re.findall(r"[a-zA-Z0-9_\-\.]+", text.lower())
    return [t for t in tokens if t not in _STOP_WORDS and len(t) > 1]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str        # e.g. "T1190" or "T1190.001"
    name: str
    description: str
    tactics: list[str]       # e.g. ["initial-access"]
    platforms: list[str]     # e.g. ["Windows", "Linux", "Network"]
    is_subtechnique: bool
    parent_id: str | None    # populated for sub-techniques
    url: str                 # MITRE ATT&CK URL
    tokens: list[str] = field(compare=False, repr=False)

    @property
    def tactic(self) -> str:
        """Primary tactic (first in list) for backward compat."""
        return self.tactics[0] if self.tactics else "unknown"


@dataclass
class AttackKnowledgeBase:
    """Immutable knowledge base built from a STIX bundle."""

    techniques: dict[str, AttackTechnique]   # keyed by technique_id
    bundle_version: str
    checksum: str
    source_path: str

    # ----- internal TF-IDF index -----
    _idf: dict[str, float] = field(default_factory=dict, init=False, repr=False)
    _built: bool = field(default=False, init=False, repr=False)

    def build_index(self) -> None:
        """Build TF-IDF inverted index over all technique tokens. Called once."""
        if self._built:
            return
        N = len(self.techniques)
        if N == 0:
            self._built = True
            return
        df: dict[str, int] = {}
        for tech in self.techniques.values():
            seen = set(tech.tokens)
            for tok in seen:
                df[tok] = df.get(tok, 0) + 1
        self._idf = {
            tok: math.log((N + 1) / (cnt + 1)) + 1.0
            for tok, cnt in df.items()
        }
        self._built = True

    def query(
        self,
        query_text: str,
        top_k: int = 5,
        min_score: float = 0.01,
        tactic_filter: list[str] | None = None,
        platform_filter: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return top-k most relevant techniques for *query_text*.

        Each result dict has keys:
            technique_id, name, tactic, tactics, description (truncated),
            platforms, is_subtechnique, parent_id, url, score
        """
        if not self._built:
            self.build_index()

        q_tokens = _tokenize(query_text)
        if not q_tokens:
            return []

        scores: dict[str, float] = {}
        for tech_id, tech in self.techniques.items():
            if tactic_filter and not any(t in tech.tactics for t in tactic_filter):
                continue
            if platform_filter and not any(p.lower() in [pl.lower() for pl in tech.platforms] for p in platform_filter):
                continue

            tf_counts: dict[str, int] = {}
            for tok in tech.tokens:
                tf_counts[tok] = tf_counts.get(tok, 0) + 1
            n_tokens = max(len(tech.tokens), 1)

            score = 0.0
            for q_tok in q_tokens:
                tf = tf_counts.get(q_tok, 0) / n_tokens
                idf = self._idf.get(q_tok, 0.0)
                score += tf * idf
            if score >= min_score:
                scores[tech_id] = score

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
        results = []
        for tech_id, score in ranked:
            tech = self.techniques[tech_id]
            results.append({
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactic": tech.tactic,
                "tactics": tech.tactics,
                "description": tech.description[:500],
                "platforms": tech.platforms,
                "is_subtechnique": tech.is_subtechnique,
                "parent_id": tech.parent_id,
                "url": tech.url,
                "score": round(score, 4),
            })
        return results


# ---------------------------------------------------------------------------
# STIX parser
# ---------------------------------------------------------------------------


def _extract_tactics(phase_names: list[dict[str, Any]]) -> list[str]:
    return [
        p.get("phase_name", "").strip()
        for p in phase_names
        if isinstance(p, dict) and p.get("phase_name")
    ]


def _extract_platforms(obj: dict[str, Any]) -> list[str]:
    raw = obj.get("x_mitre_platforms") or []
    return [str(p).strip() for p in raw if str(p).strip()]


def _technique_url(technique_id: str) -> str:
    clean = technique_id.replace(".", "/")
    return f"https://attack.mitre.org/techniques/{clean}/"


def _parse_stix_bundle(raw: dict[str, Any]) -> tuple[dict[str, AttackTechnique], str]:
    """
    Parse a STIX 2.1 bundle dict.

    Returns (techniques_dict, bundle_version).
    """
    bundle_version = "unknown"
    # ATT&CK bundles include a x-mitre-collection object with the version.
    techniques: dict[str, AttackTechnique] = {}

    objects = raw.get("objects", [])
    if not isinstance(objects, list):
        return techniques, bundle_version

    # First pass: extract version from x-mitre-collection
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "x-mitre-collection":
            bundle_version = str(obj.get("x_mitre_version", "unknown"))
            break

    # Second pass: extract attack-pattern objects (techniques / sub-techniques)
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "attack-pattern":
            continue

        # Skip deprecated / revoked entries
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = ""
        for ext_ref in obj.get("external_references", []):
            if isinstance(ext_ref, dict) and ext_ref.get("source_name") == "mitre-attack":
                technique_id = str(ext_ref.get("external_id", "")).strip()
                break
        if not technique_id:
            continue

        name = str(obj.get("name", "")).strip()
        description = str(obj.get("description", "")).strip()
        tactics = _extract_tactics(obj.get("kill_chain_phases", []))
        platforms = _extract_platforms(obj)
        is_subtechnique = bool(obj.get("x_mitre_is_subtechnique", False))
        parent_id = technique_id.split(".")[0] if is_subtechnique and "." in technique_id else None

        combined_text = f"{name} {description} {technique_id} {' '.join(tactics)} {' '.join(platforms)}"
        tokens = _tokenize(combined_text)

        techniques[technique_id] = AttackTechnique(
            technique_id=technique_id,
            name=name,
            description=description,
            tactics=tactics,
            platforms=platforms,
            is_subtechnique=is_subtechnique,
            parent_id=parent_id,
            url=_technique_url(technique_id),
            tokens=tokens,
        )

    return techniques, bundle_version


# ---------------------------------------------------------------------------
# Loader with singleton caching
# ---------------------------------------------------------------------------

_cache_lock = threading.Lock()
_loaded_cache: dict[str, AttackKnowledgeBase] = {}


def load_attack_knowledge(stix_path: str | Path | None = None) -> AttackKnowledgeBase:
    """
    Load and return the ATT&CK knowledge base.

    Results are cached by resolved path — safe to call multiple times.
    Returns an empty knowledge base on any load failure (never raises).
    """
    path = Path(stix_path) if stix_path else _DEFAULT_STIX_PATH
    resolved = str(path.resolve()) if path.exists() else str(path)

    with _cache_lock:
        if resolved in _loaded_cache:
            return _loaded_cache[resolved]

    kb = _load_uncached(path)

    with _cache_lock:
        _loaded_cache[resolved] = kb
    return kb


def _load_uncached(path: Path) -> AttackKnowledgeBase:
    if not path.exists():
        log.warning(
            "attack_knowledge.stix_file_not_found",
            path=str(path),
            hint="Download from https://github.com/mitre/cti and set rag.attack_stix_path",
        )
        return _empty_kb(str(path))

    try:
        raw_bytes = path.read_bytes()
        checksum = hashlib.sha256(raw_bytes).hexdigest()
        raw = json.loads(raw_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        log.error("attack_knowledge.stix_load_error", path=str(path), exc=str(exc))
        return _empty_kb(str(path))

    try:
        techniques, bundle_version = _parse_stix_bundle(raw)
    except Exception as exc:  # noqa: BLE001
        log.error("attack_knowledge.stix_parse_error", path=str(path), exc=str(exc))
        return _empty_kb(str(path))

    kb = AttackKnowledgeBase(
        techniques=techniques,
        bundle_version=bundle_version,
        checksum=checksum,
        source_path=str(path),
    )
    kb.build_index()
    log.info(
        "attack_knowledge.loaded",
        technique_count=len(techniques),
        bundle_version=bundle_version,
        checksum=checksum[:16],
        path=str(path),
    )
    return kb


def _empty_kb(source_path: str) -> AttackKnowledgeBase:
    kb = AttackKnowledgeBase(
        techniques={},
        bundle_version="unknown",
        checksum="",
        source_path=source_path,
    )
    kb.build_index()
    return kb


def clear_cache() -> None:
    """Flush the in-process knowledge base cache (useful in tests)."""
    with _cache_lock:
        _loaded_cache.clear()
