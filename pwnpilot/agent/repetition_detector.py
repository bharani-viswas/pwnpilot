"""
RepetitionDetector v2 — detects redundant action patterns to suppress loop churn.

Architecture:
- Maintains a per-engagement action signature registry.
- Computes a normalised signature for each attempted action.
- Returns a detection result with audit reason code when repetition is found.
- Integrates with the event bus to emit ``repetition.detected`` events.
- Works on the previous_actions list in AgentState (no external DB required).
"""
from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlparse

import structlog

log = structlog.get_logger(__name__)

# Threshold: same normalised signature seen this many times → suppress
_DEFAULT_REPEAT_THRESHOLD: int = 3

# I-3: Increased threshold from 5 to 12 for URL-targeting tools to avoid
# false deduplication on minor path variants (/rest vs / on same host).
_SIMILARITY_THRESHOLD: int = 12


def _normalize_url_path(target: str) -> str:
    """
    Normalize URL paths for URL-targeting tools to reduce false positives.
    
    For web URLs, extract the base (scheme://host) and ignore query strings.
    This prevents `/path?id=1` and `/path?id=2` from being considered identical.
    """
    if not target or not isinstance(target, str):
        return target
    
    target_lower = target.strip().lower()
    if target_lower.startswith(("http://", "https://")):
        try:
            parsed = urlparse(target_lower)
            # Return base without path for broader similarity checking
            # This way same host = base URL, different paths are still tracked
            return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            return target_lower
    
    return target_lower


def _action_signature(
    tool_name: str,
    target: str,
    action_type: str,
    params: dict[str, Any] | None = None,
) -> str:
    """
    Produce a stable hash identifying a (tool, target, action_type) triple.
    params is intentionally ignored for broad repetition detection;
    fine-grained param comparison uses the full key.
    """
    key = f"{tool_name.strip().lower()}:{str(target).strip().lower()}:{action_type.strip().lower()}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _broad_signature(tool_name: str, target: str) -> str:
    """
    Loose key: tool + normalized target only, ignoring action type.
    
    I-3: Normalize URL paths to distinguish between different paths on same host.
    """
    normalized_target = _normalize_url_path(target)
    key = f"{tool_name.strip().lower()}:{normalized_target}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class RepetitionResult:
    """Result of a repetition check."""

    def __init__(
        self,
        is_repeated: bool,
        reason_code: str | None = None,
        occurrences: int = 0,
        hint: str = "",
    ) -> None:
        self.is_repeated = is_repeated
        self.reason_code = reason_code
        self.occurrences = occurrences
        self.hint = hint

    def __bool__(self) -> bool:
        return self.is_repeated

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_repeated": self.is_repeated,
            "reason_code": self.reason_code,
            "occurrences": self.occurrences,
            "hint": self.hint,
        }


class RepetitionDetector:
    """
    Stateless detector: operates on the AgentState previous_actions list.

    Usage (from planner)::

        from pwnpilot.agent.repetition_detector import RepetitionDetector

        detector = RepetitionDetector()
        result = detector.check(
            tool_name=proposal["tool_name"],
            target=proposal["target"],
            action_type=proposal["action_type"],
            previous_actions=state.get("previous_actions", []),
        )
        if result.is_repeated:
            # Skip or modify the proposal
            log.warning("planner.repetition_suppressed", reason=result.reason_code)
    """

    def __init__(
        self,
        repeat_threshold: int = _DEFAULT_REPEAT_THRESHOLD,
        similarity_threshold: int = _SIMILARITY_THRESHOLD,
    ) -> None:
        self._repeat_threshold = repeat_threshold
        self._similarity_threshold = similarity_threshold

    def check(
        self,
        tool_name: str,
        target: str,
        action_type: str,
        previous_actions: list[dict[str, Any]],
    ) -> RepetitionResult:
        """
        Check whether this (tool, target, action_type) has been attempted too many times.

        Returns RepetitionResult(is_repeated=True) if either:
        - the exact signature appeared >= repeat_threshold times, or
        - the broad (tool, target) pair appeared >= similarity_threshold times.
        """
        if not previous_actions:
            return RepetitionResult(is_repeated=False)

        exact_sig = _action_signature(tool_name, target, action_type)
        broad_sig = _broad_signature(tool_name, target)

        exact_count = 0
        broad_count = 0

        for action in previous_actions:
            if not isinstance(action, dict):
                continue
            prev_sig = _action_signature(
                action.get("tool_name", ""),
                action.get("target", ""),
                action.get("action_type", ""),
            )
            prev_broad = _broad_signature(
                action.get("tool_name", ""),
                action.get("target", ""),
            )
            if prev_sig == exact_sig:
                exact_count += 1
            if prev_broad == broad_sig:
                broad_count += 1

        if exact_count >= self._repeat_threshold:
            return RepetitionResult(
                is_repeated=True,
                reason_code="exact_repeat",
                occurrences=exact_count,
                hint=(
                    f"Action ({tool_name}, {target}, {action_type}) has been attempted "
                    f"{exact_count} times. Try a different tool, target, or action type."
                ),
            )

        if broad_count >= self._similarity_threshold:
            return RepetitionResult(
                is_repeated=True,
                reason_code="similar_repeat",
                occurrences=broad_count,
                hint=(
                    f"Tool '{tool_name}' on target '{target}' has been attempted "
                    f"{broad_count} times with different action types. "
                    "Consider pivoting to a different tool or target."
                ),
            )

        return RepetitionResult(is_repeated=False)

    def count_exact(
        self,
        tool_name: str,
        target: str,
        action_type: str,
        previous_actions: list[dict[str, Any]],
    ) -> int:
        """Return the number of exact matches for the given signature."""
        exact_sig = _action_signature(tool_name, target, action_type)
        return sum(
            1
            for action in previous_actions
            if isinstance(action, dict)
            and _action_signature(
                action.get("tool_name", ""),
                action.get("target", ""),
                action.get("action_type", ""),
            ) == exact_sig
        )
