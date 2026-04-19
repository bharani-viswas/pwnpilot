"""
Policy Engine — deny-by-default action gate with per-engagement rate limiting.

Action classes and default gates:
  recon_passive  → allow   (soft rate limit: 60/min per engagement — warns, never blocks)
  active_scan    → allow   (hard token-bucket: 10/min per engagement — blocks on breach)
  exploit        → requires_approval
  post_exploit   → requires_approval
  data_exfil     → deny
  <unknown>      → deny

ADR-001: Deny-by-default; unknown action class is blocked.
ADR-014: Rate-limit storage is SQLite-backed for resume persistence.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final
from uuid import UUID

import structlog

from pwnpilot.control.engagement import EngagementService, ScopeViolationError
from pwnpilot.data.models import (
    ActionRequest,
    ActionType,
    GateType,
    PolicyDecision,
    PolicyVerdict,
)

if TYPE_CHECKING:
    from pwnpilot.data.rate_limit_store import RateLimitStore

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Rate-limit configuration
# ---------------------------------------------------------------------------

_SOFT_RATE_LIMIT: Final[int] = 60   # recon_passive: warns above this
_HARD_RATE_LIMIT: Final[int] = 10   # active_scan: blocks above this
_WINDOW_SECONDS: Final[int] = 60


@dataclass
class _TokenBucket:
    """Simple sliding-window token counter (thread-safe)."""

    capacity: int
    window: int = _WINDOW_SECONDS
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _timestamps: list[float] = field(default_factory=list, init=False, repr=False)

    def try_consume(self) -> bool:
        """Return True (allowed) or False (rate limit exceeded)."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            self._timestamps = [t for t in self._timestamps if t > cutoff]
            if len(self._timestamps) >= self.capacity:
                return False
            self._timestamps.append(now)
            return True

    def peek_count(self) -> int:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            return sum(1 for t in self._timestamps if t > cutoff)


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Evaluates every ActionRequest and returns a PolicyDecision.

    The engine is the single authoritative gate between agent proposals and tool
    execution.  It must be called for every action before execution begins.
    """

    def __init__(
        self,
        engagement_service: EngagementService,
        rate_limit_store: RateLimitStore | None = None,
    ) -> None:
        self._engagement_svc = engagement_service
        self._rate_limit_store = rate_limit_store
        # Per-engagement rate limiters keyed by (engagement_id, action_class) — fallback in-memory
        self._hard_buckets: dict[str, _TokenBucket] = defaultdict(
            lambda: _TokenBucket(capacity=_HARD_RATE_LIMIT)
        )
        self._soft_counts: dict[str, int] = defaultdict(int)
        self._soft_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, action: ActionRequest) -> PolicyDecision:
        """
        Evaluate the action against engagement scope, action class gates, and rate
        limits.  Returns a PolicyDecision.  Never raises.
        """
        eng_id = str(action.engagement_id)

        # 1. Scope check
        try:
            target = action.params.get("target", "")
            if target:
                self._engagement_svc.require_in_scope(target)
        except ScopeViolationError as exc:
            log.warning("policy.scope_violation", action_id=str(action.action_id),
                        target=target)
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                reason=str(exc),
                gate_type=GateType.SCOPE_VIOLATION,
                action_id=action.action_id,
            )

        # 2. Engagement validity check (calls assert_valid internally)
        try:
            self._engagement_svc.assert_valid()
        except Exception as exc:
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                reason=str(exc),
                gate_type=GateType.DENY,
                action_id=action.action_id,
            )

        # 3. Action class gate
        decision = self._evaluate_action_class(action, eng_id)

        log.info(
            "policy.decision",
            action_id=str(action.action_id),
            action_type=action.action_type,
            verdict=decision.verdict,
            reason=decision.reason,
        )
        return decision

    def reset_engagement(self, engagement_id: UUID | str) -> None:
        """
        Clear rate-limit counters for a completed engagement.
        
        Called when an engagement finishes to prevent in-memory counter leaks
        across engagements in the same process.
        """
        eng_id = str(engagement_id)
        
        # Clear in-memory buckets
        keys_to_delete = [k for k in self._hard_buckets.keys() if k.startswith(f"{eng_id}:")]
        for key in keys_to_delete:
            del self._hard_buckets[key]
        
        # Clear in-memory soft counts
        with self._soft_lock:
            soft_keys_to_delete = [k for k in self._soft_counts.keys() if k.startswith(f"{eng_id}:")]
            for key in soft_keys_to_delete:
                del self._soft_counts[key]
        
        # Clear from persistent store
        if self._rate_limit_store:
            self._rate_limit_store.reset_engagement(engagement_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_action_class(
        self, action: ActionRequest, eng_id: str
    ) -> PolicyDecision:
        atype = action.action_type

        if atype == ActionType.DATA_EXFIL:
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                reason="data_exfil actions are unconditionally denied.",
                gate_type=GateType.DENY,
                action_id=action.action_id,
            )

        if atype in (ActionType.EXPLOIT, ActionType.POST_EXPLOIT):
            return PolicyDecision(
                verdict=PolicyVerdict.REQUIRES_APPROVAL,
                reason=f"{atype.value} actions require operator approval.",
                gate_type=GateType.REQUIRES_APPROVAL,
                action_id=action.action_id,
            )

        if atype == ActionType.ACTIVE_SCAN:
            bucket_key = f"{eng_id}:active_scan"
            
            # Try persistent store first, fall back to in-memory
            if self._rate_limit_store:
                count = self._rate_limit_store.count_recent(eng_id, "active_scan")
                if count >= _HARD_RATE_LIMIT:
                    log.warning(
                        "policy.rate_limit_exceeded",
                        action_type=atype,
                        engagement_id=eng_id,
                        limit=_HARD_RATE_LIMIT,
                        source="persistent_store",
                    )
                    return PolicyDecision(
                        verdict=PolicyVerdict.DENY,
                        reason=(
                            f"RATE_LIMIT_EXCEEDED: active_scan limit of "
                            f"{_HARD_RATE_LIMIT}/min exceeded."
                        ),
                        gate_type=GateType.RATE_LIMIT,
                        action_id=action.action_id,
                    )
                self._rate_limit_store.record_action(eng_id, "active_scan")
            else:
                # Fallback: use in-memory bucket
                if not self._hard_buckets[bucket_key].try_consume():
                    log.warning(
                        "policy.rate_limit_exceeded",
                        action_type=atype,
                        engagement_id=eng_id,
                        limit=_HARD_RATE_LIMIT,
                        source="in_memory",
                    )
                    return PolicyDecision(
                        verdict=PolicyVerdict.DENY,
                        reason=(
                            f"RATE_LIMIT_EXCEEDED: active_scan limit of "
                            f"{_HARD_RATE_LIMIT}/min exceeded."
                        ),
                        gate_type=GateType.RATE_LIMIT,
                        action_id=action.action_id,
                    )
            
            return PolicyDecision(
                verdict=PolicyVerdict.ALLOW,
                reason="active_scan allowed within rate limit.",
                gate_type=GateType.ALLOW,
                action_id=action.action_id,
            )

        if atype == ActionType.RECON_PASSIVE:
            soft_key = f"{eng_id}:recon_passive"
            
            # Soft rate limit — use persistent store if available
            if self._rate_limit_store:
                count = self._rate_limit_store.count_recent(eng_id, "recon_passive")
                if count > _SOFT_RATE_LIMIT:
                    log.warning(
                        "policy.soft_rate_limit_breach",
                        action_type=atype,
                        count=count,
                        limit=_SOFT_RATE_LIMIT,
                        source="persistent_store",
                    )
                self._rate_limit_store.record_action(eng_id, "recon_passive")
            else:
                # Fallback: use in-memory
                with self._soft_lock:
                    self._soft_counts[soft_key] += 1
                    count = self._soft_counts[soft_key]
                if count > _SOFT_RATE_LIMIT:
                    log.warning(
                        "policy.soft_rate_limit_breach",
                        action_type=atype,
                        count=count,
                        limit=_SOFT_RATE_LIMIT,
                        source="in_memory",
                    )
            
            return PolicyDecision(
                verdict=PolicyVerdict.ALLOW,
                reason="recon_passive allowed.",
                gate_type=GateType.ALLOW,
                action_id=action.action_id,
            )

        # Unknown action class — deny by default (ADR-001)
        log.warning("policy.unknown_action_class", action_type=atype)
        return PolicyDecision(
            verdict=PolicyVerdict.DENY,
            reason=f"Unknown action class '{atype}' is denied by default.",
            gate_type=GateType.DENY,
            action_id=action.action_id,
        )
