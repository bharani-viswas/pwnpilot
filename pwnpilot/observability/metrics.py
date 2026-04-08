"""
Observability metrics module for the pwnpilot framework.

Provides lightweight, in-process metrics collection that does not require
an external metrics backend.  All metrics are process-local and can be
exported to a dict for logging, TUI display, or forwarding to an OpenTelemetry
collector via the ``export()`` method.

Design goals
------------
- Zero external dependencies (no prometheus-client, no opentelemetry required).
- Thread-safe: uses a single ``threading.Lock`` per ``EngagementMetrics`` instance.
- Append-only event log for timing data (approval latency, tool latency).
- Counters for policy events, errors, iteration pace.

Usage::

    from pwnpilot.observability.metrics import EngagementMetrics, metrics_registry

    m = metrics_registry.get_or_create("eid-abc123")
    m.record_policy_deny("exploit_rce")
    m.record_tool_invoked("nmap", duration_ms=412.3)
    print(m.summary())
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Per-Engagement metrics
# ---------------------------------------------------------------------------


@dataclass
class EngagementMetrics:
    """Collects runtime observability data for a single engagement."""

    engagement_id: str

    # --- Counters ---
    _iteration_count: int = field(default=0, init=False, repr=False)
    _policy_deny_count: int = field(default=0, init=False, repr=False)
    _parser_error_count: int = field(default=0, init=False, repr=False)
    _timeout_count: int = field(default=0, init=False, repr=False)
    _approval_count: int = field(default=0, init=False, repr=False)
    _kill_switch_triggers: int = field(default=0, init=False, repr=False)

    # --- Per-tool invocation counts and latencies (ms) ---
    _tool_invocation_counts: dict[str, int] = field(
        default_factory=dict, init=False, repr=False
    )
    _tool_latencies_ms: dict[str, list[float]] = field(
        default_factory=dict, init=False, repr=False
    )

    # --- Approval latencies (ms, from queue to resolution) ---
    _approval_latencies_ms: list[float] = field(
        default_factory=list, init=False, repr=False
    )

    # --- Policy deny breakdown by action type ---
    _policy_deny_by_type: dict[str, int] = field(
        default_factory=dict, init=False, repr=False
    )

    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )
    _start_time: float = field(default_factory=time.monotonic, init=False, repr=False)

    # ------------------------------------------------------------------
    # Record helpers
    # ------------------------------------------------------------------

    def record_iteration(self) -> None:
        with self._lock:
            self._iteration_count += 1

    def record_policy_deny(self, action_type: str = "unknown") -> None:
        with self._lock:
            self._policy_deny_count += 1
            self._policy_deny_by_type[action_type] = (
                self._policy_deny_by_type.get(action_type, 0) + 1
            )

    def record_parser_error(self) -> None:
        with self._lock:
            self._parser_error_count += 1

    def record_timeout(self) -> None:
        with self._lock:
            self._timeout_count += 1

    def record_approval_queued(self) -> float:
        """Call when an approval ticket is created.  Returns a monotonic start time."""
        return time.monotonic()

    def record_approval_resolved(self, queued_at: float) -> None:
        """Call when the approval ticket is resolved.  Pass the value from record_approval_queued."""
        latency = (time.monotonic() - queued_at) * 1000.0
        with self._lock:
            self._approval_count += 1
            self._approval_latencies_ms.append(latency)

    def record_tool_invoked(self, tool_name: str, duration_ms: float = 0.0) -> None:
        with self._lock:
            self._tool_invocation_counts[tool_name] = (
                self._tool_invocation_counts.get(tool_name, 0) + 1
            )
            self._tool_latencies_ms.setdefault(tool_name, []).append(duration_ms)

    def record_kill_switch(self) -> None:
        with self._lock:
            self._kill_switch_triggers += 1

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    @property
    def iteration_count(self) -> int:
        return self._iteration_count

    @property
    def policy_deny_count(self) -> int:
        return self._policy_deny_count

    @property
    def parser_error_count(self) -> int:
        return self._parser_error_count

    @property
    def timeout_count(self) -> int:
        return self._timeout_count

    @property
    def approval_count(self) -> int:
        return self._approval_count

    @property
    def tool_invocation_counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._tool_invocation_counts)

    @property
    def approval_latencies_ms(self) -> list[float]:
        with self._lock:
            return list(self._approval_latencies_ms)

    def _avg_latency(self, latencies: list[float]) -> float | None:
        return sum(latencies) / len(latencies) if latencies else None

    def _p95_latency(self, latencies: list[float]) -> float | None:
        if not latencies:
            return None
        sorted_l = sorted(latencies)
        # Round up so that for n=1 we return that single value,
        # and for n=3 we return the last value (sorted_l[2]).
        idx = min(len(sorted_l) - 1, int(len(sorted_l) * 0.95 + 0.999))
        return sorted_l[idx]

    def summary(self) -> dict[str, Any]:
        """Return a snapshot of all metrics as a plain dict."""
        with self._lock:
            elapsed = time.monotonic() - self._start_time
            tool_stats: dict[str, dict[str, Any]] = {}
            for tool, lats in self._tool_latencies_ms.items():
                tool_stats[tool] = {
                    "invocations": self._tool_invocation_counts.get(tool, 0),
                    "avg_latency_ms": self._avg_latency(lats),
                    "p95_latency_ms": self._p95_latency(lats),
                }
            return {
                "engagement_id": self.engagement_id,
                "elapsed_seconds": round(elapsed, 2),
                "iteration_count": self._iteration_count,
                "policy_deny_count": self._policy_deny_count,
                "policy_deny_by_type": dict(self._policy_deny_by_type),
                "parser_error_count": self._parser_error_count,
                "timeout_count": self._timeout_count,
                "approval_count": self._approval_count,
                "approval_avg_latency_ms": self._avg_latency(self._approval_latencies_ms),
                "approval_p95_latency_ms": self._p95_latency(self._approval_latencies_ms),
                "kill_switch_triggers": self._kill_switch_triggers,
                "tool_stats": tool_stats,
            }

    def export(self) -> dict[str, Any]:
        """Alias for summary() — used by exporters / TUI."""
        return self.summary()


# ---------------------------------------------------------------------------
# Registry — one EngagementMetrics per engagement_id
# ---------------------------------------------------------------------------


class MetricsRegistry:
    """Process-wide registry of per-engagement metrics objects."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[str, EngagementMetrics] = {}

    def get_or_create(self, engagement_id: str) -> EngagementMetrics:
        with self._lock:
            if engagement_id not in self._store:
                self._store[engagement_id] = EngagementMetrics(engagement_id)
            return self._store[engagement_id]

    def get(self, engagement_id: str) -> EngagementMetrics | None:
        with self._lock:
            return self._store.get(engagement_id)

    def all_summaries(self) -> list[dict[str, Any]]:
        with self._lock:
            ids = list(self._store.keys())
        return [self._store[eid].summary() for eid in ids]

    def remove(self, engagement_id: str) -> None:
        with self._lock:
            self._store.pop(engagement_id, None)


#: Global singleton registry imported by other modules
metrics_registry: MetricsRegistry = MetricsRegistry()
