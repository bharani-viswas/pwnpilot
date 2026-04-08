"""
Observability tracing — structured trace spans for the pwnpilot framework.

Provides lightweight, in-process span recording that requires no external
tracing backend (no OpenTelemetry collector, no Jaeger).  Spans are stored
in memory and can be logged or exported as JSON.

Key concepts:
  - ``Span``: a named, timed unit of work with a parent_id and attributes.
  - ``Tracer``: creates spans and manages the active span stack (thread-local).
  - ``TraceContext``: context-manager helper for automatic span lifecycle.
  - ``tracer``: global singleton imported by other modules.

Usage::

    from pwnpilot.observability.tracing import tracer

    with tracer.span("planner.invoke", engagement_id="abc", iteration=3) as span:
        # ... do work ...
        span.set_attribute("proposed_tool", "nmap")
    # span is automatically finished and recorded

    # Or manually:
    span = tracer.start_span("executor.tool_run", tool="nmap")
    try:
        ... work ...
    finally:
        tracer.finish_span(span)

    # Export all finished spans for an engagement
    spans = tracer.export(engagement_id="abc")
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Span
# ---------------------------------------------------------------------------


@dataclass
class Span:
    """A single trace span."""

    name: str
    span_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_id: str | None = None
    start_time: float = field(default_factory=time.monotonic)
    end_time: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    status: str = "ok"  # ok | error

    @property
    def duration_ms(self) -> float | None:
        if self.end_time is None:
            return None
        return (self.end_time - self.start_time) * 1000.0

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def set_error(self, message: str) -> None:
        self.status = "error"
        self.attributes["error"] = message

    def finish(self) -> None:
        if self.end_time is None:
            self.end_time = time.monotonic()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "attributes": self.attributes,
        }


# ---------------------------------------------------------------------------
# Context manager for a span
# ---------------------------------------------------------------------------


class TraceContext:
    """Context manager that automatically finishes a span."""

    def __init__(self, span: Span, tracer: "Tracer") -> None:
        self._span = span
        self._tracer = tracer

    def __enter__(self) -> Span:
        return self._span

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None:
            self._span.set_error(str(exc_val))
        self._tracer.finish_span(self._span)


# ---------------------------------------------------------------------------
# Tracer
# ---------------------------------------------------------------------------


class Tracer:
    """
    In-process tracer.  Thread-local active span stack for correct parent_id
    linking in multi-threaded execution.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._finished: list[Span] = []
        self._local = threading.local()  # per-thread stack of active spans

    # ------------------------------------------------------------------
    # Span lifecycle
    # ------------------------------------------------------------------

    def start_span(self, name: str, **attributes: Any) -> Span:
        """Create and activate a new span."""
        stack = self._get_stack()
        parent_id = stack[-1].span_id if stack else None
        span = Span(name=name, parent_id=parent_id, attributes=dict(attributes))
        stack.append(span)
        return span

    def finish_span(self, span: Span) -> None:
        """Finish a span, remove it from the active stack, and record it."""
        span.finish()
        stack = self._get_stack()
        # Remove from stack (handle out-of-order finishes gracefully)
        if span in stack:
            stack.remove(span)
        with self._lock:
            self._finished.append(span)

    def span(self, name: str, **attributes: Any) -> TraceContext:
        """Return a context manager that wraps a new span."""
        s = self.start_span(name, **attributes)
        return TraceContext(s, self)

    # ------------------------------------------------------------------
    # Active span access
    # ------------------------------------------------------------------

    def current_span(self) -> Span | None:
        stack = self._get_stack()
        return stack[-1] if stack else None

    def current_span_id(self) -> str | None:
        s = self.current_span()
        return s.span_id if s else None

    # ------------------------------------------------------------------
    # Export / introspection
    # ------------------------------------------------------------------

    def export(self, engagement_id: str | None = None) -> list[dict[str, Any]]:
        """
        Return finished spans as a list of dicts.

        If *engagement_id* is provided, only spans whose ``engagement_id``
        attribute matches are returned.
        """
        with self._lock:
            spans = list(self._finished)
        if engagement_id:
            spans = [
                s for s in spans
                if s.attributes.get("engagement_id") == engagement_id
            ]
        return [s.to_dict() for s in spans]

    def clear(self) -> None:
        """Remove all finished spans (e.g. after export or between tests)."""
        with self._lock:
            self._finished.clear()

    def finished_count(self) -> int:
        with self._lock:
            return len(self._finished)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_stack(self) -> list[Span]:
        if not hasattr(self._local, "stack"):
            self._local.stack = []
        return self._local.stack


#: Global singleton tracer imported by other modules
tracer: Tracer = Tracer()
