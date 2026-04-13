"""
ExecutionEventBus v2 — single source of live execution truth.

All live events (runner lifecycle, tool output chunks, operator directives,
approval decisions, finalization) are published here and delivered to
registered subscribers.

Architecture:
- Thread-safe pub/sub with a per-engagement fan-out.
- Subscribers receive events synchronously on the publishing thread in the
  order they were registered.  Subscribers must not block; use a queue if
  async consumption is needed.
- The bus also persists every event to the AuditStore when one is wired in.
- Module-level singleton ``event_bus`` is used by runner, executor, CLI, and TUI.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from typing import Callable
from uuid import UUID

import structlog

from pwnpilot.data.models import ExecutionEvent, ExecutionEventType

log = structlog.get_logger(__name__)

# Type alias for subscriber callables
EventHandler = Callable[[ExecutionEvent], None]


class ExecutionEventBus:
    """
    In-process event bus for v2 execution events.

    Usage::

        bus = ExecutionEventBus()

        # Subscribe to all events for an engagement
        bus.subscribe(engagement_id, handler_fn)

        # Subscribe to specific event types
        bus.subscribe(engagement_id, handler_fn, event_types={ExecutionEventType.ACTION_STARTED})

        # Publish
        bus.publish(event)

        # Unsubscribe
        bus.unsubscribe(engagement_id, handler_fn)
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # engagement_id_str → list of (handler, event_type_filter | None)
        self._subscribers: dict[str, list[tuple[EventHandler, frozenset[ExecutionEventType] | None]]] = (
            defaultdict(list)
        )
        # Optional audit persistence backend (set by runtime wiring)
        self._audit_store: object | None = None

    # ------------------------------------------------------------------
    # Wiring
    # ------------------------------------------------------------------

    def set_audit_store(self, audit_store: object) -> None:
        """Wire an AuditStore for automatic event persistence."""
        self._audit_store = audit_store

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    def subscribe(
        self,
        engagement_id: UUID | str,
        handler: EventHandler,
        event_types: set[ExecutionEventType] | None = None,
    ) -> None:
        """
        Register *handler* to receive events for *engagement_id*.

        Args:
            engagement_id: Engagement to subscribe to.
            handler:       Callable receiving ExecutionEvent; must not block.
            event_types:   If provided, only deliver these event types.
        """
        key = str(engagement_id)
        filter_set = frozenset(event_types) if event_types else None
        with self._lock:
            self._subscribers[key].append((handler, filter_set))
        log.debug(
            "event_bus.subscribed",
            engagement_id=key,
            handler=getattr(handler, "__name__", str(handler)),
        )

    def unsubscribe(self, engagement_id: UUID | str, handler: EventHandler) -> None:
        """Remove *handler* from the subscriber list for *engagement_id*."""
        key = str(engagement_id)
        with self._lock:
            self._subscribers[key] = [
                (h, f) for (h, f) in self._subscribers[key] if h is not handler
            ]

    def clear_engagement(self, engagement_id: UUID | str) -> None:
        """Remove all subscribers for a completed engagement."""
        key = str(engagement_id)
        with self._lock:
            self._subscribers.pop(key, None)

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    def publish(self, event: ExecutionEvent) -> None:
        """
        Publish *event* to all matching subscribers and persist to audit store.

        Subscriber exceptions are caught and logged; they do not prevent
        delivery to subsequent subscribers.
        """
        key = str(event.engagement_id)

        # Persist to audit store if wired
        if self._audit_store is not None:
            try:
                self._audit_store.append(  # type: ignore[attr-defined]
                    engagement_id=event.engagement_id,
                    actor=event.actor,
                    event_type=event.event_type.value,
                    payload={
                        "action_id": str(event.action_id),
                        "tool_name": event.tool_name,
                        "command": event.command,
                        **event.payload,
                    },
                )
            except Exception as exc:
                log.error("event_bus.persist_failed", event_type=event.event_type.value, exc=str(exc))

        # Deliver to subscribers
        with self._lock:
            handlers = list(self._subscribers.get(key, []))

        for handler, filter_set in handlers:
            if filter_set is not None and event.event_type not in filter_set:
                continue
            try:
                handler(event)
            except Exception as exc:
                log.error(
                    "event_bus.handler_error",
                    handler=getattr(handler, "__name__", str(handler)),
                    event_type=event.event_type.value,
                    exc=str(exc),
                )

    def publish_many(self, events: list[ExecutionEvent]) -> None:
        """Convenience: publish a sequence of events in order."""
        for event in events:
            self.publish(event)


# ---------------------------------------------------------------------------
# Module-level singleton — import and use directly
# ---------------------------------------------------------------------------

event_bus: ExecutionEventBus = ExecutionEventBus()
