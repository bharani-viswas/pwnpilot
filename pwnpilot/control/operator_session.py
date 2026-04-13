"""
OperatorSessionManager v2 — tracks operator mode, directives, pause state, and messages.

Architecture:
- Stateful in-process manager (per-engagement instance).
- Decoupled from AgentState: state is propagated through event bus and state patches.
- Thread-safe: directive queue is protected by a threading.Lock.
- Integrates with ExecutionEventBus for emitting operator events.

Usage::

    manager = OperatorSessionManager(engagement_id, event_bus)
    manager.set_mode(OperatorMode.GUIDED)
    manager.submit_directive(OperatorDirective(...))

    # In the next planner iteration, read the pending directive:
    directive = manager.consume_pending_directive()
    if directive:
        state["operator_directives"] = directive.model_dump()
"""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog

from pwnpilot.agent.state import OperatorMode
from pwnpilot.data.models import ExecutionEvent, ExecutionEventType, OperatorDirective

log = structlog.get_logger(__name__)


class OperatorSessionManager:
    """
    Per-engagement operator session manager.

    Responsibilities:
    - Tracks current operator mode and directive queue.
    - Emits operator events to the event bus.
    - Provides pause/resume controls for tool family execution.
    """

    def __init__(
        self,
        engagement_id: UUID,
        operator_id: str = "operator",
        event_bus: object | None = None,
    ) -> None:
        self._engagement_id = engagement_id
        self._operator_id = operator_id
        self._event_bus = event_bus
        self._lock = threading.Lock()
        self._mode = OperatorMode.AUTONOMOUS
        self._paused_tool_families: set[str] = set()
        self._directive_queue: deque[OperatorDirective] = deque()
        self._messages: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Mode management
    # ------------------------------------------------------------------

    @property
    def mode(self) -> OperatorMode:
        with self._lock:
            return self._mode

    def set_mode(self, mode: OperatorMode) -> None:
        """Change the current operator mode and emit a mode_changed event."""
        with self._lock:
            old_mode = self._mode
            self._mode = mode

        if old_mode != mode:
            log.info(
                "operator_session.mode_changed",
                engagement_id=str(self._engagement_id),
                old_mode=old_mode.value,
                new_mode=mode.value,
            )
            self._emit(ExecutionEvent(
                engagement_id=self._engagement_id,
                action_id=UUID(int=0),  # no specific action
                event_type=ExecutionEventType.OPERATOR_MODE_CHANGED,
                actor=self._operator_id,
                payload={
                    "old_mode": old_mode.value,
                    "new_mode": mode.value,
                },
            ))

    # ------------------------------------------------------------------
    # Directive management
    # ------------------------------------------------------------------

    def submit_directive(self, directive: OperatorDirective) -> None:
        """
        Submit an operator directive.  It will be consumed by the next planner iteration.
        """
        with self._lock:
            self._directive_queue.append(directive)
            # Update pause state immediately from directive
            if directive.paused_tool_families is not None:
                self._paused_tool_families = set(directive.paused_tool_families)

        log.info(
            "operator_session.directive_submitted",
            engagement_id=str(self._engagement_id),
            directive_id=str(directive.directive_id),
            objective=directive.objective,
        )
        self._emit(ExecutionEvent(
            engagement_id=self._engagement_id,
            action_id=UUID(int=0),
            event_type=ExecutionEventType.OPERATOR_DIRECTIVE_SUBMITTED,
            actor=self._operator_id,
            payload=directive.model_dump(mode="json"),
        ))

    def consume_pending_directive(self) -> OperatorDirective | None:
        """
        Consume the next pending directive (FIFO).
        Returns None if no directives are queued.
        """
        with self._lock:
            if not self._directive_queue:
                return None
            return self._directive_queue.popleft()

    def peek_pending_directives(self) -> list[OperatorDirective]:
        """Return all pending directives without consuming them."""
        with self._lock:
            return list(self._directive_queue)

    def submit_directive_from_dict(
        self,
        objective: str | None = None,
        requested_focus: str | None = None,
        constraints: list[str] | None = None,
        paused_tool_families: list[str] | None = None,
        notes: str | None = None,
    ) -> OperatorDirective:
        """
        Convenience: create and submit a directive from keyword arguments.
        Returns the submitted directive.
        """
        directive = OperatorDirective(
            engagement_id=self._engagement_id,
            operator_id=self._operator_id,
            objective=objective,
            requested_focus=requested_focus,
            constraints=constraints or [],
            paused_tool_families=paused_tool_families or [],
            notes=notes,
        )
        self.submit_directive(directive)
        return directive

    # ------------------------------------------------------------------
    # Pause / resume controls
    # ------------------------------------------------------------------

    def pause_tool_family(self, family: str) -> None:
        with self._lock:
            self._paused_tool_families.add(family)
        self.submit_directive_from_dict(paused_tool_families=list(self._paused_tool_families))

    def resume_tool_family(self, family: str) -> None:
        with self._lock:
            self._paused_tool_families.discard(family)
        self.submit_directive_from_dict(paused_tool_families=list(self._paused_tool_families))

    @property
    def paused_tool_families(self) -> set[str]:
        with self._lock:
            return set(self._paused_tool_families)

    # ------------------------------------------------------------------
    # Operator messages (chat)
    # ------------------------------------------------------------------

    def add_message(self, role: str, content: str) -> dict[str, Any]:
        """Add an operator/agent message to the session log."""
        msg = {
            "role": role,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._messages.append(msg)
        self._emit(ExecutionEvent(
            engagement_id=self._engagement_id,
            action_id=UUID(int=0),
            event_type=ExecutionEventType.OPERATOR_MESSAGE_SENT,
            actor=self._operator_id,
            payload={"role": role, "content": content[:2000]},  # truncate for event payload
        ))
        return msg

    @property
    def messages(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._messages)

    # ------------------------------------------------------------------
    # State projection for AgentState
    # ------------------------------------------------------------------

    def state_patch(self) -> dict[str, Any]:
        """
        Return a dict of AgentState fields that should be updated from this session.
        Consume the next directive and merge into the patch.
        """
        directive = self.consume_pending_directive()
        patch: dict[str, Any] = {
            "operator_mode": self.mode.value,
        }
        if directive:
            # Build operator_directives dict from the directive
            dirs: dict[str, Any] = {}
            if directive.objective:
                dirs["objective"] = directive.objective
            if directive.requested_focus:
                dirs["requested_focus"] = directive.requested_focus
            if directive.constraints:
                dirs["constraints"] = directive.constraints
            if directive.paused_tool_families is not None:
                dirs["paused_tool_families"] = directive.paused_tool_families
            if directive.notes:
                dirs["notes"] = directive.notes
            patch["operator_directives"] = dirs

        messages_snapshot = self.messages
        if messages_snapshot:
            patch["operator_messages"] = messages_snapshot

        return patch

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit(self, event: ExecutionEvent) -> None:
        if self._event_bus is not None:
            try:
                self._event_bus.publish(event)  # type: ignore[attr-defined]
            except Exception as exc:
                log.warning("operator_session.emit_failed", exc=str(exc))
