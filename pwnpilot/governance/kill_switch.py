"""
Kill Switch — thread-safe global halt signal.

Implemented as a threading.Event (ADR-009) so it is safe to set and check from any
thread without a race condition.  SIGTERM and SIGINT both call KillSwitch.trigger().

On trigger:
- threading.Event is set (immediately visible to all polling threads).
- A KillSwitchTriggered audit event is written atomically.
- The tool runner checks is_set() before every subprocess spawn.
- In-flight futures are cancelled; running subprocesses receive SIGTERM then SIGKILL
  after a 5-second drain window.
"""
from __future__ import annotations

import threading
from typing import Callable

import structlog

log = structlog.get_logger(__name__)


class KillSwitch:
    """
    Global halt signal.  Thread-safe via threading.Event.

    Args:
        audit_fn:  Optional callback(reason: str) called atomically on trigger.
                   Typically points to AuditStore.append().
    """

    def __init__(
        self, audit_fn: Callable[[str], None] | None = None
    ) -> None:
        self._event = threading.Event()
        self._reason: str = ""
        self._audit_fn = audit_fn
        self._lock = threading.Lock()

    def trigger(self, reason: str = "manual") -> None:
        """Set the kill switch.  Idempotent — safe to call multiple times."""
        with self._lock:
            if self._event.is_set():
                return
            self._reason = reason
            self._event.set()

        log.warning("kill_switch.triggered", reason=reason)

        if self._audit_fn:
            try:
                self._audit_fn(reason)
            except Exception as exc:
                log.error("kill_switch.audit_write_failed", exc=str(exc))

    def is_set(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout=timeout)

    def clear(self) -> None:
        """Reset the kill switch (used in tests only)."""
        with self._lock:
            self._event.clear()
            self._reason = ""

    @property
    def reason(self) -> str:
        return self._reason
