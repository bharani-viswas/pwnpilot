"""Unit tests for centralized logging configuration and runtime integration."""
from __future__ import annotations

import logging
from pathlib import Path

from pwnpilot.observability.logging_setup import _should_use_console_colors, configure_logging


def test_configure_logging_writes_rotating_file(tmp_path: Path) -> None:
    """Configuring file logging should create file and write structured events."""
    log_file = tmp_path / "pwnpilot.log"

    configure_logging(level="INFO", log_file=str(log_file), rotation_days=7)

    logger = logging.getLogger("pwnpilot.tests.logging")
    logger.info("framework-test-event")

    assert log_file.exists()
    contents = log_file.read_text(encoding="utf-8")
    assert "framework-test-event" in contents


def test_should_use_console_colors_when_stdout_is_tty(monkeypatch) -> None:
    """Color output should be enabled when stdout is an interactive TTY."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("CLICOLOR_FORCE", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")

    class _TTY:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("pwnpilot.observability.logging_setup.sys.stdout", _TTY())
    assert _should_use_console_colors() is True


def test_should_use_console_colors_respects_no_color(monkeypatch) -> None:
    """NO_COLOR must disable colors even on a TTY."""
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("CLICOLOR_FORCE", raising=False)

    class _TTY:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("pwnpilot.observability.logging_setup.sys.stdout", _TTY())
    assert _should_use_console_colors() is False


def test_should_use_console_colors_honors_force_color(monkeypatch) -> None:
    """FORCE_COLOR should enable colors even without a TTY."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)

    class _Pipe:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr("pwnpilot.observability.logging_setup.sys.stdout", _Pipe())
    assert _should_use_console_colors() is True
