"""Unit tests for centralized logging configuration and runtime integration."""
from __future__ import annotations

import logging
from pathlib import Path

from pwnpilot.observability.logging_setup import configure_logging


def test_configure_logging_writes_rotating_file(tmp_path: Path) -> None:
    """Configuring file logging should create file and write structured events."""
    log_file = tmp_path / "pwnpilot.log"

    configure_logging(level="INFO", log_file=str(log_file), rotation_days=7)

    logger = logging.getLogger("pwnpilot.tests.logging")
    logger.info("framework-test-event")

    assert log_file.exists()
    contents = log_file.read_text(encoding="utf-8")
    assert "framework-test-event" in contents
