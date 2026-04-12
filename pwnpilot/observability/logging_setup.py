"""Centralized structured logging setup for the pwnpilot runtime.

This module wires stdlib logging + structlog with JSON output and optional
rotating file handlers. It is safe to call multiple times; existing handlers
are replaced on reconfiguration.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Any

import structlog


def _safe_level(level: str | None) -> int:
    raw = (level or "INFO").upper()
    return getattr(logging, raw, logging.INFO)


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _prepare_log_file(path: str) -> str:
    expanded = str(Path(path).expanduser())
    parent = Path(expanded).parent
    parent.mkdir(parents=True, exist_ok=True)
    return expanded


def configure_logging(
    level: str = "INFO",
    log_file: str = "",
    rotation_days: int = 30,
    stdout_format: str = "console",
    service: str = "pwnpilot",
) -> None:
    """Configure structured logging for the entire process.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path. Empty means stdout only.
        rotation_days: Number of rotated files to retain (daily rotation).
        stdout_format: stdout renderer format, "console" (human-readable) or "json".
        service: Service name bound on each log event.
    """
    log_level = _safe_level(level)
    keep_days = max(1, _coerce_int(rotation_days, 30))

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    stdout_renderer = (
        structlog.processors.JSONRenderer(sort_keys=True)
        if str(stdout_format).lower() == "json"
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    stdout_formatter = structlog.stdlib.ProcessorFormatter(
        processor=stdout_renderer,
        foreign_pre_chain=shared_processors,
    )

    file_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(sort_keys=True),
        foreign_pre_chain=shared_processors,
    )

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(log_level)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(stdout_formatter)
    root.addHandler(stream_handler)

    if log_file:
        resolved_file = _prepare_log_file(log_file)
        file_handler = logging.handlers.TimedRotatingFileHandler(
            filename=resolved_file,
            when="D",
            interval=1,
            backupCount=keep_days,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(file_formatter)
        root.addHandler(file_handler)

    logging.captureWarnings(True)

    # Suppress verbose third-party library logs to reduce noise
    # These libraries are too chatty at INFO level
    noisy_loggers = [
        "LiteLLM",
        "litellm",
        "urllib3",
        "httpx",
        "langchain",
        "langgraph",
        "httpcore",
        "anyio",
    ]
    for logger_name in noisy_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    structlog.get_logger(__name__).info(
        "logging.configured",
        service=service,
        level=logging.getLevelName(log_level),
        log_file=log_file or "stdout",
        stdout_format=("json" if str(stdout_format).lower() == "json" else "console"),
        rotation_days=keep_days,
        pid=os.getpid(),
    )


def configure_logging_from_config(logging_cfg: Any | None) -> None:
    """Configure logging from a config object with level/file/rotation_days."""
    if logging_cfg is None:
        configure_logging()
        return

    configure_logging(
        level=str(getattr(logging_cfg, "level", "INFO")),
        log_file=str(getattr(logging_cfg, "file", "") or ""),
        rotation_days=_coerce_int(getattr(logging_cfg, "rotation_days", 30), 30),
        stdout_format=str(getattr(logging_cfg, "stdout_format", "console")),
        service="pwnpilot",
    )
