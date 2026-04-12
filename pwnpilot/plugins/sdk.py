"""
Plugin SDK — contract every tool adapter must satisfy.

Every adapter must:
1. Provide a PluginManifest (name, version, risk_class, input_schema, output_schema,
   checksum_sha256, signature_b64).
2. Subclass BaseAdapter and implement build_command() returning list[str].
3. Pass checksum and signature verification at load time (plugins/trust.py).

ADR-002: build_command() must return list[str].  String interpolation from LLM output
         is forbidden.
ADR-006: Adapter manifest includes checksum_sha256; verified at load time.
ADR-007: runner.py raises ValueError if build_command() returns a string.
"""
from __future__ import annotations

import hashlib
import importlib
import inspect
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

import structlog

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Plugin manifest
# ---------------------------------------------------------------------------


class PluginManifest(BaseModel):
    name: str
    version: str
    risk_class: str  # recon_passive | active_scan | exploit | post_exploit
    description: str = ""
    input_schema: dict[str, Any] = {}
    output_schema: dict[str, Any] = {}
    checksum_sha256: str = ""
    signature_b64: str = ""
    schema_version: str = "v1"


# ---------------------------------------------------------------------------
# Tool params / output types
# ---------------------------------------------------------------------------


class ToolParams(BaseModel):
    """Validated, typed parameters for a single tool invocation."""
    target: str
    extra: dict[str, Any] = {}


class ParsedOutput(BaseModel):
    """Structured output returned by an adapter's parse() method."""
    hosts: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    execution_hints: list[dict[str, Any]] = []
    raw_summary: str = ""
    new_findings_count: int = 0
    confidence: float = 0.5
    parser_error: str | None = None


# ---------------------------------------------------------------------------
# Base adapter
# ---------------------------------------------------------------------------


class BaseAdapter(ABC):
    """Abstract base class for all tool adapters."""

    @property
    @abstractmethod
    def manifest(self) -> PluginManifest: ...

    @abstractmethod
    def validate_params(self, params: dict[str, Any]) -> ToolParams:
        """Validate and return typed ToolParams.  Raise ValueError on invalid input."""
        ...

    @abstractmethod
    def build_command(self, params: ToolParams) -> list[str]:
        """
        Return the subprocess argument list for this tool invocation.

        MUST return list[str].  MUST NOT interpolate any LLM-derived strings without
        explicit allow-listing.  ADR-002 / ADR-007.
        """
        ...

    @abstractmethod
    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        """Parse raw tool output into a structured ParsedOutput."""
        ...
