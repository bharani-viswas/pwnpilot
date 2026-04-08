"""
Redactor — pattern-based secret scrubber applied to all LLM prompts and logged responses.

Applied on:
- Cloud LLM fallback prompts (before dispatch)
- LLM responses (before logging)

Note (ADR §7.3): The redactor is pattern-only.  Novel secret formats may not be caught.
Vault keys are excluded from LLM context entirely — they never reach the redactor.
"""
from __future__ import annotations

import re
from typing import Any

_REDACT_PLACEHOLDER = "[REDACTED]"

# Ordered list of (name, compiled pattern) tuples
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Private IPv4
    ("private_ipv4", re.compile(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3})\b"
    )),
    # Generic public IPv4
    ("public_ipv4", re.compile(
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    )),
    # Domain names (simple heuristic — 2+ labels)
    ("domain", re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"{1,}(?:com|net|org|io|co|uk|de|fr|internal|local|corp)\b"
    )),
    # Bearer / API tokens
    ("bearer_token", re.compile(
        r"(?i)bearer\s+[A-Za-z0-9\-_\.~\+\/]+=*"
    )),
    # Generic API keys (long hex/base64 strings)
    ("api_key", re.compile(
        r"(?i)(?:api[_\-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*\S+"
    )),
    # AWS access key IDs
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    # AWS secret access keys
    ("aws_secret", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*\S+")),
    # Generic hex strings 32+ chars (SHA hashes, tokens)
    ("hex_token", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
]


class Redactor:
    """
    Scrubs known secret patterns from text strings.

    Usage::

        r = Redactor()
        safe = r.scrub("Target is 192.168.1.5, token=abc123secret")
    """

    def __init__(self, extra_patterns: list[re.Pattern[str]] | None = None) -> None:
        self._patterns = _PATTERNS.copy()
        if extra_patterns:
            for i, pat in enumerate(extra_patterns):
                self._patterns.append((f"custom_{i}", pat))

    def scrub(self, text: str) -> str:
        """Return a copy of *text* with all detected secrets replaced."""
        for _name, pattern in self._patterns:
            text = pattern.sub(_REDACT_PLACEHOLDER, text)
        return text

    def scrub_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively scrub all string values in a dict."""
        result: dict[str, Any] = {}
        for k, v in data.items():
            if isinstance(v, str):
                result[k] = self.scrub(v)
            elif isinstance(v, dict):
                result[k] = self.scrub_dict(v)
            elif isinstance(v, list):
                result[k] = [
                    self.scrub(item) if isinstance(item, str) else item
                    for item in v
                ]
            else:
                result[k] = v
        return result
