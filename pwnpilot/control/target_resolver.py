"""TargetResolver service: canonical target normalization for all runtime actions."""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel

_HOST_PORT_RE = re.compile(r"^(?P<host>[a-zA-Z0-9_.\-]+):(?P<port>\d{1,5})$")


class ResolvedTarget(BaseModel):
    raw_input: str
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    base_url: str | None = None
    normalized_url: str | None = None
    authority: str | None = None
    target_type: str = "unknown"


class TargetResolver:
    """Canonicalizes raw target strings into a normalized snapshot."""

    def resolve(self, raw_target: str) -> ResolvedTarget:
        raw = str(raw_target or "").strip()
        if not raw:
            return ResolvedTarget(raw_input="", target_type="unknown")

        parsed = urlparse(raw)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            host = parsed.hostname or parsed.netloc
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            authority = f"{host}:{port}" if host else None
            path = parsed.path or ""
            query = f"?{parsed.query}" if parsed.query else ""
            normalized_url = f"{parsed.scheme}://{authority}{path}{query}" if authority else raw
            return ResolvedTarget(
                raw_input=raw,
                scheme=parsed.scheme,
                host=host,
                port=port,
                base_url=f"{parsed.scheme}://{authority}" if authority else None,
                normalized_url=normalized_url,
                authority=authority,
                target_type="url",
            )

        host_port_match = _HOST_PORT_RE.match(raw)
        if host_port_match:
            host = host_port_match.group("host")
            port = int(host_port_match.group("port"))
            authority = f"{host}:{port}"
            return ResolvedTarget(
                raw_input=raw,
                scheme="http",
                host=host,
                port=port,
                base_url=f"http://{authority}",
                normalized_url=f"http://{authority}",
                authority=authority,
                target_type=self._classify_non_url_target(host),
            )

        target_type = self._classify_non_url_target(raw)
        authority = raw
        base_url = None
        normalized_url = raw
        if target_type in {"ip", "domain"}:
            base_url = f"http://{raw}"

        return ResolvedTarget(
            raw_input=raw,
            scheme=None,
            host=raw if target_type in {"ip", "domain"} else None,
            port=None,
            base_url=base_url,
            normalized_url=normalized_url,
            authority=authority,
            target_type=target_type,
        )

    def target_for_tool(self, raw_target: str, supported_target_types: list[str] | None = None) -> str:
        resolved = self.resolve(raw_target)
        supported = {str(v).strip().lower() for v in (supported_target_types or []) if str(v).strip()}
        if not supported:
            return resolved.normalized_url or resolved.raw_input

        if resolved.target_type == "url" and "url" in supported:
            return resolved.normalized_url or resolved.raw_input
        if resolved.target_type in {"ip", "domain", "cidr"} and resolved.target_type in supported:
            return resolved.host or resolved.raw_input

        # Fallback: keep canonical URL form if it exists, otherwise original input.
        return resolved.normalized_url or resolved.raw_input

    @staticmethod
    def _classify_non_url_target(raw: str) -> str:
        if not raw:
            return "unknown"
        if "/" in raw:
            try:
                ipaddress.ip_network(raw, strict=False)
                return "cidr"
            except Exception:
                pass
        try:
            ipaddress.ip_address(raw)
            return "ip"
        except Exception:
            pass
        if re.match(r"^[a-zA-Z0-9.-]+$", raw):
            return "domain"
        return "unknown"


def capability_compatible_target(target: ResolvedTarget, supported_target_types: list[str]) -> bool:
    supported = {str(v).strip().lower() for v in supported_target_types if str(v).strip()}
    if not supported:
        return True
    return target.target_type in supported or "unknown" in supported
