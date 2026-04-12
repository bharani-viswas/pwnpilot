"""
Engagement Service — defines and validates the scope of a pentest engagement.

Exposes:
  - EngagementService: loads/validates an engagement and provides is_in_scope()
  - ScopeViolationError: raised when a target is outside the declared scope
  - EngagementExpiredError: raised when the engagement authorisation window has passed
"""
from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import structlog

from pwnpilot.data.models import Engagement, EngagementScope

log = structlog.get_logger(__name__)


class ScopeViolationError(Exception):
    """Raised when a target is outside the declared engagement scope."""


class EngagementExpiredError(Exception):
    """Raised when the engagement authorisation window has expired or not yet started."""


class EngagementAuthorizationError(Exception):
    """Raised when the engagement is missing required authorisation metadata."""


def _normalise_target(target: str) -> str:
    """Strip scheme and path from a target string, returning the bare host/IP/CIDR."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.strip().rstrip("/")


def _is_ip_in_cidrs(ip_str: str, cidrs: list[str]) -> bool:
    """Return True if *ip_str* falls within any of the given CIDR ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if addr in network:
                return True
        except ValueError:
            continue
    return False


def _domain_matches(target: str, scope_domains: list[str]) -> bool:
    """Return True if *target* is equal to or a subdomain of any scope domain."""
    target_lower = target.lower().lstrip(".")
    for domain in scope_domains:
        domain_lower = domain.lower().lstrip(".")
        if target_lower == domain_lower or target_lower.endswith("." + domain_lower):
            return True
    return False


def _url_matches(target: str, scope_urls: list[str]) -> bool:
    """Return True if *target* URL is under any declared scope URL prefix."""
    for prefix in scope_urls:
        if target.startswith(prefix):
            return True
    return False


def _local_aliases(value: str) -> set[str]:
    aliases = {value.lower()}
    if value.lower() in {"localhost", "127.0.0.1", "::1"}:
        aliases.update({"localhost", "127.0.0.1", "::1"})
    return aliases


def _resolve_identities(value: str) -> set[str]:
    identities = _local_aliases(value)
    try:
        infos = socket.getaddrinfo(value, None)
    except OSError:
        return identities

    for info in infos:
        addr = info[4][0]
        identities.add(addr.lower())
        identities.update(_local_aliases(addr))
    return identities


def _scope_url_host_matches(target: str, scope_urls: list[str]) -> bool:
    host = _normalise_target(target)
    host_identities = _resolve_identities(host)
    for scope_url in scope_urls:
        parsed = urlparse(scope_url)
        if not parsed.hostname:
            continue
        if host_identities & _resolve_identities(parsed.hostname):
            return True
    return False


class EngagementService:
    """
    Validates the engagement object and provides scope-checking for every downstream
    component.  Construction fails if the engagement is missing required authorisation
    metadata or has an invalid time window.
    """

    def __init__(self, engagement: Engagement) -> None:
        self._validate_auth(engagement)
        self._engagement = engagement

    # ------------------------------------------------------------------
    # Construction-time validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_auth(engagement: Engagement) -> None:
        if not engagement.roe_document_hash:
            raise EngagementAuthorizationError("ROE document hash is missing.")
        if not engagement.authoriser_identity:
            raise EngagementAuthorizationError("Authoriser identity is missing.")
        if engagement.valid_from >= engagement.valid_until:
            raise EngagementAuthorizationError(
                "valid_from must be strictly before valid_until."
            )

    # ------------------------------------------------------------------
    # Runtime validity check (called by orchestrator on every run)
    # ------------------------------------------------------------------

    def assert_valid(self) -> None:
        """Raise EngagementExpiredError if the engagement window is not current."""
        now = datetime.now(timezone.utc)
        eng = self._engagement
        if now < eng.valid_from:
            raise EngagementExpiredError(
                f"Engagement '{eng.engagement_id}' has not started yet "
                f"(valid_from={eng.valid_from.isoformat()})."
            )
        if now > eng.valid_until:
            raise EngagementExpiredError(
                f"Engagement '{eng.engagement_id}' has expired "
                f"(valid_until={eng.valid_until.isoformat()})."
            )

    # ------------------------------------------------------------------
    # Scope checking
    # ------------------------------------------------------------------

    def is_in_scope(self, target: str) -> bool:
        """
        Return True if *target* (IP, CIDR, domain, or URL) falls within the declared
        engagement scope.  Both IP-based and domain-based checks are performed.
        """
        self.assert_valid()
        scope: EngagementScope = self._engagement.scope

        # URL prefix match first (most specific)
        if scope.scope_urls and _url_matches(target, scope.scope_urls):
            log.debug("scope.in_scope", target=target, match="url")
            return True

        # Normalise bare host for domain / IP checks
        host = _normalise_target(target)

        # Host equivalence with scoped URLs, including localhost/loopback aliases.
        if scope.scope_urls and _scope_url_host_matches(target, scope.scope_urls):
            log.debug("scope.in_scope", target=target, match="url_host_equivalence")
            return True

        # IP or CIDR check
        if scope.scope_cidrs and _is_ip_in_cidrs(host, scope.scope_cidrs):
            log.debug("scope.in_scope", target=target, match="cidr")
            return True

        # Domain check (exact or subdomain)
        if scope.scope_domains and _domain_matches(host, scope.scope_domains):
            log.debug("scope.in_scope", target=target, match="domain")
            return True

        log.warning("scope.out_of_scope", target=target)
        return False

    def require_in_scope(self, target: str) -> None:
        """Raise ScopeViolationError if the target is outside scope."""
        if not self.is_in_scope(target):
            raise ScopeViolationError(
                f"Target '{target}' is outside the declared engagement scope."
            )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def engagement(self) -> Engagement:
        return self._engagement
