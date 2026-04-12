"""Plugin trust policy decisions for first-party and third-party plugins."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TrustDecision:
    allowed: bool
    status: str
    reason: str


class PluginTrustPolicy:
    """
    Trust policy modes:
    - first_party_only: load first-party plugins, reject third-party.
    - allow_trusted_third_party: allow first-party plus third-party that pass signature checks.
    - strict_signed_all: require valid signature checks for all plugins.
    """

    def __init__(
        self,
        mode: str = "first_party_only",
        allow_unsigned_first_party: bool = True,
    ) -> None:
        self.mode = mode
        self.allow_unsigned_first_party = allow_unsigned_first_party

    def decide(self, source: str, verification_ok: bool, verification_error: str) -> TrustDecision:
        if self.mode == "strict_signed_all":
            if verification_ok:
                return TrustDecision(True, "trusted", "signature and checksum verified")
            return TrustDecision(False, "rejected", verification_error or "verification failed")

        if self.mode == "first_party_only":
            if source != "first_party":
                return TrustDecision(False, "rejected", "third-party plugins disabled by trust policy")
            if verification_ok:
                return TrustDecision(True, "trusted", "first-party signature and checksum verified")
            if self.allow_unsigned_first_party:
                return TrustDecision(True, "trusted_with_exception", verification_error or "unsigned first-party plugin allowed by policy")
            return TrustDecision(False, "rejected", verification_error or "unsigned first-party plugin blocked")

        # allow_trusted_third_party
        if verification_ok:
            return TrustDecision(True, "trusted", "signature and checksum verified")
        if source == "first_party" and self.allow_unsigned_first_party:
            return TrustDecision(True, "trusted_with_exception", verification_error or "unsigned first-party plugin allowed by policy")
        return TrustDecision(False, "rejected", verification_error or "verification failed")
