"""
Plugin Trust — checksum and Ed25519 signature verification for adapter manifests.

Trust model:
- First-party adapters are signed with the project Ed25519 private key.
- Third-party adapters must supply their own signing key, which the operator explicitly
  adds to the trust_store/ directory and approves via `pwnpilot plugin trust <name>`.
- An adapter with an unrecognised or invalid signature raises PluginTrustError.

PWNPILOT_DEV_ALLOW_UNSIGNED=1 env var bypasses signature checks for local development.
This is blocked in production mode.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import structlog
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from pwnpilot.plugins.sdk import PluginManifest

log = structlog.get_logger(__name__)

_DEV_BYPASS_ENV = "PWNPILOT_DEV_ALLOW_UNSIGNED"
_TRUST_STORE_DIR = Path(__file__).parent / "trust_store"


class PluginTrustError(Exception):
    """Raised when an adapter fails checksum or signature verification."""


def verify_adapter_file(adapter_path: Path, manifest: PluginManifest) -> None:
    """
    Verify the adapter source file checksum and manifest signature.
    Raises PluginTrustError on any failure.
    """
    # Dev bypass (never allowed in production)
    if os.environ.get(_DEV_BYPASS_ENV) == "1":
        if os.environ.get("PWNPILOT_ENV", "").lower() == "production":
            raise PluginTrustError(
                f"{_DEV_BYPASS_ENV} is not permitted in production mode."
            )
        log.warning("trust.unsigned_bypass_active", adapter=manifest.name)
        return

    # 1. Checksum verification
    if not manifest.checksum_sha256:
        raise PluginTrustError(
            f"Adapter '{manifest.name}' has no checksum_sha256 in manifest."
        )

    actual = hashlib.sha256(adapter_path.read_bytes()).hexdigest()
    if actual != manifest.checksum_sha256:
        raise PluginTrustError(
            f"Checksum mismatch for adapter '{manifest.name}': "
            f"expected={manifest.checksum_sha256}, actual={actual}"
        )

    # 2. Signature verification
    if not manifest.signature_b64:
        raise PluginTrustError(
            f"Adapter '{manifest.name}' has no signature in manifest."
        )

    pub_key = _load_trusted_key(manifest.name)
    try:
        sig = base64.b64decode(manifest.signature_b64)
        message = manifest.checksum_sha256.encode()
        pub_key.verify(sig, message)
    except InvalidSignature:
        raise PluginTrustError(
            f"Signature verification failed for adapter '{manifest.name}'."
        )

    log.info("trust.verified", adapter=manifest.name, version=manifest.version)


def _load_trusted_key(adapter_name: str) -> Ed25519PublicKey:
    """Load the trusted public key for the adapter from the trust store."""
    # Try adapter-specific key first, then fall back to project root key
    candidates = [
        _TRUST_STORE_DIR / f"{adapter_name}.pub",
        _TRUST_STORE_DIR / "pwnpilot_plugin_signing.pub",
    ]
    for path in candidates:
        if path.exists():
            key = load_pem_public_key(path.read_bytes())
            if not isinstance(key, Ed25519PublicKey):
                raise PluginTrustError(
                    f"Key at {path} is not an Ed25519 public key."
                )
            return key  # type: ignore[return-value]

    raise PluginTrustError(
        f"No trusted public key found for adapter '{adapter_name}'. "
        f"Looked in: {[str(c) for c in candidates]}"
    )
