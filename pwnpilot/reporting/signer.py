"""
Report Signer — Ed25519 signing and verification of report bundles.

Usage:
    from pwnpilot.reporting.signer import ReportSigner

    signer = ReportSigner.from_key_file(private_key_path)
    sig_path = signer.sign(bundle_path)            # writes <bundle>.sig

    # Verification (no private key needed)
    ReportSigner.verify(bundle_path, sig_path, public_key_path)

Key management:
    Generate a new operator key pair:
        ReportSigner.generate_key_pair(private_key_path, public_key_path)

    Private key is stored in PEM format (Ed25519PrivateKey).
    Public key embedded in the JSON bundle under "operator_pubkey_b64".
    Signature file contains raw 64-byte Ed25519 signature, hex-encoded.

Security notes:
    - Private key never logged, never included in audit payloads.
    - Key file path comes from environment ($PWNPILOT_SIGNING_KEY) or config.
    - Verification uses the public key embedded in the bundle; caller should
      cross-check against a locally trusted keyring.
"""
from __future__ import annotations

import hashlib
import json
import os
from base64 import b64decode, b64encode
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import structlog

log = structlog.get_logger(__name__)

_DEFAULT_KEY_ENV = "PWNPILOT_SIGNING_KEY"


class SignatureError(Exception):
    """Raised when signature verification fails."""


class ReportSigner:
    """
    Handles Ed25519 signing and verification of report bundles.

    Args:
        private_key: Ed25519PrivateKey instance.  None for verify-only mode.
        public_key:  Ed25519PublicKey instance derived from private key.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey | None = None,
        public_key: Ed25519PublicKey | None = None,
    ) -> None:
        if private_key is None and public_key is None:
            raise ValueError("At least one of private_key or public_key is required.")
        self._private_key = private_key
        self._public_key = public_key or private_key.public_key()  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def generate_key_pair(
        cls,
        private_key_path: Path,
        public_key_path: Path,
    ) -> "ReportSigner":
        """
        Generate a new Ed25519 key pair and persist to disk.

        Private key is written in PEM (PKCS8, no password).
        Public key is written in PEM (SubjectPublicKeyInfo).
        Both files are created with mode 0o600.
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key_path.write_bytes(private_pem)
        private_key_path.chmod(0o600)

        public_key_path.parent.mkdir(parents=True, exist_ok=True)
        public_key_path.write_bytes(public_pem)
        public_key_path.chmod(0o644)

        log.info(
            "signer.key_pair_generated",
            private_key=str(private_key_path),
            public_key=str(public_key_path),
        )
        return cls(private_key=private_key, public_key=public_key)

    @classmethod
    def from_key_file(cls, private_key_path: Path) -> "ReportSigner":
        """Load a signer from a PEM private key file."""
        pem = private_key_path.read_bytes()
        private_key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError(
                f"Key at {private_key_path} is not an Ed25519 private key."
            )
        return cls(private_key=private_key)

    @classmethod
    def from_public_key_file(cls, public_key_path: Path) -> "ReportSigner":
        """Load a verify-only signer from a PEM public key file."""
        pem = public_key_path.read_bytes()
        public_key = serialization.load_pem_public_key(pem)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError(
                f"Key at {public_key_path} is not an Ed25519 public key."
            )
        return cls(public_key=public_key)

    @classmethod
    def from_env_or_config(
        cls, config_key_path: str | None = None
    ) -> "ReportSigner | None":
        """
        Try to load signing key from $PWNPILOT_SIGNING_KEY env var or config path.
        Returns None if no key is configured (signing is optional).
        """
        key_path_str = os.environ.get(_DEFAULT_KEY_ENV) or config_key_path
        if not key_path_str:
            return None
        key_path = Path(key_path_str).expanduser()
        if not key_path.exists():
            log.warning("signer.key_not_found", path=str(key_path))
            return None
        return cls.from_key_file(key_path)

    # ------------------------------------------------------------------
    # Public key helpers
    # ------------------------------------------------------------------

    def public_key_b64(self) -> str:
        """Return the raw public key bytes as a base64 string (for bundle embedding)."""
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return b64encode(raw).decode()

    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    # ------------------------------------------------------------------
    # Sign
    # ------------------------------------------------------------------

    def sign(self, bundle_path: Path) -> Path:
        """
        Sign a report bundle JSON file.

        Computes SHA-256 over the bundle bytes, then signs the digest with
        the Ed25519 private key.  Writes the hex-encoded signature to
        ``<bundle_path>.sig``.

        Returns the signature file path.
        """
        if self._private_key is None:
            raise RuntimeError("Cannot sign: no private key loaded.")

        bundle_bytes = bundle_path.read_bytes()
        digest = hashlib.sha256(bundle_bytes).digest()
        signature = self._private_key.sign(digest)
        sig_hex = signature.hex()

        sig_path = bundle_path.with_suffix(".sig")
        sig_path.write_text(sig_hex)
        log.info(
            "signer.bundle_signed",
            bundle=str(bundle_path),
            sig_file=str(sig_path),
            sha256=hashlib.sha256(bundle_bytes).hexdigest(),
        )
        return sig_path

    def embed_pubkey_in_bundle(self, bundle_path: Path) -> None:
        """
        Add the ``operator_pubkey_b64`` field to an existing JSON bundle in-place.
        Called after ``build_bundle()`` and before ``sign()``.
        """
        bundle = json.loads(bundle_path.read_text())
        bundle["operator_pubkey_b64"] = self.public_key_b64()
        bundle_path.write_text(json.dumps(bundle, indent=2, default=str))

    # ------------------------------------------------------------------
    # Verify (static — only needs public key)
    # ------------------------------------------------------------------

    @staticmethod
    def verify(
        bundle_path: Path,
        sig_path: Path,
        public_key_path: Path | None = None,
    ) -> bool:
        """
        Verify a bundle's signature.

        Public key resolution order:
        1. ``public_key_path`` argument (explicit file).
        2. ``operator_pubkey_b64`` embedded in the bundle JSON.

        Raises ``SignatureError`` if verification fails.
        Returns True on success.
        """
        bundle_bytes = bundle_path.read_bytes()
        digest = hashlib.sha256(bundle_bytes).digest()
        sig_hex = sig_path.read_text().strip()
        signature = bytes.fromhex(sig_hex)

        # Resolve public key
        if public_key_path and public_key_path.exists():
            pem = public_key_path.read_bytes()
            pub_key: Ed25519PublicKey = serialization.load_pem_public_key(pem)  # type: ignore[assignment]
        else:
            # Try embedded key from bundle
            bundle = json.loads(bundle_bytes)
            b64 = bundle.get("operator_pubkey_b64")
            if not b64:
                raise SignatureError(
                    "No public key provided and none embedded in bundle."
                )
            raw = b64decode(b64)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _PK
            pub_key = _PK.from_public_bytes(raw)  # type: ignore[attr-defined]

        try:
            pub_key.verify(signature, digest)
        except InvalidSignature as exc:
            raise SignatureError(
                f"Signature verification FAILED for {bundle_path.name}"
            ) from exc

        log.info("signer.bundle_verified", bundle=str(bundle_path))
        return True
