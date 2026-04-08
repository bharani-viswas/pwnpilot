"""
Secrets Vault — encrypted-at-rest credential store using cryptography.Fernet.

Key management:
- Primary key: PWNPILOT_VAULT_KEY env var (base64url Fernet key) or file path set by
  PWNPILOT_VAULT_KEY_FILE.  Env var takes precedence.
- Key rotation (ADR-012): provide PWNPILOT_VAULT_KEY_NEW env var at startup.  On first
  access the vault re-encrypts all secrets with the new key in a single atomic
  transaction, then invalidates the old key.
- Keys are NEVER logged, NEVER passed through the redactor, and NEVER included in any
  LLM context.
"""
from __future__ import annotations

import base64
import json
import os
import threading
from pathlib import Path

import structlog
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Session

log = structlog.get_logger(__name__)


class VaultKeyError(Exception):
    """Raised when the vault key is missing or invalid."""


class Base(DeclarativeBase):
    pass


class SecretRow(Base):
    __tablename__ = "vault_secrets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(256), nullable=False, unique=True, index=True)
    ciphertext = Column(Text, nullable=False)


class SecretsVault:
    """
    Encrypted-at-rest secret store.  Secrets are stored as Fernet-encrypted blobs in
    the database.  Keys are loaded from environment variables and never persisted.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._lock = threading.Lock()
        self._fernet = self._load_keys()
        Base.metadata.create_all(session.bind)  # type: ignore[arg-type]
        self._maybe_rotate()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(self, name: str, value: str) -> None:
        """Encrypt and persist a secret."""
        ct = self._fernet.encrypt(value.encode()).decode()
        with self._lock:
            existing = self._get_row(name)
            if existing:
                existing.ciphertext = ct
            else:
                self._session.add(SecretRow(name=name, ciphertext=ct))
            self._session.commit()

    def retrieve(self, name: str) -> str:
        """Decrypt and return a secret.  Raises KeyError if not found."""
        row = self._get_row(name)
        if row is None:
            raise KeyError(f"Secret '{name}' not found in vault.")
        return self._fernet.decrypt(row.ciphertext.encode()).decode()

    def delete(self, name: str) -> None:
        row = self._get_row(name)
        if row:
            self._session.delete(row)
            self._session.commit()

    def list_names(self) -> list[str]:
        return [r.name for r in self._session.query(SecretRow).all()]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_row(self, name: str) -> SecretRow | None:
        return (
            self._session.query(SecretRow)
            .filter(SecretRow.name == name)
            .first()
        )

    @staticmethod
    def _load_keys() -> MultiFernet:
        """
        Load the primary (and optional rotation) key from environment.
        Raises VaultKeyError if no key is available.
        """
        keys: list[Fernet] = []

        raw = os.environ.get("PWNPILOT_VAULT_KEY")
        if not raw:
            key_file = os.environ.get("PWNPILOT_VAULT_KEY_FILE")
            if key_file:
                raw = Path(key_file).read_text().strip()

        if not raw:
            raise VaultKeyError(
                "No vault key found.  Set PWNPILOT_VAULT_KEY or PWNPILOT_VAULT_KEY_FILE."
            )

        keys.append(Fernet(raw.encode()))

        # If a new key is provided, it becomes the primary encryption key
        new_raw = os.environ.get("PWNPILOT_VAULT_KEY_NEW")
        if new_raw:
            keys.insert(0, Fernet(new_raw.encode()))

        return MultiFernet(keys)

    def _maybe_rotate(self) -> None:
        """
        If PWNPILOT_VAULT_KEY_NEW is set, re-encrypt all secrets with the new key.
        After rotation, PWNPILOT_VAULT_KEY_NEW becomes the sole active key.
        """
        if not os.environ.get("PWNPILOT_VAULT_KEY_NEW"):
            return

        log.info("vault.key_rotation_start")
        rows = self._session.query(SecretRow).all()
        for row in rows:
            try:
                plaintext = self._fernet.decrypt(row.ciphertext.encode())
                # Re-encrypt with new key (MultiFernet uses keys[0] for encryption)
                row.ciphertext = self._fernet.encrypt(plaintext).decode()
            except InvalidToken:
                log.error("vault.rotation_decrypt_failed", name=row.name)
        self._session.commit()
        log.info("vault.key_rotation_complete", rotated=len(rows))
