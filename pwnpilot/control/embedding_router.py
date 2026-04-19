"""
Embedding Router — unified multi-provider embedding calls with retry, circuit breaker,
and policy-gated fallback routing.

This mirrors the behavior of LLMRouter for completion models while exposing a
minimal embedding API that can be reused by retrieval/indexing components.
"""
from __future__ import annotations

import os
import time
from enum import Enum
from typing import Any

import litellm
import structlog

from pwnpilot.secrets.redactor import Redactor

log = structlog.get_logger(__name__)

_BACKOFF_BASE: float = 1.0
_BACKOFF_MAX: float = 8.0
_CIRCUIT_OPEN_DURATION: float = 60.0


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class EmbeddingPolicyDeniedError(Exception):
    """Raised when fallback embedding routing is blocked by policy."""


class EmbeddingRouterError(Exception):
    """Raised when embedding generation fails on all configured routes."""


class EmbeddingRouter:
    def __init__(
        self,
        model_name: str = "ollama/nomic-embed-text",
        api_key: str = "",
        api_base_url: str = "",
        fallback_model_name: str = "text-embedding-3-small",
        fallback_api_key: str = "",
        fallback_api_base_url: str = "",
        cloud_allowed_fn: Any = None,
        redactor: Redactor | None = None,
        audit_fn: Any = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
    ) -> None:
        self._model_name = model_name
        self._api_key = api_key or os.environ.get("LITELLM_API_KEY", "")
        self._api_base_url = api_base_url

        self._fallback_model_name = fallback_model_name
        self._fallback_api_key = fallback_api_key or os.environ.get("LITELLM_FALLBACK_API_KEY", "")
        self._fallback_api_base_url = fallback_api_base_url

        self._cloud_allowed = cloud_allowed_fn or (lambda: False)
        self._redactor = redactor or Redactor()
        self._audit = audit_fn
        self._timeout = timeout_seconds
        self._max_retries = max_retries

        self._circuit_state = CircuitState.CLOSED
        self._circuit_open_at: float = 0.0
        self._consecutive_failures: int = 0

        litellm.suppress_debug_info = True

    def embed(self, text: str) -> list[float]:
        vectors = self.embed_many([text])
        if not vectors:
            raise EmbeddingRouterError("Embedding response returned no vectors.")
        return vectors[0]

    def embed_many(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        self._check_circuit()

        if self._circuit_state != CircuitState.OPEN:
            try:
                vectors = self._embed_with_retry(
                    self._model_name,
                    self._api_key,
                    self._api_base_url,
                    texts,
                )
                self._on_success()
                if self._audit:
                    self._audit("EmbeddingRouted", {"routing": "primary", "model": self._model_name})
                return vectors
            except Exception as exc:
                self._on_failure()
                log.warning("embedding_router.primary_failed", exc=str(exc), model=self._model_name)

        if not self._cloud_allowed():
            raise EmbeddingPolicyDeniedError(
                "Fallback embedding routing is not permitted by current policy."
            )

        if not self._fallback_model_name:
            raise EmbeddingRouterError("No fallback embedding model configured and primary is unavailable.")

        safe_texts = [self._redactor.scrub(t) for t in texts]

        try:
            vectors = self._embed_with_retry(
                self._fallback_model_name,
                self._fallback_api_key,
                self._fallback_api_base_url,
                safe_texts,
            )
            if self._audit:
                self._audit("EmbeddingRouted", {"routing": "fallback", "model": self._fallback_model_name})
            return vectors
        except Exception as exc:
            raise EmbeddingRouterError(f"Fallback embedding model also failed: {exc}") from exc

    def _embed_with_retry(
        self,
        model_name: str,
        api_key: str,
        api_base_url: str,
        texts: list[str],
    ) -> list[list[float]]:
        last_exc: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                return self._litellm_embed(model_name, api_key, api_base_url, texts)
            except Exception as exc:
                last_exc = exc
                wait = min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_MAX)
                log.debug(
                    "embedding_router.retry",
                    model=model_name,
                    attempt=attempt + 1,
                    wait=wait,
                    exc=str(exc),
                )
                time.sleep(wait)
        raise last_exc or RuntimeError(f"Embedding model {model_name} failed after {self._max_retries} retries.")

    def _litellm_embed(
        self,
        model_name: str,
        api_key: str,
        api_base_url: str,
        texts: list[str],
    ) -> list[list[float]]:
        if api_key:
            os.environ["LITELLM_API_KEY"] = api_key

        kwargs: dict[str, Any] = {
            "model": model_name,
            "input": texts,
            "timeout": self._timeout,
            "max_retries": 1,
        }
        if api_base_url:
            kwargs["api_base"] = api_base_url

        response = litellm.embedding(**kwargs)
        data = getattr(response, "data", None)
        if data is None and isinstance(response, dict):
            data = response.get("data")
        if not data:
            raise EmbeddingRouterError("Embedding API returned empty data payload.")

        vectors: list[list[float]] = []
        for item in data:
            embedding = getattr(item, "embedding", None)
            if embedding is None and isinstance(item, dict):
                embedding = item.get("embedding")
            if embedding is None:
                raise EmbeddingRouterError("Embedding item missing vector data.")
            vectors.append(list(embedding))
        return vectors

    def _check_circuit(self) -> None:
        now = time.monotonic()
        if self._circuit_state == CircuitState.OPEN:
            if now - self._circuit_open_at >= _CIRCUIT_OPEN_DURATION:
                log.info("embedding_router.circuit_half_open")
                self._circuit_state = CircuitState.HALF_OPEN

    def _on_success(self) -> None:
        self._consecutive_failures = 0
        if self._circuit_state != CircuitState.CLOSED:
            log.info("embedding_router.circuit_closed")
            self._circuit_state = CircuitState.CLOSED

    def _on_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._max_retries:
            log.warning(
                "embedding_router.circuit_open",
                failures=self._consecutive_failures,
                model=self._model_name,
            )
            self._circuit_state = CircuitState.OPEN
            self._circuit_open_at = time.monotonic()
