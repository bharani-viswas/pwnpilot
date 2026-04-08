"""
LLM Router — local-first inference with redaction, retry, circuit breaker, and
policy-gated cloud fallback.

Routing logic (ADR-004):
1. Attempt local model (Ollama/vLLM endpoint) up to 3 times with exponential backoff.
2. After 3 consecutive failures, open circuit breaker for 60s.
3. If circuit is open: evaluate cloud fallback policy gate.
4. If cloud denied: raise PolicyDeniedError; orchestrator halts.
5. Before cloud dispatch: run redactor.scrub() on the prompt.
6. Log all routing decisions to audit store.

Circuit breaker states: CLOSED → OPEN → HALF_OPEN → CLOSED
"""
from __future__ import annotations

import json
import time
from enum import Enum
from typing import Any

import httpx
import structlog

from pwnpilot.secrets.redactor import Redactor

log = structlog.get_logger(__name__)

_LOCAL_TIMEOUT: float = 120.0
_CLOUD_TIMEOUT: float = 60.0
_MAX_RETRIES: int = 3
_BACKOFF_BASE: float = 1.0
_BACKOFF_MAX: float = 8.0
_CIRCUIT_OPEN_DURATION: float = 60.0


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class PolicyDeniedError(Exception):
    """Raised when cloud fallback is blocked by policy."""


class LLMRouterError(Exception):
    """Raised when all LLM paths are exhausted."""


class LLMRouter:
    """
    Routes LLM inference requests: local first, cloud fallback if policy permits.

    Args:
        local_base_url:       Base URL for Ollama/vLLM (e.g. http://localhost:11434).
        local_model:          Model name for local inference.
        cloud_client:         Optional pre-configured cloud client (openai.OpenAI etc.).
        cloud_model:          Cloud model name.
        cloud_allowed_fn:     Callable() -> bool: returns True if cloud is policy-allowed.
        redactor:             Redactor instance for prompt scrubbing.
        audit_fn:             Optional audit logging callback(event_type, payload).
    """

    def __init__(
        self,
        local_base_url: str = "http://localhost:11434",
        local_model: str = "llama3",
        cloud_client: Any = None,
        cloud_model: str = "gpt-4o",
        cloud_allowed_fn: Any = None,
        redactor: Redactor | None = None,
        audit_fn: Any = None,
    ) -> None:
        self._local_url = local_base_url.rstrip("/")
        self._local_model = local_model
        self._cloud_client = cloud_client
        self._cloud_model = cloud_model
        self._cloud_allowed = cloud_allowed_fn or (lambda: False)
        self._redactor = redactor or Redactor()
        self._audit = audit_fn

        # Circuit breaker state
        self._circuit_state = CircuitState.CLOSED
        self._circuit_open_at: float = 0.0
        self._consecutive_failures: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """
        Send a completion request.  Returns the model response string.
        Tries local first; falls back to cloud if policy permits.
        """
        routing = "local"
        self._check_circuit()

        if self._circuit_state != CircuitState.OPEN:
            try:
                response = self._local_complete_with_retry(system_prompt, user_prompt)
                self._on_local_success()
                if self._audit:
                    self._audit("LLMRouted", {"routing": "local", "model": self._local_model})
                return response
            except Exception as exc:
                self._on_local_failure()
                log.warning("llm_router.local_failed", exc=str(exc))

        # Cloud fallback
        routing = "cloud"
        if not self._cloud_allowed():
            raise PolicyDeniedError(
                "Cloud LLM fallback is not permitted by current policy."
            )

        if self._cloud_client is None:
            raise LLMRouterError("No cloud client configured and local model is unavailable.")

        # Redact prompt before cloud dispatch
        safe_system = self._redactor.scrub(system_prompt)
        safe_user = self._redactor.scrub(user_prompt)

        try:
            response = self._cloud_complete(safe_system, safe_user)
            if self._audit:
                self._audit("LLMRouted", {"routing": "cloud", "model": self._cloud_model})
            return response
        except Exception as exc:
            raise LLMRouterError(f"Cloud LLM also failed: {exc}") from exc

    def plan(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Ask the LLM to produce a PlannerProposal dict given *context*.
        The response is parsed as JSON and returned as a dict.
        """
        system = (
            "You are a penetration testing planner.  Given the engagement context, "
            "produce a single JSON object matching the PlannerProposal schema.  "
            "Return ONLY the raw JSON object, no markdown, no explanation."
        )
        user = json.dumps(context, default=str)
        raw = self.complete(system, user)
        return self._parse_json(raw, "PlannerProposal")

    def validate(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Ask the LLM to produce a ValidationResult dict given *context*.
        """
        system = (
            "You are a penetration testing risk validator.  Given the proposed action, "
            "produce a single JSON object matching the ValidationResult schema "
            "(verdict: approve|reject|escalate, risk_override: null|str, rationale: str).  "
            "Return ONLY the raw JSON object."
        )
        user = json.dumps(context, default=str)
        raw = self.complete(system, user)
        return self._parse_json(raw, "ValidationResult")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _local_complete_with_retry(self, system: str, user: str) -> str:
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                return self._ollama_complete(system, user)
            except Exception as exc:
                last_exc = exc
                wait = min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_MAX)
                log.debug(
                    "llm_router.local_retry",
                    attempt=attempt + 1,
                    wait=wait,
                    exc=str(exc),
                )
                time.sleep(wait)
        raise last_exc or RuntimeError("Local LLM failed after retries.")

    def _ollama_complete(self, system: str, user: str) -> str:
        """Call the Ollama /api/chat endpoint."""
        payload = {
            "model": self._local_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
        }
        resp = httpx.post(
            f"{self._local_url}/api/chat",
            json=payload,
            timeout=_LOCAL_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    def _cloud_complete(self, system: str, user: str) -> str:
        """Call the configured cloud client (OpenAI-compatible)."""
        resp = self._cloud_client.chat.completions.create(
            model=self._cloud_model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            timeout=_CLOUD_TIMEOUT,
        )
        return resp.choices[0].message.content or ""

    def _check_circuit(self) -> None:
        now = time.monotonic()
        if self._circuit_state == CircuitState.OPEN:
            if now - self._circuit_open_at >= _CIRCUIT_OPEN_DURATION:
                log.info("llm_router.circuit_half_open")
                self._circuit_state = CircuitState.HALF_OPEN

    def _on_local_success(self) -> None:
        self._consecutive_failures = 0
        if self._circuit_state != CircuitState.CLOSED:
            log.info("llm_router.circuit_closed")
            self._circuit_state = CircuitState.CLOSED

    def _on_local_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= _MAX_RETRIES:
            log.warning(
                "llm_router.circuit_open",
                failures=self._consecutive_failures,
            )
            self._circuit_state = CircuitState.OPEN
            self._circuit_open_at = time.monotonic()

    @staticmethod
    def _parse_json(raw: str, schema_name: str) -> dict[str, Any]:
        """Extract and parse the first JSON object from the LLM response."""
        # Strip markdown code fences if present
        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"LLM did not return valid JSON for {schema_name}: {exc}\nRaw: {raw[:500]!r}"
            ) from exc
