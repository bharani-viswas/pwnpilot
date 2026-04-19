from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from pwnpilot.cli import app
from pwnpilot.control.llm_router import LLMRouter, LLMRouterError, PolicyDeniedError
from pwnpilot.control.embedding_router import (
    EmbeddingRouter,
    EmbeddingRouterError,
    EmbeddingPolicyDeniedError,
)


runner = CliRunner()


def test_llm_router_fallback_policy_denied() -> None:
    router = LLMRouter(cloud_allowed_fn=lambda: False)

    with patch.object(router, "_complete_with_retry", side_effect=Exception("primary failed")):
        try:
            router.complete("system", "user")
            assert False, "Expected PolicyDeniedError"
        except PolicyDeniedError:
            pass


def test_llm_router_no_fallback_model_configured() -> None:
    router = LLMRouter(
        cloud_allowed_fn=lambda: True,
        fallback_model_name="",
    )

    with patch.object(router, "_complete_with_retry", side_effect=Exception("primary failed")):
        try:
            router.complete("system", "user")
            assert False, "Expected LLMRouterError"
        except LLMRouterError:
            pass


def test_llm_router_fallback_success_path_records_model() -> None:
    audit_events: list[tuple[str, dict]] = []

    router = LLMRouter(
        cloud_allowed_fn=lambda: True,
        audit_fn=lambda evt, payload: audit_events.append((evt, payload)),
    )

    def _retry(model_name: str, api_key: str, api_base_url: str, system: str, user: str) -> str:
        if model_name == router._model_name:
            raise RuntimeError("primary down")
        return '{"ok": true}'

    with patch.object(router, "_complete_with_retry", side_effect=_retry):
        out = router.complete("system prompt", "user prompt")

    assert '"ok": true' in out
    assert any(evt == "LLMRouted" and p.get("routing") == "fallback" for evt, p in audit_events)


def test_embedding_router_fallback_policy_denied() -> None:
    router = EmbeddingRouter(cloud_allowed_fn=lambda: False)

    with patch.object(router, "_embed_with_retry", side_effect=Exception("primary failed")):
        try:
            router.embed_many(["hello"])
            assert False, "Expected EmbeddingPolicyDeniedError"
        except EmbeddingPolicyDeniedError:
            pass


def test_embedding_router_no_fallback_model_configured() -> None:
    router = EmbeddingRouter(
        cloud_allowed_fn=lambda: True,
        fallback_model_name="",
    )

    with patch.object(router, "_embed_with_retry", side_effect=Exception("primary failed")):
        try:
            router.embed_many(["hello"])
            assert False, "Expected EmbeddingRouterError"
        except EmbeddingRouterError:
            pass


def test_embedding_router_fallback_success_path_records_model() -> None:
    audit_events: list[tuple[str, dict]] = []

    router = EmbeddingRouter(
        cloud_allowed_fn=lambda: True,
        audit_fn=lambda evt, payload: audit_events.append((evt, payload)),
    )

    def _retry(model_name: str, api_key: str, api_base_url: str, texts: list[str]) -> list[list[float]]:
        if model_name == router._model_name:
            raise RuntimeError("primary down")
        return [[0.1, 0.2, 0.3] for _ in texts]

    with patch.object(router, "_embed_with_retry", side_effect=_retry):
        out = router.embed_many(["system prompt", "user prompt"])

    assert len(out) == 2
    assert any(evt == "EmbeddingRouted" and p.get("routing") == "fallback" for evt, p in audit_events)
