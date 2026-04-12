from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from typer.testing import CliRunner

from pwnpilot.cli import app
from pwnpilot.control.llm_router import LLMRouter, LLMRouterError, PolicyDeniedError


runner = CliRunner()


def _preflight_with_missing() -> dict:
    return {
        "target_family": "web",
        "sequence": [
            {
                "name": "Discover Routes/Endpoints",
                "preferred_tools": ["zap", "gobuster"],
                "preferred_available": ["gobuster"],
                "preferred_missing": ["zap"],
            }
        ],
        "missing_recommended_tools": ["zap"],
    }


def test_start_preflight_missing_tools_user_declines_install() -> None:
    with patch("pwnpilot.runtime.get_engagement_preflight", return_value=_preflight_with_missing()):
        with patch("pwnpilot.runtime.create_and_run_engagement", return_value=str(uuid4())):
            with patch("typer.confirm", return_value=False):
                result = runner.invoke(
                    app,
                    [
                        "start",
                        "--name",
                        "preflight-no-install",
                        "--cidr",
                        "10.0.0.0/24",
                        "--roe-hash",
                        "a" * 64,
                        "--authoriser",
                        "operator",
                    ],
                )

    assert result.exit_code == 0
    assert "Missing recommended tools" in result.output
    assert "Proceeding with currently available tools" in result.output


def test_start_preflight_install_requested_but_installer_missing() -> None:
    original_exists = Path.exists

    def _exists(self: Path) -> bool:
        if str(self).endswith("scripts/install_security_tools.sh"):
            return False
        return original_exists(self)

    with patch("pwnpilot.runtime.get_engagement_preflight", return_value=_preflight_with_missing()):
        with patch("pwnpilot.runtime.create_and_run_engagement", return_value=str(uuid4())):
            with patch("typer.confirm", return_value=True):
                with patch("pathlib.Path.exists", _exists):
                    result = runner.invoke(
                        app,
                        [
                            "start",
                            "--name",
                            "preflight-installer-missing",
                            "--cidr",
                            "10.0.0.0/24",
                            "--roe-hash",
                            "a" * 64,
                            "--authoriser",
                            "operator",
                        ],
                    )

    assert result.exit_code == 0
    assert "Installer script not found" in result.output


def test_start_preflight_install_runs_and_refreshes() -> None:
    preflight1 = _preflight_with_missing()
    preflight2 = {
        "target_family": "web",
        "sequence": [],
        "missing_recommended_tools": [],
    }

    original_exists = Path.exists

    def _exists(self: Path) -> bool:
        if str(self).endswith("scripts/install_security_tools.sh"):
            return True
        return original_exists(self)

    with patch("pwnpilot.runtime.get_engagement_preflight", side_effect=[preflight1, preflight2]) as preflight_mock:
        with patch("pwnpilot.runtime.create_and_run_engagement", return_value=str(uuid4())):
            with patch("typer.confirm", side_effect=[True, True]):
                with patch("subprocess.run", return_value=MagicMock(returncode=0)) as subproc:
                    with patch("pathlib.Path.exists", _exists):
                        result = runner.invoke(
                            app,
                            [
                                "start",
                                "--name",
                                "preflight-install-success",
                                "--cidr",
                                "10.0.0.0/24",
                                "--roe-hash",
                                "a" * 64,
                                "--authoriser",
                                "operator",
                            ],
                        )

    assert result.exit_code == 0
    assert preflight_mock.call_count == 2
    assert subproc.call_count == 1


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
