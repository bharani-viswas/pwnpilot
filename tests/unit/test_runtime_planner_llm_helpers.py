from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest

from pwnpilot.agent.planner import _classify_target_type, _strategy_progress
from pwnpilot.control.llm_router import CircuitState, LLMRouter
from pwnpilot.plugins.registry import ToolDescriptor, ToolRegistry
from pwnpilot.runtime import (
    _build_tool_registry_from_typed_config,
    _compute_executable_tool_names,
    _filter_tools_catalog,
    invalidate_tool_registry_cache,
    run_policy_simulation,
)


def _typed_cfg() -> SimpleNamespace:
    return SimpleNamespace(
        tools=SimpleNamespace(
            trust_mode="first_party_only",
            allow_unsigned_first_party=True,
            plugin_package="pwnpilot.plugins.adapters",
            entrypoint_group="pwnpilot.plugins",
            discovery_mode="package",
            enabled_tools=[],
            disabled_tools=[],
        )
    )


def test_runtime_registry_builder_uses_cache(monkeypatch) -> None:
    calls = {"count": 0}

    class _Loader:
        def __init__(self, **kwargs):
            pass

        def load_registry(self, enabled_tools, disabled_tools):
            calls["count"] += 1
            return ToolRegistry()

    invalidate_tool_registry_cache()
    monkeypatch.setattr("pwnpilot.runtime.PluginLoader", _Loader)

    cfg = _typed_cfg()
    r1 = _build_tool_registry_from_typed_config(cfg)
    r2 = _build_tool_registry_from_typed_config(cfg)

    assert r1 is r2
    assert calls["count"] == 1


def test_compute_executable_tools_and_filter_catalog(monkeypatch) -> None:
    reg = ToolRegistry()
    reg.add(
        ToolDescriptor(
            tool_name="shell",
            adapter=object(),
            adapter_class="ShellAdapter",
            adapter_module="x",
            source="first_party",
            risk_class="recon_passive",
            binary_name="",
        )
    )
    reg.add(
        ToolDescriptor(
            tool_name="nmap",
            adapter=object(),
            adapter_class="NmapAdapter",
            adapter_module="x",
            source="first_party",
            risk_class="active_scan",
            binary_name="nmap",
        )
    )
    reg.add(
        ToolDescriptor(
            tool_name="zap",
            adapter=object(),
            adapter_class="ZapAdapter",
            adapter_module="x",
            source="first_party",
            risk_class="active_scan",
            binary_name="zaproxy",
            enabled=False,
        )
    )

    monkeypatch.setattr(
        "pwnpilot.runtime.resolve_binary_for_tool",
        lambda tool_name, binary: "/usr/bin/nmap" if tool_name == "nmap" else None,
    )

    executable = _compute_executable_tool_names(reg)
    assert executable == ["nmap", "shell"]

    catalog = [
        {"tool_name": "shell", "x": 1},
        {"tool_name": "nmap", "x": 2},
        {"tool_name": "zap", "x": 3},
    ]
    filtered = _filter_tools_catalog(catalog, ["nmap", "shell"])
    assert filtered == [{"tool_name": "shell", "x": 1}, {"tool_name": "nmap", "x": 2}]


def test_run_policy_simulation_returns_decisions(monkeypatch) -> None:
    monkeypatch.setattr("pwnpilot.runtime._build_runtime", lambda config_path=None: {})

    actions = [
        {
            "engagement_id": str(uuid4()),
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "params": {"target": "127.0.0.1"},
            "risk_level": "low",
        }
    ]

    out = run_policy_simulation(actions=actions, engagement_id=uuid4())
    assert len(out) == 1
    assert out[0]["tool_name"] == "nmap"
    assert out[0]["verdict"] in {"allow", "deny", "requires_approval"}


def test_planner_target_type_and_strategy_progress() -> None:
    assert _classify_target_type("https://example.com") == "url"
    assert _classify_target_type("10.0.0.0/24") == "cidr"
    assert _classify_target_type("10.0.0.1") == "ip"
    assert _classify_target_type("example.com") == "domain"
    assert _classify_target_type("") == "unknown"

    plan = {
        "sequence": [
            {"step_id": "s1", "preferred_tools": ["whatweb"], "fallback_tools": ["nikto"]},
            {"step_id": "s2", "preferred_tools": ["gobuster"], "fallback_tools": []},
        ]
    }
    previous = [{"tool_name": "whatweb"}]
    progress = _strategy_progress(plan, previous)
    assert progress["completed_steps"] == ["s1"]
    assert progress["current_step"]["step_id"] == "s2"
    assert progress["remaining_steps"] == 1


def test_llm_router_helpers_format_parse_and_retry(monkeypatch) -> None:
    router = LLMRouter(cloud_allowed_fn=lambda: False)

    formatted = router._format_tool_schemas(
        {
            "nmap": {
                "description": "Network mapper",
                "risk_class": "active_scan",
                "required_params": ["target"],
                "parameters": {
                    "target": {"type": "string", "description": "host"},
                    "scan_type": {"type": "string", "enum": ["sS", "sV"], "default": "sV"},
                },
            }
        }
    )
    assert "#### nmap" in formatted
    assert "Values: sS, sV" in formatted
    assert "Default: sV" in formatted

    parsed = LLMRouter._parse_json("```json\n{\"ok\": true}\n```", "Schema")
    assert parsed["ok"] is True

    with pytest.raises(ValueError):
        LLMRouter._parse_json("not-json", "Schema")

    attempts = {"n": 0}

    def _flaky(*args, **kwargs):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise RuntimeError("temporary")
        return "ok"

    monkeypatch.setattr(router, "_litellm_complete", _flaky)
    monkeypatch.setattr("time.sleep", lambda _s: None)

    out = router._complete_with_retry("m", "k", "", "s", "u")
    assert out == "ok"
    assert attempts["n"] == 3


def test_llm_router_circuit_state_transitions(monkeypatch) -> None:
    router = LLMRouter(cloud_allowed_fn=lambda: False, max_retries=2)

    router._on_failure()
    router._on_failure()
    assert router._circuit_state == CircuitState.OPEN

    monkeypatch.setattr("time.monotonic", lambda: router._circuit_open_at + 120.0)
    router._check_circuit()
    assert router._circuit_state == CircuitState.HALF_OPEN

    router._on_success()
    assert router._circuit_state == CircuitState.CLOSED
