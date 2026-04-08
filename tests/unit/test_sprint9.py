"""
Sprint 9 tests — Config management, Observability metrics.

TUI is excluded from unit tests because launching a Textual App requires a
real or mock terminal (it can be tested with pytest-textual but that is an
optional dependency).  The important paths in TUI are import-path tested.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import yaml


# ---------------------------------------------------------------------------
# Config management
# ---------------------------------------------------------------------------


class TestPwnpilotConfig:
    """Tests for pwnpilot.config.PwnpilotConfig and load_config()."""

    def test_defaults_are_valid(self):
        from pwnpilot.config import PwnpilotConfig

        cfg = PwnpilotConfig()
        assert cfg.database.url == "sqlite:///pwnpilot.db"
        assert cfg.llm.local_model == "llama3"
        assert cfg.llm.cloud_allowed is False
        assert cfg.agent.max_iterations == 50
        assert cfg.storage.evidence_dir == "~/.pwnpilot/evidence"
        assert cfg.storage.report_dir == "reports"

    def test_load_config_returns_defaults_when_no_file(self, tmp_path: Path):
        from pwnpilot.config import load_config

        # Ensure no config.yaml in cwd
        cfg = load_config(config_path=tmp_path / "nonexistent.yaml")
        assert cfg.database.url == "sqlite:///pwnpilot.db"

    def test_load_config_from_yaml(self, tmp_path: Path):
        from pwnpilot.config import load_config

        config_data = {
            "database": {"url": "sqlite:///custom.db"},
            "llm": {"local_model": "mistral", "cloud_allowed": True},
            "agent": {"max_iterations": 100},
        }
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(config_data))

        cfg = load_config(config_path=config_file)
        assert cfg.database.url == "sqlite:///custom.db"
        assert cfg.llm.local_model == "mistral"
        assert cfg.llm.cloud_allowed is True
        assert cfg.agent.max_iterations == 100

    def test_env_var_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        from pwnpilot.config import load_config

        config_data = {"llm": {"local_model": "llama3"}}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(config_data))

        monkeypatch.setenv("PWNPILOT_LLM__LOCAL_MODEL", "phi3")
        monkeypatch.setenv("PWNPILOT_DATABASE__URL", "sqlite:///env_override.db")

        cfg = load_config(config_path=config_file)
        assert cfg.llm.local_model == "phi3"
        assert cfg.database.url == "sqlite:///env_override.db"

    def test_invalid_log_level_exits(self, tmp_path: Path):
        from pwnpilot.config import load_config
        import sys

        config_data = {"logging": {"level": "NONSENSE"}}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(config_data))

        with pytest.raises(SystemExit) as exc:
            load_config(config_path=config_file)
        assert exc.value.code == 1

    def test_valid_log_levels_accepted(self):
        from pwnpilot.config import LoggingConfig

        for level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            lc = LoggingConfig(level=level)
            assert lc.level == level

    def test_policy_config_bounds(self):
        from pwnpilot.config import PolicyConfig
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            PolicyConfig(active_scan_rate_limit=0)  # below ge=1

        with pytest.raises(pydantic.ValidationError):
            PolicyConfig(active_scan_rate_limit=999)  # above le=100

    def test_agent_config_max_iterations_bounds(self):
        from pwnpilot.config import AgentConfig
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            AgentConfig(max_iterations=0)

        with pytest.raises(pydantic.ValidationError):
            AgentConfig(max_iterations=501)

    def test_extra_keys_ignored(self, tmp_path: Path):
        from pwnpilot.config import load_config

        config_data = {"unknown_section": {"foo": "bar"}}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(config_data))

        cfg = load_config(config_path=config_file)
        assert cfg.database.url == "sqlite:///pwnpilot.db"  # still valid defaults


# ---------------------------------------------------------------------------
# Observability metrics
# ---------------------------------------------------------------------------


class TestEngagementMetrics:
    """Tests for pwnpilot.observability.metrics.EngagementMetrics."""

    def test_defaults(self):
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics("eng-001")
        assert m.engagement_id == "eng-001"
        assert m.iteration_count == 0
        assert m.policy_deny_count == 0
        assert m.parser_error_count == 0
        assert m.timeout_count == 0
        assert m.approval_count == 0
        assert m.tool_invocation_counts == {}

    def test_record_iteration(self):
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics("eng-002")
        m.record_iteration()
        m.record_iteration()
        assert m.iteration_count == 2

    def test_record_policy_deny_counts(self):
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics("eng-003")
        m.record_policy_deny("exploit_rce")
        m.record_policy_deny("exploit_rce")
        m.record_policy_deny("post_exploit")
        assert m.policy_deny_count == 3
        s = m.summary()
        assert s["policy_deny_by_type"]["exploit_rce"] == 2
        assert s["policy_deny_by_type"]["post_exploit"] == 1

    def test_record_tool_invoked(self):
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics("eng-004")
        m.record_tool_invoked("nmap", 412.3)
        m.record_tool_invoked("nmap", 390.1)
        m.record_tool_invoked("nikto", 800.0)
        counts = m.tool_invocation_counts
        assert counts["nmap"] == 2
        assert counts["nikto"] == 1

    def test_summary_tool_stats(self):
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics("eng-005")
        m.record_tool_invoked("nuclei", 100.0)
        m.record_tool_invoked("nuclei", 200.0)
        m.record_tool_invoked("nuclei", 300.0)
        s = m.summary()
        ts = s["tool_stats"]["nuclei"]
        assert ts["invocations"] == 3
        assert abs(ts["avg_latency_ms"] - 200.0) < 0.1
        assert ts["p95_latency_ms"] == 300.0

    def test_record_approval_latency(self):
        from pwnpilot.observability.metrics import EngagementMetrics
        import time

        m = EngagementMetrics("eng-006")
        t0 = m.record_approval_queued()
        time.sleep(0.02)  # ~20ms
        m.record_approval_resolved(t0)
        assert m.approval_count == 1
        lats = m.approval_latencies_ms
        assert len(lats) == 1
        assert lats[0] >= 10.0  # at least 10ms

    def test_record_kill_switch(self):
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics("eng-007")
        m.record_kill_switch()
        s = m.summary()
        assert s["kill_switch_triggers"] == 1

    def test_summary_contains_elapsed(self):
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics("eng-008")
        s = m.summary()
        assert "elapsed_seconds" in s
        assert s["elapsed_seconds"] >= 0.0

    def test_export_is_alias_for_summary(self):
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics("eng-009")
        m.record_iteration()
        assert m.export() == m.summary()

    def test_parser_error_and_timeout(self):
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics("eng-010")
        m.record_parser_error()
        m.record_timeout()
        m.record_timeout()
        assert m.parser_error_count == 1
        assert m.timeout_count == 2


class TestMetricsRegistry:
    """Tests for the global MetricsRegistry."""

    def test_get_or_create_returns_same_instance(self):
        from pwnpilot.observability.metrics import MetricsRegistry

        reg = MetricsRegistry()
        m1 = reg.get_or_create("eid-1")
        m2 = reg.get_or_create("eid-1")
        assert m1 is m2

    def test_get_returns_none_for_unknown(self):
        from pwnpilot.observability.metrics import MetricsRegistry

        reg = MetricsRegistry()
        assert reg.get("does-not-exist") is None

    def test_remove(self):
        from pwnpilot.observability.metrics import MetricsRegistry

        reg = MetricsRegistry()
        reg.get_or_create("eid-remove")
        reg.remove("eid-remove")
        assert reg.get("eid-remove") is None

    def test_all_summaries(self):
        from pwnpilot.observability.metrics import MetricsRegistry

        reg = MetricsRegistry()
        reg.get_or_create("eid-a")
        reg.get_or_create("eid-b")
        summaries = reg.all_summaries()
        ids = [s["engagement_id"] for s in summaries]
        assert "eid-a" in ids
        assert "eid-b" in ids


# ---------------------------------------------------------------------------
# TUI import smoke test (no terminal required)
# ---------------------------------------------------------------------------


class TestTUIImport:
    def test_tui_module_importable(self):
        import pwnpilot.tui.app as tui_app
        assert hasattr(tui_app, "TUIDashboard")
        assert hasattr(tui_app, "run_dashboard")

    def test_tui_init_importable(self):
        from pwnpilot.tui import TUIDashboard, run_dashboard
        assert TUIDashboard is not None
        assert run_dashboard is not None
