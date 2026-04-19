from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from pwnpilot.runtime import (
    create_and_run_engagement,
    generate_report,
    get_approval_service,
    get_audit_store,
    get_tool_registry,
    resume_engagement,
)


def test_create_and_run_engagement_dry_run(monkeypatch) -> None:
    monkeypatch.setattr("pwnpilot.runtime._build_runtime", lambda config_path=None, engagement_id=None: {})

    eid = create_and_run_engagement(
        name="dry-run",
        scope_cidrs=["10.0.0.0/24"],
        scope_domains=[],
        scope_urls=[],
        roe_document_hash="a" * 64,
        authoriser_identity="operator",
        dry_run=True,
    )
    assert isinstance(eid, str)
    assert len(eid) > 10


def test_runtime_getters_and_generate_report(monkeypatch, tmp_path: Path) -> None:
    fake_approval = object()
    fake_audit = object()
    fake_registry = object()

    class _ReportGen:
        def build_bundle(self, engagement_id, output_dir):
            return output_dir / "bundle.json", output_dir / "summary.md"

    monkeypatch.setattr(
        "pwnpilot.runtime._build_runtime",
            lambda config_path=None, engagement_id=None: {
            "approval_service": fake_approval,
            "audit_store": fake_audit,
            "report_generator": _ReportGen(),
        },
    )
    monkeypatch.setattr("pwnpilot.runtime._load_typed_config", lambda config_path=None: SimpleNamespace())
    monkeypatch.setattr("pwnpilot.runtime._build_tool_registry_from_typed_config", lambda cfg: fake_registry)

    assert get_approval_service() is fake_approval
    assert get_audit_store() is fake_audit
    assert get_tool_registry() is fake_registry

    bundle, summary = generate_report(uuid4(), output_dir=tmp_path)
    assert bundle.name == "bundle.json"
    assert summary.name == "summary.md"


def test_resume_engagement_raises_when_checkpoint_missing(monkeypatch) -> None:
    fake_rt = {
        "typed_cfg": SimpleNamespace(database=SimpleNamespace(url="sqlite:///pwnpilot.db")),
        "audit_store": SimpleNamespace(append=lambda **kwargs: None),
    }
    monkeypatch.setattr("pwnpilot.runtime._build_runtime", lambda config_path=None, engagement_id=None: fake_rt)

    class _CP:
        def get_tuple(self, cfg):
            return None

    monkeypatch.setattr("pwnpilot.runtime.SqliteCheckpointer.from_path", lambda path: _CP())

    with pytest.raises(ValueError):
        resume_engagement(uuid4())


def test_create_and_run_engagement_full_path(monkeypatch, tmp_path: Path) -> None:
    class _Caps:
        def contracts_for_tools(self, _tools):
            return []

    fake_rt = {
        "llm_router": object(),
        "audit_store": SimpleNamespace(append=lambda **kwargs: None),
        "finding_store": object(),
        "recon_store": object(),
        "tool_runner": object(),
        "event_bus": object(),
        "approval_service": object(),
        "report_generator": object(),
        "kill_switch": object(),
        "planner_available_tools": ["nmap"],
        "planner_tools_catalog": [{"tool_name": "nmap"}],
        "capability_registry": _Caps(),
        "target_resolver": object(),
        "runtime_mode": "headless",
        "has_display": False,
        "typed_cfg": SimpleNamespace(
            storage=SimpleNamespace(report_dir=str(tmp_path / "reports")),
            database=SimpleNamespace(url="sqlite:///pwnpilot.db"),
        ),
    }

    monkeypatch.setattr("pwnpilot.runtime._build_runtime", lambda config_path=None, engagement_id=None: fake_rt)
    monkeypatch.setattr("pwnpilot.runtime.PlannerNode", lambda **kwargs: object())
    monkeypatch.setattr("pwnpilot.runtime.ValidatorNode", lambda **kwargs: object())
    monkeypatch.setattr("pwnpilot.runtime.ExecutorNode", lambda **kwargs: object())
    monkeypatch.setattr("pwnpilot.runtime.ReporterNode", lambda **kwargs: object())
    monkeypatch.setattr("pwnpilot.runtime.build_graph", lambda *args, **kwargs: object())

    class _Sup:
        def __init__(self, **kwargs):
            pass

        def run(self, initial_state, thread_id):
            return {"error": None}

    monkeypatch.setattr("pwnpilot.runtime.Supervisor", _Sup)
    monkeypatch.setattr("pwnpilot.runtime.SqliteCheckpointer.from_path", lambda path: object())

    eid = create_and_run_engagement(
        name="full-path",
        scope_cidrs=["10.0.0.0/24"],
        scope_domains=[],
        scope_urls=["http://example.com"],
        roe_document_hash="a" * 64,
        authoriser_identity="authorizer",
        dry_run=False,
    )
    assert isinstance(eid, str)


def test_resume_engagement_success_path(monkeypatch, tmp_path: Path) -> None:
    class _Caps:
        def contracts_for_tools(self, _tools):
            return []

    class _Tuple:
        checkpoint = {
            "id": "cp-1",
            "channel_values": {"engagement_id": "name-from-state"},
        }

    class _CP:
        def get_tuple(self, cfg):
            return _Tuple()

    fake_rt = {
        "typed_cfg": SimpleNamespace(
            storage=SimpleNamespace(report_dir=str(tmp_path / "reports")),
            database=SimpleNamespace(url="sqlite:///pwnpilot.db"),
        ),
        "audit_store": SimpleNamespace(append=lambda **kwargs: None),
        "llm_router": object(),
        "finding_store": object(),
        "recon_store": object(),
        "tool_runner": object(),
        "approval_service": object(),
        "report_generator": object(),
        "kill_switch": object(),
        "planner_available_tools": ["nmap"],
        "planner_tools_catalog": [{"tool_name": "nmap"}],
        "capability_registry": _Caps(),
        "target_resolver": object(),
        "runtime_mode": "headless",
        "has_display": False,
        "event_bus": object(),
    }

    monkeypatch.setattr("pwnpilot.runtime._build_runtime", lambda config_path=None, engagement_id=None: fake_rt)
    monkeypatch.setattr("pwnpilot.runtime.SqliteCheckpointer.from_path", lambda path: _CP())
    monkeypatch.setattr("pwnpilot.runtime.PlannerNode", lambda **kwargs: object())
    monkeypatch.setattr("pwnpilot.runtime.ValidatorNode", lambda **kwargs: object())
    monkeypatch.setattr("pwnpilot.runtime.ExecutorNode", lambda **kwargs: object())
    monkeypatch.setattr("pwnpilot.runtime.ReporterNode", lambda **kwargs: object())
    monkeypatch.setattr("pwnpilot.runtime.build_graph", lambda *args, **kwargs: object())

    class _Sup:
        def __init__(self, **kwargs):
            pass

        def run(self, initial_state, thread_id):
            return {"error": None}

    monkeypatch.setattr("pwnpilot.runtime.Supervisor", _Sup)

    eid = uuid4()
    resumed = resume_engagement(eid)
    assert resumed == str(eid)
