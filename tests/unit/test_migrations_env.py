from __future__ import annotations

import importlib
import sys
from contextlib import nullcontext
from types import SimpleNamespace

import pytest


class _FakeAlembicConfig:
    def __init__(self, main_url: str = "", section: dict | None = None) -> None:
        self.config_file_name = None
        self.config_ini_section = "alembic"
        self._main_url = main_url
        self._section = section or {}

    def get_main_option(self, key: str) -> str:
        if key == "sqlalchemy.url":
            return self._main_url
        return ""

    def get_section(self, name: str, default: dict | None = None) -> dict:
        return dict(self._section or default or {})


def _load_env_module(offline: bool):
    calls = {"configure": 0, "run_migrations": 0}

    fake_context = SimpleNamespace(
        config=_FakeAlembicConfig(),
        configure=lambda **kwargs: calls.__setitem__("configure", calls["configure"] + 1),
        begin_transaction=lambda: nullcontext(),
        run_migrations=lambda: calls.__setitem__("run_migrations", calls["run_migrations"] + 1),
        is_offline_mode=lambda: offline,
    )

    class _Conn:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return False

    class _Engine:
        def connect(self):
            return _Conn()

    module_name = "pwnpilot.migrations.env"
    sys.modules.pop(module_name, None)

    import alembic

    old_context = alembic.context
    alembic.context = fake_context
    try:
        mod = importlib.import_module(module_name)
        # If online path is chosen at import time, provide a fake connectable.
        mod.engine_from_config = lambda *args, **kwargs: _Engine()
        if not offline:
            mod.run_migrations_online()
    finally:
        alembic.context = old_context

    return mod, calls


def test_import_executes_offline_branch() -> None:
    _mod, calls = _load_env_module(offline=True)
    assert calls["configure"] >= 1
    assert calls["run_migrations"] >= 1


def test_import_executes_online_branch() -> None:
    _mod, calls = _load_env_module(offline=False)
    assert calls["configure"] >= 1
    assert calls["run_migrations"] >= 1


def test_get_db_url_prefers_env(monkeypatch: pytest.MonkeyPatch) -> None:
    mod, _ = _load_env_module(offline=True)
    monkeypatch.setenv("PWNPILOT_DB_URL", "sqlite:///custom.db")
    assert mod._get_db_url() == "sqlite:///custom.db"


def test_get_db_url_uses_typed_config_when_env_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    mod, _ = _load_env_module(offline=True)
    monkeypatch.delenv("PWNPILOT_DB_URL", raising=False)

    import pwnpilot.config

    monkeypatch.setattr(
        pwnpilot.config,
        "load_config",
        lambda: SimpleNamespace(database=SimpleNamespace(url="sqlite:///typed.db")),
    )
    assert mod._get_db_url() == "sqlite:///typed.db"


def test_get_db_url_falls_back_on_systemexit(monkeypatch: pytest.MonkeyPatch) -> None:
    mod, _ = _load_env_module(offline=True)
    monkeypatch.delenv("PWNPILOT_DB_URL", raising=False)

    import pwnpilot.config

    def _raise_system_exit():
        raise SystemExit(2)

    monkeypatch.setattr(pwnpilot.config, "load_config", _raise_system_exit)
    url = mod._get_db_url()
    assert url.startswith("sqlite:///")
    assert ".pwnpilot" in url


def test_run_migrations_offline_uses_configured_url() -> None:
    mod, _ = _load_env_module(offline=True)

    captured: dict = {}
    mod.config = _FakeAlembicConfig(main_url="sqlite:///from-main-option.db")
    mod.context = SimpleNamespace(
        configure=lambda **kwargs: captured.update(kwargs),
        begin_transaction=lambda: nullcontext(),
        run_migrations=lambda: captured.update({"ran": True}),
    )

    mod.run_migrations_offline()
    assert captured["url"] == "sqlite:///from-main-option.db"
    assert captured["render_as_batch"] is True
    assert captured["ran"] is True


def test_run_migrations_online_sets_url_and_runs() -> None:
    mod, _ = _load_env_module(offline=True)

    captured: dict = {}
    mod.config = _FakeAlembicConfig(section={"sqlalchemy.url": "sqlite:///placeholder.db"})
    mod._get_db_url = lambda: "sqlite:///resolved.db"

    class _Conn:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return False

    class _Engine:
        def connect(self):
            return _Conn()

    def _engine_from_config(cfg_section, prefix, poolclass):
        captured["cfg_section"] = dict(cfg_section)
        captured["prefix"] = prefix
        captured["poolclass"] = poolclass
        return _Engine()

    mod.engine_from_config = _engine_from_config
    mod.context = SimpleNamespace(
        configure=lambda **kwargs: captured.update(kwargs),
        begin_transaction=lambda: nullcontext(),
        run_migrations=lambda: captured.update({"ran": True}),
    )

    mod.run_migrations_online()

    assert captured["cfg_section"]["sqlalchemy.url"] == "sqlite:///resolved.db"
    assert captured["prefix"] == "sqlalchemy."
    assert captured["render_as_batch"] is True
    assert captured["ran"] is True
