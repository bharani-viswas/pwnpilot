from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pwnpilot.runtime import run_startup_checks


def test_run_startup_checks_reports_migration_not_head() -> None:
    mock_session = MagicMock()

    with patch("pwnpilot.runtime._load_typed_config", return_value=SimpleNamespace()):
        with patch("pwnpilot.runtime.get_db_session", return_value=mock_session):
            with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="abc", stderr="")):
                with patch("pathlib.Path.exists", return_value=True):
                    with patch("pwnpilot.runtime._build_tool_registry_from_typed_config") as reg:
                        reg.return_value.binary_requirements.return_value = {}
                        issues = run_startup_checks()

    assert any("MIGRATIONS: database is not at head" in i for i in issues)


def test_run_startup_checks_reports_missing_alembic_binary() -> None:
    mock_session = MagicMock()

    with patch("pwnpilot.runtime._load_typed_config", return_value=SimpleNamespace()):
        with patch("pwnpilot.runtime.get_db_session", return_value=mock_session):
            with patch("subprocess.run", side_effect=FileNotFoundError()):
                with patch("pathlib.Path.exists", return_value=True):
                    with patch("pwnpilot.runtime._build_tool_registry_from_typed_config") as reg:
                        reg.return_value.binary_requirements.return_value = {}
                        issues = run_startup_checks()

    assert any("MIGRATIONS: alembic binary not found" in i for i in issues)


def test_run_startup_checks_reports_missing_tool_binaries() -> None:
    mock_session = MagicMock()
    fake_registry = MagicMock()
    fake_registry.binary_requirements.return_value = {"zap": "zaproxy", "nmap": "nmap"}

    with patch("pwnpilot.runtime._load_typed_config", return_value=SimpleNamespace()):
        with patch("pwnpilot.runtime.get_db_session", return_value=mock_session):
            with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="(head)", stderr="")):
                with patch("pathlib.Path.exists", return_value=True):
                    with patch("pwnpilot.runtime._build_tool_registry_from_typed_config", return_value=fake_registry):
                        with patch("pwnpilot.runtime.resolve_binary_for_tool", side_effect=[None, "/usr/bin/nmap"]):
                            with patch("pwnpilot.runtime.candidate_binaries", return_value=["zaproxy", "zap.sh"]):
                                issues = run_startup_checks()

    assert any("TOOLS: binaries not on PATH" in i and "zap" in i for i in issues)
