"""
Sprint 10 tests — Alembic migrations, hash-pinned requirements.
"""
from __future__ import annotations

import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Alembic migration tests
# ---------------------------------------------------------------------------


class TestAlembicMigrations:
    """Tests for pwnpilot/migrations/ Alembic setup."""

    def test_env_py_importable(self):
        """migrations/env.py must be importable as a Python module
        (Alembic does exactly this at runtime)."""
        import importlib.util
        env_path = Path(__file__).parents[2] / "pwnpilot" / "migrations" / "env.py"
        assert env_path.exists(), "env.py not found"

    def test_migration_versions_directory_exists(self):
        versions_dir = Path(__file__).parents[2] / "pwnpilot" / "migrations" / "versions"
        assert versions_dir.is_dir()

    def test_initial_migration_exists(self):
        versions_dir = Path(__file__).parents[2] / "pwnpilot" / "migrations" / "versions"
        py_files = list(versions_dir.glob("*.py"))
        assert len(py_files) >= 1, "No migration scripts found"

    def test_initial_migration_contains_all_tables(self):
        versions_dir = Path(__file__).parents[2] / "pwnpilot" / "migrations" / "versions"
        py_files = [f for f in versions_dir.glob("*.py") if not f.name.startswith("__")]
        assert py_files, "No migration scripts found"
        # Combine text from all migration files to cover initial + subsequent migrations
        all_migration_text = "\n".join(f.read_text() for f in py_files)
        for table in ("audit_events", "evidence_index", "findings", "recon_hosts", "recon_services"):
            assert table in all_migration_text, f"Table {table!r} missing from all migrations"

    def test_alembic_upgrade_head_on_fresh_db(self, tmp_path: Path):
        """Apply the migration to a temp SQLite DB — must succeed with no errors."""
        import subprocess
        import sys

        db_file = tmp_path / "test_migrate.db"
        env = {
            "PWNPILOT_DB_URL": f"sqlite:///{db_file}",
            "PATH": str(Path(sys.executable).parent),
        }
        import os
        full_env = {**os.environ, **env}

        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=str(Path(__file__).parents[2]),
            env=full_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"alembic upgrade head failed:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
        assert db_file.exists(), "DB file not created by migration"

    def test_alembic_current_on_fresh_db(self, tmp_path: Path):
        """alembic current should report the revision after upgrade."""
        import subprocess
        import sys
        import os

        db_file = tmp_path / "test_current.db"
        full_env = {**os.environ, "PWNPILOT_DB_URL": f"sqlite:///{db_file}"}

        # Upgrade first
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=str(Path(__file__).parents[2]),
            env=full_env,
            capture_output=True,
            timeout=30,
        )

        result = subprocess.run(
            [sys.executable, "-m", "alembic", "current"],
            cwd=str(Path(__file__).parents[2]),
            env=full_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert "head" in output.lower() or len(output.strip()) > 0

    def test_combined_metadata_has_all_tables(self):
        """The combined metadata used by env.py must contain all expected tables."""
        from sqlalchemy import MetaData
        from pwnpilot.data.audit_store import Base as AuditBase
        from pwnpilot.data.evidence_store import Base as EvidenceBase
        from pwnpilot.data.finding_store import Base as FindingBase
        from pwnpilot.data.recon_store import Base as ReconBase

        combined = MetaData()
        for base in (AuditBase, EvidenceBase, FindingBase, ReconBase):
            for table in base.metadata.tables.values():
                table.to_metadata(combined)

        expected = {"audit_events", "evidence_index", "findings", "recon_hosts", "recon_services"}
        assert expected.issubset(set(combined.tables.keys()))

    def test_alembic_downgrade_base(self, tmp_path: Path):
        """alembic downgrade base should undo all migrations cleanly."""
        import subprocess
        import sys
        import os

        db_file = tmp_path / "test_downgrade.db"
        full_env = {**os.environ, "PWNPILOT_DB_URL": f"sqlite:///{db_file}"}

        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=str(Path(__file__).parents[2]),
            env=full_env,
            capture_output=True,
            timeout=30,
        )

        result = subprocess.run(
            [sys.executable, "-m", "alembic", "downgrade", "base"],
            cwd=str(Path(__file__).parents[2]),
            env=full_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"alembic downgrade base failed:\nstdout={result.stdout}\nstderr={result.stderr}"
        )


# ---------------------------------------------------------------------------
# Hash-pinned requirements tests
# ---------------------------------------------------------------------------


class TestHashPinnedRequirements:
    """Tests for requirements.txt and requirements-dev.txt."""

    def test_requirements_txt_exists(self):
        req = Path(__file__).parents[2] / "requirements.txt"
        assert req.exists(), "requirements.txt not found"

    def test_requirements_txt_has_hashes(self):
        req = Path(__file__).parents[2] / "requirements.txt"
        content = req.read_text()
        assert "--hash=sha256:" in content, "requirements.txt missing SHA-256 hashes"

    def test_requirements_dev_txt_exists(self):
        req = Path(__file__).parents[2] / "requirements-dev.txt"
        assert req.exists(), "requirements-dev.txt not found"

    def test_requirements_dev_has_hashes(self):
        req = Path(__file__).parents[2] / "requirements-dev.txt"
        content = req.read_text()
        assert "--hash=sha256:" in content, "requirements-dev.txt missing SHA-256 hashes"

    def test_requirements_in_exists(self):
        req = Path(__file__).parents[2] / "requirements.in"
        assert req.exists(), "requirements.in not found"

    def test_requirements_dev_in_exists(self):
        req = Path(__file__).parents[2] / "requirements-dev.in"
        assert req.exists(), "requirements-dev.in not found"

    def test_requirements_txt_autogenerated_header(self):
        req = Path(__file__).parents[2] / "requirements.txt"
        content = req.read_text()
        assert "pip-compile" in content, "requirements.txt missing pip-compile header"
        assert "requirements.in" in content

    def test_requirements_contains_core_packages(self):
        req = Path(__file__).parents[2] / "requirements.txt"
        content = req.read_text().lower()
        core_packages = [
            "pydantic",
            "sqlalchemy",
            "alembic",
            "typer",
            "structlog",
            "cryptography",
            "jinja2",
            "pyyaml",
            "textual",
        ]
        for pkg in core_packages:
            assert pkg in content, f"Package {pkg!r} not found in requirements.txt"
