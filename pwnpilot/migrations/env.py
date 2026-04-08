"""
Alembic migration environment for the pwnpilot framework.

Combines the metadata from all four SQLAlchemy Base objects so that a single
``alembic upgrade head`` creates / migrates all application tables.

Database URL resolution (highest priority first):
  1. $PWNPILOT_DB_URL  environment variable
  2. $PWNPILOT_CONFIG  → config.yaml database.url
  3. ./config.yaml     database.url
  4. ~/.pwnpilot/config.yaml database.url
  5. Fallback: sqlite:///pwnpilot.db
"""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import MetaData, create_engine, pool
from sqlalchemy import engine_from_config

from alembic import context

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so pwnpilot imports work
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Import all four ORM bases (one per data-store module)
# ---------------------------------------------------------------------------
from pwnpilot.data.audit_store import Base as AuditBase
from pwnpilot.data.evidence_store import Base as EvidenceBase
from pwnpilot.data.finding_store import Base as FindingBase
from pwnpilot.data.recon_store import Base as ReconBase
from pwnpilot.data.approval_store import _Base as ApprovalBase

# Merge all table metadata into a single combined MetaData object.
# Alembic's autogenerate will diff against this combined metadata.
_combined = MetaData()
for base in (AuditBase, EvidenceBase, FindingBase, ReconBase, ApprovalBase):
    for table in base.metadata.tables.values():
        table.to_metadata(_combined)

target_metadata = _combined

# ---------------------------------------------------------------------------
# Alembic config object
# ---------------------------------------------------------------------------
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _get_db_url() -> str:
    """Resolve the database URL from environment / config file / fallback."""
    env_url = os.environ.get("PWNPILOT_DB_URL")
    if env_url:
        return env_url

    # Try loading via pwnpilot.config (handles config.yaml + env-var overrides)
    try:
        from pwnpilot.config import load_config

        cfg = load_config()
        return cfg.database.url
    except SystemExit:
        # Hard validation failure — fall back to default
        pass
    except Exception:
        pass

    # Use absolute path for consistency with config.py
    from pathlib import Path
    return f"sqlite:///{Path.home() / '.pwnpilot' / 'pwnpilot.db'}"


# ---------------------------------------------------------------------------
# Offline migration
# ---------------------------------------------------------------------------


def run_migrations_offline() -> None:
    """Emit migration SQL to stdout without a live DB connection."""
    url = config.get_main_option("sqlalchemy.url") or _get_db_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # required for SQLite ALTER TABLE support
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migration
# ---------------------------------------------------------------------------


def run_migrations_online() -> None:
    """Run migrations against a live DB connection."""
    # Prefer the programmatic URL over alembic.ini placeholder
    cfg_section = config.get_section(config.config_ini_section, {})
    resolved_url = _get_db_url()
    cfg_section["sqlalchemy.url"] = resolved_url

    connectable = engine_from_config(
        cfg_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # required for SQLite ALTER TABLE support
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

