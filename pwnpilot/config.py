"""
Config management — Pydantic-validated configuration for pwnpilot.

Config is loaded from (in priority order):
1. Path passed explicitly to load_config()
2. $PWNPILOT_CONFIG env var
3. ./config.yaml  (cwd)
4. ~/.pwnpilot/config.yaml

All values can be overridden with PWNPILOT_<SECTION>__<KEY> env vars
(double underscore separates nested keys).  E.g.:
    PWNPILOT_LLM__LOCAL_MODEL=mistral
    PWNPILOT_DATABASE__URL=postgresql://...

Startup hard-fails with a clear message if required fields are missing.

Usage::

    from pwnpilot.config import load_config, PwnpilotConfig

    cfg = load_config()          # auto-detect from filesystem
    print(cfg.llm.local_model)   # 'llama3'
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator, ValidationError

# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class DatabaseConfig(BaseModel):
    url: str = Field(
        default="sqlite:///pwnpilot.db",
        description="SQLAlchemy database URL",
    )
    pool_size: int = Field(default=5, ge=1, le=50)
    max_overflow: int = Field(default=10, ge=0, le=100)


class LLMConfig(BaseModel):
    local_url: str = Field(
        default="http://localhost:11434",
        description="Ollama / vLLM inference server base URL",
    )
    local_model: str = Field(default="llama3")
    validator_model: str = Field(default="mistral")
    cloud_provider: str = Field(default="openai")
    cloud_model: str = Field(default="gpt-4o-mini")
    cloud_allowed: bool = Field(
        default=False,
        description="Enable cloud LLM fallback (requires API key env var)",
    )
    max_retries: int = Field(default=3, ge=1, le=10)
    timeout_seconds: int = Field(default=30, ge=5, le=300)


class PolicyConfig(BaseModel):
    active_scan_rate_limit: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Max active_scan actions per minute",
    )
    recon_passive_soft_limit: int = Field(
        default=60,
        ge=1,
        le=1000,
        description="Soft rate limit for recon_passive (warn only)",
    )
    require_approval_for_exploit: bool = Field(default=True)
    require_approval_for_post_exploit: bool = Field(default=True)


class AgentConfig(BaseModel):
    max_iterations: int = Field(default=50, ge=1, le=500)
    convergence_threshold: int = Field(
        default=3,
        ge=1,
        le=20,
        description="Consecutive no-new-findings cycles before triggering report",
    )


class StorageConfig(BaseModel):
    evidence_dir: str = Field(
        default="~/.pwnpilot/evidence",
        description="Root directory for raw evidence files",
    )
    report_dir: str = Field(
        default="reports",
        description="Output directory for generated reports",
    )


class LoggingConfig(BaseModel):
    level: str = Field(default="INFO")
    file: str = Field(
        default="",
        description="Log file path (empty = stdout only)",
    )
    rotation_days: int = Field(default=30, ge=1, le=365)

    @field_validator("level")
    @classmethod
    def level_must_be_valid(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"Log level must be one of {allowed}, got {v!r}")
        return v.upper()


class EngagementDefaults(BaseModel):
    valid_hours: int = Field(default=24, ge=1, le=720)
    operator_id: str = Field(default="operator")


# ---------------------------------------------------------------------------
# Root config model
# ---------------------------------------------------------------------------


class PwnpilotConfig(BaseModel):
    """Root configuration model for the pwnpilot framework."""

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    engagement: EngagementDefaults = Field(default_factory=EngagementDefaults)

    model_config = {"extra": "ignore"}  # tolerate unknown top-level keys


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_ENV_PREFIX = "PWNPILOT_"


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Apply PWNPILOT_SECTION__KEY env vars onto the raw config dict.

    E.g. PWNPILOT_LLM__LOCAL_MODEL=mistral writes raw["llm"]["local_model"]="mistral".
    """
    for key, value in os.environ.items():
        if not key.startswith(_ENV_PREFIX):
            continue
        parts = key[len(_ENV_PREFIX):].lower().split("__", maxsplit=1)
        if len(parts) == 2:
            section, field = parts
            raw.setdefault(section, {})[field] = value
        elif len(parts) == 1:
            raw[parts[0]] = value
    return raw


_CONFIG_SEARCH_PATHS = [
    Path(os.environ.get("PWNPILOT_CONFIG", "")),
    Path("config.yaml"),
    Path.home() / ".pwnpilot" / "config.yaml",
]


def load_config(config_path: Path | None = None) -> PwnpilotConfig:
    """
    Load and validate the configuration.

    Raises SystemExit with a human-readable message on validation failure.
    """
    raw: dict[str, Any] = {}

    candidates = ([config_path] if config_path else []) + _CONFIG_SEARCH_PATHS
    for path in candidates:
        if path and path.exists() and path.is_file():
            with path.open() as fh:
                loaded = yaml.safe_load(fh) or {}
                raw.update(loaded)
            break

    raw = _apply_env_overrides(raw)

    try:
        return PwnpilotConfig(**raw)
    except ValidationError as exc:
        # Hard-fail with a clear message — never start with invalid config
        import sys
        lines = ["[pwnpilot] Configuration validation failed:\n"]
        for err in exc.errors():
            loc = " → ".join(str(e) for e in err["loc"])
            lines.append(f"  {loc}: {err['msg']}")
        print("\n".join(lines), file=sys.stderr)
        sys.exit(1)
