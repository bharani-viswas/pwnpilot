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
    """
    Unified LLM configuration supporting 100+ providers via LiteLLM.
    
    Supports: OpenAI, Anthropic, Google, Ollama, vLLM, LocalAI, Mistral, Cohere, and 90+ more.
    
    QUICK START:
    ============
    Local Model (Privacy-First):
        model_name: "ollama/llama3"
        api_key: ""
        api_base_url: "http://localhost:11434"
    
    OpenAI GPT-4:
        model_name: "gpt-4"
        api_key: "sk-..."
        api_base_url: ""
    
    Claude 3:
        model_name: "claude-3-sonnet-20240229"
        api_key: "sk-ant-..."
        api_base_url: ""
    
    Self-Hosted vLLM:
        model_name: "mistral"
        api_key: ""
        api_base_url: "http://internal-gpu:8000/v1"
    
    ROUTING LOGIC:
    ==============
    1. Attempt primary model (local-first by default)
    2. Circuit breaker opens after 3 consecutive failures
    3. If circuit opens and policy allows: use fallback model
    4. Before cloud dispatch: sensitive data scrubbed via redactor
    5. Automatic retry with exponential backoff
    
    ENVIRONMENT VARIABLE OVERRIDE:
    ==============================
    All fields can be overridden: PWNPILOT_LLM__<FIELD_NAME>=value
    Examples:
        PWNPILOT_LLM__MODEL_NAME=gpt-4
        PWNPILOT_LLM__API_KEY=sk-...
        PWNPILOT_LLM__CLOUD_ALLOWED=true
    """
    model_name: str = Field(
        default="ollama/llama3",
        description="Model identifier for LiteLLM provider routing. Examples: 'gpt-4' (OpenAI), 'claude-3-sonnet-20240229' (Anthropic), 'gemini-pro' (Google), 'ollama/llama3' (local Ollama), 'mistral/mistral-large-latest' (Mistral AI). LiteLLM automatically detects the provider from the prefix.",
    )
    api_key: str = Field(
        default="",
        description="API key for the provider. Leave empty for local models (Ollama, vLLM on localhost). For cloud: set to your API key (OpenAI: sk-..., Anthropic: sk-ant-..., Google: your-key, Mistral: your-key). Can also be set via PWNPILOT_LLM__API_KEY env var for security.",
    )
    api_base_url: str = Field(
        default="",
        description="Custom API base URL for self-hosted or non-standard endpoints. Examples: 'http://localhost:11434' (Ollama), 'http://localhost:8000/v1' (vLLM on localhost), 'http://internal-gpu-01:8000/v1' (internal vLLM cluster), 'http://localhost:8080/v1' (LocalAI). Leave empty for official cloud APIs (OpenAI, Anthropic, Google, Mistral).",
    )
    fallback_model_name: str = Field(
        default="gpt-4o-mini",
        description="Fallback model when primary exhausts retries and cloud_allowed=true. Recommended: cheaper cloud provider for redundancy (e.g. 'gpt-3.5-turbo', 'claude-3-haiku-20240307', 'gemini-1.5-pro'). Circuit breaker opens after 3 failures before attempting fallback.",
    )
    fallback_api_key: str = Field(
        default="",
        description="API key for fallback model provider. Can be set via PWNPILOT_LLM__FALLBACK_API_KEY env var. Only used if primary model fails and cloud_allowed=true.",
    )
    fallback_api_base_url: str = Field(
        default="",
        description="Custom API base URL for fallback model (for self-hosted fallback endpoints). Leave empty for official cloud APIs.",
    )
    cloud_allowed: bool = Field(
        default=False,
        description="SECURITY GATE: Allow cloud LLM fallback when primary fails? true=may incur API costs, false=halt if primary fails (zero cloud costs). If true, make sure fallback_api_key is set (env var or config). Can override with PWNPILOT_LLM__CLOUD_ALLOWED env var.",
    )
    max_retries: int = Field(default=3, ge=1, le=10, description="Max retry attempts per model before circuit breaker opens. Includes exponential backoff: wait = min(1 * (2^attempt), 8) seconds.")
    timeout_seconds: int = Field(default=30, ge=5, le=300, description="Request timeout in seconds. Increase for slow models/networks (60-120 for local), decrease for fast failover (20-30 for cloud). A 60s timeout on localhost Ollama is typical.")
    
    # Backward compatibility aliases
    @property
    def local_model(self) -> str:
        """Backward compatibility: maps to model_name"""
        model = self.model_name
        if model.startswith("ollama/"):
            return model.split("/", 1)[1]
        return model
    
    @property
    def cloud_model(self) -> str:
        """Backward compatibility: maps to fallback_model_name"""
        return self.fallback_model_name


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
    stdout_format: str = Field(
        default="console",
        description="Stdout log format: console (human-readable) or json.",
    )
    rotation_days: int = Field(default=30, ge=1, le=365)

    @field_validator("level")
    @classmethod
    def level_must_be_valid(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"Log level must be one of {allowed}, got {v!r}")
        return v.upper()

    @field_validator("stdout_format")
    @classmethod
    def stdout_format_must_be_valid(cls, v: str) -> str:
        raw = (v or "console").strip().lower()
        allowed = {"console", "json"}
        if raw not in allowed:
            raise ValueError(f"stdout_format must be one of {allowed}, got {v!r}")
        return raw


class EngagementDefaults(BaseModel):
    valid_hours: int = Field(default=24, ge=1, le=720)
    operator_id: str = Field(default="operator")


class ToolsConfig(BaseModel):
    enabled_tools: list[str] = Field(
        default_factory=list,
        description="Optional allowlist of tool names. Empty means all discovered tools.",
    )
    disabled_tools: list[str] = Field(
        default_factory=list,
        description="Optional denylist of tool names.",
    )
    discovery_mode: str = Field(
        default="package",
        description="Tool discovery mode: package, entrypoints, package_and_entrypoints.",
    )
    plugin_package: str = Field(
        default="pwnpilot.plugins.adapters",
        description="Python package used for first-party adapter discovery.",
    )
    entrypoint_group: str = Field(
        default="pwnpilot.plugins",
        description="Python entry point group for third-party plugins.",
    )
    trust_mode: str = Field(
        default="first_party_only",
        description="Trust policy: first_party_only, allow_trusted_third_party, strict_signed_all.",
    )
    allow_unsigned_first_party: bool = Field(
        default=True,
        description="Allow unsigned first-party adapters when trust_mode is not strict.",
    )
    static_fallback_when_empty: bool = Field(
        default=False,
        description="If true, use built-in static adapters when registry resolves no enabled tools.",
    )
    memory_limit_mb: int = Field(
        default=2048,
        ge=256,
        le=16384,
        description="Maximum virtual memory per tool subprocess (MB). Default 2048MB. Increase for memory-intensive tools like Nuclei (min 2GB recommended).",
    )
    cpu_limit_seconds: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Maximum CPU time per tool subprocess (seconds). Default 300s (5 minutes).",
    )

    @field_validator("discovery_mode")
    @classmethod
    def discovery_mode_must_be_valid(cls, v: str) -> str:
        allowed = {"package", "entrypoints", "package_and_entrypoints"}
        if v not in allowed:
            raise ValueError(f"discovery_mode must be one of {allowed}, got {v!r}")
        return v

    @field_validator("trust_mode")
    @classmethod
    def trust_mode_must_be_valid(cls, v: str) -> str:
        allowed = {"first_party_only", "allow_trusted_third_party", "strict_signed_all"}
        if v not in allowed:
            raise ValueError(f"trust_mode must be one of {allowed}, got {v!r}")
        return v


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
    tools: ToolsConfig = Field(default_factory=ToolsConfig)

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

    # Backward compatibility aliases for v1 config keys.
    llm_cfg = raw.get("llm")
    if isinstance(llm_cfg, dict):
        if "local_model" in llm_cfg and "model_name" not in llm_cfg:
            llm_cfg["model_name"] = llm_cfg["local_model"]
        if "cloud_model" in llm_cfg and "fallback_model_name" not in llm_cfg:
            llm_cfg["fallback_model_name"] = llm_cfg["cloud_model"]

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

    # If explicit path is provided and missing, do not silently fall back to cwd/home.
    candidates = [config_path] if config_path else _CONFIG_SEARCH_PATHS
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
