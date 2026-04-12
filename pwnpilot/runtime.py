"""
Runtime — wires together control plane, agent layer, data stores, and tool runner.

Provides the high-level entry points used by the CLI:
  - create_and_run_engagement()
  - resume_engagement()
  - generate_report()
  - get_approval_service()
  - get_db_session()
  - run_policy_simulation()
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog
import yaml
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

from pwnpilot.agent.checkpointer import SqliteCheckpointer
from pwnpilot.config import PwnpilotConfig, load_config as _pydantic_load_config
from pwnpilot.agent.executor import ExecutorNode
from pwnpilot.agent.planner import PlannerNode
from pwnpilot.agent.reporter import ReporterNode
from pwnpilot.agent.state import AgentState
from pwnpilot.agent.supervisor import Supervisor, build_graph
from pwnpilot.agent.validator import ValidatorNode
from pwnpilot.control.approval import ApprovalService
from pwnpilot.control.target_strategy import build_engagement_strategy
from pwnpilot.data.approval_store import ApprovalStore
from pwnpilot.control.engagement import EngagementService
from pwnpilot.control.llm_router import LLMRouter
from pwnpilot.control.policy import PolicyEngine
from pwnpilot.data.audit_store import AuditStore
from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.data.finding_store import FindingStore
from pwnpilot.data.models import Engagement, EngagementScope
from pwnpilot.data.recon_store import ReconStore
from pwnpilot.governance.authorization import AuthorizationArtifact, assert_authorized
from pwnpilot.governance.kill_switch import KillSwitch
from pwnpilot.governance.simulation import SimulationEngine
from pwnpilot.plugins.loader import PluginLoader
from pwnpilot.plugins.binaries import candidate_binaries, resolve_binary_for_tool
from pwnpilot.plugins.policy import PluginTrustPolicy
from pwnpilot.plugins.runner import ToolRunner
from pwnpilot.plugins.registry import ToolRegistry
from pwnpilot.observability.logging_setup import configure_logging_from_config
from pwnpilot.reporting.generator import ReportGenerator
from pwnpilot.secrets.redactor import Redactor

log = structlog.get_logger(__name__)

_REGISTRY_CACHE_LOCK = threading.Lock()
_REGISTRY_CACHE: dict[tuple[str, str, str, str, str, tuple[str, ...], tuple[str, ...]], ToolRegistry] = {}

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

_CONFIG_SEARCH_PATHS = [
    Path(os.environ.get("PWNPILOT_CONFIG", "")) if os.environ.get("PWNPILOT_CONFIG") else None,
    Path("config.yaml"),
    Path.home() / ".pwnpilot" / "config.yaml",
]


def _load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load YAML config from known locations.  Returns empty dict if not found."""
    candidates = ([config_path] if config_path else []) + _CONFIG_SEARCH_PATHS
    for path in candidates:
        if path and path.exists() and path.is_file():
            with path.open() as fh:
                return yaml.safe_load(fh) or {}
    return {}


def _load_typed_config(config_path: Path | None = None) -> PwnpilotConfig:
    """Return a validated PwnpilotConfig (hard-fails on invalid config)."""
    return _pydantic_load_config(config_path)


def invalidate_tool_registry_cache() -> None:
    with _REGISTRY_CACHE_LOCK:
        _REGISTRY_CACHE.clear()


def _build_tool_registry_from_typed_config(typed_cfg: PwnpilotConfig) -> ToolRegistry:
    tools_cfg = getattr(typed_cfg, "tools", None)
    trust_mode = str(getattr(tools_cfg, "trust_mode", "first_party_only"))
    allow_unsigned_first_party = bool(getattr(tools_cfg, "allow_unsigned_first_party", True))
    plugin_package = str(getattr(tools_cfg, "plugin_package", "pwnpilot.plugins.adapters"))
    entrypoint_group = str(getattr(tools_cfg, "entrypoint_group", "pwnpilot.plugins"))
    discovery_mode = str(getattr(tools_cfg, "discovery_mode", "package"))

    enabled_tools_raw = getattr(tools_cfg, "enabled_tools", []) if tools_cfg else []
    disabled_tools_raw = getattr(tools_cfg, "disabled_tools", []) if tools_cfg else []
    enabled_tools = enabled_tools_raw if isinstance(enabled_tools_raw, list) else []
    disabled_tools = disabled_tools_raw if isinstance(disabled_tools_raw, list) else []

    cache_key = (
        trust_mode,
        str(allow_unsigned_first_party),
        plugin_package,
        entrypoint_group,
        discovery_mode,
        tuple(sorted(enabled_tools)),
        tuple(sorted(disabled_tools)),
    )
    with _REGISTRY_CACHE_LOCK:
        cached = _REGISTRY_CACHE.get(cache_key)
        if cached is not None:
            return cached

    trust_policy = PluginTrustPolicy(
        mode=trust_mode,
        allow_unsigned_first_party=allow_unsigned_first_party,
    )
    loader = PluginLoader(
        trust_policy=trust_policy,
        package_name=plugin_package,
        entrypoint_group=entrypoint_group,
        discovery_mode=discovery_mode,
    )
    registry = loader.load_registry(
        enabled_tools=enabled_tools,
        disabled_tools=disabled_tools,
    )
    with _REGISTRY_CACHE_LOCK:
        _REGISTRY_CACHE[cache_key] = registry
    return registry


def _emit_plugin_load_audit(audit_store: AuditStore, tool_registry: ToolRegistry) -> None:
    system_engagement_id = UUID(int=0)
    for tool_name, desc in tool_registry.tools.items():
        payload = {
            "tool_name": tool_name,
            "enabled": desc.enabled,
            "enablement_source": desc.enablement_source,
            "source": desc.source,
            "risk_class": desc.risk_class,
            "binary_name": desc.binary_name,
            "trust_status": desc.trust_status,
            "trust_reason": desc.trust_reason,
            "manifest_version": desc.manifest_version,
            "manifest_schema_version": desc.manifest_schema_version,
            "load_error": desc.load_error,
            "loaded_at": desc.loaded_at,
            "verified_at": desc.verified_at,
        }
        try:
            audit_store.append(
                engagement_id=system_engagement_id,
                actor="system",
                event_type="PluginLoad",
                payload=payload,
            )
        except Exception as exc:
            log.warning("runtime.plugin_audit_failed", tool=tool_name, exc=str(exc))


def _compute_executable_tool_names(tool_registry: ToolRegistry) -> list[str]:
    """Return tools that are both enabled and executable in the current environment."""
    executable: list[str] = []
    for tool_name, desc in tool_registry.enabled_tools.items():
        binary = (desc.binary_name or "").strip()
        if not binary:
            executable.append(tool_name)
            continue
        if resolve_binary_for_tool(tool_name, binary):
            executable.append(tool_name)
    return sorted(executable)


def _filter_tools_catalog(
    tools_catalog: list[dict[str, Any]],
    allowed_tools: list[str],
) -> list[dict[str, Any]]:
    allowed = set(allowed_tools)
    return [t for t in tools_catalog if t.get("tool_name") in allowed]


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------


def get_db_session(config_path: Path | None = None) -> Any:
    cfg = _load_config(config_path)
    db_url = (
        os.environ.get("PWNPILOT_DB_URL")
        or cfg.get("database", {}).get("url")
        or "sqlite:///pwnpilot.db"
    )
    if db_url.startswith("sqlite"):
        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(engine, "connect")
        def _wal(conn: Any, _: Any) -> None:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")

    elif "postgresql" in db_url or "postgres" in db_url:
        engine = create_engine(
            db_url,
            poolclass=QueuePool,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
        )
    else:
        engine = create_engine(db_url)

    Session = sessionmaker(bind=engine)
    return Session()


# ---------------------------------------------------------------------------
# Full runtime factory
# ---------------------------------------------------------------------------


def _build_runtime(
    config_path: Path | None = None,
) -> dict[str, Any]:
    """Build and return all runtime components."""
    cfg = _load_config(config_path)
    typed_cfg = _load_typed_config(config_path)

    # Configure process-wide structured logging from runtime config.
    configure_logging_from_config(getattr(typed_cfg, "logging", None))

    session = get_db_session(config_path)

    evidence_dir = Path(
        os.environ.get("PWNPILOT_EVIDENCE_DIR")
        or typed_cfg.storage.evidence_dir
    ).expanduser()

    # Stores
    audit_store = AuditStore(session)
    evidence_store = EvidenceStore(base_dir=evidence_dir, session=session)
    recon_store = ReconStore(session)
    finding_store = FindingStore(session)
    from pwnpilot.data.permission_store import PermissionStore
    permission_store = PermissionStore(session)

    # Governance — kill switch wired to audit store for KillSwitchTriggered events
    def _kill_switch_audit(reason: str) -> None:
        try:
            audit_store.append(
                engagement_id=None,  # type: ignore[arg-type]
                actor="system",
                event_type="KillSwitchTriggered",
                payload={"reason": reason},
            )
        except Exception:
            pass  # Never let audit failure suppress the kill switch

    kill_switch = KillSwitch(audit_fn=_kill_switch_audit)

    # Registry-driven plugin loading
    tool_registry = _build_tool_registry_from_typed_config(typed_cfg)
    adapters = tool_registry.adapters_for_runner()

    _emit_plugin_load_audit(audit_store, tool_registry)

    if not adapters:
        log.warning("runtime.no_tools_loaded", reason="No enabled tools were loaded from registry")
        if bool(getattr(getattr(typed_cfg, "tools", None), "static_fallback_when_empty", False)):
            from pwnpilot.plugins.adapters.cve_enrich import CveEnrichAdapter
            from pwnpilot.plugins.adapters.dns import DnsAdapter
            from pwnpilot.plugins.adapters.gobuster import GobusterAdapter
            from pwnpilot.plugins.adapters.nikto import NiktoAdapter
            from pwnpilot.plugins.adapters.nmap import NmapAdapter
            from pwnpilot.plugins.adapters.nuclei import NucleiAdapter
            from pwnpilot.plugins.adapters.searchsploit import SearchsploitAdapter
            from pwnpilot.plugins.adapters.shell import ShellAdapter
            from pwnpilot.plugins.adapters.sqlmap import SqlmapAdapter
            from pwnpilot.plugins.adapters.whatweb import WhatWebAdapter
            from pwnpilot.plugins.adapters.whois import WhoisAdapter
            from pwnpilot.plugins.adapters.zap import ZapAdapter

            adapters = {
                "nmap": NmapAdapter(),
                "nikto": NiktoAdapter(),
                "nuclei": NucleiAdapter(),
                "searchsploit": SearchsploitAdapter(),
                "shell": ShellAdapter(),  # Shell adapter without permission context (permissions granted via approval flow)
                "sqlmap": SqlmapAdapter(),
                "whatweb": WhatWebAdapter(),
                "whois": WhoisAdapter(),
                "dns": DnsAdapter(),
                "gobuster": GobusterAdapter(),
                "zap": ZapAdapter(),
                "cve_enrich": CveEnrichAdapter(),
            }
            log.warning("runtime.static_fallback_enabled", tools=sorted(adapters.keys()))

    # Tool runner — pass memory/CPU limits from config
    tools_cfg = getattr(typed_cfg, "tools", None)
    mem_limit_mb = int(getattr(tools_cfg, "memory_limit_mb", 2048)) if tools_cfg else 2048
    cpu_limit_sec = int(getattr(tools_cfg, "cpu_limit_seconds", 300)) if tools_cfg else 300
    
    tool_runner = ToolRunner(
        adapters=adapters,
        evidence_store=evidence_store,
        kill_switch=kill_switch,
        mem_limit=mem_limit_mb * 1024 * 1024,  # Convert MB to bytes
        cpu_limit=cpu_limit_sec,
    )

    planner_available_tools = _compute_executable_tool_names(tool_registry)
    if not planner_available_tools:
        planner_available_tools = tool_runner.available_tools
    planner_tools_catalog = _filter_tools_catalog(
        tool_registry.planner_context().get("tools_catalog", []),
        planner_available_tools,
    )

    # LLM router — unified multi-provider support via LiteLLM
    redactor = Redactor()
    llm_router = LLMRouter(
        model_name=typed_cfg.llm.model_name,
        api_key=typed_cfg.llm.api_key,
        api_base_url=typed_cfg.llm.api_base_url,
        fallback_model_name=typed_cfg.llm.fallback_model_name,
        fallback_api_key=typed_cfg.llm.fallback_api_key,
        fallback_api_base_url=typed_cfg.llm.fallback_api_base_url,
        cloud_allowed_fn=lambda: typed_cfg.llm.cloud_allowed,
        redactor=redactor,
        timeout_seconds=typed_cfg.llm.timeout_seconds,
        max_retries=typed_cfg.llm.max_retries,
    )

    # Approval service — wired to DB for crash durability
    approval_store = ApprovalStore(session)
    approval_service = ApprovalService(
        persist_fn=approval_store.upsert,
        load_fn=approval_store.load_pending,
    )

    # Report generator
    report_generator = ReportGenerator(
        finding_store=finding_store,
        recon_store=recon_store,
        evidence_store=evidence_store,
        audit_store=audit_store,
    )

    return {
        "session": session,
        "audit_store": audit_store,
        "evidence_store": evidence_store,
        "recon_store": recon_store,
        "finding_store": finding_store,
        "permission_store": permission_store,
        "kill_switch": kill_switch,
        "adapters": adapters,
        "tool_registry": tool_registry,
        "tool_runner": tool_runner,
        "planner_available_tools": planner_available_tools,
        "planner_tools_catalog": planner_tools_catalog,
        "llm_router": llm_router,
        "approval_service": approval_service,
        "report_generator": report_generator,
        "cfg": cfg,
        "typed_cfg": typed_cfg,
    }


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def create_and_run_engagement(
    name: str,
    scope_cidrs: list[str],
    scope_domains: list[str],
    scope_urls: list[str],
    roe_document_hash: str,
    authoriser_identity: str,
    valid_hours: int = 24,
    max_iterations: int = 50,
    config_path: Path | None = None,
    dry_run: bool = False,
) -> str:
    rt = _build_runtime(config_path)

    now = datetime.now(timezone.utc)
    engagement = Engagement(
        name=name,
        operator_id=os.environ.get("USER", "operator"),
        scope=EngagementScope(
            scope_cidrs=scope_cidrs,
            scope_domains=scope_domains,
            scope_urls=scope_urls,
        ),
        roe_document_hash=roe_document_hash,
        authoriser_identity=authoriser_identity,
        valid_from=now,
        valid_until=now + timedelta(hours=valid_hours),
    )

    eng_svc = EngagementService(engagement)
    policy_engine = PolicyEngine(eng_svc)

    if dry_run:
        sim = SimulationEngine(eng_svc)
        log.info("runtime.dry_run_enabled", engagement_id=str(engagement.engagement_id))
        return str(engagement.engagement_id)

    # Build agent nodes
    engagement_summary = {
        "engagement_id": str(engagement.engagement_id),
        "name": name,
        "scope_cidrs": scope_cidrs,
        "scope_domains": scope_domains,
        "scope_urls": scope_urls,
        "strategy_plan": build_engagement_strategy(
            scope_cidrs=scope_cidrs,
            scope_domains=scope_domains,
            scope_urls=scope_urls,
            available_tools=rt["planner_available_tools"],
        ),
    }

    planner = PlannerNode(
        llm_router=rt["llm_router"],
        engagement_summary=engagement_summary,
        audit_store=rt["audit_store"],
        finding_store=rt["finding_store"],
        available_tools=rt["planner_available_tools"],
        tools_catalog=rt["planner_tools_catalog"],
    )
    validator = ValidatorNode(
        llm_router=rt["llm_router"],
        policy_context={
            "gates": "recon_passive:allow,active_scan:allow,exploit:requires_approval",
            "available_tools": rt["planner_available_tools"],
            "tools_catalog": rt["planner_tools_catalog"],
        },
        audit_store=rt["audit_store"],
    )
    executor = ExecutorNode(
        policy_engine=policy_engine,
        tool_runner=rt["tool_runner"],
        approval_service=rt["approval_service"],
        audit_store=rt["audit_store"],
        finding_store=rt["finding_store"],
        recon_store=rt["recon_store"],
        planner_available_tools=rt["planner_available_tools"],
    )
    output_dir = Path(rt["typed_cfg"].storage.report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    reporter = ReporterNode(
        report_generator=rt["report_generator"],
        audit_store=rt["audit_store"],
        output_dir=output_dir,
    )

    db_path = Path(
        os.environ.get("PWNPILOT_DB_URL", "").replace("sqlite:///", "")
        or rt["typed_cfg"].database.url.replace("sqlite:///", "")
        or "pwnpilot.db"
    )
    checkpointer = SqliteCheckpointer.from_path(db_path)

    graph = build_graph(planner, validator, executor, reporter, checkpointer=checkpointer)
    supervisor = Supervisor(
        compiled_graph=graph,
        kill_switch=rt["kill_switch"],
        checkpointer=checkpointer,
    )

    initial_state: AgentState = {
        "engagement_id": str(engagement.engagement_id),
        "iteration_count": 0,
        "max_iterations": max_iterations,
        "no_new_findings_streak": 0,
        "recon_summary": {},
        "previous_actions": [],
        "temporarily_unavailable_tools": {},
        "proposed_action": None,
        "validation_result": None,
        "last_result": None,
        "evidence_ids": [],
        "kill_switch": False,
        "report_complete": False,
        "error": None,
    }

    rt["audit_store"].append(
        engagement_id=engagement.engagement_id,
        actor="system",
        event_type="EngagementStarted",
        payload={"engagement_id": str(engagement.engagement_id), "name": name},
    )

    final_state = supervisor.run(initial_state, thread_id=str(engagement.engagement_id))

    if final_state.get("error"):
        log.error("runtime.engagement_error", error=final_state["error"])

    return str(engagement.engagement_id)


def get_engagement_preflight(
    scope_cidrs: list[str],
    scope_domains: list[str],
    scope_urls: list[str],
    config_path: Path | None = None,
) -> dict[str, Any]:
    """Return deterministic target strategy and tool availability for a scope."""
    rt = _build_runtime(config_path)
    return build_engagement_strategy(
        scope_cidrs=scope_cidrs,
        scope_domains=scope_domains,
        scope_urls=scope_urls,
        available_tools=rt["planner_available_tools"],
    )


def resume_engagement(engagement_id: UUID, config_path: Path | None = None) -> str:
    """
    Resume an engagement from its last saved checkpoint.

    The graph is re-compiled with the same SqliteCheckpointer that persisted the
    original run; LangGraph will automatically resume from the last checkpoint for
    the given thread_id (engagement_id).
    """
    rt = _build_runtime(config_path)

    db_path = Path(
        os.environ.get("PWNPILOT_DB_URL", "").replace("sqlite:///", "")
        or rt["typed_cfg"].database.url.replace("sqlite:///", "")
        or "pwnpilot.db"
    )
    checkpointer = SqliteCheckpointer.from_path(db_path)

    # Verify a checkpoint exists for this engagement
    thread_id = str(engagement_id)
    cfg_check = {"configurable": {"thread_id": thread_id}}
    existing = checkpointer.get_tuple(cfg_check)
    if existing is None:
        raise ValueError(
            f"No checkpoint found for engagement {engagement_id}. "
            "Cannot resume an engagement that was never started or has no saved state."
        )

    log.info(
        "runtime.resuming_engagement",
        engagement_id=thread_id,
        checkpoint_id=existing.checkpoint["id"],
    )

    rt["audit_store"].append(
        engagement_id=engagement_id,
        actor="system",
        event_type="EngagementResumed",
        payload={"engagement_id": thread_id, "checkpoint_id": existing.checkpoint["id"]},
    )

    # Rebuild a minimal engagement service from the checkpoint state
    saved_state: AgentState = existing.checkpoint.get("channel_values", {})
    name = saved_state.get("engagement_id", str(engagement_id))

    now = datetime.now(timezone.utc)
    engagement = Engagement(
        engagement_id=engagement_id,
        name=name,
        operator_id=os.environ.get("USER", "operator"),
        scope=EngagementScope(),
        roe_document_hash="0" * 64,
        authoriser_identity="resumed",
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=24),
    )
    eng_svc = EngagementService(engagement)
    policy_engine = PolicyEngine(eng_svc)

    planner = PlannerNode(
        llm_router=rt["llm_router"],
        engagement_summary={
            "engagement_id": thread_id,
            "strategy_plan": build_engagement_strategy(
                scope_cidrs=[],
                scope_domains=[],
                scope_urls=[],
                available_tools=rt["planner_available_tools"],
            ),
        },
        audit_store=rt["audit_store"],
        finding_store=rt["finding_store"],
        available_tools=rt["planner_available_tools"],
        tools_catalog=rt["planner_tools_catalog"],
    )
    validator = ValidatorNode(
        llm_router=rt["llm_router"],
        policy_context={
            "available_tools": rt["planner_available_tools"],
            "tools_catalog": rt["planner_tools_catalog"],
        },
        audit_store=rt["audit_store"],
    )
    executor = ExecutorNode(
        policy_engine=policy_engine,
        tool_runner=rt["tool_runner"],
        approval_service=rt["approval_service"],
        audit_store=rt["audit_store"],
        finding_store=rt["finding_store"],
        recon_store=rt["recon_store"],
        planner_available_tools=rt["planner_available_tools"],
    )
    output_dir = Path(rt["typed_cfg"].storage.report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reporter = ReporterNode(
        report_generator=rt["report_generator"],
        audit_store=rt["audit_store"],
        output_dir=output_dir,
    )

    graph = build_graph(planner, validator, executor, reporter, checkpointer=checkpointer)
    supervisor = Supervisor(
        compiled_graph=graph,
        kill_switch=rt["kill_switch"],
        checkpointer=checkpointer,
    )

    # Invoke with None: LangGraph resumes from the last checkpoint
    final_state = supervisor.run(None, thread_id=thread_id)  # type: ignore[arg-type]

    if final_state and final_state.get("error"):
        log.error("runtime.resume_error", error=final_state["error"])

    return thread_id


def generate_report(
    engagement_id: UUID,
    output_dir: Path = Path("."),
    config_path: Path | None = None,
) -> tuple[Path, Path]:
    rt = _build_runtime(config_path)
    return rt["report_generator"].build_bundle(
        engagement_id=engagement_id,
        output_dir=output_dir,
    )


def get_approval_service(config_path: Path | None = None) -> ApprovalService:
    rt = _build_runtime(config_path)
    return rt["approval_service"]


def get_audit_store(config_path: Path | None = None) -> AuditStore:
    rt = _build_runtime(config_path)
    return rt["audit_store"]


def get_tool_registry(config_path: Path | None = None) -> ToolRegistry:
    typed_cfg = _load_typed_config(config_path)
    return _build_tool_registry_from_typed_config(typed_cfg)


def run_startup_checks(config_path: Path | None = None) -> list[str]:
    """
    Run preflight validation checks and return a list of warning/error strings.

    Checks performed (in order):
    1. Config loads and passes Pydantic validation.
    2. Database is reachable.
    3. Alembic migrations are at head (warns if behind, does not auto-migrate).
    4. PWNPILOT_SIGNING_KEY env var or key file is present (optional warning).
    5. Tool binaries — key adapters are present on PATH.

    Returns a list of human-readable issue strings (empty list = all checks passed).
    """
    import subprocess  # noqa: S404 — fixed, trusted args only

    issues: list[str] = []

    # 1. Config validation
    typed_cfg: PwnpilotConfig | None = None
    try:
        typed_cfg = _load_typed_config(config_path)
    except Exception as exc:
        issues.append(f"CONFIG: validation failed — {exc}")

    # 2. DB connectivity
    db_ok = False
    try:
        session = get_db_session(config_path)
        session.execute(text("SELECT 1"))
        session.close()
        db_ok = True
    except Exception as exc:
        issues.append(f"DATABASE: not reachable — {exc}")

    # 3. Alembic migration state (only if DB is reachable)
    if db_ok:
        try:
            result = subprocess.run(  # noqa: S603
                ["alembic", "current"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                issues.append(f"MIGRATIONS: alembic current failed — {result.stderr.strip()}")
            elif "(head)" not in result.stdout:
                issues.append(
                    "MIGRATIONS: database is not at head — run 'alembic upgrade head'"
                )
        except FileNotFoundError:
            issues.append("MIGRATIONS: alembic binary not found — install alembic")
        except Exception as exc:
            issues.append(f"MIGRATIONS: check failed — {exc}")

    # 4. Signing key presence (informational warning)
    signing_key_env = os.environ.get("PWNPILOT_SIGNING_KEY")
    default_key_path = Path("~/.pwnpilot/operator.key").expanduser()
    if not signing_key_env and not default_key_path.exists():
        issues.append(
            "SIGNING: no Ed25519 key found — reports will be unsigned "
            "(run 'pwnpilot keys --generate' to create one)"
        )

    # 5. Plugin binary availability (derived from registry)
    tool_binaries: dict[str, str] = {}
    if typed_cfg is not None:
        try:
            registry = _build_tool_registry_from_typed_config(typed_cfg)
            tool_binaries = registry.binary_requirements()
        except Exception as exc:
            issues.append(f"TOOLS: registry build failed — {exc}")

    missing: list[str] = []
    for name, binary in tool_binaries.items():
        if not binary:
            continue
        if resolve_binary_for_tool(name, binary):
            continue
        candidates = candidate_binaries(name, binary)
        missing.append(f"{name} (tried: {', '.join(candidates)})")
    if missing:
        issues.append(f"TOOLS: binaries not on PATH: {', '.join(missing)}")

    return issues


def run_policy_simulation(
    actions: list[dict],
    engagement_id: UUID,
    config_path: Path | None = None,
) -> list[dict]:
    from pwnpilot.data.models import ActionRequest

    rt = _build_runtime(config_path)
    # Build a minimal engagement for simulation
    now = datetime.now(timezone.utc)
    engagement = Engagement(
        engagement_id=engagement_id,
        name="simulation",
        operator_id="sim",
        scope=EngagementScope(),
        roe_document_hash="0" * 64,
        authoriser_identity="sim",
        valid_from=now,
        valid_until=now + timedelta(hours=1),
    )
    eng_svc = EngagementService(engagement)
    sim = SimulationEngine(eng_svc)

    results = []
    for a in actions:
        action = ActionRequest(**a)
        decision = sim.simulate(action)
        results.append({
            "action_type": action.action_type.value,
            "tool_name": action.tool_name,
            "verdict": decision.verdict.value,
            "reason": decision.reason,
        })
    return results
