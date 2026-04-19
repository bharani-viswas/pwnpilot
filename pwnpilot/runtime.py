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
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import structlog
import yaml
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

from pwnpilot.agent.checkpointer import SqliteCheckpointer
from pwnpilot.config import PwnpilotConfig, load_config as _pydantic_load_config
from pwnpilot.agent.event_bus import ExecutionEventBus
from pwnpilot.agent.executor import ExecutorNode
from pwnpilot.agent.planner import PlannerNode
from pwnpilot.agent.reporter import ReporterNode
from pwnpilot.agent.state import AgentState, CompletionState, OperatorMode, make_initial_state
from pwnpilot.agent.supervisor import Supervisor, build_graph
from pwnpilot.agent.validator import ValidatorNode
from pwnpilot.control.approval import ApprovalService
from pwnpilot.control.operator_session import OperatorSessionManager
from pwnpilot.data.approval_store import ApprovalStore
from pwnpilot.control.engagement import EngagementService
from pwnpilot.control.embedding_router import EmbeddingRouter
from pwnpilot.control.llm_router import LLMRouter
from pwnpilot.control.attack_surface_graph import AttackSurfaceGraphStore
from pwnpilot.control.policy_prior import PolicyPriorScorer
from pwnpilot.control.rag_retriever import build_rag_retriever
from pwnpilot.control.specialist_router import SpecialistRouter
from pwnpilot.control.policy import PolicyEngine
from pwnpilot.data.audit_store import AuditStore
from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.control.capability_registry import CapabilityRegistry
from pwnpilot.control.target_resolver import TargetResolver
from pwnpilot.data.finding_store import FindingStore
from pwnpilot.data.models import Engagement, EngagementScope
from pwnpilot.data.recon_store import ReconStore
from pwnpilot.governance.authorization import AuthorizationArtifact, assert_authorized
from pwnpilot.data.correlation import CorrelationEngine
from pwnpilot.data.engagement_name_store import EngagementNameStore
from pwnpilot.governance.retention import RetentionManager, EngagementClassification
from pwnpilot.governance.kill_switch import KillSwitch
from pwnpilot.governance.simulation import SimulationEngine
from pwnpilot.plugins.loader import PluginLoader
from pwnpilot.plugins.binaries import candidate_binaries, resolve_binary_for_tool
from pwnpilot.plugins.policy import PluginTrustPolicy
from pwnpilot.plugins.runner import ToolRunner
from pwnpilot.plugins.registry import ToolRegistry
from pwnpilot.observability.logging_setup import configure_logging_from_config
from pwnpilot.observability.metrics import metrics_registry
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
            # I-5: Warn if config is loaded from CWD fallback
            if path == Path("config.yaml"):
                resolved = path.resolve()
                log.warning(
                    "runtime.config_cwd_fallback",
                    config_source="cwd_fallback",
                    resolved_path=str(resolved),
                    message="Config loaded from current working directory (CWD). "
                            "This may not be the intended config. "
                            f"Set PWNPILOT_CONFIG env var or place config in ~/.pwnpilot/ to override.",
                )
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


def _agent_runtime_settings(typed_cfg: Any) -> dict[str, Any]:
    agent_cfg = getattr(typed_cfg, "agent", None)
    return {
        "per_step_budget": int(getattr(agent_cfg, "per_step_budget", 3)),
        "adaptive_cooldown_enabled": bool(getattr(agent_cfg, "adaptive_cooldown_enabled", True)),
        "adaptive_cooldown_max": int(getattr(agent_cfg, "adaptive_cooldown_max", 6)),
        "max_pv_cycles_without_executor": int(
            getattr(agent_cfg, "max_planner_validator_cycles_without_executor", 40)
        ),
        "max_consecutive_rejects_per_reason": int(
            getattr(agent_cfg, "max_consecutive_rejects_per_reason", 12)
        ),
    }


def _memory_runtime_settings(typed_cfg: Any) -> dict[str, int]:
    memory_cfg = getattr(typed_cfg, "memory", None)
    return {
        "task_tree_max_open_nodes": int(getattr(memory_cfg, "task_tree_max_open_nodes", 20)),
        "summarize_every_n_actions": int(getattr(memory_cfg, "summarize_every_n_actions", 4)),
        "prune_keep_last_actions": int(getattr(memory_cfg, "prune_keep_last_actions", 60)),
    }


def _payload_runtime_settings(typed_cfg: Any) -> dict[str, Any]:
    payload_cfg = getattr(typed_cfg, "payload", None)
    return {
        "enabled": bool(getattr(payload_cfg, "enabled", True)),
        "allow_classes": list(getattr(payload_cfg, "allow_classes", ["sqli", "xss"])),
        "max_candidates": int(getattr(payload_cfg, "max_candidates", 4)),
        "max_mutation_rounds": int(getattr(payload_cfg, "max_mutation_rounds", 3)),
    }


def _emit_terminal_lifecycle_events(
    audit_store: AuditStore,
    engagement_id: UUID,
    final_state: AgentState | None,
    postmortem_artifact_path: str | None = None,
) -> None:
    """Write deterministic terminal engagement/report lifecycle audit events."""
    state = final_state or {}
    completion_state = str(state.get("completion_state", "")).strip() or None
    error_text = _normalize_optional_text(state.get("error")) or ""
    termination_reason = _normalize_optional_text(state.get("termination_reason"))
    report_complete = bool(state.get("report_complete", False))
    finalization_failed = bool(state.get("finalization_failed", False))

    engagement_failed = bool(
        error_text
        or finalization_failed
        or completion_state == CompletionState.FAILED.value
    )
    engagement_event = "EngagementFailed" if engagement_failed else "EngagementCompleted"
    try:
        audit_store.append(
            engagement_id=engagement_id,
            actor="system",
            event_type=engagement_event,
            payload={
                "engagement_id": str(engagement_id),
                "termination_reason": termination_reason,
                "error": error_text or None,
                "completion_state": completion_state,
                "finalization_failed": finalization_failed,
            },
        )
    except Exception as exc:
        log.error("runtime.terminal_event_write_failed", exc=str(exc), event_type=engagement_event)

    if report_complete:
        try:
            audit_store.append(
                engagement_id=engagement_id,
                actor="system",
                event_type="ReportGenerationSucceeded",
                payload={
                    "engagement_id": str(engagement_id),
                    "bundle_path": _normalize_optional_text(state.get("report_bundle_path")),
                    "summary_path": _normalize_optional_text(state.get("report_summary_path")),
                    "completion_state": completion_state,
                },
            )
            log.info(
                "runtime.report_generation_succeeded",
                engagement_id=str(engagement_id),
                bundle_path=_normalize_optional_text(state.get("report_bundle_path")),
                summary_path=_normalize_optional_text(state.get("report_summary_path")),
            )
        except Exception as exc:
            log.error("runtime.report_success_event_write_failed", exc=str(exc))
        return

    try:
        audit_store.append(
            engagement_id=engagement_id,
            actor="system",
            event_type="ReportGenerationFailed",
            payload={
                "engagement_id": str(engagement_id),
                "reason": error_text or termination_reason or "report_not_generated",
                "postmortem_artifact_path": postmortem_artifact_path,
            },
        )
    except Exception as exc:
        log.error("runtime.report_outcome_event_write_failed", exc=str(exc))


def _normalize_terminal_state(
    state: AgentState | None,
    default_termination_reason: str | None = None,
    default_error: str | None = None,
) -> AgentState:
    """Return a terminal-ready state with deterministic completion markers."""
    normalized: AgentState = dict(state or {})
    normalized["termination_reason"] = _normalize_optional_text(normalized.get("termination_reason"))
    normalized["error"] = _normalize_optional_text(normalized.get("error"))

    fallback_termination_reason = _normalize_optional_text(default_termination_reason)
    fallback_error = _normalize_optional_text(default_error)

    if fallback_termination_reason and not normalized.get("termination_reason"):
        normalized["termination_reason"] = fallback_termination_reason
    if fallback_error and not normalized.get("error"):
        normalized["error"] = fallback_error

    report_complete = bool(normalized.get("report_complete", False))
    completion_state = str(normalized.get("completion_state", "")).strip()
    if completion_state not in {
        CompletionState.PENDING.value,
        CompletionState.FINALIZED.value,
        CompletionState.FAILED.value,
    }:
        completion_state = ""

    if report_complete:
        normalized["completion_state"] = CompletionState.FINALIZED.value
        normalized["finalization_failed"] = False
        normalized["finalization_failure_reason"] = None
    else:
        normalized["completion_state"] = CompletionState.FAILED.value
        normalized["finalization_failed"] = True
        if not normalized.get("finalization_failure_reason"):
            normalized["finalization_failure_reason"] = (
                _normalize_optional_text(normalized.get("error"))
                or _normalize_optional_text(normalized.get("termination_reason"))
                or "report_not_generated"
            )
        if completion_state == CompletionState.PENDING.value:
            normalized["completion_state"] = CompletionState.FAILED.value

    return normalized


def _normalize_optional_text(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or text.lower() in {"none", "null"}:
        return None
    return text


def _objective_counts(state: AgentState | dict[str, Any]) -> tuple[int, int]:
    progress = state.get("objective_progress", {}) if isinstance(state, dict) else {}
    if isinstance(progress, dict) and progress:
        open_count = int(progress.get("open", 0) or 0)
        in_progress_count = int(progress.get("in_progress", 0) or 0)
        return open_count, in_progress_count

    open_count = 0
    in_progress_count = 0
    objectives = state.get("assessment_objectives", []) if isinstance(state, dict) else []
    if not isinstance(objectives, list):
        return 0, 0
    for item in objectives:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "")).strip().lower()
        if status == "open":
            open_count += 1
        elif status == "in_progress":
            in_progress_count += 1
    return open_count, in_progress_count


def _should_persist_postmortem(state: AgentState | dict[str, Any]) -> bool:
    previous_actions = state.get("previous_actions", []) if isinstance(state, dict) else []
    failed_or_degraded_actions = any(
        isinstance(item, dict)
        and str(item.get("outcome_status", "")).strip() in {"failed", "degraded"}
        for item in previous_actions
    )
    open_objectives, in_progress_objectives = _objective_counts(state)
    degradation_reasons = state.get("degradation_reasons", []) if isinstance(state, dict) else []
    operator_mode = str(state.get("operator_mode", "")).strip().lower() if isinstance(state, dict) else ""
    operator_messages = state.get("operator_messages", []) if isinstance(state, dict) else []
    operator_directives = state.get("operator_directives", {}) if isinstance(state, dict) else {}

    return bool(
        _normalize_optional_text(state.get("error"))
        or state.get("finalization_failed")
        or not state.get("report_complete", False)
        or failed_or_degraded_actions
        or open_objectives > 0
        or in_progress_objectives > 0
        or bool(degradation_reasons)
        or _normalize_optional_text(state.get("termination_reason"))
        or operator_mode in {"guided", "monitor"}
        or bool(operator_messages)
        or bool(operator_directives)
    )


def _derive_engagement_outcome(state: AgentState | dict[str, Any]) -> str:
    completion_state = str(state.get("completion_state", "")).strip().lower() if isinstance(state, dict) else ""
    report_complete = bool(state.get("report_complete", False)) if isinstance(state, dict) else False
    finalization_failed = bool(state.get("finalization_failed", False)) if isinstance(state, dict) else False
    run_verdict = str(state.get("run_verdict", "")).strip().lower() if isinstance(state, dict) else ""
    open_objectives, in_progress_objectives = _objective_counts(state)
    degradation_reasons = state.get("degradation_reasons", []) if isinstance(state, dict) else []
    previous_actions = state.get("previous_actions", []) if isinstance(state, dict) else []
    failed_or_degraded_actions = any(
        isinstance(item, dict)
        and str(item.get("outcome_status", "")).strip() in {"failed", "degraded"}
        for item in previous_actions
    )

    if finalization_failed or not report_complete or completion_state == CompletionState.FAILED.value:
        return "failed"

    if (
        run_verdict == "completed_with_degradation"
        or bool(degradation_reasons)
        or open_objectives > 0
        or in_progress_objectives > 0
        or failed_or_degraded_actions
        or _normalize_optional_text(state.get("termination_reason")) is not None
    ):
        return "completed_with_degradation"

    return "completed"


def _extract_payload_telemetry(previous_actions: list[Any]) -> dict[str, Any]:
    """Extract and aggregate payload telemetry from action history."""
    total_generations = 0
    preflight_rejected = 0
    tools_used: set[str] = set()
    techniques_attempted: set[str] = set()
    mutation_rounds = 0
    semantic_outcomes: dict[str, int] = {}
    
    for action in previous_actions:
        if not isinstance(action, dict):
            continue
        
        # Count payload generations
        if action.get("payload_generation_mode"):
            total_generations += 1
        
        # Track tools that generated payloads
        if action.get("generated_payloads"):
            tool_name = action.get("tool_name", "unknown")
            if tool_name:
                tools_used.add(tool_name)
            
            # Track attempted techniques
            attempt_technique = action.get("attempt_technique")
            if attempt_technique:
                techniques_attempted.add(attempt_technique)
        
        # Count preflight rejections
        if action.get("preflight_rejected"):
            preflight_rejected += 1
        
        # Track mutation rounds
        if action.get("mutation_round"):
            mutation_round_num = action.get("mutation_round", 0)
            mutation_rounds = max(mutation_rounds, mutation_round_num)
        
        # Aggregate semantic outcomes
        if action.get("reflection_summary"):
            reflection = action.get("reflection_summary", {})
            if isinstance(reflection, dict):
                semantic_outcome = reflection.get("semantic_outcome")
                if semantic_outcome:
                    semantic_outcomes[semantic_outcome] = semantic_outcomes.get(semantic_outcome, 0) + 1
    
    return {
        "total_generations": total_generations,
        "preflight_rejected": preflight_rejected,
        "tools_used": sorted(list(tools_used)),
        "techniques_attempted": sorted(list(techniques_attempted)),
        "mutation_rounds": mutation_rounds,
        "semantic_outcomes": semantic_outcomes,
    }


def _persist_postmortem_artifact(
    audit_store: AuditStore,
    output_dir: Path,
    engagement_id: UUID,
    final_state: AgentState | None,
) -> str | None:
    """Persist a compact terminal snapshot for forensic/debug reporting."""
    state = final_state or {}
    should_persist = _should_persist_postmortem(state)
    if not should_persist:
        return None

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        recent_events = list(audit_store.events_for_engagement(engagement_id))[-50:]
        artifact_path = output_dir / f"postmortem_{engagement_id}.json"
        raw_error = _normalize_optional_text(state.get("error"))
        engagement_outcome = _derive_engagement_outcome(state)
        fatal_error = raw_error if engagement_outcome == "failed" else None
        diagnostic_error = raw_error if engagement_outcome != "failed" else None
        
        # Extract payload telemetry from previous_actions
        previous_actions = state.get("previous_actions", []) or []
        payload_telemetry = _extract_payload_telemetry(previous_actions)
        
        payload = {
            "engagement_id": str(engagement_id),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "engagement_outcome": engagement_outcome,
            "error": fatal_error,
            "diagnostic_error": diagnostic_error,
            "termination_reason": _normalize_optional_text(state.get("termination_reason")),
            "completion_state": state.get("completion_state"),
            "finalization_failed": bool(state.get("finalization_failed", False)),
            "finalization_failure_reason": state.get("finalization_failure_reason"),
            "report_complete": bool(state.get("report_complete", False)),
            "report_trigger_reason": state.get("report_trigger_reason"),
            "stall_state": state.get("stall_state"),
            "degradation_reasons": state.get("degradation_reasons", []),
            "objective_progress": state.get("objective_progress", {}),
            "loop_state": {
                "iteration_count": state.get("iteration_count", 0),
                "no_new_findings_streak": state.get("no_new_findings_streak", 0),
                "nonproductive_cycle_streak": state.get("nonproductive_cycle_streak", 0),
                "planner_validator_cycle_streak": state.get("planner_validator_cycle_streak", 0),
                "reject_reason_streak_count": state.get("reject_reason_streak_count", 0),
                "last_reject_reason_fingerprint": state.get("last_reject_reason_fingerprint"),
            },
            "last_result": state.get("last_result"),
            "last_execution_hints": state.get("last_execution_hints", []),
            "payload_telemetry": payload_telemetry,
            "recent_audit_events": [
                {
                    "timestamp": evt.timestamp.isoformat(),
                    "actor": evt.actor,
                    "event_type": evt.event_type,
                    "payload": evt.payload,
                }
                for evt in recent_events
            ],
        }
        artifact_path.write_text(json.dumps(payload, indent=2, default=str))
        audit_store.append(
            engagement_id=engagement_id,
            actor="system",
            event_type="PostmortemArtifactGenerated",
            payload={"path": str(artifact_path), "event_count": len(recent_events)},
        )
        return str(artifact_path)
    except Exception as exc:
        log.warning(
            "runtime.postmortem_artifact_failed",
            engagement_id=str(engagement_id),
            exc=str(exc),
        )
        return None


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------


def _engagement_db_path(base_url: str, engagement_id: str | None) -> str:
    """Derive a per-engagement SQLite path from the base URL.

    For SQLite databases, each engagement gets its own file:
        sqlite:///pwnpilot.db  →  sqlite:///pwnpilot-{engagement_id}.db

    For non-SQLite databases (PostgreSQL etc.) the base URL is returned
    unchanged because schema-level isolation (engagement_id columns) is
    sufficient and per-engagement databases are not practical.
    """
    if engagement_id and base_url.startswith("sqlite"):
        # Strip the sqlite:/// prefix, inject engagement id before extension
        prefix = "sqlite:///" if base_url.startswith("sqlite:///") else "sqlite://"
        path_part = base_url[len(prefix):]
        stem, _, ext = path_part.rpartition(".")
        if not stem:
            stem = path_part
            ext = ""
        new_path = f"{stem}-{engagement_id}.{ext}" if ext else f"{stem}-{engagement_id}"
        return f"{prefix}{new_path}"
    return base_url


def get_db_session(config_path: Path | None = None, engagement_id: str | None = None) -> Any:
    """Return a SQLAlchemy session.

    When *engagement_id* is provided and the configured backend is SQLite,
    a per-engagement database file is used (e.g. ``pwnpilot-<id>.db``).
    This gives each run full isolation: no cross-engagement table sharing,
    no uniqueness collisions from repeated tool output, and simple cleanup.
    """
    cfg = _load_config(config_path)
    base_url = (
        os.environ.get("PWNPILOT_DB_URL")
        or cfg.get("database", {}).get("url")
        or "sqlite:///pwnpilot.db"
    )
    db_url = _engagement_db_path(base_url, engagement_id)
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


def bind_engagement_name(
    name: str,
    engagement_id: UUID,
    config_path: Path | None = None,
) -> str:
    """Bind a user-friendly engagement name to a canonical engagement UUID."""
    session = get_db_session(config_path=config_path)
    try:
        store = EngagementNameStore(session)
        return store.bind(name=name, engagement_id=engagement_id)
    finally:
        try:
            session.close()
        except Exception:
            pass


def resolve_engagement_reference(
    reference: str,
    config_path: Path | None = None,
) -> UUID:
    """Resolve engagement name or UUID string to canonical engagement UUID."""
    try:
        return UUID(reference)
    except Exception:
        pass

    session = get_db_session(config_path=config_path)
    try:
        store = EngagementNameStore(session)
        resolved = store.resolve(reference)
    finally:
        try:
            session.close()
        except Exception:
            pass

    if resolved is None:
        raise ValueError(
            f"Unknown engagement reference {reference!r}. "
            "Use an existing engagement name or UUID."
        )
    return resolved


# ---------------------------------------------------------------------------
# Full runtime factory
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Per-engagement live-session registry
# Stores the event_bus and operator_session for each running engagement so
# that the TUI (launched as a side process or in the same process) can attach.
# ---------------------------------------------------------------------------

_engagement_registry: dict[str, dict[str, Any]] = {}
_engagement_registry_lock = threading.Lock()


def _register_engagement_session(
    engagement_id: str,
    event_bus: Any,
    operator_session: Any,
) -> None:
    with _engagement_registry_lock:
        _engagement_registry[engagement_id] = {
            "event_bus": event_bus,
            "operator_session": operator_session,
        }


def _deregister_engagement_session(engagement_id: str) -> None:
    with _engagement_registry_lock:
        _engagement_registry.pop(engagement_id, None)


def get_engagement_session(engagement_id: str) -> dict[str, Any] | None:
    """Return the live event_bus and operator_session for a running engagement.

    Returns a dict with keys ``event_bus`` and ``operator_session``, or
    ``None`` if no session is registered for the given engagement UUID.
    Used by ``pwnpilot tui`` to attach to the live event stream.
    """
    with _engagement_registry_lock:
        return _engagement_registry.get(engagement_id)


# ---------------------------------------------------------------------------
# Full runtime factory
# ---------------------------------------------------------------------------


def _build_runtime(
    config_path: Path | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """Build and return all runtime components.

    When *engagement_id* is provided, all stores are backed by a dedicated
    per-engagement SQLite file (e.g. ``pwnpilot-<id>.db``) so that runs are
    fully isolated from each other.
    """
    cfg = _load_config(config_path)
    typed_cfg = _load_typed_config(config_path)

    # Configure process-wide structured logging from runtime config.
    configure_logging_from_config(getattr(typed_cfg, "logging", None))

    session = get_db_session(config_path, engagement_id=engagement_id)

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
    from pwnpilot.data.retrieval_store import RetrievalStore
    retrieval_store = RetrievalStore(session)
    from pwnpilot.data.task_tree_store import TaskTreeStore
    task_tree_store = TaskTreeStore(session)
    correlation_engine = CorrelationEngine(finding_store, recon_store)
    retention_manager = RetentionManager(evidence_store, audit_store)
    from pwnpilot.data.operator_decision_store import OperatorDecisionStore
    operator_decision_store = OperatorDecisionStore(session)

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
            from pwnpilot.plugins.adapters.shell import ShellAdapter

            adapters = {
                "shell": ShellAdapter(permission_context={"permission_store": permission_store}),
                "dns": DnsAdapter(),
                "cve_enrich": CveEnrichAdapter(),
            }
            log.warning(
                "runtime.static_fallback_enabled",
                tools=sorted(adapters.keys()),
                reason="hard cutover keeps only non-CLI Python-native adapters",
            )

    # Tool runner — pass memory/CPU limits from config
    tools_cfg = getattr(typed_cfg, "tools", None)
    mem_limit_mb = int(getattr(tools_cfg, "memory_limit_mb", 2048)) if tools_cfg else 2048

    # v2: Wire event bus — tool runner and executor emit to it; audit store persists events.
    engagement_event_bus = ExecutionEventBus()
    engagement_event_bus.set_audit_store(audit_store)

    tool_runner = ToolRunner(
        adapters=adapters,
        evidence_store=evidence_store,
        kill_switch=kill_switch,
        mem_limit=mem_limit_mb * 1024 * 1024,
        event_bus=engagement_event_bus,
    )

    planner_available_tools = _compute_executable_tool_names(tool_registry)
    if not planner_available_tools:
        planner_available_tools = tool_runner.available_tools
    runtime_mode = str(os.environ.get("PWNPILOT_RUNTIME_MODE", "headless")).strip() or "headless"
    has_display = bool(os.environ.get("DISPLAY"))
    full_tools_catalog = tool_registry.planner_context().get("tools_catalog", [])
    capability_registry = CapabilityRegistry(
        tools_catalog=full_tools_catalog,
        runtime_mode=runtime_mode,
        has_display=has_display,
    )
    planner_available_tools = capability_registry.filter_runtime_compatible(planner_available_tools)
    planner_tools_catalog = _filter_tools_catalog(full_tools_catalog, planner_available_tools)
    target_resolver = TargetResolver()
    attack_surface_graph = AttackSurfaceGraphStore()
    specialist_router = (
        SpecialistRouter()
        if bool(getattr(getattr(typed_cfg, "specialists", None), "enabled", True))
        else None
    )
    policy_prior = PolicyPriorScorer(
        enabled=bool(getattr(getattr(typed_cfg, "learning", None), "enabled", False)),
        policy_file=str(getattr(getattr(typed_cfg, "learning", None), "policy_file", "")),
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

    # Embedding router — mirrors LLM routing semantics for embedding models
    embedding_router = EmbeddingRouter(
        model_name=typed_cfg.embedding.model_name,
        api_key=typed_cfg.embedding.api_key,
        api_base_url=typed_cfg.embedding.api_base_url,
        fallback_model_name=typed_cfg.embedding.fallback_model_name,
        fallback_api_key=typed_cfg.embedding.fallback_api_key,
        fallback_api_base_url=typed_cfg.embedding.fallback_api_base_url,
        cloud_allowed_fn=lambda: typed_cfg.embedding.cloud_allowed,
        redactor=redactor,
        timeout_seconds=typed_cfg.embedding.timeout_seconds,
        max_retries=typed_cfg.embedding.max_retries,
    )

    # RAG retriever — dual-mode ATT&CK + engagement history retrieval
    rag_retriever = build_rag_retriever(
        rag_cfg=typed_cfg.rag,
        retrieval_store=retrieval_store,
        embedding_router=embedding_router if typed_cfg.rag.mode in {"embedding", "hybrid"} else None,
    )

    # Approval service — wired to DB for crash durability, v2 decisions recorded
    approval_store = ApprovalStore(session)
    approval_service = ApprovalService(
        persist_fn=approval_store.upsert,
        load_fn=approval_store.load_pending,
        decision_store=operator_decision_store,
    )

    # Report generator — v2 includes timeline and operator decisions
    report_generator = ReportGenerator(
        finding_store=finding_store,
        recon_store=recon_store,
        evidence_store=evidence_store,
        audit_store=audit_store,
        operator_decision_store=operator_decision_store,
        correlation_engine=correlation_engine,
    )

    return {
        "session": session,
        "audit_store": audit_store,
        "evidence_store": evidence_store,
        "recon_store": recon_store,
        "finding_store": finding_store,
        "retrieval_store": retrieval_store,
        "task_tree_store": task_tree_store,
        "rag_retriever": rag_retriever,
        "correlation_engine": correlation_engine,
        "retention_manager": retention_manager,
        "permission_store": permission_store,
        "operator_decision_store": operator_decision_store,
        "kill_switch": kill_switch,
        "adapters": adapters,
        "tool_registry": tool_registry,
        "tool_runner": tool_runner,
        "event_bus": engagement_event_bus,
        "planner_available_tools": planner_available_tools,
        "planner_tools_catalog": planner_tools_catalog,
        "capability_registry": capability_registry,
        "target_resolver": target_resolver,
        "attack_surface_graph": attack_surface_graph,
        "specialist_router": specialist_router,
        "policy_prior": policy_prior,
        "runtime_mode": runtime_mode,
        "has_display": has_display,
        "llm_router": llm_router,
        "embedding_router": embedding_router,
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
    event_subscriber: object | None = None,
    operator_mode: OperatorMode = OperatorMode.AUTONOMOUS,
    operator_directives: dict[str, Any] | None = None,
) -> str:
    """Start and run a full engagement.

    *event_subscriber* — optional callable(ExecutionEvent) -> None.  When
    provided it is subscribed to all events for this engagement so callers (e.g.
    the CLI) can print live output without coupling to the TUI.
    """
    # Pre-generate the engagement UUID so the per-engagement SQLite database
    # file can be created by _build_runtime before any stores are initialised.
    _engagement_uuid = uuid4()
    rt = _build_runtime(config_path, engagement_id=str(_engagement_uuid))

    now = datetime.now(timezone.utc)
    engagement = Engagement(
        engagement_id=_engagement_uuid,
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

    name_key = bind_engagement_name(
        name=name,
        engagement_id=engagement.engagement_id,
        config_path=config_path,
    )
    log.info(
        "runtime.engagement_name_bound",
        engagement_id=str(engagement.engagement_id),
        engagement_name=name,
        name_key=name_key,
    )

    eng_svc = EngagementService(engagement)
    policy_engine = PolicyEngine(eng_svc)

    # Enforce authorization before every run (governance invariant).
    _auth_artifact = AuthorizationArtifact(
        engagement_id=engagement.engagement_id,
        approver_identity=authoriser_identity,
        ticket_reference=roe_document_hash[:16] if roe_document_hash else "none",
        roe_document_hash=roe_document_hash or ("0" * 64),
        valid_from=engagement.valid_from,
        valid_until=engagement.valid_until,
        signed_at=engagement.valid_from,
    )
    assert_authorized(_auth_artifact)

    # Wire engagement_id into the shell adapter permission context so runtime-granted
    # shell commands are validated against PermissionStore for this specific engagement.
    _tool_runner = rt.get("tool_runner")
    _adapters = getattr(_tool_runner, "_adapters", None)
    _shell = _adapters.get("shell") if hasattr(_adapters, "get") else None
    if _shell is not None and hasattr(_shell, "_permission_context"):
        _permission_store = rt.get("permission_store")
        if _permission_store is not None:
            _shell._permission_context["permission_store"] = _permission_store
        _shell._permission_context["engagement_id"] = engagement.engagement_id

    if dry_run:
        sim = SimulationEngine(eng_svc)
        log.info("runtime.dry_run_enabled", engagement_id=str(engagement.engagement_id))
        return str(engagement.engagement_id)

    # Wire optional live-output subscriber (e.g. CLI stdout handler) before the
    # graph starts so no events are missed.
    if event_subscriber is not None:
        rt["event_bus"].subscribe(engagement.engagement_id, event_subscriber)  # type: ignore[attr-defined]

    # Build agent nodes
    agent_settings = _agent_runtime_settings(rt["typed_cfg"])
    memory_settings = _memory_runtime_settings(rt["typed_cfg"])
    payload_settings = _payload_runtime_settings(rt["typed_cfg"])
    engagement_summary = {
        "engagement_id": str(engagement.engagement_id),
        "name": name,
        "scope_cidrs": scope_cidrs,
        "scope_domains": scope_domains,
        "scope_urls": scope_urls,
        # Runtime planning is intentionally dynamic (LLM-driven).
        # Keep deterministic strategy only for preflight visibility and guidance,
        # not as a hard execution-time gate.
        "strategy_plan": {},
    }

    metrics = metrics_registry.get_or_create(str(engagement.engagement_id))
    operator_session = OperatorSessionManager(
        engagement_id=engagement.engagement_id,
        operator_id=os.environ.get("USER", "operator"),
        event_bus=rt["event_bus"],
    )
    operator_session.set_mode(operator_mode)
    if operator_directives:
        operator_session.submit_directive_from_dict(
            objective=operator_directives.get("objective"),
            requested_focus=operator_directives.get("requested_focus"),
            constraints=operator_directives.get("constraints"),
            paused_tool_families=operator_directives.get("paused_tool_families"),
            notes=operator_directives.get("notes"),
        )

    planner = PlannerNode(
        llm_router=rt["llm_router"],
        engagement_summary=engagement_summary,
        audit_store=rt["audit_store"],
        finding_store=rt["finding_store"],
        available_tools=rt["planner_available_tools"],
        tools_catalog=rt["planner_tools_catalog"],
        per_step_budget=agent_settings["per_step_budget"],
        adaptive_cooldown_enabled=agent_settings["adaptive_cooldown_enabled"],
        adaptive_cooldown_max=agent_settings["adaptive_cooldown_max"],
        metrics=metrics,
        operator_session_manager=operator_session,
        retrieval_store=rt.get("retrieval_store"),
        rag_retriever=rt.get("rag_retriever"),
        task_tree_store=rt.get("task_tree_store"),
        specialist_router=rt.get("specialist_router"),
        policy_prior=rt.get("policy_prior"),
        task_tree_context_limit=memory_settings["task_tree_max_open_nodes"],
        tactical_memory_window=max(6, memory_settings["summarize_every_n_actions"] * 3),
    )
    validator = ValidatorNode(
        llm_router=rt["llm_router"],
        policy_context={
            "gates": "recon_passive:allow,active_scan:allow,exploit:requires_approval",
            "available_tools": rt["planner_available_tools"],
            "tools_catalog": rt["planner_tools_catalog"],
            "capability_contracts": rt["capability_registry"].contracts_for_tools(rt["planner_available_tools"]),
            "runtime_mode": rt["runtime_mode"],
            "has_display": rt["has_display"],
        },
        audit_store=rt["audit_store"],
        metrics=metrics,
        event_bus=rt["event_bus"],
    )
    executor = ExecutorNode(
        policy_engine=policy_engine,
        tool_runner=rt["tool_runner"],
        approval_service=rt["approval_service"],
        audit_store=rt["audit_store"],
        finding_store=rt["finding_store"],
        recon_store=rt["recon_store"],
        planner_available_tools=rt["planner_available_tools"],
        metrics=metrics,
        target_family="multi_scope",
        target_resolver=rt["target_resolver"],
        capability_registry=rt["capability_registry"],
        event_bus=rt["event_bus"],
        retrieval_store=rt.get("retrieval_store"),
        task_tree_store=rt.get("task_tree_store"),
        payload_cfg=payload_settings,
        attack_surface_graph=rt.get("attack_surface_graph"),
        memory_summary_every_n_actions=memory_settings["summarize_every_n_actions"],
        memory_prune_keep_last_actions=memory_settings["prune_keep_last_actions"],
    )
    output_dir = Path(rt["typed_cfg"].storage.report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    reporter = ReporterNode(
        report_generator=rt["report_generator"],
        audit_store=rt["audit_store"],
        output_dir=output_dir,
        event_bus=rt["event_bus"],
    )

    _base_db_url = (
        os.environ.get("PWNPILOT_DB_URL")
        or rt["typed_cfg"].database.url
        or "sqlite:///pwnpilot.db"
    )
    _eng_db_url = _engagement_db_path(_base_db_url, str(engagement.engagement_id))
    db_path = Path(_eng_db_url.replace("sqlite:///", "").replace("sqlite://", ""))
    checkpointer = SqliteCheckpointer.from_path(db_path)

    graph = build_graph(planner, validator, executor, reporter, checkpointer=checkpointer)
    supervisor = Supervisor(
        compiled_graph=graph,
        kill_switch=rt["kill_switch"],
        checkpointer=checkpointer,
        operator_session_manager=operator_session,
    )

    initial_state: AgentState = make_initial_state(
        engagement_id=str(engagement.engagement_id),
        max_iterations=max_iterations,
        max_pv_cycles_without_executor=agent_settings["max_pv_cycles_without_executor"],
        max_consecutive_rejects_per_reason=agent_settings["max_consecutive_rejects_per_reason"],
        operator_mode=operator_mode,
        operator_directives=operator_directives,
    )

    rt["audit_store"].append(
        engagement_id=engagement.engagement_id,
        actor="system",
        event_type="EngagementStarted",
        payload={"engagement_id": str(engagement.engagement_id), "name": name},
    )

    final_state: AgentState | None = None
    runtime_exception: Exception | None = None
    try:
        _register_engagement_session(
            str(engagement.engagement_id), rt["event_bus"], operator_session
        )
        final_state = supervisor.run(initial_state, thread_id=str(engagement.engagement_id))
    except Exception as exc:
        runtime_exception = exc
        log.exception(
            "runtime.engagement_run_failed",
            engagement_id=str(engagement.engagement_id),
            exc=str(exc),
        )
    finally:
        _deregister_engagement_session(str(engagement.engagement_id))
        normalized_state = _normalize_terminal_state(
            final_state,
            default_termination_reason=(
                "unhandled_runtime_exception" if runtime_exception else "terminal_exit"
            ),
            default_error=(str(runtime_exception) if runtime_exception else None),
        )
        postmortem_path = _persist_postmortem_artifact(
            rt["audit_store"],
            output_dir,
            engagement.engagement_id,
            normalized_state,
        )
        _emit_terminal_lifecycle_events(
            rt["audit_store"],
            engagement.engagement_id,
            normalized_state,
            postmortem_artifact_path=postmortem_path,
        )
        final_state = normalized_state

    if runtime_exception is not None:
        raise runtime_exception

    if final_state.get("report_trigger_reason"):
        metrics.record_report_trigger(str(final_state.get("report_trigger_reason")))

    if final_state.get("error"):
        log.error("runtime.engagement_error", error=final_state["error"])

    return str(engagement.engagement_id)


def resume_engagement(
    engagement_id: UUID,
    config_path: Path | None = None,
    operator_mode: OperatorMode | None = None,
    operator_directives: dict[str, Any] | None = None,
) -> str:
    """
    Resume an engagement from its last saved checkpoint.

    The graph is re-compiled with the same SqliteCheckpointer that persisted the
    original run; LangGraph will automatically resume from the last checkpoint for
    the given thread_id (engagement_id).
    """
    rt = _build_runtime(config_path, engagement_id=str(engagement_id))

    _base_db_url = (
        os.environ.get("PWNPILOT_DB_URL")
        or rt["typed_cfg"].database.url
        or "sqlite:///pwnpilot.db"
    )
    _eng_db_url = _engagement_db_path(_base_db_url, str(engagement_id))
    db_path = Path(_eng_db_url.replace("sqlite:///", "").replace("sqlite://", ""))
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

    # --- Approval-gate resume check ---
    # If the previous run halted waiting for an approval ticket, check its status.
    # If APPROVED: clear pending state and let execution continue.
    # If still PENDING or DENIED: raise early so the operator is informed.
    _pending_ticket_id = saved_state.get("pending_approval_ticket_id")
    if _pending_ticket_id:
        try:
            from pwnpilot.data.approval_store import ApprovalStore as _ApprovalStore
            from pwnpilot.data.models import ApprovalStatus as _ApprovalStatus
            _a_store = _ApprovalStore(rt["db_session"] if "db_session" in rt else __import__("pwnpilot.runtime", fromlist=["get_db_session"]).get_db_session(config_path))
            _tickets = _a_store.load_pending()
            _ticket = next((t for t in _tickets if str(t.ticket_id) == str(_pending_ticket_id)), None)
            if _ticket is None:
                # Not in PENDING — look up any status
                _approval_service_temp = rt["approval_service"]
                try:
                    from uuid import UUID as _UUID
                    _ticket = _approval_service_temp.get_ticket(_UUID(_pending_ticket_id))
                except Exception:
                    _ticket = None
            if _ticket is not None:
                if _ticket.status.value if hasattr(_ticket.status, "value") else str(_ticket.status) == "approved":
                    log.info("runtime.approval_gate_cleared", ticket_id=_pending_ticket_id)
                    saved_state = dict(saved_state)
                    saved_state["pending_approval_ticket_id"] = None
                    saved_state["kill_switch"] = False
                elif str(_ticket.status.value if hasattr(_ticket.status, "value") else _ticket.status) == "denied":
                    log.info("runtime.approval_gate_denied", ticket_id=_pending_ticket_id)
                    saved_state = dict(saved_state)
                    saved_state["pending_approval_ticket_id"] = None
                    saved_state["kill_switch"] = False
                    saved_state["proposed_action"] = None  # let planner re-plan
                else:
                    raise ValueError(
                        f"Engagement {engagement_id} is halted pending approval ticket "
                        f"{_pending_ticket_id} (status={_ticket.status}). "
                        f"Run: pwnpilot approve {_pending_ticket_id}"
                    )
            else:
                log.warning("runtime.approval_ticket_not_found", ticket_id=_pending_ticket_id)
                saved_state = dict(saved_state)
                saved_state["pending_approval_ticket_id"] = None
                saved_state["kill_switch"] = False
        except ValueError:
            raise
        except Exception as _ae:
            log.warning("runtime.approval_check_error", exc=str(_ae))

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

    # Enforce authorization on resume.
    _resume_auth = AuthorizationArtifact(
        engagement_id=engagement_id,
        approver_identity="resumed",
        ticket_reference="resumed",
        roe_document_hash=saved_state.get("roe_document_hash") or ("0" * 64),
        valid_from=engagement.valid_from,
        valid_until=engagement.valid_until,
        signed_at=engagement.valid_from,
    )
    assert_authorized(_resume_auth)

    _tool_runner = rt.get("tool_runner")
    _adapters = getattr(_tool_runner, "_adapters", None)
    _shell = _adapters.get("shell") if hasattr(_adapters, "get") else None
    if _shell is not None and hasattr(_shell, "_permission_context"):
        _permission_store = rt.get("permission_store")
        if _permission_store is not None:
            _shell._permission_context["permission_store"] = _permission_store
        _shell._permission_context["engagement_id"] = engagement_id

    agent_settings = _agent_runtime_settings(rt["typed_cfg"])
    memory_settings = _memory_runtime_settings(rt["typed_cfg"])
    payload_settings = _payload_runtime_settings(rt["typed_cfg"])
    operator_session = OperatorSessionManager(
        engagement_id=engagement_id,
        operator_id=os.environ.get("USER", "operator"),
        event_bus=rt["event_bus"],
    )
    saved_mode_raw = str(saved_state.get("operator_mode", OperatorMode.AUTONOMOUS.value))
    if operator_mode is not None:
        operator_session.set_mode(operator_mode)
    else:
        try:
            operator_session.set_mode(OperatorMode(saved_mode_raw))
        except Exception:
            operator_session.set_mode(OperatorMode.AUTONOMOUS)

    resume_directives = dict(saved_state.get("operator_directives") or {})
    if operator_directives:
        resume_directives.update(operator_directives)
    if resume_directives:
        operator_session.submit_directive_from_dict(
            objective=resume_directives.get("objective"),
            requested_focus=resume_directives.get("requested_focus"),
            constraints=resume_directives.get("constraints"),
            paused_tool_families=resume_directives.get("paused_tool_families"),
            notes=resume_directives.get("notes"),
        )

    metrics = metrics_registry.get_or_create(thread_id)
    planner = PlannerNode(
        llm_router=rt["llm_router"],
        engagement_summary={
            "engagement_id": thread_id,
            # Resume should preserve dynamic planning semantics as well.
            "strategy_plan": {},
        },
        audit_store=rt["audit_store"],
        finding_store=rt["finding_store"],
        available_tools=rt["planner_available_tools"],
        tools_catalog=rt["planner_tools_catalog"],
        per_step_budget=agent_settings["per_step_budget"],
        adaptive_cooldown_enabled=agent_settings["adaptive_cooldown_enabled"],
        adaptive_cooldown_max=agent_settings["adaptive_cooldown_max"],
        metrics=metrics,
        operator_session_manager=operator_session,
        retrieval_store=rt.get("retrieval_store"),
        rag_retriever=rt.get("rag_retriever"),
        task_tree_store=rt.get("task_tree_store"),
        specialist_router=rt.get("specialist_router"),
        policy_prior=rt.get("policy_prior"),
        task_tree_context_limit=memory_settings["task_tree_max_open_nodes"],
        tactical_memory_window=max(6, memory_settings["summarize_every_n_actions"] * 3),
    )
    validator = ValidatorNode(
        llm_router=rt["llm_router"],
        policy_context={
            "available_tools": rt["planner_available_tools"],
            "tools_catalog": rt["planner_tools_catalog"],
            "capability_contracts": rt["capability_registry"].contracts_for_tools(rt["planner_available_tools"]),
            "runtime_mode": rt["runtime_mode"],
            "has_display": rt["has_display"],
        },
        audit_store=rt["audit_store"],
        metrics=metrics,
        event_bus=rt["event_bus"],
    )
    executor = ExecutorNode(
        policy_engine=policy_engine,
        tool_runner=rt["tool_runner"],
        approval_service=rt["approval_service"],
        audit_store=rt["audit_store"],
        finding_store=rt["finding_store"],
        recon_store=rt["recon_store"],
        planner_available_tools=rt["planner_available_tools"],
        metrics=metrics,
        target_family="resumed",
        target_resolver=rt["target_resolver"],
        capability_registry=rt["capability_registry"],
        event_bus=rt["event_bus"],
        retrieval_store=rt.get("retrieval_store"),
        task_tree_store=rt.get("task_tree_store"),
        payload_cfg=payload_settings,
        attack_surface_graph=rt.get("attack_surface_graph"),
        memory_summary_every_n_actions=memory_settings["summarize_every_n_actions"],
        memory_prune_keep_last_actions=memory_settings["prune_keep_last_actions"],
    )
    output_dir = Path(rt["typed_cfg"].storage.report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reporter = ReporterNode(
        report_generator=rt["report_generator"],
        audit_store=rt["audit_store"],
        output_dir=output_dir,
        event_bus=rt["event_bus"],
    )

    graph = build_graph(planner, validator, executor, reporter, checkpointer=checkpointer)
    supervisor = Supervisor(
        compiled_graph=graph,
        kill_switch=rt["kill_switch"],
        checkpointer=checkpointer,
        operator_session_manager=operator_session,
    )

    # Invoke with None: LangGraph resumes from the last checkpoint
    final_state: AgentState | None = None
    runtime_exception: Exception | None = None
    try:
        _register_engagement_session(thread_id, rt["event_bus"], operator_session)
        final_state = supervisor.run(None, thread_id=thread_id)  # type: ignore[arg-type]
    except Exception as exc:
        runtime_exception = exc
        log.exception("runtime.resume_run_failed", engagement_id=thread_id, exc=str(exc))
    finally:
        _deregister_engagement_session(thread_id)
        normalized_state = _normalize_terminal_state(
            final_state,
            default_termination_reason=(
                "unhandled_runtime_exception" if runtime_exception else "terminal_exit"
            ),
            default_error=(str(runtime_exception) if runtime_exception else None),
        )
        postmortem_path = _persist_postmortem_artifact(
            rt["audit_store"],
            output_dir,
            engagement_id,
            normalized_state,
        )
        _emit_terminal_lifecycle_events(
            rt["audit_store"],
            engagement_id,
            normalized_state,
            postmortem_artifact_path=postmortem_path,
        )
        final_state = normalized_state

    if runtime_exception is not None:
        raise runtime_exception

    if final_state and final_state.get("report_trigger_reason"):
        metrics.record_report_trigger(str(final_state.get("report_trigger_reason")))

    if final_state and final_state.get("error"):
        log.error("runtime.resume_error", error=final_state["error"])

    return thread_id


def generate_report(
    engagement_id: UUID,
    output_dir: Path = Path("."),
    config_path: Path | None = None,
) -> tuple[Path, Path]:
    rt = _build_runtime(config_path, engagement_id=str(engagement_id))
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

    rt = _build_runtime(config_path, engagement_id=str(engagement_id))
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
