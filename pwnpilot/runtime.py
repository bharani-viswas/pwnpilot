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
from pwnpilot.plugins.adapters.nmap import NmapAdapter
from pwnpilot.plugins.adapters.nikto import NiktoAdapter
from pwnpilot.plugins.adapters.nuclei import NucleiAdapter
from pwnpilot.plugins.adapters.searchsploit import SearchsploitAdapter
from pwnpilot.plugins.adapters.sqlmap import SqlmapAdapter
from pwnpilot.plugins.adapters.whatweb import WhatWebAdapter
from pwnpilot.plugins.adapters.whois import WhoisAdapter
from pwnpilot.plugins.adapters.dns import DnsAdapter
from pwnpilot.plugins.adapters.zap import ZapAdapter
from pwnpilot.plugins.adapters.cve_enrich import CveEnrichAdapter
from pwnpilot.plugins.runner import ToolRunner
from pwnpilot.reporting.generator import ReportGenerator
from pwnpilot.secrets.redactor import Redactor

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

_CONFIG_SEARCH_PATHS = [
    Path(os.environ.get("PWNPILOT_CONFIG", "")),
    Path("config.yaml"),
    Path.home() / ".pwnpilot" / "config.yaml",
]


def _load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load YAML config from known locations.  Returns empty dict if not found."""
    candidates = ([config_path] if config_path else []) + _CONFIG_SEARCH_PATHS
    for path in candidates:
        if path and path.exists():
            with path.open() as fh:
                return yaml.safe_load(fh) or {}
    return {}


def _load_typed_config(config_path: Path | None = None) -> PwnpilotConfig:
    """Return a validated PwnpilotConfig (hard-fails on invalid config)."""
    return _pydantic_load_config(config_path)


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

    # Adapters
    adapters = {
        "nmap": NmapAdapter(),
        "nikto": NiktoAdapter(),
        "nuclei": NucleiAdapter(),
        "searchsploit": SearchsploitAdapter(),
        "sqlmap": SqlmapAdapter(),
        "whatweb": WhatWebAdapter(),
        "whois": WhoisAdapter(),
        "dns": DnsAdapter(),
        "zap": ZapAdapter(),
        "cve_enrich": CveEnrichAdapter(),
    }

    # Tool runner
    tool_runner = ToolRunner(
        adapters=adapters,
        evidence_store=evidence_store,
        kill_switch=kill_switch,
    )

    # LLM router
    redactor = Redactor()
    llm_router = LLMRouter(
        local_base_url=typed_cfg.llm.local_url,
        local_model=typed_cfg.llm.local_model,
        redactor=redactor,
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
        "kill_switch": kill_switch,
        "adapters": adapters,
        "tool_runner": tool_runner,
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
    }

    planner = PlannerNode(
        llm_router=rt["llm_router"],
        engagement_summary=engagement_summary,
        audit_store=rt["audit_store"],
    )
    validator = ValidatorNode(
        llm_router=rt["llm_router"],
        policy_context={"gates": "recon_passive:allow,active_scan:allow,exploit:requires_approval"},
        audit_store=rt["audit_store"],
    )
    executor = ExecutorNode(
        policy_engine=policy_engine,
        tool_runner=rt["tool_runner"],
        approval_service=rt["approval_service"],
        audit_store=rt["audit_store"],
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
        engagement_summary={"engagement_id": thread_id},
        audit_store=rt["audit_store"],
    )
    validator = ValidatorNode(
        llm_router=rt["llm_router"],
        policy_context={},
        audit_store=rt["audit_store"],
    )
    executor = ExecutorNode(
        policy_engine=policy_engine,
        tool_runner=rt["tool_runner"],
        approval_service=rt["approval_service"],
        audit_store=rt["audit_store"],
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
    import shutil
    import subprocess  # noqa: S404 — fixed, trusted args only

    issues: list[str] = []

    # 1. Config validation
    try:
        _load_typed_config(config_path)
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

    # 5. Plugin binary availability
    _tool_binaries = {
        "nmap": "nmap",
        "nikto": "nikto",
        "nuclei": "nuclei",
        "whois": "whois",
        "dns (dig)": "dig",
    }
    missing = [name for name, binary in _tool_binaries.items() if not shutil.which(binary)]
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
