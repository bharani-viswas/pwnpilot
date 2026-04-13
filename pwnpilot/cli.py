"""
Intruder CLI — Typer-based primary entry point.

Commands:
  pwnpilot start     — create engagement and start the agent loop
  pwnpilot resume    — resume from last LangGraph checkpoint
  pwnpilot approve   — approve a pending ticket
  pwnpilot deny      — deny a pending ticket
  pwnpilot report    — generate report now
  pwnpilot simulate  — policy dry-run for preflight checks
  pwnpilot verify    — verify audit chain integrity
  pwnpilot version   — print version
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID

import structlog
import typer
from rich.console import Console
from rich.table import Table

from pwnpilot import __version__
from pwnpilot.config import load_config
from pwnpilot.observability.logging_setup import configure_logging_from_config

app = typer.Typer(
    name="pwnpilot",
    help="Policy-first, multi-agent LLM-driven pentesting framework.",
    add_completion=False,
)
console = Console()
log = structlog.get_logger(__name__)

plugins_app = typer.Typer(
    help="Plugin registry inspection commands.",
    add_completion=False,
)
app.add_typer(plugins_app, name="plugins")


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


@app.command("version")
def cmd_version() -> None:
    """Print the pwnpilot version."""
    console.print(f"pwnpilot v{__version__}")


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------

_SEPARATOR = "─" * 72


def _make_live_output_handler() -> object:
    """Return a callable that prints execution events as plain human-readable text.

    Design rationale (from hackingBuddyGPT / CAI research):
    - Print the command being run so the operator sees what's executing.
    - Stream stdout/stderr as raw text so they can follow tool progress live.
    - Print a brief result line when the action finishes (outcome + exit code).
    No JSON, no structured formatting — just readable terminal output.
    """
    from pwnpilot.data.models import ExecutionEventType

    def _handler(event: object) -> None:
        et = getattr(event, "event_type", None)
        payload: dict = getattr(event, "payload", None) or {}
        tool = getattr(event, "tool_name", "") or ""
        cmd = getattr(event, "command", "") or ""

        if et == ExecutionEventType.ACTION_STARTED:
            sys.stdout.write(f"\n{_SEPARATOR}\n")
            sys.stdout.write(f"[>] {tool}")
            if cmd:
                sys.stdout.write(f"  {cmd}")
            sys.stdout.write("\n")
            sys.stdout.flush()

        elif et == ExecutionEventType.TOOL_OUTPUT_CHUNK:
            stream = payload.get("stream", "stdout")
            data = payload.get("data", "")
            if data:
                # Prefix stderr chunks so operator can distinguish them
                prefix = "[stderr] " if stream == "stderr" else ""
                lines = data.splitlines(keepends=True)
                for line in lines:
                    sys.stdout.write(prefix + line)
                if data and not data.endswith("\n"):
                    sys.stdout.write("\n")
                sys.stdout.flush()

        elif et in (ExecutionEventType.ACTION_COMPLETED, ExecutionEventType.ACTION_FAILED):
            exit_code = payload.get("exit_code", "?")
            outcome = payload.get("outcome_status", "unknown")
            duration_ms = payload.get("duration_ms", 0)
            color_start = "\033[32m" if et == ExecutionEventType.ACTION_COMPLETED else "\033[31m"
            color_end = "\033[0m"
            sys.stdout.write(
                f"{color_start}[done]{color_end} {tool} — "
                f"exit {exit_code} — {outcome} — {duration_ms}ms\n"
            )
            sys.stdout.flush()

        elif et == ExecutionEventType.VALIDATOR_REJECTED:
            code = payload.get("rejection_reason_code", "VALIDATOR_REJECT")
            cls = payload.get("rejection_class", "policy")
            streak = payload.get("nonproductive_cycle_streak", "?")
            rationale = str(payload.get("rationale", "")).strip()
            summary = rationale[:200] + ("..." if len(rationale) > 200 else "")
            sys.stdout.write(
                f"[reject] code={code} class={cls} streak={streak}"
            )
            if summary:
                sys.stdout.write(f" — {summary}")
            sys.stdout.write("\n")
            sys.stdout.flush()

        elif et == ExecutionEventType.EXECUTOR_RECOVERY_HINT:
            hint = payload.get("hint", "")
            if hint:
                sys.stdout.write(f"[hint] {hint}\n")
                sys.stdout.flush()

    return _handler


def _render_preflight(preflight: dict[str, object]) -> None:
    family = str(preflight.get("target_family", "unknown"))
    console.print(f"[bold cyan]Target family:[/bold cyan] {family}")

    table = Table(title="Preflight Sequence and Tool Availability")
    table.add_column("Step", style="cyan")
    table.add_column("Preferred", style="green")
    table.add_column("Available", style="green")
    table.add_column("Missing", style="yellow")

    for step in preflight.get("sequence", []):
        if not isinstance(step, dict):
            continue
        table.add_row(
            str(step.get("name", "")),
            ", ".join(step.get("preferred_tools", [])),
            ", ".join(step.get("preferred_available", [])),
            ", ".join(step.get("preferred_missing", [])),
        )

    console.print(table)


@app.command("start")
def cmd_start(
    name: str = typer.Option(..., "--name", "-n", help="Engagement name"),
    roe_file: Optional[Path] = typer.Option(None, "--roe-file", help="Path to ROE YAML file (new engagement flow)"),
    scope_cidr: list[str] = typer.Option([], "--cidr", help="Scope CIDR range (repeatable, legacy)"),
    scope_domain: list[str] = typer.Option([], "--domain", help="Scope domain (repeatable, legacy)"),
    scope_url: list[str] = typer.Option([], "--url", help="Scope URL prefix (repeatable, legacy)"),
    roe_hash: str = typer.Option("", "--roe-hash", help="SHA-256 hash of the ROE document (legacy)"),
    authoriser: str = typer.Option("", "--authoriser", help="Authoriser identity (legacy)"),
    roe_dry_run: bool = typer.Option(False, "--roe-dry-run", help="Validate ROE file only (do not create engagement)"),
    roe_skip_approval: bool = typer.Option(False, "--roe-skip-approval", help="Skip approval workflow (admin override)"),
    valid_hours: int = typer.Option(24, "--valid-hours", help="Engagement validity window (hours)"),
    max_iterations: int = typer.Option(50, "--max-iter", help="Maximum agent loop iterations"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Config YAML path"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Policy simulation only (no execution)"),
) -> None:
    """Start a new engagement with the given scope.
    
    NEW: Use --roe-file for ROE-based engagement creation (recommended).
    LEGACY: Use --cidr/--domain/--url/--roe-hash for direct scope specification.
    """
    from pwnpilot.runtime import create_and_run_engagement, get_engagement_preflight
    from pwnpilot.data.roe_validator import validate_roe_file
    from pwnpilot.agent.roe_interpreter import ROEInterpreter
    from pwnpilot.control.roe_approval import ApprovalWorkflow
    import yaml

    if roe_file:
        # NEW ROE-based workflow
        if not roe_file.exists():
            console.print(f"[red]Error: ROE file not found:[/red] {roe_file}")
            raise typer.Exit(code=1)
        
        # Check if file is empty before parsing
        if roe_file.stat().st_size == 0:
            console.print(f"[red]Error: ROE file is empty:[/red] {roe_file}")
            console.print("[yellow]Hint:[/yellow] Create a valid ROE file with required fields (engagement, scope, policy)")
            raise typer.Exit(code=1)

        try:
            # Load and validate ROE file
            try:
                with open(roe_file) as f:
                    roe_yaml = yaml.safe_load(f)
            except yaml.YAMLError as e:
                console.print("[red]Error: Invalid YAML in ROE file[/red]")
                console.print(f"[yellow]Details:[/yellow] {str(e)}")
                raise typer.Exit(code=1)
            except Exception as e:
                console.print(f"[red]Error reading ROE file: {e}[/red]")
                raise typer.Exit(code=1)
            
            # Explicit None check after YAML parsing
            if roe_yaml is None:
                console.print("[red]Error: ROE file contains no valid YAML content[/red]")
                console.print("[yellow]Hint:[/yellow] File appears to be empty or contains only comments")
                raise typer.Exit(code=1)
            
            is_valid, error_msg = validate_roe_file(roe_yaml)
            if not is_valid:
                console.print("[red]ROE validation failed:[/red]")
                console.print(error_msg)
                raise typer.Exit(code=1)
            
            if not roe_dry_run:
                # Step 1: Interpret ROE with AI
                console.print("[bold cyan]Step 1: Interpreting ROE policies with AI...[/bold cyan]")
                config = load_config(config_file)
                interpreter = ROEInterpreter(
                    litellm_api_key=config.llm.api_key,
                    model_name=config.llm.model_name,
                    api_base_url=config.llm.api_base_url,
                )
                interpretation_result = interpreter.interpret(roe_yaml)
                
                if not interpretation_result.is_valid:
                    console.print(f"[red]Policy interpretation failed:[/red] {interpretation_result.error_message}")
                    raise typer.Exit(code=1)
                
                # Step 2: Request user approval
                console.print("\n[bold cyan]Step 2: Requesting user approval...[/bold cyan]")
                workflow = ApprovalWorkflow()
                session = workflow.create_session(
                    user=os.getenv("USER", "unknown"),
                    engagement_id=None,
                )
                
                try:
                    workflow.display_policies(session.session_id, interpretation_result)
                    workflow.request_approval(session.session_id)
                    
                    if not roe_skip_approval:
                        console.print("\n[bold cyan]Step 3: Verifying sudo password...[/bold cyan]")
                        password = typer.prompt("Sudo password", hide_input=True)
                        approval_record = workflow.approve_policies(
                            session.session_id,
                            interpretation_result,
                            password,
                        )
                        console.print("[green]✓ Approval recorded and sudo verified.[/green]")
                    else:
                        console.print("[yellow]Skipping sudo verification (admin override).[/yellow]")
                        approval_record = None
                    
                    # Extract scope from interpreted policy
                    policy = interpretation_result.extracted_policy
                    scope_cidr = policy.scope_cidrs
                    scope_domain = policy.scope_domains
                    scope_url = policy.scope_urls
                    roe_hash = hashlib.sha256(yaml.dump(roe_yaml).encode()).hexdigest()
                    authoriser = os.getenv("USER", "unknown")
                    
                except Exception as e:
                    console.print(f"[red]Approval workflow failed:[/red] {e}")
                    raise typer.Exit(code=1)
            else:
                # Dry run - just validate
                console.print("[green]✓ ROE validation passed (dry run).[/green]")
                raise typer.Exit(code=0)
        
        except yaml.YAMLError as e:
            console.print(f"[red]Invalid YAML in ROE file:[/red] {e}")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[red]ROE processing failed:[/red] {e}")
            log.error("cli.roe_processing_failed", exc=str(e))
            raise typer.Exit(code=1)
    else:
        # LEGACY scope-based workflow
        if not scope_cidr and not scope_domain and not scope_url:
            console.print("[red]Error: --roe-file required, or at least one scope target (--cidr, --domain, or --url).")
            raise typer.Exit(code=1)
        
        if not roe_hash:
            console.print("[red]Error: --roe-hash required for legacy scope-based engagement.")
            raise typer.Exit(code=1)
        
        if not authoriser:
            authoriser = os.getenv("USER", "unknown")

    console.print(f"[bold green]Starting engagement:[/bold green] {name}")
    if dry_run:
        console.print("[yellow]DRY RUN: policy simulation only, no tool execution.[/yellow]")

    preflight = get_engagement_preflight(
        scope_cidrs=scope_cidr,
        scope_domains=scope_domain,
        scope_urls=scope_url,
        config_path=config_file,
    )
    _render_preflight(preflight)

    missing = preflight.get("missing_recommended_tools", [])
    missing_tools = [str(t) for t in missing] if isinstance(missing, list) else []
    if missing_tools:
        console.print(
            "[yellow]Missing recommended tools:[/yellow] " + ", ".join(sorted(missing_tools))
        )
        install_now = typer.confirm(
            "Install missing recommended tools before starting?",
            default=False,
        )
        if install_now:
            installer = Path(__file__).resolve().parents[1] / "scripts" / "install_security_tools.sh"
            if installer.exists():
                run_installer = typer.confirm(
                    "Run automated installer now (sudo required)?",
                    default=False,
                )
                if run_installer:
                    result = subprocess.run(
                        ["sudo", "bash", str(installer)],
                        check=False,
                    )
                    if result.returncode != 0:
                        console.print(
                            "[yellow]Installer did not complete successfully. Continuing with available tools.[/yellow]"
                        )
                    preflight = get_engagement_preflight(
                        scope_cidrs=scope_cidr,
                        scope_domains=scope_domain,
                        scope_urls=scope_url,
                        config_path=config_file,
                    )
                    _render_preflight(preflight)
            else:
                console.print(
                    "[yellow]Installer script not found. Install tools manually, then rerun start if desired.[/yellow]"
                )
        else:
            console.print(
                "[yellow]Proceeding with currently available tools as requested.[/yellow]"
            )

    if scope_url and not scope_cidr and not scope_domain:
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if any(any(host in str(url) for host in local_hosts) for url in scope_url):
            console.print(
                "[yellow]Scope warning:[/yellow] URL-only local scope can require host-equivalence checks for tools like nmap. "
                "Consider adding loopback CIDRs or localhost domain scope when appropriate."
            )

    try:
        engagement_id = create_and_run_engagement(
            name=name,
            scope_cidrs=scope_cidr,
            scope_domains=scope_domain,
            scope_urls=scope_url,
            roe_document_hash=roe_hash,
            authoriser_identity=authoriser,
            valid_hours=valid_hours,
            max_iterations=max_iterations,
            config_path=config_file,
            dry_run=dry_run,
            event_subscriber=_make_live_output_handler(),
        )
        console.print(f"\n[green]Engagement complete:[/green] {engagement_id}")
    except Exception as exc:
        console.print(f"[red]Error: {exc}")
        log.error("cli.start_failed", exc=str(exc))
        raise typer.Exit(code=1) from exc


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------


@app.command("resume")
def cmd_resume(
    engagement_id: str = typer.Argument(..., help="Engagement UUID to resume"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Config YAML path"),
) -> None:
    """Resume an interrupted engagement from the last LangGraph checkpoint."""
    from pwnpilot.runtime import resume_engagement

    console.print(f"[bold]Resuming engagement:[/bold] {engagement_id}")
    try:
        resume_engagement(UUID(engagement_id), config_path=config_file)
        console.print(f"[green]Resume complete for {engagement_id}")
    except Exception as exc:
        console.print(f"[red]Error: {exc}")
        raise typer.Exit(code=1) from exc


# ---------------------------------------------------------------------------
# Approve / Deny
# ---------------------------------------------------------------------------


@app.command("approve")
def cmd_approve(
    ticket_id: str = typer.Argument(..., help="Ticket UUID to approve"),
    reason: str = typer.Option("", "--reason", "-r", help="Approval reason"),
    operator: str = typer.Option("operator", "--operator", help="Operator identity"),
    config_file: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Approve a pending high-risk action ticket."""
    from pwnpilot.runtime import get_approval_service

    svc = get_approval_service(config_path=config_file)
    ticket = svc.approve(UUID(ticket_id), resolved_by=operator, reason=reason)
    console.print(f"[green]Approved ticket {ticket_id}[/green]")


@app.command("deny")
def cmd_deny(
    ticket_id: str = typer.Argument(..., help="Ticket UUID to deny"),
    reason: str = typer.Option("", "--reason", "-r", help="Denial reason"),
    operator: str = typer.Option("operator", "--operator", help="Operator identity"),
    config_file: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Deny a pending high-risk action ticket."""
    from pwnpilot.runtime import get_approval_service

    svc = get_approval_service(config_path=config_file)
    ticket = svc.deny(UUID(ticket_id), resolved_by=operator, reason=reason)
    console.print(f"[red]Denied ticket {ticket_id}[/red]")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@app.command("report")
def cmd_report(
    engagement_id: str = typer.Argument(..., help="Engagement UUID"),
    output_dir: Path = typer.Option(Path("."), "--output", "-o", help="Output directory"),
    config_file: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Generate a report for a completed or in-progress engagement."""
    from pwnpilot.runtime import generate_report

    console.print(f"[bold]Generating report for:[/bold] {engagement_id}")
    try:
        bundle, summary = generate_report(
            UUID(engagement_id), output_dir=output_dir, config_path=config_file
        )
        console.print(f"[green]Bundle:[/green]  {bundle}")
        console.print(f"[green]Summary:[/green] {summary}")
    except Exception as exc:
        console.print(f"[red]Error: {exc}")
        raise typer.Exit(code=1) from exc


# ---------------------------------------------------------------------------
# Verify audit chain
# ---------------------------------------------------------------------------


@app.command("verify")
def cmd_verify(
    engagement_id: str = typer.Argument(..., help="Engagement UUID"),
    config_file: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Verify the audit chain integrity for an engagement."""
    from pwnpilot.runtime import get_audit_store, get_db_session

    session = get_db_session(config_path=config_file)
    from pwnpilot.data.audit_store import AuditStore
    store = AuditStore(session)
    try:
        store.verify_chain(UUID(engagement_id))
        console.print(f"[green]Audit chain OK[/green] for {engagement_id}")
    except Exception as exc:
        console.print(f"[red]Audit chain FAILED:[/red] {exc}")
        raise typer.Exit(code=1) from exc


# ---------------------------------------------------------------------------
# Simulate (policy dry-run)
# ---------------------------------------------------------------------------


@app.command("simulate")
def cmd_simulate(
    actions_file: Path = typer.Argument(..., help="JSON file with list of ActionRequest dicts"),
    engagement_id: str = typer.Option(..., "--engagement", help="Engagement UUID"),
    config_file: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Run policy simulation against a list of actions (no tool execution)."""
    from pwnpilot.runtime import run_policy_simulation

    data = json.loads(actions_file.read_text())
    results = run_policy_simulation(
        actions=data,
        engagement_id=UUID(engagement_id),
        config_path=config_file,
    )

    table = Table(title="Policy Simulation Results")
    table.add_column("Action", style="cyan")
    table.add_column("Tool")
    table.add_column("Verdict", style="bold")
    table.add_column("Reason")

    for r in results:
        colour = "green" if r["verdict"] == "allow" else "red"
        table.add_row(
            r["action_type"],
            r["tool_name"],
            f"[{colour}]{r['verdict']}[/{colour}]",
            r["reason"],
        )
    console.print(table)


# ---------------------------------------------------------------------------
# TUI dashboard
# ---------------------------------------------------------------------------


@app.command("tui")
def cmd_tui(
    engagement_id: Optional[str] = typer.Option(
        None, "--engagement", "-e", help="Engagement UUID to watch (default: latest)"
    ),
    refresh: float = typer.Option(2.0, "--refresh", help="Refresh interval in seconds"),
) -> None:
    """Launch the live Textual TUI dashboard."""
    from pwnpilot.tui.app import run_dashboard

    run_dashboard(engagement_id=engagement_id, refresh_interval=refresh)


# ---------------------------------------------------------------------------
# Keys — generate operator signing key pair
# ---------------------------------------------------------------------------


@app.command("keys")
def cmd_keys(
    generate: bool = typer.Option(False, "--generate", help="Generate a new Ed25519 key pair"),
    private_key_path: Path = typer.Option(
        Path("~/.pwnpilot/operator.key").expanduser(),
        "--private-key",
        help="Path to write private key (PEM)",
    ),
    public_key_path: Path = typer.Option(
        Path("~/.pwnpilot/operator.pub").expanduser(),
        "--public-key",
        help="Path to write public key (PEM)",
    ),
) -> None:
    """Manage operator signing keys."""
    if not generate:
        console.print("[yellow]Use --generate to create a new key pair.[/yellow]")
        raise typer.Exit(code=1)

    from pwnpilot.reporting.signer import ReportSigner

    if private_key_path.exists():
        confirm = typer.confirm(
            f"Private key already exists at {private_key_path}. Overwrite?",
            default=False,
        )
        if not confirm:
            raise typer.Exit(code=0)

    ReportSigner.generate_key_pair(private_key_path, public_key_path)
    console.print(f"[green]Private key:[/green] {private_key_path}")
    console.print(f"[green]Public key: [/green] {public_key_path}")
    console.print("[yellow]Keep the private key secret. Back it up securely.[/yellow]")


# ---------------------------------------------------------------------------
# Report verify — verify a signed report bundle
# ---------------------------------------------------------------------------


@app.command("verify-report")
def cmd_verify_report(
    bundle: Path = typer.Argument(..., help="Path to report JSON bundle"),
    sig_file: Optional[Path] = typer.Option(None, "--sig", help="Signature file (default: <bundle>.sig)"),
    public_key_file: Optional[Path] = typer.Option(
        None, "--public-key", help="Public key PEM file (default: embedded in bundle)"
    ),
) -> None:
    """Verify the Ed25519 signature on a report bundle."""
    from pwnpilot.reporting.signer import ReportSigner, SignatureError

    if not bundle.exists():
        console.print(f"[red]Bundle not found:[/red] {bundle}")
        raise typer.Exit(code=1)

    resolved_sig = sig_file or bundle.with_suffix(".sig")
    if not resolved_sig.exists():
        console.print(f"[red]Signature file not found:[/red] {resolved_sig}")
        raise typer.Exit(code=1)

    try:
        ReportSigner.verify(bundle, resolved_sig, public_key_file)
        console.print(f"[green]✓ Signature VALID[/green] — {bundle.name}")
    except SignatureError as exc:
        console.print(f"[red]✗ Signature INVALID:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        console.print(f"[red]Error during verification:[/red] {exc}")
        raise typer.Exit(code=1) from exc


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
# DB — database maintenance commands
# ---------------------------------------------------------------------------

db_app = typer.Typer(name="db", help="Database maintenance commands.")
app.add_typer(db_app)


@db_app.command("backup")
def cmd_db_backup(
    output: Path = typer.Option(
        None, "--output", "-o",
        help="Backup destination path (default: pwnpilot-backup-<timestamp>.db for SQLite "
             "or pwnpilot-backup-<timestamp>.sql for PostgreSQL)",
    ),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Config YAML path"),
) -> None:
    """
    Create a backup of the pwnpilot database.

    For SQLite, uses the SQLite online backup API (via '.backup' dot-command).
    For PostgreSQL, runs pg_dump.
    """
    import shutil
    import subprocess  # noqa: S404 — fixed, trusted args only
    import yaml as _yaml

    cfg: dict = {}
    if config_file and config_file.exists():
        with config_file.open() as fh:
            cfg = _yaml.safe_load(fh) or {}

    db_url: str = (
        os.environ.get("PWNPILOT_DB_URL")
        or cfg.get("database", {}).get("url")
        or "sqlite:///pwnpilot.db"
    )

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if db_url.startswith("sqlite"):
        db_file = db_url.replace("sqlite:///", "").replace("sqlite://", "")
        if not Path(db_file).exists():
            console.print(f"[red]SQLite database not found:[/red] {db_file}")
            raise typer.Exit(code=1)

        backup_path: Path = output or Path(f"pwnpilot-backup-{ts}.db")
        sqlite3_bin = shutil.which("sqlite3")
        if not sqlite3_bin:
            console.print("[red]sqlite3 binary not found on PATH — cannot backup.[/red]")
            raise typer.Exit(code=1)

        result = subprocess.run(  # noqa: S603
            [sqlite3_bin, db_file, f".backup {backup_path}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            console.print(f"[red]Backup failed:[/red] {result.stderr.strip()}")
            raise typer.Exit(code=1)

        import stat as _stat
        backup_path.chmod(0o600)
        console.print(f"[green]Backup written:[/green] {backup_path}")

    elif "postgresql" in db_url or "postgres" in db_url:
        pg_dump = shutil.which("pg_dump")
        if not pg_dump:
            console.print("[red]pg_dump not found on PATH — install postgresql-client.[/red]")
            raise typer.Exit(code=1)

        backup_path = output or Path(f"pwnpilot-backup-{ts}.sql")
        result = subprocess.run(  # noqa: S603
            [pg_dump, db_url, "-f", str(backup_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            console.print(f"[red]pg_dump failed:[/red] {result.stderr.strip()}")
            raise typer.Exit(code=1)

        backup_path.chmod(0o600)
        console.print(f"[green]Backup written:[/green] {backup_path}")

    else:
        console.print(f"[red]Unsupported database URL scheme:[/red] {db_url}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Check — run startup validation
# ---------------------------------------------------------------------------


@app.command("check")
def cmd_check(
    config_file: Optional[Path] = typer.Option(None, "--config", help="Config YAML path"),
) -> None:
    """
    Run preflight checks: config, DB connectivity, migration state, signing key, tool binaries.
    Exits 1 if any issues are found.
    """
    from pwnpilot.runtime import run_startup_checks

    issues = run_startup_checks(config_path=config_file)
    if not issues:
        console.print("[green]✓ All startup checks passed.[/green]")
        return

    for issue in issues:
        prefix = issue.split(":")[0]
        console.print(f"[red]✗ {issue}[/red]")

    raise typer.Exit(code=1)


@plugins_app.command("list")
def cmd_plugins_list(
    config_file: Optional[Path] = typer.Option(None, "--config", help="Config YAML path"),
    show_disabled: bool = typer.Option(False, "--show-disabled", help="Include disabled/rejected tools"),
) -> None:
    """Show effective tool catalog from the plugin registry."""
    from pwnpilot.runtime import get_tool_registry

    registry = get_tool_registry(config_path=config_file)
    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool")
    table.add_column("Enabled")
    table.add_column("Risk")
    table.add_column("Binary")
    table.add_column("Source")
    table.add_column("Trust")
    table.add_column("Reason")

    rows = registry.tools
    for tool_name in sorted(rows.keys()):
        desc = rows[tool_name]
        if not show_disabled and not desc.enabled:
            continue
        table.add_row(
            tool_name,
            "yes" if desc.enabled else "no",
            desc.risk_class,
            desc.binary_name or "-",
            desc.source,
            desc.trust_status,
            desc.trust_reason or "-",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# ROE Commands (Phase 5-6)
# ---------------------------------------------------------------------------


roe_app = typer.Typer(
    help="ROE (Rules of Engagement) management and verification.",
    add_completion=False,
)
app.add_typer(roe_app, name="roe")


@roe_app.command("verify")
def cmd_roe_verify(
    file: Path = typer.Argument(..., help="Path to ROE YAML file"),
) -> None:
    """Validate a ROE file against the schema."""
    from pwnpilot.data.roe_validator import validate_roe_file, _parse_comma_separated_string
    import yaml

    if not file.exists():
        console.print(f"[red]Error: File not found:[/red] {file}")
        raise typer.Exit(code=1)

    try:
        with open(file) as f:
            roe_yaml = yaml.safe_load(f)
        
        is_valid, error_msg = validate_roe_file(roe_yaml)
        
        if is_valid:
            console.print(f"[green]✓ ROE file is valid:[/green] {file}")
            console.print(f"  Schema version: v1")
            # Parse comma-separated strings from scope
            scope = roe_yaml.get('scope', {})
            cidrs = _parse_comma_separated_string(scope.get('cidrs', ''))
            domains = _parse_comma_separated_string(scope.get('domains', ''))
            restricted_actions = _parse_comma_separated_string(scope.get('restricted_actions', ''))
            console.print(f"  Scope targets: {len(cidrs) + len(domains)}")
            console.print(f"  Allowed actions: {len(restricted_actions)}")
        else:
            console.print(f"[red]✗ ROE file validation failed:[/red] {file}")
            console.print(error_msg)
            raise typer.Exit(code=1)
    except yaml.YAMLError as e:
        console.print(f"[red]Invalid YAML:[/red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@roe_app.command("list")
def cmd_roe_list(
    engagement_id: Optional[str] = typer.Option(None, "--engagement", "-e", help="Filter by engagement ID"),
    active_only: bool = typer.Option(True, "--all", help="Show inactive ROE files"),
    config_file: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """List approved ROE decisions for an engagement."""
    from pwnpilot.runtime import get_db_session
    from pwnpilot.data.operator_decision_store import OperatorDecisionStore
    from pwnpilot.data.models import OperatorDecisionType

    console.print("[bold cyan]ROE Approvals[/bold cyan]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Decision ID")
    table.add_column("Engagement ID")
    table.add_column("Actor")
    table.add_column("Scope")
    table.add_column("Decided At")

    try:
        session = get_db_session(config_path=config_file)
        store = OperatorDecisionStore(session)
        if engagement_id:
            decisions = list(store.decisions_by_type(UUID(engagement_id), OperatorDecisionType.ROE_APPROVAL))
        else:
            console.print("[yellow]Specify --engagement to list ROE approvals for a specific engagement.[/yellow]")
            return
        for d in decisions:
            table.add_row(
                str(d.decision_id)[:8],
                str(d.engagement_id)[:8],
                d.actor,
                d.scope,
                d.decided_at.isoformat() if d.decided_at else "",
            )
        console.print(table)
        if not decisions:
            console.print("[yellow]No ROE approvals found.[/yellow]")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)


@roe_app.command("audit")
def cmd_roe_audit(
    engagement_id: str = typer.Argument(..., help="Engagement UUID"),
    config_file: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Show approval and audit trail for an engagement."""
    from pwnpilot.runtime import get_db_session
    from pwnpilot.data.audit_store import AuditStore
    from pwnpilot.data.operator_decision_store import OperatorDecisionStore

    console.print(f"[bold cyan]Audit Trail for Engagement:[/bold cyan] {engagement_id}")

    try:
        session = get_db_session(config_path=config_file)
        audit_store = AuditStore(session)
        decision_store = OperatorDecisionStore(session)

        # Audit events table
        table = Table(show_header=True, header_style="bold")
        table.add_column("Timestamp")
        table.add_column("Actor")
        table.add_column("Event")
        table.add_column("Details")
        events = list(audit_store.events_for_engagement(UUID(engagement_id)))
        for ev in events:
            table.add_row(
                str(ev.get("created_at", ""))[:19],
                str(ev.get("actor", "")),
                str(ev.get("event_type", "")),
                str(ev.get("payload", ""))[:80],
            )
        console.print(table)

        # Operator decisions summary
        decisions = list(decision_store.decisions_for_engagement(UUID(engagement_id)))
        if decisions:
            console.print(f"\n[bold]Operator Decisions:[/bold] {len(decisions)}")
            dtable = Table(show_header=True, header_style="bold")
            dtable.add_column("Type")
            dtable.add_column("Scope")
            dtable.add_column("Actor")
            dtable.add_column("Decided At")
            for d in decisions:
                dtable.add_row(
                    d.decision_type.value,
                    d.scope,
                    d.actor,
                    d.decided_at.isoformat() if d.decided_at else "",
                )
            console.print(dtable)
        else:
            console.print("[yellow]No operator decisions found.[/yellow]")

    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)


@roe_app.command("export")
def cmd_roe_export(
    engagement_id: str = typer.Argument(..., help="Engagement UUID"),
    output: Path = typer.Option(None, "--output", "-o", help="Export file path (default: roe-audit-{engagement_id}.json)"),
    config_file: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Export audit report with ROE, approval chain, and timeline."""
    from pwnpilot.runtime import get_db_session
    from pwnpilot.data.audit_store import AuditStore
    from pwnpilot.data.operator_decision_store import OperatorDecisionStore
    from pwnpilot.services.export_service import ExportService

    output_path = output or Path(f"roe-audit-{engagement_id}.json")
    try:
        session = get_db_session(config_path=config_file)
        audit_store = AuditStore(session)
        decision_store = OperatorDecisionStore(session)
        svc = ExportService(audit_store=audit_store, operator_decision_store=decision_store)
        written = svc.export(UUID(engagement_id), output_path=output_path)
        console.print(f"[green]✓ Audit report exported:[/green] {written}")
    except Exception as exc:
        console.print(f"[red]Error exporting report:[/red] {exc}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------


def main() -> None:
    try:
        cfg = load_config()
        configure_logging_from_config(getattr(cfg, "logging", None))
    except Exception:
        # Fall back to defaults if config is unavailable during CLI startup.
        configure_logging_from_config(None)
    app()
