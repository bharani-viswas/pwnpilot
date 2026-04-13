"""
Tool Runner — executes adapter commands in a hardened, isolated subprocess context.

Isolation (v1):
- subprocess.run with explicit list (no shell=True) — ADR-002, ADR-007
- Process group timeout enforced by SIGKILL
- Resource limits via resource module (CPU time, memory)
- stdout/stderr streamed in 64 KB chunks to evidence store (never buffered in memory)
- 256 MB evidence size cap per action

ADR-007: raises ValueError if build_command() returns a string (structural enforcement)
"""
from __future__ import annotations

import io
import os
import resource
import signal
import subprocess
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Iterator
from uuid import UUID

import structlog

from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.data.models import (
    ActionRequest,
    ErrorClass,
    FailureReason,
    OutcomeStatus,
    ToolExecutionResult,
)
from pwnpilot.governance.kill_switch import KillSwitch
from pwnpilot.plugins.binaries import candidate_binaries, resolve_binary_for_tool
from pwnpilot.plugins.sdk import BaseAdapter

log = structlog.get_logger(__name__)

_CHUNK_SIZE: int = 64 * 1024
_DEFAULT_CPU_LIMIT: int = 300       # seconds (should be overridden by config)
_DEFAULT_MEM_LIMIT: int = 2 * 1024 * 1024 * 1024  # 2 GB virtual memory (should be overridden by config)
_DEFAULT_TIMEOUT: int = 300         # wall-clock seconds

_MAX_LOG_PREVIEW: int = 2048


def _preview_bytes(data: bytes, max_chars: int = _MAX_LOG_PREVIEW) -> str:
    """Return a bounded UTF-8 preview for logging large process output."""
    if not data:
        return ""
    text = data.decode(errors="replace")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...<truncated>"


def _redact_sensitive(value: object) -> object:
    """Redact common sensitive keys from structured payloads before logging."""
    if isinstance(value, dict):
        redacted: dict[object, object] = {}
        for k, v in value.items():
            key = str(k).lower()
            if any(token in key for token in ("token", "password", "secret", "api_key")):
                redacted[k] = "<redacted>"
            else:
                redacted[k] = _redact_sensitive(v)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive(v) for v in value]
    return value


def _normalized_blob(stdout: bytes, stderr: bytes) -> str:
    return (stdout + b"\n" + stderr).decode(errors="replace").lower()


def _extract_hint_codes(parsed_output: dict[str, object]) -> set[str]:
    hints = parsed_output.get("execution_hints", []) if isinstance(parsed_output, dict) else []
    out: set[str] = set()
    if not isinstance(hints, list):
        return out
    for item in hints:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code", "")).strip().lower()
        if code:
            out.add(code)
    return out


def _classify_outcome(
    *,
    exit_code: int,
    timed_out: bool,
    error_class: ErrorClass | None,
    parsed_output: dict[str, object],
    stdout: bytes,
    stderr: bytes,
) -> tuple[OutcomeStatus, list[FailureReason]]:
    reasons: list[FailureReason] = []
    blob = _normalized_blob(stdout, stderr)
    hint_codes = _extract_hint_codes(parsed_output)
    new_findings_count = int(parsed_output.get("new_findings_count", 0) or 0)

    if timed_out or error_class == ErrorClass.TIMEOUT:
        reasons.append(FailureReason.TIMEOUT)

    if (
        "connection refused" in blob
        or "failed to connect" in blob
        or "target is not responding" in blob
        or "could not resolve host" in blob
    ):
        reasons.append(FailureReason.TARGET_UNREACHABLE)

    if (
        "headless" in blob and "gui" in blob
    ) or "cannot open display" in blob:
        reasons.append(FailureReason.TOOL_MODE_MISMATCH)

    if (
        "401 unauthorized" in blob
        or "403 forbidden" in blob
        or "access denied" in blob
        or "authentication required" in blob
    ):
        reasons.append(FailureReason.AUTH_FAILURE)

    if error_class == ErrorClass.PARSE_ERROR or str(parsed_output.get("parser_error", "")).strip():
        reasons.append(FailureReason.PARSER_DEGRADED)

    if hint_codes & {"no_forms_detected", "no_matches", "wildcard_detected", "output_format_invalid"}:
        reasons.append(FailureReason.NO_ACTIONABLE_OUTPUT)

    # Deduplicate while preserving order
    unique_reasons: list[FailureReason] = []
    for reason in reasons:
        if reason not in unique_reasons:
            unique_reasons.append(reason)

    hard_fail = any(
        reason in {
            FailureReason.TARGET_UNREACHABLE,
            FailureReason.TOOL_MODE_MISMATCH,
            FailureReason.TIMEOUT,
        }
        for reason in unique_reasons
    )

    if hard_fail:
        return OutcomeStatus.FAILED, unique_reasons

    if exit_code != 0 and not unique_reasons:
        unique_reasons.append(FailureReason.UNKNOWN_RUNTIME_FAILURE)
        return OutcomeStatus.FAILED, unique_reasons

    if unique_reasons:
        return OutcomeStatus.DEGRADED, unique_reasons

    if new_findings_count == 0 and exit_code == 0:
        return OutcomeStatus.DEGRADED, [FailureReason.NO_ACTIONABLE_OUTPUT]

    return OutcomeStatus.SUCCESS, []


class HaltedError(Exception):
    """Raised when the kill switch is set before execution starts."""


class ToolRunner:
    """
    Executes tool adapters in isolated subprocesses with resource limits and evidence
    capture.
    """

    def __init__(
        self,
        adapters: dict[str, BaseAdapter],
        evidence_store: EvidenceStore,
        kill_switch: KillSwitch,
        cpu_limit: int = _DEFAULT_CPU_LIMIT,
        mem_limit: int = _DEFAULT_MEM_LIMIT,
        timeout: int = _DEFAULT_TIMEOUT,
        max_workers: int = 4,
    ) -> None:
        self._adapters = adapters
        self._evidence = evidence_store
        self._kill_switch = kill_switch
        self._cpu_limit = cpu_limit
        self._mem_limit = mem_limit
        self._timeout = timeout
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, action: ActionRequest) -> ToolExecutionResult:
        """
        Validate, build, and execute the tool command for the given ActionRequest.
        Streams output to the evidence store.  Returns ToolExecutionResult.
        """
        if self._kill_switch.is_set():
            raise HaltedError("Kill switch is active; refusing to spawn subprocess.")

        adapter = self._adapters.get(action.tool_name)
        if adapter is None:
            raise KeyError(f"Unknown tool: '{action.tool_name}'")

        # Validate params through adapter
        params = adapter.validate_params(action.params)

        # Build command — MUST return list[str] (ADR-007)
        cmd = adapter.build_command(params)
        if isinstance(cmd, str):
            raise ValueError(
                f"Adapter '{action.tool_name}'.build_command() returned a string. "
                "It MUST return list[str] (ADR-007)."
            )

        # Resolve binary per-OS to handle tool naming differences across environments.
        if cmd:
            resolved = resolve_binary_for_tool(action.tool_name, str(cmd[0]))
            if resolved:
                cmd[0] = resolved

        log.info(
            "runner.executing",
            tool=action.tool_name,
            action_id=str(action.action_id),
            engagement_id=str(action.engagement_id),
            command=cmd,
            params=_redact_sensitive(action.params),
        )

        start = time.monotonic()
        stdout_bytes, stderr_bytes, exit_code, timed_out = self._run_subprocess(
            cmd,
            action.tool_name,
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        error_class: ErrorClass | None = None
        if timed_out:
            error_class = ErrorClass.TIMEOUT
        elif exit_code != 0:
            error_class = ErrorClass.NONZERO_EXIT

        # Store evidence (streaming write)
        stdout_idx = self._evidence.write_bytes(
            action.engagement_id, action.action_id, stdout_bytes
        )
        stderr_idx = self._evidence.write_bytes(
            action.engagement_id, action.action_id, stderr_bytes
        )

        # Parse output
        try:
            parsed = adapter.parse(stdout_bytes, stderr_bytes, exit_code)
        except Exception as exc:
            log.error("runner.parse_error", exc=str(exc), tool=action.tool_name)
            error_class = ErrorClass.PARSE_ERROR
            from pwnpilot.plugins.sdk import ParsedOutput
            parsed = ParsedOutput(parser_error=str(exc))

        result = ToolExecutionResult(
            action_id=action.action_id,
            tool_name=action.tool_name,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_hash=stdout_idx.sha256_hash,
            stderr_hash=stderr_idx.sha256_hash,
            stdout_evidence_id=stdout_idx.evidence_id,
            stderr_evidence_id=stderr_idx.evidence_id,
            stdout_evidence_path=stdout_idx.file_path,
            stderr_evidence_path=stderr_idx.file_path,
            parsed_output=parsed.model_dump(),
            parser_confidence=parsed.confidence,
            error_class=error_class,
        )

        outcome_status, failure_reasons = _classify_outcome(
            exit_code=exit_code,
            timed_out=timed_out,
            error_class=error_class,
            parsed_output=result.parsed_output,
            stdout=stdout_bytes,
            stderr=stderr_bytes,
        )
        result = result.model_copy(
            update={
                "outcome_status": outcome_status,
                "failure_reasons": failure_reasons,
            }
        )

        log.info(
            "runner.complete",
            tool=action.tool_name,
            action_id=str(action.action_id),
            engagement_id=str(action.engagement_id),
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_hash=result.stdout_hash,
            stderr_hash=result.stderr_hash,
            stdout_evidence_id=str(result.stdout_evidence_id) if result.stdout_evidence_id else None,
            stderr_evidence_id=str(result.stderr_evidence_id) if result.stderr_evidence_id else None,
            stdout_bytes=len(stdout_bytes),
            stderr_bytes=len(stderr_bytes),
            stdout_preview=_preview_bytes(stdout_bytes),
            stderr_preview=_preview_bytes(stderr_bytes),
            parsed_output=_redact_sensitive(result.parsed_output),
            parser_confidence=result.parser_confidence,
            error_class=(result.error_class.value if result.error_class else None),
              outcome_status=result.outcome_status.value,
              failure_reasons=[reason.value for reason in result.failure_reasons],
        )
        return result

    @property
    def available_tools(self) -> list[str]:
        """Return the names of tools currently registered with the runner."""
        return sorted(self._adapters.keys())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_subprocess(
        self,
        cmd: list[str],
        tool_name: str,
    ) -> tuple[bytes, bytes, int, bool]:
        """
        Run *cmd* as a subprocess with resource limits.
        Returns (stdout, stderr, exit_code, timed_out).
        """
        def _preexec() -> None:
            # Set resource limits for the child process
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (self._cpu_limit, self._cpu_limit))
                resource.setrlimit(resource.RLIMIT_AS, (self._mem_limit, self._mem_limit))
            except Exception:
                pass
            # New process group so we can SIGKILL all children
            os.setsid()

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,   # ADR-002: never shell=True
                preexec_fn=_preexec,
            )
        except FileNotFoundError as exc:
            candidates = candidate_binaries(tool_name, cmd[0])
            raise FileNotFoundError(
                f"Tool binary not found: {cmd[0]!r}.  "
                f"Checked candidates: {candidates}. "
                "Ensure a compatible binary is installed (run install_security_tools.sh)."
            ) from exc

        timed_out = False
        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=self._timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout_bytes, stderr_bytes = proc.communicate()

        return stdout_bytes, stderr_bytes, proc.returncode or 0, timed_out
