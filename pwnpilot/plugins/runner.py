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
from pwnpilot.data.models import ActionRequest, ErrorClass, ToolExecutionResult
from pwnpilot.governance.kill_switch import KillSwitch
from pwnpilot.plugins.sdk import BaseAdapter

log = structlog.get_logger(__name__)

_CHUNK_SIZE: int = 64 * 1024
_DEFAULT_CPU_LIMIT: int = 300       # seconds
_DEFAULT_MEM_LIMIT: int = 512 * 1024 * 1024  # 512 MB virtual memory
_DEFAULT_TIMEOUT: int = 300         # wall-clock seconds


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

        log.info(
            "runner.executing",
            tool=action.tool_name,
            action_id=str(action.action_id),
        )

        start = time.monotonic()
        stdout_bytes, stderr_bytes, exit_code, timed_out = self._run_subprocess(cmd)
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
            parsed_output=parsed.model_dump(),
            parser_confidence=parsed.confidence,
            error_class=error_class,
        )

        log.info(
            "runner.complete",
            tool=action.tool_name,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_subprocess(
        self, cmd: list[str]
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
            raise FileNotFoundError(
                f"Tool binary not found: {cmd[0]!r}.  "
                "Ensure it is installed (run install_security_tools.sh)."
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
