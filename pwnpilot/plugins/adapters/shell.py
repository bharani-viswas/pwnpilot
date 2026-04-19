"""
shell adapter — controlled terminal command execution.

Risk class: recon_passive
Input: target context, allow-listed command name, optional args
Output: command stdout/stderr summary and execution metadata
"""
from __future__ import annotations

import hmac
import os
import re
from typing import Any

from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams

_SAFE_ARG_RE = re.compile(r"^[a-zA-Z0-9_./:@%+=,\-]+$")
_SAFE_TARGET_RE = re.compile(r"^[a-zA-Z0-9.\-:/\[\]_]+$")
_SAFE_COMMAND_RE = re.compile(r"^[a-zA-Z0-9_.\-]+$")

_ALLOWED_COMMANDS: set[str] = {
    "pwd",
    "ls",
    "whoami",
    "id",
    "uname",
    "ip",
    "ss",
    "netstat",
    "ps",
    "cat",
    "head",
    "tail",
    "grep",
    "find",
    "dig",
    "nslookup",
    "curl",
}

_MAX_ARGS = 12
_MAX_ARGS_UNSAFE = 64
_UNSAFE_ENABLE_ENV = "PWNPILOT_SHELL_ALLOW_UNSAFE"
_UNSAFE_TOKEN_ENV = "PWNPILOT_SHELL_PERMISSION_TOKEN"


class ShellAdapter(BaseAdapter):
    """Adapter for controlled terminal command execution.
    
    Supports permission grants: when a command is not in the allow-list,
    if a permission has been granted for that command in the current engagement,
    it will be allowed.
    """

    _MANIFEST = PluginManifest(
        name="shell",
        version="1.0",
        risk_class="recon_passive",
        # Shell commands span both passive recon (ls, id, ps, dig) and
        # active investigation (curl, netstat).  Allow either action_type
        # so the planner can use shell for active_scan proposals without
        # triggering a risk-class mismatch rejection in the validator.
        compatible_action_types=["recon_passive", "active_scan"],
        description="Controlled, allow-listed terminal command execution",
        input_schema={
            "type": "object",
            "required": ["target", "command"],
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target context (host/domain/url or localhost)",
                },
                "command": {
                    "type": "string",
                    "description": "Allow-listed command binary",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
                "unsafe": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable unrestricted command mode (requires permission token)",
                },
                "permission_token": {
                    "type": "string",
                    "default": "",
                    "description": "Operator permission token required for unsafe mode",
                },
            },
            "x_supported_target_types": ["ip", "domain", "url", "cidr", "unknown"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "findings": {"type": "array"},
                "raw_summary": {"type": "string"},
            },
        },
    )

    def __init__(self, permission_context: dict[str, Any] | None = None) -> None:
        """Initialize shell adapter with optional permission context.
        
        Args:
            permission_context: Dict with 'permission_store' and 'engagement_id' keys
                               for checking runtime-granted permissions.
        """
        super().__init__()
        self._permission_context = permission_context or {}

    @property
    def manifest(self) -> PluginManifest:
        return self._MANIFEST

    def validate_params(self, params: dict[str, Any]) -> ToolParams:
        target = str(params.get("target", "")).strip()
        if not target:
            raise ValueError("shell: 'target' parameter is required.")
        if not _SAFE_TARGET_RE.match(target):
            raise ValueError(f"shell: target contains unsafe characters: {target!r}")

        command = str(params.get("command", "")).strip()
        if not command:
            raise ValueError("shell: 'command' parameter is required.")

        unsafe = bool(params.get("unsafe", False))
        permission_token = str(params.get("permission_token", "")).strip()
        unsafe_enabled = os.environ.get(_UNSAFE_ENABLE_ENV, "0") == "1"
        expected_token = os.environ.get(_UNSAFE_TOKEN_ENV, "").strip()

        if unsafe:
            if not unsafe_enabled:
                raise ValueError(
                    f"shell: unsafe mode is disabled. Set {_UNSAFE_ENABLE_ENV}=1 to enable it."
                )
            if not expected_token:
                raise ValueError(
                    f"shell: unsafe mode requires {_UNSAFE_TOKEN_ENV} to be configured on the runtime host."
                )
            # H-1: Use constant-time comparison to prevent timing attacks
            if not hmac.compare_digest(permission_token.encode(), expected_token.encode()):
                raise ValueError("shell: unsafe mode denied; invalid permission token.")
            if not _SAFE_COMMAND_RE.match(command):
                raise ValueError(f"shell: invalid command name: {command!r}")
        else:
            # Check if command is in allow-list or has been granted permission
            command_allowed = command in _ALLOWED_COMMANDS
            
            if not command_allowed:
                # Check if permission has been granted for this command
                permission_store = self._permission_context.get("permission_store")
                engagement_id = self._permission_context.get("engagement_id")
                
                if permission_store and engagement_id:
                    if permission_store.has_permission(
                        engagement_id,
                        "shell_command",
                        command,
                    ):
                        command_allowed = True
            
            if not command_allowed:
                raise ValueError(
                    f"shell: command '{command}' is not allow-listed. Allowed: {sorted(_ALLOWED_COMMANDS)}"
                )

        raw_args = params.get("args", [])
        if not isinstance(raw_args, list):
            raise ValueError("shell: 'args' must be an array of strings.")
        max_args = _MAX_ARGS_UNSAFE if unsafe else _MAX_ARGS
        if len(raw_args) > max_args:
            raise ValueError(f"shell: too many args ({len(raw_args)}), max is {max_args}.")

        args: list[str] = []
        for item in raw_args:
            arg = str(item).strip()
            if not arg:
                continue
            if unsafe:
                if "\x00" in arg:
                    raise ValueError("shell: null-byte argument rejected.")
            else:
                if not _SAFE_ARG_RE.match(arg):
                    raise ValueError(f"shell: unsafe argument rejected: {arg!r}")
            args.append(arg)

        return ToolParams(
            target=target,
            extra={
                "command": command,
                "args": args,
                "unsafe": unsafe,
            },
        )

    def build_command(self, params: ToolParams) -> list[str]:
        return [str(params.extra["command"]), *[str(a) for a in params.extra.get("args", [])]]

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
        out = stdout.decode(errors="replace").strip()
        err = stderr.decode(errors="replace").strip()

        summary_parts = [f"exit_code={exit_code}"]
        if out:
            summary_parts.append(f"stdout_lines={len(out.splitlines())}")
        if err:
            summary_parts.append(f"stderr_lines={len(err.splitlines())}")

        findings = [
            {
                "title": "Shell command output",
                "vuln_ref": "shell:command-output",
                "severity": "info",
                "stdout_preview": "\n".join(out.splitlines()[:10]),
                "stderr_preview": "\n".join(err.splitlines()[:10]),
            }
        ]

        return ParsedOutput(
            findings=findings,
            new_findings_count=0,
            confidence=0.7 if exit_code == 0 else 0.4,
            raw_summary="shell " + ", ".join(summary_parts),
            parser_error=None if exit_code == 0 else f"shell command exited with code {exit_code}",
        )
