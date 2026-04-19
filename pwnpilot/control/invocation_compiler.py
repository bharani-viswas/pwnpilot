"""Invocation compiler: bridges planner intent and adapter-feasible invocation params."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class InvocationCompileResult:
    feasible: bool
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    reason_code: str = ""
    reason_detail: str = ""
    remediation_hint: str = ""
    diagnostics: dict[str, Any] = field(default_factory=dict)


class InvocationCompiler:
    """Compile planner proposal intent into a tool-feasible invocation payload."""

    def compile(
        self,
        *,
        tool_name: str,
        target: str,
        params: dict[str, Any],
        resolved_target: dict[str, Any],
        supported_target_types: list[str] | None,
        previous_actions: list[dict[str, Any]] | None,
    ) -> InvocationCompileResult:
        tool = str(tool_name or "").strip().lower()
        current_target = str(target or "").strip()
        current_params = dict(params or {})
        resolved = dict(resolved_target or {})
        supported = {
            str(v).strip().lower()
            for v in (supported_target_types or [])
            if str(v).strip()
        }
        previous = list(previous_actions or [])

        if not tool:
            return InvocationCompileResult(
                feasible=False,
                target=current_target,
                params=current_params,
                reason_code="INVOCATION_UNFIT",
                reason_detail="Tool name missing for invocation compile.",
                remediation_hint="Planner must provide a concrete tool_name.",
            )

        if tool == "nmap":
            host = str(resolved.get("host", "")).strip()
            target_type = str(resolved.get("target_type", "")).strip().lower()
            if target_type == "url" and host:
                return InvocationCompileResult(
                    feasible=True,
                    target=host,
                    params=current_params,
                    diagnostics={
                        "invocation_subcode": "target_projection_invalid",
                        "coercion": "url_to_host",
                        "original_target": current_target,
                        "projected_target": host,
                    },
                )
            if target_type in {"ip", "domain", "cidr"}:
                return InvocationCompileResult(
                    feasible=True,
                    target=current_target,
                    params=current_params,
                    diagnostics={
                        "invocation_subcode": "target_projection_valid",
                    },
                )
            if supported and "url" not in supported and target_type == "url":
                return InvocationCompileResult(
                    feasible=False,
                    target=current_target,
                    params=current_params,
                    reason_code="INVOCATION_UNFIT",
                    reason_detail="nmap target must resolve to host/IP/CIDR.",
                    remediation_hint="Provide a domain/IP/CIDR target or URL with resolvable host.",
                    diagnostics={"invocation_subcode": "target_projection_invalid"},
                )

        if tool == "gobuster":
            mode_value = current_params.get("mode")
            if mode_value is None:
                return InvocationCompileResult(
                    feasible=True,
                    target=current_target,
                    params=current_params,
                    diagnostics={"invocation_subcode": "target_projection_valid"},
                )

            mode = str(mode_value).strip().lower()
            if mode == "dir":
                base_url = str(resolved.get("base_url", "")).strip()
                parsed = urlparse(current_target)
                if parsed.scheme in {"http", "https"} and parsed.netloc:
                    normalized = base_url or f"{parsed.scheme}://{parsed.netloc}"
                    return InvocationCompileResult(
                        feasible=True,
                        target=normalized,
                        params=current_params,
                        diagnostics={
                            "invocation_subcode": "target_projection_valid",
                            "coercion": "url_to_base_url",
                            "original_target": current_target,
                            "projected_target": normalized,
                        },
                    )
                return InvocationCompileResult(
                    feasible=False,
                    target=current_target,
                    params=current_params,
                    reason_code="INVOCATION_UNFIT",
                    reason_detail="gobuster dir mode requires an http/https URL target.",
                    remediation_hint="Provide a web URL target for gobuster dir mode.",
                    diagnostics={"invocation_subcode": "target_projection_invalid"},
                )

        if tool == "sqlmap":
            next_params = dict(current_params)
            if self._recent_no_forms_hint(previous, current_target):
                next_params["forms"] = False
                if not str(next_params.get("mode_selection_reason", "")).strip():
                    next_params["mode_selection_reason"] = "no_forms_hint_recovery"
                return InvocationCompileResult(
                    feasible=True,
                    target=current_target,
                    params=next_params,
                    diagnostics={
                        "invocation_subcode": "low_value_repetition",
                        "coercion": "force_non_forms_mode",
                    },
                )
            return InvocationCompileResult(
                feasible=True,
                target=current_target,
                params=next_params,
                diagnostics={"invocation_subcode": "target_projection_valid"},
            )

        return InvocationCompileResult(
            feasible=True,
            target=current_target,
            params=current_params,
            diagnostics={"invocation_subcode": "target_projection_valid"},
        )

    @staticmethod
    def _recent_no_forms_hint(previous_actions: list[dict[str, Any]], target: str, lookback: int = 8) -> bool:
        base_target = InvocationCompiler._base_target(target)
        recent = previous_actions[-max(1, lookback):]
        for action in recent:
            if not isinstance(action, dict):
                continue
            if str(action.get("tool_name", "")).strip() != "sqlmap":
                continue
            action_target = str(action.get("target", "")).strip()
            if InvocationCompiler._base_target(action_target) != base_target:
                continue
            hint_codes = {
                str(code).strip()
                for code in action.get("execution_hint_codes", [])
                if str(code).strip()
            }
            if "no_forms_detected" in hint_codes:
                return True
        return False

    @staticmethod
    def _base_target(target: str) -> str:
        parsed = urlparse(str(target or "").strip())
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}".lower()
        return str(target or "").strip().lower()
