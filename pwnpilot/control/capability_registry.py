"""CapabilityRegistry service: normalized tool capability contracts and compatibility checks."""
from __future__ import annotations

from typing import Any

from pwnpilot.plugins.binaries import candidate_binaries


class CapabilityRegistry:
    def __init__(
        self,
        tools_catalog: list[dict[str, Any]],
        runtime_mode: str = "headless",
        has_display: bool = False,
    ) -> None:
        self._runtime_mode = str(runtime_mode or "headless")
        self._has_display = bool(has_display)
        self._contracts: dict[str, dict[str, Any]] = {}

        for item in tools_catalog:
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("tool_name", "")).strip()
            if not tool_name:
                continue
            binary_name = str(item.get("binary_name", "")).strip() or tool_name
            invocation_variants = candidate_binaries(tool_name, binary_name)
            self._contracts[tool_name] = {
                "tool_name": tool_name,
                "runtime_modes_supported": ["headless", "interactive"],
                "invocation_variants": invocation_variants,
                "requires_display": False,
                "network_profile": "remote",
                "supported_target_types": list(item.get("supported_target_types", [])),
                "capabilities": dict(item.get("capabilities", {}) if isinstance(item.get("capabilities", {}), dict) else {}),
                "preferred_target_types": list(item.get("preferred_target_types", [])),
                "preconditions": list(item.get("preconditions", [])),
                "low_value_hint_codes": list(item.get("low_value_hint_codes", [])),
                "fallback_family": str(item.get("fallback_family", "")).strip(),
                "preflight_required_params": list(item.get("preflight_required_params", [])),
            }

    def contract_for(self, tool_name: str) -> dict[str, Any] | None:
        return self._contracts.get(str(tool_name or "").strip())

    def contracts_for_tools(self, tool_names: list[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name in tool_names:
            contract = self.contract_for(name)
            if contract:
                out.append(contract)
        return out

    def is_runtime_compatible(self, tool_name: str) -> tuple[bool, str | None]:
        contract = self.contract_for(tool_name)
        if not contract:
            return True, None

        modes = {str(v).strip().lower() for v in contract.get("runtime_modes_supported", []) if str(v).strip()}
        if modes and self._runtime_mode.lower() not in modes:
            return False, (
                f"Tool '{tool_name}' does not support runtime mode '{self._runtime_mode}'. "
                f"Supported modes: {sorted(modes)}"
            )

        if bool(contract.get("requires_display", False)) and not self._has_display:
            return False, f"Tool '{tool_name}' requires a display but runtime is headless."

        return True, None

    def filter_runtime_compatible(self, tool_names: list[str]) -> list[str]:
        out: list[str] = []
        for name in tool_names:
            ok, _ = self.is_runtime_compatible(name)
            if ok:
                out.append(name)
        return sorted(out)
