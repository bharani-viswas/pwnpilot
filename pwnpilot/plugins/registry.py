"""Tool registry: authoritative in-memory catalog of discovered plugins."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ToolDescriptor:
    tool_name: str
    adapter: Any
    adapter_class: str
    adapter_module: str
    source: str  # first_party | third_party
    risk_class: str
    binary_name: str
    manifest_version: str = ""
    manifest_schema_version: str = ""
    categories: list[str] = field(default_factory=list)
    supported_target_types: list[str] = field(default_factory=list)
    required_params: list[str] = field(default_factory=list)
    optional_params: list[str] = field(default_factory=list)
    description: str = ""
    parameter_schema: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    preferred_target_types: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    low_value_hint_codes: list[str] = field(default_factory=list)
    fallback_family: str = ""
    preflight_required_params: list[str] = field(default_factory=list)
    # Additional action_types this tool is valid for beyond risk_class.
    # Empty list means only risk_class is accepted (legacy default).
    compatible_action_types: list[str] = field(default_factory=list)
    trust_status: str = "unknown"
    trust_reason: str = ""
    enabled: bool = True
    enablement_source: str = "default_enabled"
    load_error: str = ""
    loaded_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    verified_at: str = ""

    def to_planner_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "risk_class": self.risk_class,
            "compatible_action_types": list(self.compatible_action_types),
            "manifest_version": self.manifest_version,
            "binary_name": self.binary_name,
            "categories": list(self.categories),
            "supported_target_types": list(self.supported_target_types),
            "required_params": list(self.required_params),
            "optional_params": list(self.optional_params),
            "description": self.description,
            "parameter_schema": dict(self.parameter_schema),
            "capabilities": dict(self.capabilities),
            "preferred_target_types": list(self.preferred_target_types),
            "preconditions": list(self.preconditions),
            "low_value_hint_codes": list(self.low_value_hint_codes),
            "fallback_family": self.fallback_family,
            "preflight_required_params": list(self.preflight_required_params),
        }


class ToolRegistry:
    """Central tool catalog used by runtime, planner, and startup checks."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDescriptor] = {}

    def add(self, descriptor: ToolDescriptor) -> None:
        self._tools[descriptor.tool_name] = descriptor

    def set_enablement(self, enabled_tools: list[str], disabled_tools: list[str]) -> None:
        enabled_set = {t.strip() for t in enabled_tools if t.strip()}
        disabled_set = {t.strip() for t in disabled_tools if t.strip()}

        for name, desc in self._tools.items():
            if enabled_set:
                desc.enabled = name in enabled_set
                desc.enablement_source = (
                    "enabled_allowlist" if name in enabled_set else "disabled_not_in_allowlist"
                )
            if name in disabled_set:
                desc.enabled = False
                desc.enablement_source = "disabled_blocklist"
            if not enabled_set and name not in disabled_set and desc.enablement_source == "default_enabled":
                desc.enablement_source = "default_enabled"

    @property
    def tools(self) -> dict[str, ToolDescriptor]:
        return dict(self._tools)

    @property
    def enabled_tools(self) -> dict[str, ToolDescriptor]:
        return {name: desc for name, desc in self._tools.items() if desc.enabled and not desc.load_error}

    def adapters_for_runner(self) -> dict[str, Any]:
        return {name: desc.adapter for name, desc in self.enabled_tools.items()}

    def planner_context(self) -> dict[str, Any]:
        enabled = self.enabled_tools
        return {
            "available_tools": sorted(enabled.keys()),
            "tools_catalog": [enabled[name].to_planner_dict() for name in sorted(enabled.keys())],
        }

    def binary_requirements(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for name, desc in self.enabled_tools.items():
            if desc.binary_name:
                out[name] = desc.binary_name
        return out
