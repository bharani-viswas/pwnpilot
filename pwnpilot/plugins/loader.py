"""Unified plugin loader for first-party and third-party adapters."""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from datetime import datetime, timezone
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Iterator

import structlog

from pwnpilot.plugins.policy import PluginTrustPolicy
from pwnpilot.plugins.registry import ToolDescriptor, ToolRegistry
from pwnpilot.plugins.sdk import BaseAdapter
from pwnpilot.plugins.trust import verify_adapter_file

log = structlog.get_logger(__name__)

_FALLBACK_BINARIES = {
    "shell": "",
    "gobuster": "gobuster",
    "nmap": "nmap",
    "nikto": "nikto",
    "nuclei": "nuclei",
    "searchsploit": "searchsploit",
    "sqlmap": "sqlmap",
    "whatweb": "whatweb",
    "whois": "whois",
    "dns": "dig",
    "zap": "zap-cli",
    "cve_enrich": "",
}


class PluginLoader:
    """Discovers adapters and registers them through one trust-gated path."""

    def __init__(
        self,
        trust_policy: PluginTrustPolicy,
        package_name: str = "pwnpilot.plugins.adapters",
        entrypoint_group: str = "pwnpilot.plugins",
        discovery_mode: str = "package",
    ) -> None:
        self._trust_policy = trust_policy
        self._package_name = package_name
        self._entrypoint_group = entrypoint_group
        self._discovery_mode = discovery_mode

    def load_registry(self, enabled_tools: list[str], disabled_tools: list[str]) -> ToolRegistry:
        registry = ToolRegistry()
        for module_name, source, object_hint in self._discover_candidates():
            for adapter_cls in self._load_adapter_classes(module_name, object_hint):
                descriptor = self._build_descriptor(adapter_cls, source)
                if descriptor is None:
                    continue
                registry.add(descriptor)

        registry.set_enablement(enabled_tools, disabled_tools)
        return registry

    def _discover_candidates(self) -> Iterator[tuple[str, str, str | None]]:
        # Package discovery path (first-party)
        if self._discovery_mode in ("package", "package_and_entrypoints"):
            pkg = importlib.import_module(self._package_name)
            for mod in pkgutil.iter_modules(pkg.__path__, prefix=f"{self._package_name}."):
                if mod.name.endswith(".__init__"):
                    continue
                yield mod.name, "first_party", None

        # Optional entrypoint discovery (third-party)
        if self._discovery_mode in ("entrypoints", "package_and_entrypoints"):
            eps = entry_points()
            selected = eps.select(group=self._entrypoint_group)
            for ep in selected:
                # entry point value can be module:Class
                value = getattr(ep, "value", "")
                if not value:
                    continue
                module_name = value.split(":", maxsplit=1)[0]
                yield module_name, "third_party", value

    def _load_adapter_classes(self, module_name: str, object_hint: str | None) -> list[type[BaseAdapter]]:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            log.warning("plugins.module_import_failed", module=module_name, exc=str(exc))
            return []

        classes: list[type[BaseAdapter]] = []
        if object_hint and ":" in object_hint:
            cls_name = object_hint.split(":", maxsplit=1)[1]
            obj = getattr(module, cls_name, None)
            if inspect.isclass(obj) and issubclass(obj, BaseAdapter) and obj is not BaseAdapter:
                classes.append(obj)
            return classes

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseAdapter) and obj is not BaseAdapter and obj.__module__ == module.__name__:
                classes.append(obj)
        return classes

    def _build_descriptor(self, adapter_cls: type[BaseAdapter], source: str) -> ToolDescriptor | None:
        try:
            adapter = adapter_cls()
            manifest = adapter.manifest
        except Exception as exc:
            log.warning("plugins.adapter_init_failed", adapter=str(adapter_cls), exc=str(exc))
            return None

        verification_ok, verification_error = self._verify_adapter(adapter_cls, manifest)
        verified_at = datetime.now(timezone.utc).isoformat()
        decision = self._trust_policy.decide(source, verification_ok, verification_error)
        if not decision.allowed:
            log.warning(
                "plugins.adapter_rejected",
                tool=manifest.name,
                source=source,
                reason=decision.reason,
            )
            return ToolDescriptor(
                tool_name=manifest.name,
                adapter=adapter,
                adapter_class=adapter_cls.__name__,
                adapter_module=adapter_cls.__module__,
                source=source,
                risk_class=manifest.risk_class,
                manifest_version=manifest.version,
                manifest_schema_version=manifest.schema_version,
                binary_name=self._infer_binary_name(manifest.name),
                categories=self._infer_categories(manifest.risk_class),
                supported_target_types=self._infer_target_types(manifest.input_schema),
                required_params=list(manifest.input_schema.get("required", [])),
                optional_params=self._infer_optional_params(manifest.input_schema),
                description=manifest.description,
                parameter_schema=dict(manifest.input_schema.get("properties", {})),
                trust_status=decision.status,
                trust_reason=decision.reason,
                enablement_source="trust_rejected",
                enabled=False,
                load_error=decision.reason,
                verified_at=verified_at,
            )

        descriptor = ToolDescriptor(
            tool_name=manifest.name,
            adapter=adapter,
            adapter_class=adapter_cls.__name__,
            adapter_module=adapter_cls.__module__,
            source=source,
            risk_class=manifest.risk_class,
            manifest_version=manifest.version,
            manifest_schema_version=manifest.schema_version,
            binary_name=self._infer_binary_name(manifest.name),
            categories=self._infer_categories(manifest.risk_class),
            supported_target_types=self._infer_target_types(manifest.input_schema),
            required_params=list(manifest.input_schema.get("required", [])),
            optional_params=self._infer_optional_params(manifest.input_schema),
            description=manifest.description,
            parameter_schema=dict(manifest.input_schema.get("properties", {})),
            trust_status=decision.status,
            trust_reason=decision.reason,
            verified_at=verified_at,
        )
        return descriptor

    def _verify_adapter(self, adapter_cls: type[BaseAdapter], manifest: Any) -> tuple[bool, str]:
        try:
            source_path = inspect.getsourcefile(adapter_cls)
        except Exception as exc:
            return False, f"unable to determine adapter source file: {exc}"
        if not source_path:
            return False, "unable to determine adapter source file"
        try:
            verify_adapter_file(Path(source_path), manifest)
            return True, ""
        except Exception as exc:
            return False, str(exc)

    def _infer_binary_name(self, tool_name: str) -> str:
        return _FALLBACK_BINARIES.get(tool_name, tool_name)

    def _infer_categories(self, risk_class: str) -> list[str]:
        mapping = {
            "recon_passive": ["reconnaissance"],
            "active_scan": ["scanning"],
            "exploit": ["exploitation"],
            "post_exploit": ["post-exploitation"],
        }
        return mapping.get(risk_class, ["general"])

    def _infer_target_types(self, input_schema: dict[str, Any]) -> list[str]:
        explicit = input_schema.get("x_supported_target_types")
        if isinstance(explicit, list) and explicit:
            return [str(v) for v in explicit]

        # v1 heuristic: all current adapters are target-string based and can support ip/domain/url
        if "target" in input_schema.get("properties", {}):
            return ["ip", "domain", "url", "cidr"]
        return ["unknown"]

    def _infer_optional_params(self, input_schema: dict[str, Any]) -> list[str]:
        props = set(input_schema.get("properties", {}).keys())
        required = set(input_schema.get("required", []))
        return sorted(list(props - required))
