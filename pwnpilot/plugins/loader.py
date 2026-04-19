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

from pwnpilot.plugins.generic_adapter import GenericCLIAdapter
from pwnpilot.plugins.manifest_loader import load_manifests_dir
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

_MANIFEST_RUNTIME_TOOLS = {
    "gobuster",
    "nikto",
    "nmap",
    "nuclei",
    "searchsploit",
    "sqlmap",
    "whatweb",
    "whois",
    "zap",
}


class PluginLoader:
    """Discovers adapters and registers them through one trust-gated path."""

    def __init__(
        self,
        trust_policy: PluginTrustPolicy,
        package_name: str = "pwnpilot.plugins.adapters",
        entrypoint_group: str = "pwnpilot.plugins",
        discovery_mode: str = "package",
        manifest_dir: str | None = None,
    ) -> None:
        self._trust_policy = trust_policy
        self._package_name = package_name
        self._entrypoint_group = entrypoint_group
        self._discovery_mode = discovery_mode
        self._manifest_dir = manifest_dir or str(Path(__file__).resolve().parent / "manifests")

    def load_registry(self, enabled_tools: list[str], disabled_tools: list[str]) -> ToolRegistry:
        registry = ToolRegistry()
        for spec in load_manifests_dir(Path(self._manifest_dir)):
            adapter = GenericCLIAdapter(spec)
            descriptor = self._build_descriptor_for_instance(adapter, GenericCLIAdapter, "first_party")
            if descriptor is None:
                continue
            registry.add(descriptor)

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
                short_name = mod.name.rsplit(".", maxsplit=1)[-1]
                if short_name in _MANIFEST_RUNTIME_TOOLS:
                    # Hard cutover: legacy class adapters for these tools are disabled.
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
        except Exception as exc:
            log.warning("plugins.adapter_init_failed", adapter=str(adapter_cls), exc=str(exc))
            return None

        return self._build_descriptor_for_instance(adapter, adapter_cls, source)

    def _build_descriptor_for_instance(
        self,
        adapter: BaseAdapter,
        adapter_cls: type[BaseAdapter],
        source: str,
    ) -> ToolDescriptor | None:
        manifest = adapter.manifest
        capabilities = self._extract_capabilities(adapter)

        if manifest.name in _MANIFEST_RUNTIME_TOOLS and adapter_cls is not GenericCLIAdapter:
            log.warning(
                "plugins.legacy_cli_adapter_rejected",
                tool=manifest.name,
                adapter=str(adapter_cls),
                reason="legacy class-based CLI adapters are disabled by hard cutover",
            )
            return None

        # For GenericCLIAdapter (manifest-based tools), handle trust differently
        # since they are first-party and don't have file-based verification
        if adapter_cls is GenericCLIAdapter:
            verification_ok = bool(manifest.checksum_sha256 and manifest.signature_b64)
            verification_error = ""
            
            if verification_ok:
                try:
                    from pwnpilot.plugins.trust import _load_trusted_key
                    import base64
                    
                    pub_key = _load_trusted_key(manifest.name)
                    sig = base64.b64decode(manifest.signature_b64)
                    message = manifest.checksum_sha256.encode()
                    pub_key.verify(sig, message)
                except Exception as exc:
                    verification_ok = False
                    verification_error = f"manifest signature verification failed: {str(exc)}"
            else:
                verification_error = "manifest missing checksum_sha256 or signature_b64"
        else:
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
                compatible_action_types=list(getattr(manifest, "compatible_action_types", []) or []),
                manifest_version=manifest.version,
                manifest_schema_version=manifest.schema_version,
                binary_name=self._resolve_binary_name(adapter, manifest.name),
                categories=self._infer_categories(manifest.risk_class),
                supported_target_types=self._infer_target_types(manifest.input_schema),
                required_params=list(manifest.input_schema.get("required", [])),
                optional_params=self._infer_optional_params(manifest.input_schema),
                description=manifest.description,
                parameter_schema=dict(manifest.input_schema.get("properties", {})),
                capabilities=capabilities,
                preferred_target_types=self._infer_preferred_target_types(manifest.input_schema),
                preconditions=self._infer_preconditions(manifest.input_schema),
                low_value_hint_codes=self._infer_low_value_hint_codes(manifest.input_schema),
                fallback_family=self._infer_fallback_family(manifest.input_schema),
                preflight_required_params=self._infer_preflight_required_params(manifest.input_schema),
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
            compatible_action_types=list(getattr(manifest, "compatible_action_types", []) or []),
            manifest_version=manifest.version,
            manifest_schema_version=manifest.schema_version,
            binary_name=self._resolve_binary_name(adapter, manifest.name),
            categories=self._infer_categories(manifest.risk_class),
            supported_target_types=self._infer_target_types(manifest.input_schema),
            required_params=list(manifest.input_schema.get("required", [])),
            optional_params=self._infer_optional_params(manifest.input_schema),
            description=manifest.description,
            parameter_schema=dict(manifest.input_schema.get("properties", {})),
            capabilities=capabilities,
            preferred_target_types=self._infer_preferred_target_types(manifest.input_schema),
            preconditions=self._infer_preconditions(manifest.input_schema),
            low_value_hint_codes=self._infer_low_value_hint_codes(manifest.input_schema),
            fallback_family=self._infer_fallback_family(manifest.input_schema),
            preflight_required_params=self._infer_preflight_required_params(manifest.input_schema),
            trust_status=decision.status,
            trust_reason=decision.reason,
            verified_at=verified_at,
        )
        return descriptor

    def _resolve_binary_name(self, adapter: BaseAdapter, tool_name: str) -> str:
        direct = getattr(adapter, "binary_name", "")
        if isinstance(direct, str) and direct.strip():
            return direct.strip()
        return self._infer_binary_name(tool_name)

    def _extract_capabilities(self, adapter: BaseAdapter) -> dict[str, Any]:
        spec = getattr(adapter, "_spec", None)
        capabilities = getattr(spec, "capabilities", {}) if spec is not None else {}
        return dict(capabilities) if isinstance(capabilities, dict) else {}

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

    def _infer_preferred_target_types(self, input_schema: dict[str, Any]) -> list[str]:
        explicit = input_schema.get("x_preferred_target_types")
        if isinstance(explicit, list):
            return [str(v).strip() for v in explicit if str(v).strip()]
        return []

    def _infer_preconditions(self, input_schema: dict[str, Any]) -> list[str]:
        explicit = input_schema.get("x_preconditions")
        if isinstance(explicit, list):
            return [str(v).strip() for v in explicit if str(v).strip()]
        return []

    def _infer_low_value_hint_codes(self, input_schema: dict[str, Any]) -> list[str]:
        explicit = input_schema.get("x_low_value_hint_codes")
        if isinstance(explicit, list):
            return [str(v).strip() for v in explicit if str(v).strip()]
        return []

    def _infer_fallback_family(self, input_schema: dict[str, Any]) -> str:
        return str(input_schema.get("x_fallback_family", "")).strip()

    def _infer_preflight_required_params(self, input_schema: dict[str, Any]) -> list[str]:
        explicit = input_schema.get("x_preflight_required_params")
        if isinstance(explicit, list):
            return [str(v).strip() for v in explicit if str(v).strip()]
        return []
