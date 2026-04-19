from __future__ import annotations

import sys
import types

from pwnpilot.plugins.loader import PluginLoader
from pwnpilot.plugins.policy import PluginTrustPolicy
from pwnpilot.plugins.sdk import BaseAdapter, ParsedOutput, PluginManifest, ToolParams


class TestPluginRegistryLoader:
    def test_package_discovery_loads_first_party_tools(self):
        loader = PluginLoader(
            trust_policy=PluginTrustPolicy(mode="first_party_only", allow_unsigned_first_party=True),
            discovery_mode="package",
        )
        registry = loader.load_registry(enabled_tools=[], disabled_tools=[])

        enabled = registry.enabled_tools
        assert "nmap" in enabled
        assert "nikto" in enabled
        assert "gobuster" in enabled
        assert "shell" in enabled

    def test_enable_and_disable_filters_are_applied(self):
        loader = PluginLoader(
            trust_policy=PluginTrustPolicy(mode="first_party_only", allow_unsigned_first_party=True),
            discovery_mode="package",
        )
        registry = loader.load_registry(
            enabled_tools=["nmap", "nikto"],
            disabled_tools=["nikto"],
        )

        enabled = registry.enabled_tools
        assert "nmap" in enabled
        assert "nikto" not in enabled

    def test_strict_signed_mode_rejects_unsigned_first_party_plugins(self):
        loader = PluginLoader(
            trust_policy=PluginTrustPolicy(mode="strict_signed_all", allow_unsigned_first_party=False),
            discovery_mode="package",
        )
        registry = loader.load_registry(enabled_tools=[], disabled_tools=[])

        # Manifest-based CLI tools are now signed; they should be accepted in strict mode.
        # Python-native adapters without checksum_sha256 (shell, dns, cve_enrich) should be rejected.
        enabled = registry.enabled_tools
        assert "nmap" in enabled
        assert "gobuster" in enabled
        assert "sqlmap" in enabled
        assert "shell" not in enabled
        assert "dns" not in enabled
        assert "cve_enrich" not in enabled
        
        # Check that non-CLI adapters are properly rejected
        assert registry.tools["shell"].trust_status == "rejected"
        assert registry.tools["dns"].trust_status == "rejected"
        assert registry.tools["cve_enrich"].trust_status == "rejected"

    def test_package_and_entrypoints_discovery_includes_third_party_candidate(self, monkeypatch):
        module_name = "mock_ext_plugin"
        mod = types.ModuleType(module_name)

        class MockEntryAdapter(BaseAdapter):
            _MANIFEST = PluginManifest(
                name="mock_entry_tool",
                version="1.0.0",
                risk_class="recon_passive",
                input_schema={"type": "object", "required": ["target"], "properties": {"target": {"type": "string"}}},
                output_schema={"type": "object", "properties": {}},
            )

            @property
            def manifest(self) -> PluginManifest:
                return self._MANIFEST

            def validate_params(self, params: dict):
                return ToolParams(target=str(params.get("target", "")))

            def build_command(self, params: ToolParams) -> list[str]:
                return ["echo", params.target]

            def parse(self, stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
                return ParsedOutput(raw_summary=stdout.decode(errors="replace"))

        MockEntryAdapter.__module__ = module_name
        setattr(mod, "MockEntryAdapter", MockEntryAdapter)
        sys.modules[module_name] = mod

        class MockEP:
            def __init__(self, value: str):
                self.value = value

        class MockEPResult:
            def select(self, group: str):
                if group != "pwnpilot.plugins":
                    return []
                return [MockEP(f"{module_name}:MockEntryAdapter")]

        monkeypatch.setattr("pwnpilot.plugins.loader.entry_points", lambda: MockEPResult())

        loader = PluginLoader(
            trust_policy=PluginTrustPolicy(mode="allow_trusted_third_party", allow_unsigned_first_party=True),
            discovery_mode="package_and_entrypoints",
        )
        registry = loader.load_registry(enabled_tools=[], disabled_tools=[])

        assert "nmap" in registry.tools
        assert "mock_entry_tool" in registry.tools
