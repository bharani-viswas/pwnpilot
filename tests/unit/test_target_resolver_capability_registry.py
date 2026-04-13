from __future__ import annotations

from pwnpilot.control.capability_registry import CapabilityRegistry
from pwnpilot.control.target_resolver import TargetResolver


def test_target_resolver_preserves_explicit_port_in_host_port_input() -> None:
    resolver = TargetResolver()
    resolved = resolver.resolve("localhost:3000")

    assert resolved.host == "localhost"
    assert resolved.port == 3000
    assert resolved.normalized_url == "http://localhost:3000"


def test_target_resolver_normalizes_full_url_and_keeps_path_query() -> None:
    resolver = TargetResolver()
    resolved = resolver.resolve("http://localhost:3000/api/v1/users?id=1")

    assert resolved.base_url == "http://localhost:3000"
    assert resolved.normalized_url == "http://localhost:3000/api/v1/users?id=1"
    assert resolved.target_type == "url"


def test_capability_registry_filters_incompatible_runtime_modes() -> None:
    registry = CapabilityRegistry(
        tools_catalog=[
            {
                "tool_name": "nmap",
                "binary_name": "nmap",
                "supported_target_types": ["ip", "cidr"],
            }
        ],
        runtime_mode="headless",
        has_display=False,
    )

    compatible, reason = registry.is_runtime_compatible("nmap")
    assert compatible is True
    assert reason is None


def test_capability_registry_contract_contains_invocation_variants() -> None:
    registry = CapabilityRegistry(
        tools_catalog=[
            {
                "tool_name": "zap",
                "binary_name": "zap-baseline.py",
                "supported_target_types": ["url"],
            }
        ]
    )

    contract = registry.contract_for("zap")
    assert contract is not None
    assert isinstance(contract.get("invocation_variants"), list)
    assert "runtime_modes_supported" in contract
