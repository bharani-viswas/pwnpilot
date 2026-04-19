from __future__ import annotations

from pwnpilot.control.invocation_compiler import InvocationCompiler


def test_compiler_projects_nmap_url_to_host() -> None:
    compiler = InvocationCompiler()

    result = compiler.compile(
        tool_name="nmap",
        target="http://localhost:3000/rest/products",
        params={},
        resolved_target={
            "target_type": "url",
            "host": "localhost",
            "base_url": "http://localhost:3000",
            "normalized_url": "http://localhost:3000/rest/products",
        },
        supported_target_types=["ip", "domain", "cidr"],
        previous_actions=[],
    )

    assert result.feasible is True
    assert result.target == "localhost"
    assert result.diagnostics.get("coercion") == "url_to_host"


def test_compiler_requires_url_for_gobuster_dir_mode() -> None:
    compiler = InvocationCompiler()

    result = compiler.compile(
        tool_name="gobuster",
        target="localhost",
        params={"mode": "dir"},
        resolved_target={"target_type": "domain", "host": "localhost"},
        supported_target_types=["url", "domain"],
        previous_actions=[],
    )

    assert result.feasible is False
    assert result.reason_code == "INVOCATION_UNFIT"
    assert "requires an http/https URL" in result.reason_detail


def test_compiler_forces_sqlmap_non_forms_after_hint() -> None:
    compiler = InvocationCompiler()

    result = compiler.compile(
        tool_name="sqlmap",
        target="http://localhost:3000",
        params={"forms": True},
        resolved_target={"target_type": "url", "host": "localhost"},
        supported_target_types=["url"],
        previous_actions=[
            {
                "tool_name": "sqlmap",
                "target": "http://localhost:3000/login",
                "execution_hint_codes": ["no_forms_detected"],
            }
        ],
    )

    assert result.feasible is True
    assert result.params.get("forms") is False
    assert result.params.get("mode_selection_reason") == "no_forms_hint_recovery"
    assert result.diagnostics.get("coercion") == "force_non_forms_mode"
