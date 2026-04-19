"""Contract tests for manifest-driven CLI adapters and native shell adapter."""
from __future__ import annotations

import json
from pathlib import Path

from pwnpilot.plugins.adapters.shell import ShellAdapter
from pwnpilot.plugins.generic_adapter import GenericCLIAdapter
from pwnpilot.plugins.manifest_loader import load_manifest_file


def _adapter(tool_name: str) -> GenericCLIAdapter:
    manifest_path = Path(__file__).resolve().parents[2] / "pwnpilot" / "plugins" / "manifests" / f"{tool_name}.yaml"
    return GenericCLIAdapter(load_manifest_file(manifest_path))


def test_nmap_manifest_runtime_contract() -> None:
    adapter = _adapter("nmap")
    params = adapter.validate_params({"target": "10.0.0.1", "ports": "80,443", "scan_type": "sV", "timing": 3})
    cmd = adapter.build_command(params)
    assert cmd[0] == "nmap"

    xml = b"""<?xml version=\"1.0\"?><nmaprun><host><status state=\"up\"/><address addr=\"10.0.0.1\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\"/></port></ports></host></nmaprun>"""
    parsed = adapter.parse(xml, b"", 0)
    assert parsed.parser_error is None
    assert isinstance(parsed.hosts, list)
    assert isinstance(parsed.services, list)


def test_nuclei_manifest_runtime_contract() -> None:
    adapter = _adapter("nuclei")
    params = adapter.validate_params({"target": "http://10.0.0.1", "severity": "high"})
    cmd = adapter.build_command(params)
    assert cmd[0] == "nuclei"

    line = json.dumps(
        {
            "template-id": "CVE-2024-0001",
            "matched-at": "http://10.0.0.1/vuln",
            "info": {"name": "Test Vuln", "severity": "high", "classification": {"cve-id": ["CVE-2024-0001"]}},
        }
    )
    parsed = adapter.parse(line.encode(), b"", 0)
    assert parsed.findings[0]["vuln_ref"] == "CVE-2024-0001"


def test_zap_manifest_runtime_contract() -> None:
    adapter = _adapter("zap")
    params = adapter.validate_params({"target": "http://10.0.0.1", "ajax_spider": True})
    cmd = adapter.build_command(params)
    assert cmd[0] == "zap-baseline.py"
    assert "-j" in cmd

    output = b"WARN-NEW: X-Content-Type-Options Header Missing [10021] x 3\n"
    parsed = adapter.parse(b"", output, 1)
    assert parsed.new_findings_count == 1


def test_sqlmap_manifest_runtime_contract() -> None:
    adapter = _adapter("sqlmap")
    params = adapter.validate_params({"target": "http://10.0.0.1/?id=1", "level": 1, "risk": 1})
    cmd = adapter.build_command(params)
    assert cmd[0] == "sqlmap"
    assert "--batch" in cmd

    output = b"Parameter: id (GET) is vulnerable\n"
    parsed = adapter.parse(output, b"", 0)
    assert parsed.new_findings_count >= 1
    assert parsed.findings[0]["vuln_ref"] == "sqli"


def test_shell_adapter_still_native() -> None:
    adapter = ShellAdapter()
    params = adapter.validate_params({"target": "localhost", "command": "whoami", "args": []})
    cmd = adapter.build_command(params)
    assert cmd == ["whoami"]
