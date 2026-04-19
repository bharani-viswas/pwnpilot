from __future__ import annotations

from pathlib import Path

from pwnpilot.plugins.generic_adapter import GenericCLIAdapter
from pwnpilot.plugins.manifest_loader import load_manifest_file


def _adapter(tool_name: str) -> GenericCLIAdapter:
    manifest_path = Path(__file__).resolve().parents[2] / "pwnpilot" / "plugins" / "manifests" / f"{tool_name}.yaml"
    return GenericCLIAdapter(load_manifest_file(manifest_path))


def test_gobuster_emits_wildcard_execution_hint() -> None:
    adapter = _adapter("gobuster")
    result = adapter.parse(
        b"",
        b"2026/04/12 23:43:50 [-] Wildcard response found: http://localhost:3000/foo => 200\n",
        0,
    )

    assert result.findings == []
    assert result.execution_hints[0]["code"] == "wildcard_detected"


def test_sqlmap_emits_no_forms_hint() -> None:
    adapter = _adapter("sqlmap")
    result = adapter.parse(
        b"[CRITICAL] there were no forms found at the given target URL\n",
        b"",
        1,
    )

    assert result.execution_hints[0]["code"] == "no_forms_detected"


def test_nikto_invalid_output_is_not_a_finding() -> None:
    adapter = _adapter("nikto")
    result = adapter.parse(b"", b"+ ERROR: Invalid output format\n", 0)

    assert result.findings == []
    assert result.execution_hints[0]["code"] == "output_format_invalid"


def test_nuclei_no_matches_emits_execution_hint() -> None:
    adapter = _adapter("nuclei")
    result = adapter.parse(b"", b"", 0)

    assert result.findings == []
    assert result.execution_hints[0]["code"] == "no_matches"
