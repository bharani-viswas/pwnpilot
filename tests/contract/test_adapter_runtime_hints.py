from __future__ import annotations

from pwnpilot.plugins.adapters.gobuster import GobusterAdapter
from pwnpilot.plugins.adapters.nikto import NiktoAdapter
from pwnpilot.plugins.adapters.nuclei import NucleiAdapter
from pwnpilot.plugins.adapters.sqlmap import SqlmapAdapter


def test_gobuster_emits_wildcard_execution_hint() -> None:
    adapter = GobusterAdapter()
    result = adapter.parse(
        b"",
        b"2026/04/12 23:43:50 [-] Wildcard response found: http://localhost:3000/foo => 200\n",
        0,
    )

    assert result.findings == []
    assert result.execution_hints[0]["code"] == "wildcard_detected"


def test_sqlmap_emits_no_forms_hint() -> None:
    adapter = SqlmapAdapter()
    result = adapter.parse(
        b"[CRITICAL] there were no forms found at the given target URL\n",
        b"",
        1,
    )

    assert result.execution_hints[0]["code"] == "no_forms_detected"


def test_nikto_invalid_output_is_not_a_finding() -> None:
    adapter = NiktoAdapter()
    result = adapter.parse(b"", b"+ ERROR: Invalid output format\n", 0)

    assert result.findings == []
    assert result.execution_hints[0]["code"] == "output_format_invalid"


def test_nuclei_no_matches_emits_execution_hint() -> None:
    adapter = NucleiAdapter()
    result = adapter.parse(b"", b"", 0)

    assert result.findings == []
    assert result.execution_hints[0]["code"] == "no_matches"
