from __future__ import annotations

import re

import pytest

from pwnpilot.plugins.adapters.dns import DnsAdapter
from pwnpilot.secrets.redactor import Redactor


def test_dns_validate_and_build_with_resolver() -> None:
    adapter = DnsAdapter()

    params = adapter.validate_params(
        {
            "target": "example.com",
            "record_type": "MX",
            "resolver": "8.8.8.8",
        }
    )
    cmd = adapter.build_command(params)
    assert cmd[0] == "dig"
    assert "@8.8.8.8" in cmd
    assert "MX" in cmd


def test_dns_validate_rejects_unsafe_target_and_resolver() -> None:
    adapter = DnsAdapter()

    with pytest.raises(ValueError):
        adapter.validate_params({"target": "example.com;rm -rf /"})

    with pytest.raises(ValueError):
        adapter.validate_params({"target": "example.com", "resolver": "8.8.8.8;cat"})


def test_dns_parse_ignores_comments_and_empty_lines() -> None:
    adapter = DnsAdapter()
    output = b"; comment\n\nexample.com. 300 IN A 93.184.216.34\n"

    parsed = adapter.parse(output, b"", 0)
    assert parsed.findings[0]["record_count"] == 1
    assert parsed.findings[0]["records"][0]["type"] == "A"


def test_redactor_scrub_and_scrub_dict_nested_paths() -> None:
    red = Redactor(extra_patterns=[re.compile(r"internal_secret")])

    text = "Token: bearer abc.def and ip 10.1.2.3 and domain test.internal"
    scrubbed = red.scrub(text)
    assert "[REDACTED]" in scrubbed

    payload = {
        "a": "api_key=xyz",
        "b": {"nested": "AKIAABCDEFGHIJKLMNOP"},
        "c": ["password=foo", {"leave": "dict-in-list"}, 123],
        "d": "internal_secret",
    }
    out = red.scrub_dict(payload)
    assert out["a"] == "[REDACTED]"
    assert out["b"]["nested"] == "[REDACTED]"
    assert out["c"][0] == "[REDACTED]"
    # Dicts inside lists are intentionally untouched by scrub_dict's list branch.
    assert out["c"][1] == {"leave": "dict-in-list"}
    assert out["c"][2] == 123
    assert out["d"] == "[REDACTED]"
