from pwnpilot.control.target_strategy import (
    build_engagement_strategy,
    classify_target_family,
)


def test_classify_target_family_web() -> None:
    assert classify_target_family([], [], ["http://localhost:3000"]) == "web"


def test_classify_target_family_mixed() -> None:
    assert classify_target_family(["10.0.0.0/24"], ["example.com"], ["https://example.com"]) == "mixed"


def test_build_engagement_strategy_marks_missing_tools() -> None:
    strategy = build_engagement_strategy(
        scope_cidrs=[],
        scope_domains=[],
        scope_urls=["http://localhost:3000"],
        available_tools=["whatweb", "gobuster", "nuclei"],
    )

    assert strategy["target_family"] == "web"
    missing = strategy["missing_recommended_tools"]
    assert "sqlmap" in missing
    assert "zap" in missing

    sequence = strategy["sequence"]
    discovery = next(step for step in sequence if step["step_id"] == "web_discovery")
    assert discovery["preferred_available"] == ["gobuster"]
    assert discovery["recovery_rules"][0]["hint_codes"] == ["wildcard_detected"]
