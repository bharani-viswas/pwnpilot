"""
Quality benchmark gate: Loop-rate and repetition controls.

Validates that the RepetitionDetector correctly suppresses redundant action
proposals before they reach the LLM, and that the nonproductive_cycle_rate
metric accurately reflects loop churn.
"""
from __future__ import annotations

import pytest

from pwnpilot.agent.repetition_detector import RepetitionDetector


def _make_previous(tool: str, target: str, action_type: str, n: int) -> list[dict]:
    """Build a fake previous_actions list with n identical actions."""
    return [{"tool_name": tool, "target": target, "action_type": action_type} for _ in range(n)]


class TestLoopRateGate:
    """Pass/fail gates for repetition-control quality."""

    def test_exact_repetition_detected_after_threshold(self) -> None:
        """Repetition is detected once the same action exceeds the repeat threshold."""
        detector = RepetitionDetector(repeat_threshold=3, similarity_threshold=10)
        tool, target, at = "nmap", "192.168.1.1", "recon"

        # Below threshold — not repeated
        result = detector.check(tool, target, at, _make_previous(tool, target, at, 2))
        assert not result.is_repeated

        # At/above threshold
        result = detector.check(tool, target, at, _make_previous(tool, target, at, 4))
        assert result.is_repeated
        assert result.occurrences >= 3
        assert "exact" in result.reason_code

    def test_different_actions_not_confused(self) -> None:
        """Different tools/targets are tracked independently without cross-contamination."""
        detector = RepetitionDetector(repeat_threshold=3, similarity_threshold=10)

        # sig_a is very repetitive
        prev_a = _make_previous("nmap", "10.0.0.1", "recon", 5)

        # sig_b only appears once — should not be flagged
        result_b = detector.check("nikto", "10.0.0.1", "vuln_scan", prev_a)
        assert not result_b.is_repeated

    def test_broad_similarity_detection(self) -> None:
        """Broad similarity (same tool+target) is detected when threshold is met."""
        detector = RepetitionDetector(repeat_threshold=10, similarity_threshold=3)

        # Same tool+target, different action types
        prev = [
            {"tool_name": "nmap", "target": "192.168.1.0/24", "action_type": f"scan_{i}"}
            for i in range(4)
        ]

        result = detector.check("nmap", "192.168.1.0/24", "scan_new", prev)
        assert result.is_repeated
        assert result.reason_code in ("broad", "similar_repeat", "broad_repeat")

    def test_not_repeated_when_below_broad_threshold(self) -> None:
        """Broad similarity below threshold should not trigger."""
        detector = RepetitionDetector(repeat_threshold=10, similarity_threshold=5)

        prev = [
            {"tool_name": "nmap", "target": "192.168.1.0/24", "action_type": f"scan_{i}"}
            for i in range(2)
        ]
        result = detector.check("nmap", "192.168.1.0/24", "scan_new", prev)
        assert not result.is_repeated

    def test_hint_message_is_informative(self) -> None:
        """Repetition hint must include enough context for operator diagnosis."""
        detector = RepetitionDetector(repeat_threshold=2, similarity_threshold=5)
        prev = _make_previous("gobuster", "example.com", "dir_brute", 3)

        result = detector.check("gobuster", "example.com", "dir_brute", prev)
        assert result.is_repeated
        assert result.hint
        assert len(result.hint) > 10  # Non-trivial hint


class TestNonproductiveCycleMetric:
    """Validate that nonproductive_cycle_rate metric is correctly computed."""

    def test_cycle_rate_zero_on_empty(self) -> None:
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics(engagement_id="test-cycle-empty")
        summary = m.summary()
        assert summary["nonproductive_cycle_rate"] == 0.0
        assert summary["nonproductive_cycle_count"] == 0

    def test_cycle_rate_proportional(self) -> None:
        from pwnpilot.observability.metrics import EngagementMetrics

        m = EngagementMetrics(engagement_id="test-cycle-rate")
        # Record 5 actions, 2 nonproductive
        for _ in range(5):
            m.record_action_outcome("nmap", new_findings_count=1)
        for _ in range(2):
            m.record_nonproductive_cycle()
            m.record_action_outcome("nmap", new_findings_count=0)

        summary = m.summary()
        # 2 nonproductive out of 7 total actions
        assert summary["nonproductive_cycle_count"] == 2
        assert 0.28 < summary["nonproductive_cycle_rate"] < 0.30

