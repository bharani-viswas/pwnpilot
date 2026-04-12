from __future__ import annotations

from unittest.mock import MagicMock, patch

from pwnpilot.tui.app import (
    ApprovalsPanel,
    MetricsSummaryPanel,
    PolicyLogPanel,
    StatusPanel,
    TUIDashboard,
    ToolsTablePanel,
    run_dashboard,
)


class _LabelStub:
    def __init__(self):
        self.value = ""
        self.classes = set()

    def update(self, text):
        self.value = text

    def add_class(self, cls):
        self.classes.add(cls)

    def remove_class(self, cls):
        self.classes.discard(cls)


class _TableStub:
    def __init__(self):
        self.rows = []
        self.columns = []

    def clear(self):
        self.rows.clear()

    def add_row(self, *row):
        self.rows.append(row)

    def add_columns(self, *cols):
        self.columns.extend(cols)


class _LogStub:
    def __init__(self):
        self.lines = []

    def write_line(self, text):
        self.lines.append(text)


class _MetricsStub:
    def __init__(self, summary):
        self._summary = summary

    def summary(self):
        return self._summary


def test_status_panel_refresh_with_and_without_metrics() -> None:
    panel = StatusPanel()
    assert list(panel.compose())

    nodes = {
        "#status-engagement-id": _LabelStub(),
        "#status-iteration": _LabelStub(),
        "#status-kill": _LabelStub(),
        "#status-last-action": _LabelStub(),
        "#status-elapsed": _LabelStub(),
    }
    panel.query_one = lambda selector, _type=None: nodes[selector]

    panel.refresh_data(None)
    assert "No active engagement" in nodes["#status-engagement-id"].value

    metrics = _MetricsStub(
        {
            "engagement_id": "eng-1",
            "iteration_count": 3,
            "kill_switch_triggers": 1,
            "elapsed_seconds": 12,
        }
    )
    panel.refresh_data(metrics)
    assert "eng-1" in nodes["#status-engagement-id"].value
    assert "TRIGGERED" in nodes["#status-kill"].value
    assert "error" in nodes["#status-kill"].classes

    metrics_ok = _MetricsStub(
        {
            "engagement_id": "eng-1",
            "iteration_count": 4,
            "kill_switch_triggers": 0,
            "elapsed_seconds": 13,
        }
    )
    panel.refresh_data(metrics_ok)
    assert "OFF" in nodes["#status-kill"].value
    assert "error" not in nodes["#status-kill"].classes


def test_approvals_panel_refresh_data() -> None:
    panel = ApprovalsPanel()
    assert list(panel.compose())
    table = _TableStub()
    panel.query_one = lambda selector, _type=None: table

    panel.on_mount()
    assert "Ticket ID" in table.columns

    panel.refresh_data([
        {
            "ticket_id": "1234567890abcdef",
            "action_type": "exploit",
            "risk_level": "high",
            "requested_by": "operator",
        }
    ])

    assert len(table.rows) == 1
    assert table.rows[0][1] == "exploit"


def test_tools_table_panel_refresh_data() -> None:
    panel = ToolsTablePanel()
    assert list(panel.compose())
    table = _TableStub()
    panel.query_one = lambda selector, _type=None: table

    panel.on_mount()
    assert "Tool" in table.columns

    panel.refresh_data(
        {
            "nmap": {"invocations": 2, "avg_latency_ms": 10.2, "p95_latency_ms": 20.4},
            "whois": {"invocations": 1, "avg_latency_ms": None, "p95_latency_ms": None},
        }
    )

    assert len(table.rows) == 2
    assert table.rows[0][0] in {"nmap", "whois"}


def test_metrics_summary_panel_refresh_data() -> None:
    panel = MetricsSummaryPanel()
    assert list(panel.compose())
    strip = _LabelStub()
    panel.query_one = lambda selector, _type=None: strip

    panel.refresh_data(None)

    panel.refresh_data(
        _MetricsStub(
            {
                "iteration_count": 4,
                "policy_deny_count": 1,
                "parser_error_count": 0,
                "timeout_count": 0,
                "approval_count": 2,
                "elapsed_seconds": 55,
            }
        )
    )
    assert "Iterations: 4" in strip.value


def test_policy_log_panel_append_and_noop_refresh() -> None:
    panel = PolicyLogPanel()
    assert list(panel.compose())
    log_widget = _LogStub()
    panel.query_one = lambda selector, _type=None: log_widget

    panel.append_deny("exploit", "blocked")
    panel.refresh_data({"exploit": 1})
    assert any("DENY 'exploit'" in line for line in log_widget.lines)


def test_tui_dashboard_branches_and_thread_wrappers() -> None:
    app = TUIDashboard(engagement_id=None, refresh_interval=0.2)

    app.set_interval = MagicMock()
    app.on_mount()
    app.set_interval.assert_called_once()

    # _resolve_metrics no summaries path
    with patch("pwnpilot.tui.app.metrics_registry") as reg:
        reg.all_summaries.return_value = []
        assert app._resolve_metrics() is None

    # _resolve_metrics latest summary path
    with patch("pwnpilot.tui.app.metrics_registry") as reg:
        reg.all_summaries.return_value = [{"engagement_id": "e1"}]
        reg.get.return_value = "metrics-object"
        assert app._resolve_metrics() == "metrics-object"

    # action wrappers
    app._do_refresh = MagicMock()
    app.action_refresh()
    app._do_refresh.assert_called_once()

    # thread-safe wrappers route through call_from_thread
    app.call_from_thread = MagicMock()
    app.push_approval({"ticket_id": "t1"})
    app.resolve_approval("t1")
    app.query_one = MagicMock(return_value=MagicMock())
    app.push_policy_deny("exploit", "blocked")
    assert app.call_from_thread.call_count == 3


def test_run_dashboard_invokes_app_run() -> None:
    with patch("pwnpilot.tui.app.TUIDashboard") as cls:
        inst = cls.return_value
        run_dashboard(engagement_id="eng-1", refresh_interval=0.5)
        cls.assert_called_once()
        inst.run.assert_called_once()