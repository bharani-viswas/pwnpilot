"""
Textual TUI — Live engagement dashboard for the pwnpilot framework.

Run with:
    pwnpilot tui  (via CLI)
    python -m pwnpilot.tui.app  (direct)

The TUI provides a read-only, auto-refreshing view of:
  - Active engagement status (iteration, kill switch state, last action)
  - Pending approval tickets
  - Policy deny event log
  - Per-tool invocation table
  - Observability metrics summary

The TUI talks to the process-local MetricsRegistry and, when a database
path is available, to the SQLite stores for live data.

Architecture
------------
- ``TUIDashboard(App)`` is the root Textual application.
- Panel widgets are ``Static``-derived classes that implement ``refresh_data()``.
- A ``PeriodicRefresh`` worker triggers a re-render every ``REFRESH_INTERVAL_S``
  seconds; no external event bus is required.
- All DB reads are done on the main thread (SQLite is synchronous, reads are fast
  enough at default refresh rates).
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Label,
    Log,
    ProgressBar,
    Static,
)

from pwnpilot.observability.metrics import EngagementMetrics, metrics_registry

REFRESH_INTERVAL_S = 2.0
APP_TITLE = "pwnpilot — Live Engagement Dashboard"
APP_CSS = """
Screen {
    layout: vertical;
}

#top-row {
    height: 30%;
    layout: horizontal;
}

#mid-row {
    height: 35%;
    layout: horizontal;
}

#bottom-row {
    height: auto;
    layout: horizontal;
}

.panel {
    border: solid $accent;
    padding: 1 2;
    margin: 0 1;
}

.panel-title {
    text-style: bold;
    color: $accent;
    margin-bottom: 1;
}

#status-panel { width: 40%; }
#approvals-panel { width: 60%; }
#policy-log { width: 50%; }
#tools-table { width: 50%; }
#metrics-panel { width: 100%; }

.ok { color: $success; }
.warn { color: $warning; }
.error { color: $error; }
"""


# ---------------------------------------------------------------------------
# Status panel
# ---------------------------------------------------------------------------


class StatusPanel(Static):
    """Shows current engagement iteration, kill switch state, last action."""

    DEFAULT_CSS = """
    StatusPanel { height: 100%; }
    """

    def compose(self) -> ComposeResult:
        yield Label("ENGAGEMENT STATUS", classes="panel-title")
        yield Label("No active engagement", id="status-engagement-id")
        yield Label("Iteration: —", id="status-iteration")
        yield Label("Kill switch: OFF", id="status-kill")
        yield Label("Last action: —", id="status-last-action")
        yield Label("Elapsed: —", id="status-elapsed")

    def refresh_data(self, metrics: EngagementMetrics | None) -> None:
        if metrics is None:
            self.query_one("#status-engagement-id", Label).update("No active engagement")
            return
        s = metrics.summary()
        self.query_one("#status-engagement-id", Label).update(
            f"Engagement: {s['engagement_id']}"
        )
        self.query_one("#status-iteration", Label).update(
            f"Iteration: {s['iteration_count']}"
        )
        ks_label = self.query_one("#status-kill", Label)
        if s.get("kill_switch_triggers", 0) > 0:
            ks_label.update(f"Kill switch: TRIGGERED ({s['kill_switch_triggers']}x)")
            ks_label.add_class("error")
        else:
            ks_label.update("Kill switch: OFF")
            ks_label.remove_class("error")
        self.query_one("#status-elapsed", Label).update(
            f"Elapsed: {s['elapsed_seconds']}s"
        )


# ---------------------------------------------------------------------------
# Approval queue panel
# ---------------------------------------------------------------------------


class ApprovalsPanel(Static):
    """Shows pending approval tickets."""

    DEFAULT_CSS = """
    ApprovalsPanel { height: 100%; }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._tickets: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        yield Label("PENDING APPROVALS", classes="panel-title")
        yield DataTable(id="approvals-table")

    def on_mount(self) -> None:
        table = self.query_one("#approvals-table", DataTable)
        table.add_columns("Ticket ID", "Action Type", "Risk", "Requested By")

    def refresh_data(self, tickets: list[dict[str, Any]]) -> None:
        table = self.query_one("#approvals-table", DataTable)
        table.clear()
        for t in tickets:
            table.add_row(
                str(t.get("ticket_id", ""))[:12],
                t.get("action_type", "—"),
                t.get("risk_level", "—"),
                t.get("requested_by", "—"),
            )


# ---------------------------------------------------------------------------
# Policy deny log
# ---------------------------------------------------------------------------


class PolicyLogPanel(Static):
    """Scrolling log of policy deny events."""

    DEFAULT_CSS = """
    PolicyLogPanel { height: 100%; }
    """

    def compose(self) -> ComposeResult:
        yield Label("POLICY EVENTS", classes="panel-title")
        yield Log(id="policy-log", auto_scroll=True, max_lines=200)

    def append_deny(self, action_type: str, reason: str = "") -> None:
        ts = time.strftime("%H:%M:%S")
        log_widget = self.query_one("#policy-log", Log)
        log_widget.write_line(f"[{ts}] DENY {action_type!r}  {reason}")

    def refresh_data(self, deny_by_type: dict[str, int]) -> None:
        # We do not clear — new entries are appended as they arrive.
        # This method is a no-op; use ``append_deny`` for real-time updates.
        pass


# ---------------------------------------------------------------------------
# Tool invocations table
# ---------------------------------------------------------------------------


class ToolsTablePanel(Static):
    """Per-tool invocation count and latency table."""

    DEFAULT_CSS = """
    ToolsTablePanel { height: 100%; }
    """

    def compose(self) -> ComposeResult:
        yield Label("TOOL INVOCATIONS", classes="panel-title")
        yield DataTable(id="tools-table")

    def on_mount(self) -> None:
        table = self.query_one("#tools-table", DataTable)
        table.add_columns("Tool", "Invocations", "Avg ms", "P95 ms")

    def refresh_data(self, tool_stats: dict[str, dict[str, Any]]) -> None:
        table = self.query_one("#tools-table", DataTable)
        table.clear()
        for tool, stats in sorted(tool_stats.items()):
            inv = stats.get("invocations", 0)
            avg = stats.get("avg_latency_ms")
            p95 = stats.get("p95_latency_ms")
            table.add_row(
                tool,
                str(inv),
                f"{avg:.1f}" if avg is not None else "—",
                f"{p95:.1f}" if p95 is not None else "—",
            )


# ---------------------------------------------------------------------------
# Metrics summary panel
# ---------------------------------------------------------------------------


class MetricsSummaryPanel(Static):
    """One-line KPI strip."""

    DEFAULT_CSS = """
    MetricsSummaryPanel { height: auto; }
    """

    def compose(self) -> ComposeResult:
        yield Label("METRICS SUMMARY", classes="panel-title")
        yield Label("—", id="metrics-strip")

    def refresh_data(self, metrics: EngagementMetrics | None) -> None:
        if metrics is None:
            return
        s = metrics.summary()
        strip = (
            f"Iterations: {s['iteration_count']}  |  "
            f"Policy denies: {s['policy_deny_count']}  |  "
            f"Parser errors: {s['parser_error_count']}  |  "
            f"Timeouts: {s['timeout_count']}  |  "
            f"Approvals: {s['approval_count']}  |  "
            f"Elapsed: {s['elapsed_seconds']}s"
        )
        self.query_one("#metrics-strip", Label).update(strip)


# ---------------------------------------------------------------------------
# Root application
# ---------------------------------------------------------------------------


class TUIDashboard(App[None]):
    """
    Textual TUI dashboard for the pwnpilot framework.

    Accepts an optional ``engagement_id`` kwarg to lock display to a specific
    engagement.  If omitted, it shows the most-recently-active engagement.
    """

    TITLE = APP_TITLE
    CSS = APP_CSS
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("?", "help", "Help"),
    ]

    _tick: reactive[int] = reactive(0)

    def __init__(
        self,
        engagement_id: str | None = None,
        refresh_interval: float = REFRESH_INTERVAL_S,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._engagement_id = engagement_id
        self._refresh_interval = refresh_interval
        self._pending_approvals: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="top-row"):
            yield StatusPanel(classes="panel", id="status-panel")
            yield ApprovalsPanel(classes="panel", id="approvals-panel")
        with Horizontal(id="mid-row"):
            yield PolicyLogPanel(classes="panel", id="policy-log")
            yield ToolsTablePanel(classes="panel", id="tools-table")
        with Horizontal(id="bottom-row"):
            yield MetricsSummaryPanel(classes="panel", id="metrics-panel")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(self._refresh_interval, self._do_refresh)

    # ------------------------------------------------------------------
    # Refresh callbacks
    # ------------------------------------------------------------------

    def _resolve_metrics(self) -> EngagementMetrics | None:
        if self._engagement_id:
            return metrics_registry.get(self._engagement_id)
        summaries = metrics_registry.all_summaries()
        if not summaries:
            return None
        latest_id = summaries[-1]["engagement_id"]
        return metrics_registry.get(latest_id)

    def _do_refresh(self) -> None:
        metrics = self._resolve_metrics()
        s = metrics.summary() if metrics else {}

        self.query_one(StatusPanel).refresh_data(metrics)
        self.query_one(MetricsSummaryPanel).refresh_data(metrics)
        self.query_one(ToolsTablePanel).refresh_data(s.get("tool_stats", {}))
        self.query_one(ApprovalsPanel).refresh_data(self._pending_approvals)
        self._tick += 1

    def action_refresh(self) -> None:
        self._do_refresh()

    def action_help(self) -> None:
        self.notify(
            "Keybindings: [q] Quit  [r] Refresh  [?] Help",
            title="Help",
        )

    # ------------------------------------------------------------------
    # External feed methods (called from other threads)
    # ------------------------------------------------------------------

    def push_approval(self, ticket: dict[str, Any]) -> None:
        """Add a pending approval ticket to the queue (thread-safe)."""
        self.call_from_thread(self._add_approval, ticket)

    def resolve_approval(self, ticket_id: str) -> None:
        """Remove a resolved approval from the queue (thread-safe)."""
        self.call_from_thread(self._remove_approval, ticket_id)

    def push_policy_deny(self, action_type: str, reason: str = "") -> None:
        """Append a policy deny event to the log (thread-safe)."""
        self.call_from_thread(
            self.query_one(PolicyLogPanel).append_deny, action_type, reason
        )

    def _add_approval(self, ticket: dict[str, Any]) -> None:
        self._pending_approvals.append(ticket)
        self.query_one(ApprovalsPanel).refresh_data(self._pending_approvals)

    def _remove_approval(self, ticket_id: str) -> None:
        self._pending_approvals = [
            t for t in self._pending_approvals if str(t.get("ticket_id")) != ticket_id
        ]
        self.query_one(ApprovalsPanel).refresh_data(self._pending_approvals)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------


def run_dashboard(
    engagement_id: str | None = None,
    refresh_interval: float = REFRESH_INTERVAL_S,
) -> None:
    """Launch the TUI dashboard synchronously (blocks until user quits)."""
    app = TUIDashboard(
        engagement_id=engagement_id,
        refresh_interval=refresh_interval,
    )
    app.run()


if __name__ == "__main__":
    run_dashboard()
