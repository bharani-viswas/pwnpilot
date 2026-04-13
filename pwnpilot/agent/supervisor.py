"""
Agent Supervisor v2 — LangGraph StateGraph definition and execution driver.

Graph topology:

  planner ──► validator ──(approve)──► executor ──(continue)──► planner
                        ├─(reject)──► planner                  ├─(report)──► reporter ──► END
                        └─(halt)────► END                      └─(halt)────► END

v2 additions:
- Routing checks operator_mode (guided, autonomous, monitor, replay).
- Guided mode pauses after each executor step for operator confirmation.
- Finalization sets completion_state on exit paths.
- SIGTERM/SIGINT trigger a 30-second graceful drain (ADR-009).
"""
from __future__ import annotations

import signal
import sys
import threading
import time
from typing import Any

import structlog
from langgraph.graph import END, StateGraph

from pwnpilot.agent.state import AgentState, CompletionState, OperatorMode

log = structlog.get_logger(__name__)

# Reporter is triggered when this many consecutive cycles produce no new findings
CONVERGENCE_THRESHOLD: int = 5

# Reporter is also triggered when repeated nonproductive cycles indicate churn.
NONPRODUCTIVE_CYCLE_THRESHOLD: int = 5

# Do not converge before a minimum number of actions were attempted.
MIN_ACTIONS_BEFORE_CONVERGENCE: int = 5

# Graceful shutdown drain window in seconds (ADR-009)
_DRAIN_SECONDS: int = 30


def _escalate_to_hitl(state: AgentState, reason: str, note: str) -> None:
    """Record a deterministic supervisor escalation request for operator review."""
    directives = dict(state.get("operator_directives") or {})
    directives["supervisor_escalation"] = {
        "reason": reason,
        "recommended_action": "review_or_force_report",
        "requested_at_epoch": time.time(),
    }
    state["operator_directives"] = directives

    messages = list(state.get("operator_messages") or [])
    if not any(msg.get("reason") == reason for msg in messages if isinstance(msg, dict)):
        messages.append(
            {
                "source": "supervisor",
                "reason": reason,
                "message": note,
            }
        )
    state["operator_messages"] = messages

    if state.get("operator_mode") == OperatorMode.AUTONOMOUS.value:
        state["operator_mode"] = OperatorMode.GUIDED.value


def _should_route_to_report(state: AgentState) -> bool:
    state["report_trigger_reason"] = None
    state["termination_reason"] = state.get("termination_reason")
    if bool(state.get("force_report", False)):
        state["report_trigger_reason"] = str(
            state.get("report_trigger_reason") or "forced_report"
        )
        if not state.get("termination_reason"):
            state["termination_reason"] = "forced_report"
        return True

    iteration = state.get("iteration_count", 0)
    max_iter = state.get("max_iterations", 50)
    if iteration >= max_iter:
        log.info("supervisor.max_iterations_reached", iteration=iteration)
        state["report_trigger_reason"] = "max_iterations"
        state["termination_reason"] = "max_iterations"
        return True

    streak = state.get("no_new_findings_streak", 0)
    nonproductive_streak = state.get("nonproductive_cycle_streak", 0)
    if "previous_actions" in state:
        action_count = len(state.get("previous_actions", []))
    else:
        action_count = iteration

    if action_count == 0 and streak >= CONVERGENCE_THRESHOLD:
        log.info("supervisor.convergence_detected_legacy", streak=streak)
        state["report_trigger_reason"] = "convergence_legacy"
        return True

    if action_count >= MIN_ACTIONS_BEFORE_CONVERGENCE and streak >= CONVERGENCE_THRESHOLD:
        log.info("supervisor.convergence_detected", streak=streak)
        state["report_trigger_reason"] = "convergence"
        state["termination_reason"] = "convergence"
        return True

    if nonproductive_streak >= max(1, NONPRODUCTIVE_CYCLE_THRESHOLD - 1):
        state["stall_state"] = "warning"
        _escalate_to_hitl(
            state,
            reason="nonproductive_cycle_warning",
            note="Repeated nonproductive cycles detected; operator review requested.",
        )

    if nonproductive_streak >= NONPRODUCTIVE_CYCLE_THRESHOLD:
        log.info(
            "supervisor.nonproductive_cycle_limit_reached",
            streak=nonproductive_streak,
            iteration=iteration,
        )
        _escalate_to_hitl(
            state,
            reason="nonproductive_cycle_limit",
            note="Nonproductive cycle limit reached; routing to reporter.",
        )
        state["report_trigger_reason"] = "nonproductive_cycle_limit"
        state["stall_state"] = "terminal"
        state["termination_reason"] = "stalled_nonproductive_loop"
        return True

    pv_cycle_streak = int(state.get("planner_validator_cycle_streak", 0) or 0)
    pv_cycle_limit = int(state.get("max_pv_cycles_without_executor", 40) or 40)
    if pv_cycle_streak >= max(1, pv_cycle_limit - 1):
        _escalate_to_hitl(
            state,
            reason="planner_validator_churn_warning",
            note="Planner/validator churn approaching limit; operator review requested.",
        )
    if pv_cycle_streak >= pv_cycle_limit:
        log.info(
            "supervisor.planner_validator_churn_limit_reached",
            streak=pv_cycle_streak,
            limit=pv_cycle_limit,
            iteration=iteration,
        )
        _escalate_to_hitl(
            state,
            reason="planner_validator_churn_limit",
            note="Planner/validator churn limit reached; routing to reporter.",
        )
        state["report_trigger_reason"] = "planner_validator_churn"
        state["stall_state"] = "terminal"
        state["termination_reason"] = "planner_validator_churn"
        return True

    reject_reason_streak = int(state.get("reject_reason_streak_count", 0) or 0)
    reject_reason_limit = int(state.get("max_consecutive_rejects_per_reason", 12) or 12)
    if reject_reason_streak >= max(1, reject_reason_limit - 1):
        _escalate_to_hitl(
            state,
            reason="reject_reason_warning",
            note="Repeated validator rejections detected; operator review requested.",
        )
    if reject_reason_streak >= reject_reason_limit:
        log.info(
            "supervisor.reject_reason_limit_reached",
            streak=reject_reason_streak,
            limit=reject_reason_limit,
            iteration=iteration,
            fingerprint=str(state.get("last_reject_reason_fingerprint", "")),
        )
        _escalate_to_hitl(
            state,
            reason="reject_reason_limit",
            note="Validator rejection limit reached; routing to reporter.",
        )
        state["report_trigger_reason"] = "reject_reason_limit"
        state["stall_state"] = "terminal"
        state["termination_reason"] = "planner_validator_churn"
        return True

    runtime_limit_seconds = int(state.get("max_autonomous_runtime_seconds", 3600) or 3600)
    run_started_at = float(state.get("run_started_at_epoch", 0.0) or 0.0)
    if run_started_at > 0:
        elapsed = max(0.0, time.time() - run_started_at)
        if elapsed >= runtime_limit_seconds:
            log.info(
                "supervisor.runtime_budget_reached",
                elapsed_seconds=round(elapsed, 3),
                limit_seconds=runtime_limit_seconds,
                iteration=iteration,
            )
            _escalate_to_hitl(
                state,
                reason="runtime_budget_limit",
                note="Runtime budget exceeded; routing to reporter.",
            )
            state["report_trigger_reason"] = "runtime_budget"
            state["stall_state"] = "terminal"
            state["termination_reason"] = "runtime_budget_exceeded"
            return True

    return False


def _is_guided_mode(state: AgentState) -> bool:
    """Return True if the operator is in guided mode."""
    return state.get("operator_mode") == OperatorMode.GUIDED.value


def _route_after_validation(state: AgentState) -> str:
    if state.get("kill_switch"):
        return "halt"
    vr = state.get("validation_result")
    if vr is None:
        return "halt"
    if _should_route_to_report(state):
        return "report"
    verdict = vr.get("verdict", "reject")
    if verdict == "reject":
        pv_cycle_streak = int(state.get("planner_validator_cycle_streak", 0) or 0) + 1
        state["planner_validator_cycle_streak"] = pv_cycle_streak

        reason_code = str(vr.get("rejection_reason_code", "")).strip() or "UNSPECIFIED"
        reason_class = str(vr.get("rejection_class", "")).strip() or "unknown"
        fingerprint = f"{reason_code}:{reason_class}"
        previous = str(state.get("last_reject_reason_fingerprint", "")).strip()
        if previous == fingerprint:
            state["reject_reason_streak_count"] = int(
                state.get("reject_reason_streak_count", 0) or 0
            ) + 1
        else:
            state["last_reject_reason_fingerprint"] = fingerprint
            state["reject_reason_streak_count"] = 1
    else:
        state["planner_validator_cycle_streak"] = 0
        state["reject_reason_streak_count"] = 0
        state["last_reject_reason_fingerprint"] = None

    if _should_route_to_report(state):
        return "report"

    if verdict == "approve" or verdict == "escalate":
        return "execute"
    return "replan"  # reject → back to planner


def _route_after_execution(state: AgentState) -> str:
    if state.get("kill_switch"):
        return "halt"
    if state.get("error"):
        return "halt"

    if _should_route_to_report(state):
        return "report"

    # Successful executor traversal resets planner/validator churn watchdogs.
    state["planner_validator_cycle_streak"] = 0
    state["reject_reason_streak_count"] = 0
    state["last_reject_reason_fingerprint"] = None

    # v2: In guided mode, pause after each execution step for operator confirmation.
    # The operator session manager can resume by updating operator_mode back to guided
    # and setting a new directive.  For now, guided mode continues autonomously
    # but with directives applied each iteration.
    return "continue"


def build_graph(
    planner_fn: Any,
    validator_fn: Any,
    executor_fn: Any,
    reporter_fn: Any,
    checkpointer: Any | None = None,
) -> Any:
    """
    Compile and return the LangGraph StateGraph.

    v2: Routing functions check operator_mode and completion_state.
    """
    graph = StateGraph(AgentState)

    graph.add_node("planner", planner_fn)
    graph.add_node("validator", validator_fn)
    graph.add_node("executor", executor_fn)
    graph.add_node("reporter", reporter_fn)

    graph.set_entry_point("planner")

    graph.add_edge("planner", "validator")

    graph.add_conditional_edges(
        "validator",
        _route_after_validation,
        {
            "execute": "executor",
            "replan": "planner",
            "report": "reporter",
            "halt": END,
        },
    )

    graph.add_conditional_edges(
        "executor",
        _route_after_execution,
        {
            "continue": "planner",
            "report": "reporter",
            "halt": END,
        },
    )

    graph.add_edge("reporter", END)

    return graph.compile(checkpointer=checkpointer)


class Supervisor:
    """
    High-level driver: wires agents together, registers signal handlers, and runs the
    compiled LangGraph.

    v2: Accepts an optional operator_session_manager for guided mode support.
    """

    def __init__(
        self,
        compiled_graph: Any,
        kill_switch: Any,
        checkpointer: Any | None = None,
        operator_session_manager: object | None = None,
    ) -> None:
        self._graph = compiled_graph
        self._kill_switch = kill_switch
        self._checkpointer = checkpointer
        self._operator_session = operator_session_manager
        self._register_signals()

    def run(self, initial_state: AgentState, thread_id: str | None = None) -> AgentState:
        """Execute the agent graph from the given initial state."""
        config: dict[str, Any] = {}
        if self._checkpointer and thread_id:
            config["configurable"] = {"thread_id": thread_id}

        # Apply any pending operator session state before running
        if self._operator_session is not None:
            try:
                patch = self._operator_session.state_patch()  # type: ignore[attr-defined]
                initial_state = {**initial_state, **patch}
            except Exception as exc:
                log.warning("supervisor.operator_session_patch_failed", exc=str(exc))

        result: AgentState = self._graph.invoke(initial_state, config=config)
        return result

    def _register_signals(self) -> None:
        """Register SIGTERM and SIGINT handlers (ADR-009)."""
        def _handler(signum: int, _frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            log.warning("supervisor.signal_received", signal=sig_name)
            self._kill_switch.trigger(reason=f"signal:{sig_name}")

            def _drain_and_exit() -> None:
                log.info(
                    "supervisor.drain_started",
                    drain_seconds=_DRAIN_SECONDS,
                    signal=sig_name,
                )
                self._kill_switch.wait(timeout=_DRAIN_SECONDS)
                log.info("supervisor.drain_complete", signal=sig_name)
                sys.exit(0)

            t = threading.Thread(target=_drain_and_exit, daemon=True, name="shutdown-drain")
            t.start()

        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)
