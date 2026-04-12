"""
Agent Supervisor — LangGraph StateGraph definition and execution driver.

Graph topology (ADR-013):

  planner ──► validator ──(approve)──► executor ──(continue)──► planner
                        ├─(reject)──► planner                  ├─(report)──► reporter ──► END
                        └─(halt)────► END                      └─(halt)────► END

Safety mechanisms:
- max_iterations hard cap: supervisor increments counter and routes to END if exceeded.
- kill_switch: set by SIGTERM/SIGINT handler or planner circuit breaker; routes to END.
- All agent outputs pass through the Policy Engine inside executor_node before execution.
- SIGTERM/SIGINT trigger a 30-second graceful drain (ADR-009) before sys.exit(0).
"""
from __future__ import annotations

import signal
import sys
import threading
from typing import Any

import structlog
from langgraph.graph import END, StateGraph

from pwnpilot.agent.state import AgentState

log = structlog.get_logger(__name__)

# Reporter is triggered when this many consecutive cycles produce no new findings
CONVERGENCE_THRESHOLD: int = 5

# Do not converge before a minimum number of actions were attempted.
MIN_ACTIONS_BEFORE_CONVERGENCE: int = 5

# Graceful shutdown drain window in seconds (ADR-009)
_DRAIN_SECONDS: int = 30


def _route_after_validation(state: AgentState) -> str:
    if state.get("kill_switch"):
        return "halt"
    vr = state.get("validation_result")
    if vr is None:
        return "halt"
    verdict = vr.get("verdict", "reject")
    if verdict == "approve" or verdict == "escalate":
        return "execute"
    return "replan"  # reject → back to planner


def _route_after_execution(state: AgentState) -> str:
    if state.get("kill_switch"):
        return "halt"
    if state.get("error"):
        return "halt"

    iteration = state.get("iteration_count", 0)
    max_iter = state.get("max_iterations", 50)
    streak = state.get("no_new_findings_streak", 0)
    if "previous_actions" in state:
        action_count = len(state.get("previous_actions", []))
    else:
        action_count = iteration

    if iteration >= max_iter:
        log.info("supervisor.max_iterations_reached", iteration=iteration)
        return "report"

    # Backward-compatibility path for legacy tests/states that model
    # convergence without tracking previous action history.
    if action_count == 0 and streak >= CONVERGENCE_THRESHOLD:
        log.info("supervisor.convergence_detected_legacy", streak=streak)
        return "report"

    if action_count >= MIN_ACTIONS_BEFORE_CONVERGENCE and streak >= CONVERGENCE_THRESHOLD:
        log.info("supervisor.convergence_detected", streak=streak)
        return "report"

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

    Args:
        planner_fn:   Node function for Planner agent.
        validator_fn: Node function for Validator agent.
        executor_fn:  Node function for Executor agent.
        reporter_fn:  Node function for Reporter agent.
        checkpointer: Optional BaseCheckpointSaver for crash-recovery.

    Returns:
        Compiled LangGraph runnable.
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
    """

    def __init__(
        self,
        compiled_graph: Any,
        kill_switch: Any,
        checkpointer: Any | None = None,
    ) -> None:
        self._graph = compiled_graph
        self._kill_switch = kill_switch
        self._checkpointer = checkpointer
        self._register_signals()

    def run(self, initial_state: AgentState, thread_id: str | None = None) -> AgentState:
        """Execute the agent graph from the given initial state."""
        config: dict[str, Any] = {}
        if self._checkpointer and thread_id:
            config["configurable"] = {"thread_id": thread_id}

        result: AgentState = self._graph.invoke(initial_state, config=config)
        return result

    def _register_signals(self) -> None:
        """
        Register SIGTERM and SIGINT handlers (ADR-009).

        On signal: trigger the kill switch, then wait up to _DRAIN_SECONDS for the
        current graph step to finish naturally, then call sys.exit(0).  The drain is
        run on a daemon thread so the main thread (running graph.invoke) is not
        blocked — it will observe kill_switch.is_set() at the next node boundary and
        route to END.
        """
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
