from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from uuid import uuid4

from pwnpilot.agent.executor import _normalize_params, _service_host_fields, ExecutorNode
from pwnpilot.control.engagement import EngagementService
from pwnpilot.control.policy import PolicyEngine
from pwnpilot.data.models import Engagement, EngagementScope
from pwnpilot.tui.app import TUIDashboard


def _engagement_service() -> EngagementService:
    now = datetime.now(timezone.utc)
    eng = Engagement(
        name="exec-storage-test",
        operator_id="op",
        scope=EngagementScope(scope_cidrs=["10.0.0.0/8"]),
        roe_document_hash="b" * 64,
        authoriser_identity="operator@example.com",
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=1),
    )
    return EngagementService(eng)


def _base_state(engagement_id: str) -> dict:
    return {
        "engagement_id": engagement_id,
        "kill_switch": False,
        "proposed_action": {
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "target": "10.0.0.10",
            "params": {},
            "rationale": "collect data",
            "estimated_risk": "low",
        },
        "validation_result": {
            "verdict": "approve",
            "risk_override": None,
            "rationale": "ok",
        },
        "previous_actions": [],
        "no_new_findings_streak": 0,
        "evidence_ids": [],
        "recon_summary": {},
    }


def test_normalize_params_handles_list_and_invalid_severity() -> None:
    params = _normalize_params({"severity": ["low", "critical"]}, "nuclei")
    assert params["severity"] == "critical"

    params2 = _normalize_params({"severity": ["bogus"]}, "nikto")
    assert params2["severity"] == "medium"

    params3 = _normalize_params({"severity": "HIGH"}, "sqlmap")
    assert params3["severity"] == "high"


def test_service_host_fields_fallback_parsing_and_localhost() -> None:
    ip1, host1 = _service_host_fields({"url": "http://localhost:3000"}, "http://fallback")
    assert ip1 == "127.0.0.1"
    assert host1 == "localhost"

    ip2, host2 = _service_host_fields({"url": "http://10.1.2.3:8080"}, "http://fallback")
    assert ip2 == "10.1.2.3"
    assert host2 == "10.1.2.3"


def test_executor_stores_findings_hosts_services_and_hints() -> None:
    policy = PolicyEngine(_engagement_service())
    runner = MagicMock()
    approval = MagicMock()
    audit = MagicMock()
    finding_store = MagicMock()
    recon_store = MagicMock()
    recon_store.upsert_host.return_value = "host-1"
    recon_store.get_summary.return_value = {"hosts_count": 1}
    finding_store.get_summary.return_value = {"findings_count": 1}

    result = MagicMock()
    result.exit_code = 0
    result.duration_ms = 42
    result.stdout_hash = "h1"
    result.stderr_hash = "h2"
    result.stdout_evidence_id = None
    result.stderr_evidence_id = None
    result.stdout_evidence_path = None
    result.stderr_evidence_path = None
    result.parser_confidence = 0.8
    result.error_class = None
    result.parsed_output = {
        "new_findings_count": 1,
        "execution_hints": [{"code": "no_matches"}],
        "findings": [
            {
                "title": "XSS",
                "vuln_ref": "CVE-2026-0001",
                "severity": "high",
                "asset_ref": "http://localhost:3000",
                "confidence": 0.7,
            }
        ],
        "hosts": [
            {
                "hostname": "localhost",
                "ports": [80, {"port": 443, "service": "https"}, {"service": "skip-no-port"}],
            }
        ],
        "services": [
            {
                "url": "http://localhost:3000",
                "service_name": "http",
                "protocol": "tcp",
                "status": "up",
            },
            {
                "url": "http://example.com/no-port",
                "service_name": "web",
            },
        ],
    }
    result.model_dump.return_value = {"exit_code": 0, "parsed_output": result.parsed_output}
    runner.execute.return_value = result

    executor = ExecutorNode(
        policy_engine=policy,
        tool_runner=runner,
        approval_service=approval,
        audit_store=audit,
        finding_store=finding_store,
        recon_store=recon_store,
    )

    engagement_id = str(uuid4())
    state = _base_state(engagement_id)
    out = executor(state)

    assert out["error"] is None
    assert out["last_execution_hints"][0]["code"] == "no_matches"
    assert finding_store.upsert.called
    assert recon_store.upsert_host.call_count >= 1
    assert recon_store.upsert_service.call_count >= 2
    assert out["recon_summary"]["findings_summary"]["findings_count"] == 1


def test_tui_dashboard_internal_methods_without_ui_loop() -> None:
    app = TUIDashboard(engagement_id=None, refresh_interval=0.1)

    class _Panel:
        def __init__(self):
            self.data = None

        def refresh_data(self, data):
            self.data = data

    status = _Panel()
    metrics = _Panel()
    tools = _Panel()
    approvals = _Panel()

    app.query_one = MagicMock(side_effect=[status, metrics, tools, approvals, approvals, approvals])

    # no metrics yet
    app._do_refresh()
    assert app._tick == 1

    app._add_approval({"ticket_id": "t1", "action_type": "exploit"})
    assert len(app._pending_approvals) == 1

    app._remove_approval("t1")
    assert app._pending_approvals == []

    notified = {}
    app.notify = lambda msg, title=None: notified.update({"msg": msg, "title": title})
    app.action_help()
    assert "Keybindings" in notified["msg"]
