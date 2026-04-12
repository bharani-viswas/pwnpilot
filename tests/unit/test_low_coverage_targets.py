from __future__ import annotations

import subprocess
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.agent.validator import _classify_target_type, ValidatorNode
from pwnpilot.data.recon_store import ReconStore
from pwnpilot.plugins.runner import _preview_bytes, _redact_sensitive, ToolRunner


def _session():
    engine = create_engine("sqlite:///:memory:")
    return sessionmaker(bind=engine)()


def test_validator_target_classification_and_missing_required_params() -> None:
    assert _classify_target_type("http://localhost") == "url"
    assert _classify_target_type("192.168.1.0/24") == "cidr"
    assert _classify_target_type("192.168.1.10") == "ip"
    assert _classify_target_type("example.com") == "domain"
    assert _classify_target_type("") == "unknown"

    class _LLM:
        def validate(self, _context):
            return {"verdict": "approve", "risk_override": None, "rationale": "ok"}

    node = ValidatorNode(
        llm_router=_LLM(),
        policy_context={
            "available_tools": ["nmap"],
            "tools_catalog": [
                {
                    "tool_name": "nmap",
                    "required_params": ["target", "scan_type"],
                    "supported_target_types": ["ip", "cidr"],
                }
            ],
        },
    )

    state = {
        "engagement_id": str(uuid4()),
        "proposed_action": {
            "tool_name": "nmap",
            "target": "192.168.1.10",
            "action_type": "recon_passive",
            "params": {},
            "estimated_risk": "low",
            "rationale": "x",
        },
        "kill_switch": False,
    }
    out = node(state)
    assert out["validation_result"]["verdict"] == "reject"
    assert "missing required parameters" in out["validation_result"]["rationale"]


def test_recon_store_upsert_update_and_summary_branches() -> None:
    s = _session()
    store = ReconStore(s)
    eid = uuid4()

    host_id = store.upsert_host(eid, "10.0.0.1", hostname="h1", status="up")
    # update existing host path
    host_id_2 = store.upsert_host(eid, "10.0.0.1", os_guess="linux", status="up")
    assert host_id == host_id_2

    svc_id = store.upsert_service(host_id, eid, 22, service_name="ssh", protocol="tcp")
    # update existing service path
    svc_id_2 = store.upsert_service(host_id, eid, 22, service_name="ssh", product="OpenSSH", protocol="tcp")
    assert svc_id == svc_id_2

    summary = store.get_summary(eid)
    assert summary["total_hosts"] == 1
    assert 22 in summary["all_ports_found"]
    assert "10.0.0.1" in summary["high_risk_hosts"]


def test_runner_helper_redaction_and_preview() -> None:
    payload = {
        "token": "abc",
        "nested": {"password": "x", "safe": 1},
        "items": [{"api_key": "k"}, "ok"],
    }
    red = _redact_sensitive(payload)
    assert red["token"] == "<redacted>"
    assert red["nested"]["password"] == "<redacted>"
    assert red["nested"]["safe"] == 1
    assert red["items"][0]["api_key"] == "<redacted>"

    assert _preview_bytes(b"") == ""
    long_text = ("a" * 2100).encode()
    prev = _preview_bytes(long_text)
    assert prev.endswith("...<truncated>")


def test_runner_run_subprocess_timeout_and_file_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    s = _session()
    # Minimal runner; we only call private method, so dependencies can be placeholders.
    runner = ToolRunner(
        adapters={},
        evidence_store=SimpleNamespace(),
        kill_switch=SimpleNamespace(is_set=lambda: False),
        timeout=1,
    )

    class _Proc:
        pid = 1234
        returncode = 0

        def communicate(self, timeout=None):
            if timeout is not None:
                raise subprocess.TimeoutExpired(cmd=["nmap"], timeout=timeout)
            return b"out", b"err"

    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: _Proc())
    monkeypatch.setattr("os.getpgid", lambda _pid: 999)
    monkeypatch.setattr("os.killpg", lambda _pgid, _sig: None)

    stdout, stderr, code, timed_out = runner._run_subprocess(["nmap"], "nmap")
    assert timed_out is True
    assert stdout == b"out"
    assert stderr == b"err"
    assert code == 0

    def _raise_fnf(*args, **kwargs):
        raise FileNotFoundError("missing")

    monkeypatch.setattr("subprocess.Popen", _raise_fnf)
    monkeypatch.setattr("pwnpilot.plugins.runner.candidate_binaries", lambda _tool, _bin: ["nmap", "nmap.exe"])

    with pytest.raises(FileNotFoundError) as exc:
        runner._run_subprocess(["nmap"], "nmap")
    assert "Checked candidates" in str(exc.value)
