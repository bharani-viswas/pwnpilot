from __future__ import annotations

from pathlib import Path
from unittest import mock
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.data.models import ActionRequest, ActionType, RiskLevel
from pwnpilot.governance.kill_switch import KillSwitch
from pwnpilot.plugins.generic_adapter import GenericCLIAdapter
from pwnpilot.plugins.manifest_loader import load_manifest_file
from pwnpilot.plugins.binaries import candidate_binaries, resolve_binary_for_tool
from pwnpilot.plugins.runner import ToolRunner


def _session():
    engine = create_engine("sqlite:///:memory:")
    return sessionmaker(bind=engine)()


def _nmap_adapter() -> GenericCLIAdapter:
    manifest_path = Path(__file__).resolve().parents[2] / "pwnpilot" / "plugins" / "manifests" / "nmap.yaml"
    return GenericCLIAdapter(load_manifest_file(manifest_path))


class TestBinaryResolver:
    def test_candidate_binaries_are_os_aware(self):
        with mock.patch("platform.system", return_value="Linux"):
            linux = candidate_binaries("dns", "dig")
        with mock.patch("platform.system", return_value="Windows"):
            windows = candidate_binaries("dns", "dig")

        assert "dig" in linux
        assert "nslookup" in linux
        assert "nslookup" in windows

    def test_resolve_binary_returns_first_available(self):
        with mock.patch("platform.system", return_value="Linux"):
            with mock.patch("shutil.which") as which:
                which.side_effect = [None, "/usr/bin/drill", None]
                resolved = resolve_binary_for_tool("dns", "dig")

        assert resolved == "/usr/bin/drill"

    def test_zap_candidates_prioritize_baseline_script(self) -> None:
        with mock.patch("platform.system", return_value="Linux"):
            candidates = candidate_binaries("zap", "zap-baseline.py")
        assert candidates[0] == "zap-baseline.py"
        assert "zaproxy" not in candidates


class TestToolRunnerBinaryResolution:
    def test_execute_substitutes_resolved_binary(self, tmp_path):
        session = _session()
        evidence_store = EvidenceStore(base_dir=tmp_path / "ev", session=session)
        runner = ToolRunner(
            adapters={"nmap": _nmap_adapter()},
            evidence_store=evidence_store,
            kill_switch=KillSwitch(),
        )

        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )

        nmap_xml = b"<?xml version='1.0'?><nmaprun></nmaprun>"

        with mock.patch("pwnpilot.plugins.runner.resolve_binary_for_tool", return_value="/usr/bin/nmap"):
            with mock.patch.object(runner, "_run_subprocess", return_value=(nmap_xml, b"", 0, False)) as run_spy:
                runner.execute(action)

        used_cmd = run_spy.call_args.args[0]
        used_tool_name = run_spy.call_args.args[1]
        assert used_tool_name == "nmap"
        assert used_cmd[0] == "/usr/bin/nmap"
