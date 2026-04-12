from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from typer.testing import CliRunner

from pwnpilot.cli import app


runner = CliRunner()


def test_resume_success_and_failure_paths() -> None:
    eid = str(uuid4())
    with patch("pwnpilot.runtime.resume_engagement", return_value=eid):
        ok = runner.invoke(app, ["resume", eid])
    assert ok.exit_code == 0

    with patch("pwnpilot.runtime.resume_engagement", side_effect=RuntimeError("boom")):
        bad = runner.invoke(app, ["resume", eid])
    assert bad.exit_code == 1


def test_approve_and_deny_commands() -> None:
    svc = SimpleNamespace(
        approve=lambda *args, **kwargs: SimpleNamespace(),
        deny=lambda *args, **kwargs: SimpleNamespace(),
    )
    with patch("pwnpilot.runtime.get_approval_service", return_value=svc):
        tid = str(uuid4())
        res1 = runner.invoke(app, ["approve", tid, "--operator", "op", "--reason", "ok"])
        res2 = runner.invoke(app, ["deny", tid, "--operator", "op", "--reason", "no"])
    assert res1.exit_code == 0
    assert res2.exit_code == 0


def test_report_success_and_failure(tmp_path: Path) -> None:
    eid = str(uuid4())
    bundle = tmp_path / "bundle.json"
    summary = tmp_path / "summary.md"
    with patch("pwnpilot.runtime.generate_report", return_value=(bundle, summary)):
        ok = runner.invoke(app, ["report", eid, "--output", str(tmp_path)])
    assert ok.exit_code == 0

    with patch("pwnpilot.runtime.generate_report", side_effect=RuntimeError("report-fail")):
        bad = runner.invoke(app, ["report", eid])
    assert bad.exit_code == 1


def test_verify_success_and_failure() -> None:
    eid = str(uuid4())
    store = MagicMock()
    store.verify_chain.return_value = None
    with patch("pwnpilot.runtime.get_db_session", return_value=object()):
        with patch("pwnpilot.data.audit_store.AuditStore", return_value=store):
            ok = runner.invoke(app, ["verify", eid])
    assert ok.exit_code == 0

    store2 = MagicMock()
    store2.verify_chain.side_effect = RuntimeError("bad chain")
    with patch("pwnpilot.runtime.get_db_session", return_value=object()):
        with patch("pwnpilot.data.audit_store.AuditStore", return_value=store2):
            bad = runner.invoke(app, ["verify", eid])
    assert bad.exit_code == 1


def test_simulate_command_renders_table(tmp_path: Path) -> None:
    actions = [
        {
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "params": {"target": "10.0.0.1"},
            "risk_level": "low",
            "engagement_id": str(uuid4()),
        }
    ]
    actions_file = tmp_path / "actions.json"
    actions_file.write_text(json.dumps(actions), encoding="utf-8")
    sim_out = [
        {
            "action_type": "recon_passive",
            "tool_name": "nmap",
            "verdict": "allow",
            "reason": "ok",
        }
    ]

    with patch("pwnpilot.runtime.run_policy_simulation", return_value=sim_out):
        res = runner.invoke(
            app,
            ["simulate", str(actions_file), "--engagement", str(uuid4())],
        )
    assert res.exit_code == 0
    assert "Policy Simulation Results" in res.output


def test_tui_command_calls_run_dashboard() -> None:
    with patch("pwnpilot.tui.app.run_dashboard") as run_dash:
        res = runner.invoke(app, ["tui", "--engagement", "e1", "--refresh", "0.5"])
    assert res.exit_code == 0
    run_dash.assert_called_once()


def test_keys_without_generate_and_generate_paths(tmp_path: Path) -> None:
    no_gen = runner.invoke(app, ["keys"])
    assert no_gen.exit_code == 1

    priv = tmp_path / "operator.key"
    pub = tmp_path / "operator.pub"

    with patch("pwnpilot.reporting.signer.ReportSigner.generate_key_pair", return_value=None):
        gen = runner.invoke(app, ["keys", "--generate", "--private-key", str(priv), "--public-key", str(pub)])
    assert gen.exit_code == 0

    priv.write_text("existing", encoding="utf-8")
    with patch("pwnpilot.reporting.signer.ReportSigner.generate_key_pair", return_value=None):
        no_overwrite = runner.invoke(
            app,
            ["keys", "--generate", "--private-key", str(priv), "--public-key", str(pub)],
            input="n\n",
        )
    assert no_overwrite.exit_code == 0


def test_verify_report_paths(tmp_path: Path) -> None:
    missing_bundle = runner.invoke(app, ["verify-report", str(tmp_path / "none.json")])
    assert missing_bundle.exit_code == 1

    bundle = tmp_path / "report.json"
    sig = tmp_path / "report.sig"
    bundle.write_text("{}", encoding="utf-8")

    missing_sig = runner.invoke(app, ["verify-report", str(bundle)])
    assert missing_sig.exit_code == 1

    sig.write_text("sig", encoding="utf-8")
    with patch("pwnpilot.reporting.signer.ReportSigner.verify", return_value=None):
        ok = runner.invoke(app, ["verify-report", str(bundle), "--sig", str(sig)])
    assert ok.exit_code == 0

    class _SigErr(Exception):
        pass

    with patch("pwnpilot.reporting.signer.SignatureError", _SigErr):
        with patch("pwnpilot.reporting.signer.ReportSigner.verify", side_effect=_SigErr("invalid")):
            bad = runner.invoke(app, ["verify-report", str(bundle), "--sig", str(sig)])
    assert bad.exit_code == 1

    with patch("pwnpilot.reporting.signer.ReportSigner.verify", side_effect=RuntimeError("oops")):
        bad2 = runner.invoke(app, ["verify-report", str(bundle), "--sig", str(sig)])
    assert bad2.exit_code == 1


def test_db_backup_sqlite_missing_and_unsupported(tmp_path: Path) -> None:
    # sqlite path missing
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("database:\n  url: sqlite:///does-not-exist.db\n", encoding="utf-8")
    missing = runner.invoke(app, ["db", "backup", "--config", str(cfg)])
    assert missing.exit_code == 1

    # unsupported scheme
    cfg2 = tmp_path / "cfg2.yaml"
    cfg2.write_text("database:\n  url: mysql://user:pass@localhost/db\n", encoding="utf-8")
    unsupported = runner.invoke(app, ["db", "backup", "--config", str(cfg2)])
    assert unsupported.exit_code == 1


def test_db_backup_sqlite_and_postgres_branches(tmp_path: Path) -> None:
    # sqlite existing DB + sqlite3 missing
    db = tmp_path / "pwnpilot.db"
    db.write_text("", encoding="utf-8")
    cfg_sqlite = tmp_path / "cfg_sqlite.yaml"
    cfg_sqlite.write_text(f"database:\n  url: sqlite:///{db}\n", encoding="utf-8")

    with patch("shutil.which", return_value=None):
        no_sqlite3 = runner.invoke(app, ["db", "backup", "--config", str(cfg_sqlite)])
    assert no_sqlite3.exit_code == 1

    # sqlite run failure
    with patch("shutil.which", return_value="/usr/bin/sqlite3"):
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stderr="fail")):
            sqlite_fail = runner.invoke(app, ["db", "backup", "--config", str(cfg_sqlite)])
    assert sqlite_fail.exit_code == 1

    # sqlite success
    out_db = tmp_path / "backup.db"
    out_db.write_text("", encoding="utf-8")
    with patch("shutil.which", return_value="/usr/bin/sqlite3"):
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stderr="")):
            sqlite_ok = runner.invoke(app, ["db", "backup", "--config", str(cfg_sqlite), "--output", str(out_db)])
    assert sqlite_ok.exit_code == 0

    # postgres pg_dump missing
    cfg_pg = tmp_path / "cfg_pg.yaml"
    cfg_pg.write_text("database:\n  url: postgresql://user:pass@localhost/db\n", encoding="utf-8")
    with patch("shutil.which", return_value=None):
        pg_missing = runner.invoke(app, ["db", "backup", "--config", str(cfg_pg)])
    assert pg_missing.exit_code == 1

    # postgres pg_dump failure
    with patch("shutil.which", return_value="/usr/bin/pg_dump"):
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stderr="pgfail")):
            pg_fail = runner.invoke(app, ["db", "backup", "--config", str(cfg_pg)])
    assert pg_fail.exit_code == 1

    # postgres success
    out_sql = tmp_path / "backup.sql"
    out_sql.write_text("", encoding="utf-8")
    with patch("shutil.which", return_value="/usr/bin/pg_dump"):
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stderr="")):
            pg_ok = runner.invoke(app, ["db", "backup", "--config", str(cfg_pg), "--output", str(out_sql)])
    assert pg_ok.exit_code == 0


def test_check_command_pass_and_fail() -> None:
    with patch("pwnpilot.runtime.run_startup_checks", return_value=[]):
        ok = runner.invoke(app, ["check"])
    assert ok.exit_code == 0

    with patch("pwnpilot.runtime.run_startup_checks", return_value=["CONFIG: broken"]):
        bad = runner.invoke(app, ["check"])
    assert bad.exit_code == 1


def test_plugins_list_and_roe_subcommands(tmp_path: Path) -> None:
    reg = SimpleNamespace(
        tools={
            "nmap": SimpleNamespace(
                enabled=True,
                risk_class="active_scan",
                binary_name="nmap",
                source="first_party",
                trust_status="trusted",
                trust_reason="ok",
            ),
            "zap": SimpleNamespace(
                enabled=False,
                risk_class="active_scan",
                binary_name="zap",
                source="first_party",
                trust_status="rejected",
                trust_reason="disabled",
            ),
        }
    )
    with patch("pwnpilot.runtime.get_tool_registry", return_value=reg):
        res = runner.invoke(app, ["plugins", "list"])
        res_all = runner.invoke(app, ["plugins", "list", "--show-disabled"])
    assert res.exit_code == 0
    assert res_all.exit_code == 0

    # roe verify: file missing
    rv_missing = runner.invoke(app, ["roe", "verify", str(tmp_path / "missing.yaml")])
    assert rv_missing.exit_code == 1

    # roe verify: valid
    roe_file = tmp_path / "roe.yaml"
    roe_file.write_text("engagement: {}\nscope: {}\npolicy: {}\n", encoding="utf-8")
    with patch("pwnpilot.data.roe_validator.validate_roe_file", return_value=(True, "")):
        with patch("pwnpilot.data.roe_validator._parse_comma_separated_string", return_value=[]):
            rv_ok = runner.invoke(app, ["roe", "verify", str(roe_file)])
    assert rv_ok.exit_code == 0

    rl = runner.invoke(app, ["roe", "list"])
    ra = runner.invoke(app, ["roe", "audit", str(uuid4())])
    out = tmp_path / "audit.json"
    rexp = runner.invoke(app, ["roe", "export", str(uuid4()), "--output", str(out)])
    assert rl.exit_code == 0
    assert ra.exit_code == 0
    assert rexp.exit_code == 0
    assert out.exists()


def test_start_roe_interpretation_and_approval_branches(tmp_path: Path) -> None:
    roe_file = tmp_path / "roe.yaml"
    roe_file.write_text("engagement: {}\nscope: {}\npolicy: {}\n", encoding="utf-8")

    preflight = {"target_family": "web", "sequence": [], "missing_recommended_tools": []}

    fake_cfg = SimpleNamespace(llm=SimpleNamespace(api_key="", model_name="m", api_base_url=""))

    class _InterpreterInvalid:
        def __init__(self, **kwargs):
            pass

        def interpret(self, _roe):
            return SimpleNamespace(is_valid=False, error_message="bad policy")

    with patch("pwnpilot.data.roe_validator.validate_roe_file", return_value=(True, "")):
        with patch("pwnpilot.cli.load_config", return_value=fake_cfg):
            with patch("pwnpilot.agent.roe_interpreter.ROEInterpreter", _InterpreterInvalid):
                res_invalid = runner.invoke(app, ["start", "--name", "t", "--roe-file", str(roe_file)])
    assert res_invalid.exit_code == 1

    policy_obj = SimpleNamespace(scope_cidrs=["10.0.0.0/24"], scope_domains=[], scope_urls=["http://localhost:3000"])
    good_interp = SimpleNamespace(is_valid=True, extracted_policy=policy_obj)

    class _InterpreterGood:
        def __init__(self, **kwargs):
            pass

        def interpret(self, _roe):
            return good_interp

    class _WorkflowFail:
        def create_session(self, **kwargs):
            return SimpleNamespace(session_id="s1")

        def display_policies(self, *args, **kwargs):
            pass

        def request_approval(self, *args, **kwargs):
            raise RuntimeError("approval failed")

    with patch("pwnpilot.data.roe_validator.validate_roe_file", return_value=(True, "")):
        with patch("pwnpilot.cli.load_config", return_value=fake_cfg):
            with patch("pwnpilot.agent.roe_interpreter.ROEInterpreter", _InterpreterGood):
                with patch("pwnpilot.control.roe_approval.ApprovalWorkflow", _WorkflowFail):
                    res_approval_fail = runner.invoke(app, ["start", "--name", "t", "--roe-file", str(roe_file)])
    assert res_approval_fail.exit_code == 1

    class _WorkflowGood:
        def create_session(self, **kwargs):
            return SimpleNamespace(session_id="s1")

        def display_policies(self, *args, **kwargs):
            pass

        def request_approval(self, *args, **kwargs):
            return True

        def approve_policies(self, *args, **kwargs):
            return SimpleNamespace()

    with patch("pwnpilot.data.roe_validator.validate_roe_file", return_value=(True, "")):
        with patch("pwnpilot.cli.load_config", return_value=fake_cfg):
            with patch("pwnpilot.agent.roe_interpreter.ROEInterpreter", _InterpreterGood):
                with patch("pwnpilot.control.roe_approval.ApprovalWorkflow", _WorkflowGood):
                    with patch("pwnpilot.runtime.get_engagement_preflight", return_value=preflight):
                        with patch("pwnpilot.runtime.create_and_run_engagement", return_value=str(uuid4())):
                            with patch("typer.prompt", return_value="secret"):
                                ok = runner.invoke(app, ["start", "--name", "t", "--roe-file", str(roe_file)])
    assert ok.exit_code == 0

    with patch("pwnpilot.data.roe_validator.validate_roe_file", return_value=(True, "")):
        with patch("pwnpilot.cli.load_config", return_value=fake_cfg):
            with patch("pwnpilot.agent.roe_interpreter.ROEInterpreter", _InterpreterGood):
                with patch("pwnpilot.control.roe_approval.ApprovalWorkflow", _WorkflowGood):
                    with patch("pwnpilot.runtime.get_engagement_preflight", return_value=preflight):
                        with patch("pwnpilot.runtime.create_and_run_engagement", return_value=str(uuid4())):
                            skip = runner.invoke(
                                app,
                                ["start", "--name", "t", "--roe-file", str(roe_file), "--roe-skip-approval"],
                            )
    assert skip.exit_code == 0


def test_cli_main_configure_logging_paths() -> None:
    from pwnpilot import cli as cli_mod

    with patch.object(cli_mod, "load_config", side_effect=RuntimeError("no cfg")):
        with patch.object(cli_mod, "configure_logging_from_config") as cfg_log:
            with patch.object(cli_mod, "app") as app_obj:
                cli_mod.main()
    cfg_log.assert_called_once_with(None)
    app_obj.assert_called_once()

    good_cfg = SimpleNamespace(logging=SimpleNamespace(level="INFO"))
    with patch.object(cli_mod, "load_config", return_value=good_cfg):
        with patch.object(cli_mod, "configure_logging_from_config") as cfg_log2:
            with patch.object(cli_mod, "app") as app_obj2:
                cli_mod.main()
    cfg_log2.assert_called_once_with(good_cfg.logging)
    app_obj2.assert_called_once()


def test_start_additional_error_and_legacy_branches(tmp_path: Path) -> None:
    roe_file = tmp_path / "roe.yaml"
    roe_file.write_text("engagement: {}\nscope: {}\npolicy: {}\n", encoding="utf-8")

    # reading ROE file generic error path
    with patch("builtins.open", side_effect=PermissionError("denied")):
        read_err = runner.invoke(app, ["start", "--name", "t", "--roe-file", str(roe_file)])
    assert read_err.exit_code == 1

    # validation failure path
    with patch("pwnpilot.data.roe_validator.validate_roe_file", return_value=(False, "bad schema")):
        bad_val = runner.invoke(app, ["start", "--name", "t", "--roe-file", str(roe_file)])
    assert bad_val.exit_code == 1

    # outer yaml error branch
    import yaml

    with patch("pwnpilot.data.roe_validator.validate_roe_file", side_effect=yaml.YAMLError("yaml boom")):
        outer_yaml = runner.invoke(app, ["start", "--name", "t", "--roe-file", str(roe_file)])
    assert outer_yaml.exit_code == 1

    # legacy branch: scope provided but roe-hash missing
    legacy_missing_hash = runner.invoke(app, ["start", "--name", "legacy", "--cidr", "10.0.0.0/24"])
    assert legacy_missing_hash.exit_code == 1

    # legacy branch: implicit authoriser fallback and local URL warning
    preflight = {"target_family": "web", "sequence": [], "missing_recommended_tools": []}
    with patch("pwnpilot.runtime.get_engagement_preflight", return_value=preflight):
        with patch("pwnpilot.runtime.create_and_run_engagement", return_value=str(uuid4())):
            legacy_ok = runner.invoke(
                app,
                [
                    "start",
                    "--name",
                    "legacy",
                    "--url",
                    "http://localhost:3000",
                    "--roe-hash",
                    "a" * 64,
                ],
            )
    assert legacy_ok.exit_code == 0


def test_roe_verify_failure_and_export_error_paths(tmp_path: Path) -> None:
    roe_file = tmp_path / "roe-invalid.yaml"
    roe_file.write_text("engagement: {}\nscope: {}\npolicy: {}\n", encoding="utf-8")

    # validate_roe_file false branch (lines ~745+)
    with patch("pwnpilot.data.roe_validator.validate_roe_file", return_value=(False, "bad roe")):
        fail_verify = runner.invoke(app, ["roe", "verify", str(roe_file)])
    assert fail_verify.exit_code == 1

    # yaml parse error branch
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("engagement: [broken", encoding="utf-8")
    yaml_verify = runner.invoke(app, ["roe", "verify", str(bad_yaml)])
    assert yaml_verify.exit_code == 1

    # generic exception branch
    with patch("pwnpilot.data.roe_validator.validate_roe_file", side_effect=RuntimeError("oops")):
        generic_verify = runner.invoke(app, ["roe", "verify", str(roe_file)])
    assert generic_verify.exit_code == 1

    # export error branch (lines ~817+)
    out = tmp_path / "export.json"
    with patch("builtins.open", side_effect=OSError("disk full")):
        export_fail = runner.invoke(app, ["roe", "export", str(uuid4()), "--output", str(out)])
    assert export_fail.exit_code == 1
