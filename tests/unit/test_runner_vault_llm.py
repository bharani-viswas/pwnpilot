"""Unit tests for ToolRunner (mocked subprocess), SecretsVault, LLMRouter."""
from __future__ import annotations

import os
import unittest.mock as mock
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pwnpilot.data.evidence_store import EvidenceStore
from pwnpilot.governance.kill_switch import KillSwitch
from pwnpilot.plugins.adapters.nmap import NmapAdapter
from pwnpilot.plugins.runner import HaltedError, ToolRunner
from pwnpilot.data.models import ActionRequest, ActionType, RiskLevel


def _session():
    engine = create_engine("sqlite:///:memory:")
    return sessionmaker(bind=engine)()


# ---------------------------------------------------------------------------
# Tool Runner
# ---------------------------------------------------------------------------


class TestToolRunner:
    def _make_runner(self, tmp_path):
        session = _session()
        evidence_store = EvidenceStore(base_dir=tmp_path / "ev", session=session)
        ks = KillSwitch()
        return ToolRunner(
            adapters={"nmap": NmapAdapter()},
            evidence_store=evidence_store,
            kill_switch=ks,
        ), ks

    def test_halted_raises_before_execution(self, tmp_path):
        runner, ks = self._make_runner(tmp_path)
        ks.trigger("test")
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )
        with pytest.raises(HaltedError):
            runner.execute(action)

    def test_unknown_tool_raises(self, tmp_path):
        runner, _ = self._make_runner(tmp_path)
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="unknown_tool",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )
        with pytest.raises(KeyError):
            runner.execute(action)

    def test_execute_with_mocked_subprocess(self, tmp_path):
        runner, _ = self._make_runner(tmp_path)
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )

        nmap_xml = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

        with mock.patch.object(runner, "_run_subprocess", return_value=(nmap_xml, b"", 0, False)):
            result = runner.execute(action)

        assert result.exit_code == 0
        assert result.tool_name == "nmap"
        assert result.error_class is None
        assert result.parser_confidence > 0.5

    def test_string_command_raises_value_error(self, tmp_path):
        runner, _ = self._make_runner(tmp_path)

        class BadAdapter(NmapAdapter):
            def build_command(self, params):
                return "nmap -sV 10.0.0.1"  # Returns string, not list!

        runner._adapters["bad_nmap"] = BadAdapter()
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="bad_nmap",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )
        with pytest.raises(ValueError, match="list"):
            runner.execute(action)

    def test_timeout_sets_error_class(self, tmp_path):
        runner, _ = self._make_runner(tmp_path)
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )

        with mock.patch.object(runner, "_run_subprocess", return_value=(b"", b"", 0, True)):
            result = runner.execute(action)

        from pwnpilot.data.models import ErrorClass
        assert result.error_class == ErrorClass.TIMEOUT


# ---------------------------------------------------------------------------
# Secrets Vault
# ---------------------------------------------------------------------------


class TestSecretsVault:
    def test_store_and_retrieve(self, tmp_path):
        os.environ["PWNPILOT_VAULT_KEY"] = _generate_fernet_key()
        try:
            from pwnpilot.secrets.vault import SecretsVault
            session = _session()
            vault = SecretsVault(session)
            vault.store("api_key", "supersecret")
            assert vault.retrieve("api_key") == "supersecret"
        finally:
            del os.environ["PWNPILOT_VAULT_KEY"]

    def test_missing_key_raises(self):
        os.environ.pop("PWNPILOT_VAULT_KEY", None)
        os.environ.pop("PWNPILOT_VAULT_KEY_FILE", None)
        from pwnpilot.secrets.vault import SecretsVault, VaultKeyError
        session = _session()
        with pytest.raises(VaultKeyError):
            SecretsVault(session)

    def test_delete_secret(self, tmp_path):
        os.environ["PWNPILOT_VAULT_KEY"] = _generate_fernet_key()
        try:
            from pwnpilot.secrets.vault import SecretsVault
            session = _session()
            vault = SecretsVault(session)
            vault.store("to_delete", "value")
            vault.delete("to_delete")
            with pytest.raises(KeyError):
                vault.retrieve("to_delete")
        finally:
            del os.environ["PWNPILOT_VAULT_KEY"]

    def test_list_names(self):
        os.environ["PWNPILOT_VAULT_KEY"] = _generate_fernet_key()
        try:
            from pwnpilot.secrets.vault import SecretsVault
            session = _session()
            vault = SecretsVault(session)
            vault.store("a", "1")
            vault.store("b", "2")
            names = vault.list_names()
            assert "a" in names
            assert "b" in names
        finally:
            del os.environ["PWNPILOT_VAULT_KEY"]


def _generate_fernet_key() -> str:
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()


# ---------------------------------------------------------------------------
# LLM Router (mocked HTTP)
# ---------------------------------------------------------------------------


class TestLLMRouter:
    def test_plan_returns_parsed_dict(self):
        from pwnpilot.control.llm_router import LLMRouter

        router = LLMRouter(cloud_allowed_fn=lambda: False)

        response_json = '{"action_type":"recon_passive","tool_name":"nmap","target":"10.0.0.1","rationale":"init","estimated_risk":"low"}'

        with mock.patch("litellm.completion") as mock_completion:
            mock_completion.return_value = mock.Mock(
                choices=[mock.Mock(message=mock.Mock(content=response_json))]
            )
            result = router.plan({"context": "test"})

        assert result["tool_name"] == "nmap"

    def test_cloud_fallback_denied_raises(self):
        from pwnpilot.control.llm_router import LLMRouter, PolicyDeniedError

        router = LLMRouter(cloud_allowed_fn=lambda: False)

        with mock.patch("litellm.completion") as mock_completion:
            mock_completion.side_effect = Exception("Connection refused")
            with pytest.raises(Exception):
                router.complete("sys", "user")

    def test_parse_json_strips_markdown_fence(self):
        from pwnpilot.control.llm_router import LLMRouter
        result = LLMRouter._parse_json('```json\n{"key": "val"}\n```', "Test")
        assert result["key"] == "val"

    def test_circuit_breaker_opens_after_failures(self):
        from pwnpilot.control.llm_router import LLMRouter, CircuitState

        router = LLMRouter(cloud_allowed_fn=lambda: False)

        with mock.patch("litellm.completion") as mock_completion:
            mock_completion.side_effect = Exception("Network error")
            with mock.patch("time.sleep"):  # skip backoff
                # Need MAX_RETRIES consecutive complete() calls to open circuit
                for _ in range(3):
                    try:
                        router.complete("sys", "user")
                    except Exception:
                        pass

        assert router._circuit_state == CircuitState.OPEN


# ---------------------------------------------------------------------------
# Plugin Trust (dev bypass)
# ---------------------------------------------------------------------------


class TestPluginTrust:
    def test_dev_bypass_allows_unsigned(self, tmp_path):
        os.environ["PWNPILOT_DEV_ALLOW_UNSIGNED"] = "1"
        os.environ.pop("PWNPILOT_ENV", None)
        try:
            from pwnpilot.plugins.trust import verify_adapter_file
            from pwnpilot.plugins.sdk import PluginManifest
            # Create a dummy adapter file
            adapter_file = tmp_path / "dummy.py"
            adapter_file.write_text("# dummy")
            manifest = PluginManifest(
                name="dummy",
                version="1.0",
                risk_class="recon_passive",
            )
            verify_adapter_file(adapter_file, manifest)  # should not raise
        finally:
            del os.environ["PWNPILOT_DEV_ALLOW_UNSIGNED"]

    def test_production_blocks_dev_bypass(self, tmp_path):
        os.environ["PWNPILOT_DEV_ALLOW_UNSIGNED"] = "1"
        os.environ["PWNPILOT_ENV"] = "production"
        try:
            from pwnpilot.plugins.trust import verify_adapter_file, PluginTrustError
            from pwnpilot.plugins.sdk import PluginManifest
            adapter_file = tmp_path / "dummy.py"
            adapter_file.write_text("# dummy")
            manifest = PluginManifest(
                name="dummy", version="1.0", risk_class="recon_passive"
            )
            with pytest.raises(PluginTrustError):
                verify_adapter_file(adapter_file, manifest)
        finally:
            del os.environ["PWNPILOT_DEV_ALLOW_UNSIGNED"]
            del os.environ["PWNPILOT_ENV"]

    def test_missing_checksum_raises(self, tmp_path):
        os.environ.pop("PWNPILOT_DEV_ALLOW_UNSIGNED", None)
        from pwnpilot.plugins.trust import verify_adapter_file, PluginTrustError
        from pwnpilot.plugins.sdk import PluginManifest
        adapter_file = tmp_path / "dummy.py"
        adapter_file.write_text("# dummy")
        manifest = PluginManifest(
            name="dummy", version="1.0", risk_class="recon_passive"
        )
        with pytest.raises(PluginTrustError):
            verify_adapter_file(adapter_file, manifest)

    def test_checksum_mismatch_raises(self, tmp_path):
        import hashlib
        os.environ.pop("PWNPILOT_DEV_ALLOW_UNSIGNED", None)
        from pwnpilot.plugins.trust import verify_adapter_file, PluginTrustError
        from pwnpilot.plugins.sdk import PluginManifest
        adapter_file = tmp_path / "mismatch.py"
        adapter_file.write_text("# real content")
        wrong_checksum = hashlib.sha256(b"wrong content").hexdigest()
        manifest = PluginManifest(
            name="mismatch", version="1.0", risk_class="recon_passive",
            checksum_sha256=wrong_checksum,
        )
        with pytest.raises(PluginTrustError, match="Checksum mismatch"):
            verify_adapter_file(adapter_file, manifest)

    def test_missing_signature_after_checksum_raises(self, tmp_path):
        import hashlib
        os.environ.pop("PWNPILOT_DEV_ALLOW_UNSIGNED", None)
        from pwnpilot.plugins.trust import verify_adapter_file, PluginTrustError
        from pwnpilot.plugins.sdk import PluginManifest
        adapter_file = tmp_path / "nosig.py"
        content = b"# nosig adapter code"
        adapter_file.write_bytes(content)
        correct_checksum = hashlib.sha256(content).hexdigest()
        manifest = PluginManifest(
            name="nosig", version="1.0", risk_class="recon_passive",
            checksum_sha256=correct_checksum,
            # no signature_b64 set
        )
        with pytest.raises(PluginTrustError, match="no signature"):
            verify_adapter_file(adapter_file, manifest)

    def test_invalid_signature_raises(self, tmp_path):
        """Covers Ed25519 verification path (lines 71-81 in trust.py)."""
        import hashlib, base64
        os.environ.pop("PWNPILOT_DEV_ALLOW_UNSIGNED", None)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from pwnpilot.plugins.trust import verify_adapter_file, PluginTrustError, _TRUST_STORE_DIR
        from pwnpilot.plugins.sdk import PluginManifest

        adapter_file = tmp_path / "signed.py"
        content = b"# signed adapter"
        adapter_file.write_bytes(content)
        correct_checksum = hashlib.sha256(content).hexdigest()
        # Build a real Ed25519 key pair and sign with it
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        sig = private_key.sign(correct_checksum.encode())
        # Corrupt the signature to trigger InvalidSignature
        sig_corrupt = bytes([sig[0] ^ 0xFF]) + sig[1:]
        manifest = PluginManifest(
            name="signed", version="1.0", risk_class="recon_passive",
            checksum_sha256=correct_checksum,
            signature_b64=base64.b64encode(sig_corrupt).decode(),
        )
        # Mock _load_trusted_key to return our real public key
        with mock.patch("pwnpilot.plugins.trust._load_trusted_key", return_value=public_key):
            with pytest.raises(PluginTrustError, match="Signature verification failed"):
                verify_adapter_file(adapter_file, manifest)

    def test_valid_signature_passes(self, tmp_path):
        """Covers successful Ed25519 verification (log.info line)."""
        import hashlib, base64
        os.environ.pop("PWNPILOT_DEV_ALLOW_UNSIGNED", None)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from pwnpilot.plugins.trust import verify_adapter_file
        from pwnpilot.plugins.sdk import PluginManifest

        adapter_file = tmp_path / "valid.py"
        content = b"# valid adapter"
        adapter_file.write_bytes(content)
        correct_checksum = hashlib.sha256(content).hexdigest()
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        sig = private_key.sign(correct_checksum.encode())
        manifest = PluginManifest(
            name="valid", version="1.0", risk_class="recon_passive",
            checksum_sha256=correct_checksum,
            signature_b64=base64.b64encode(sig).decode(),
        )
        with mock.patch("pwnpilot.plugins.trust._load_trusted_key", return_value=public_key):
            verify_adapter_file(adapter_file, manifest)  # should not raise

    def test_load_trusted_key_no_key_raises(self, tmp_path):
        """Covers _load_trusted_key with no key file present."""
        from pwnpilot.plugins.trust import _load_trusted_key, PluginTrustError
        import pwnpilot.plugins.trust as trust_mod
        # Point trust store to empty directory so no key file is found
        original_dir = trust_mod._TRUST_STORE_DIR
        try:
            trust_mod._TRUST_STORE_DIR = tmp_path / "empty_trust_store"
            (trust_mod._TRUST_STORE_DIR).mkdir()
            with pytest.raises(PluginTrustError):
                _load_trusted_key("nonexistent_adapter")
        finally:
            trust_mod._TRUST_STORE_DIR = original_dir


# ---------------------------------------------------------------------------
# ToolRunner — additional error paths
# ---------------------------------------------------------------------------


class TestToolRunnerErrorPaths:
    def _make_runner(self, tmp_path):
        session = _session()
        evidence_store = EvidenceStore(base_dir=tmp_path / "ev", session=session)
        ks = KillSwitch()
        return ToolRunner(
            adapters={"nmap": NmapAdapter()},
            evidence_store=evidence_store,
            kill_switch=ks,
        )

    def test_nonzero_exit_sets_error_class(self, tmp_path):
        runner = self._make_runner(tmp_path)
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )
        # Return non-zero exit code with empty XML that will parse without error
        empty_xml = b"<?xml version='1.0'?><nmaprun></nmaprun>"
        with mock.patch.object(runner, "_run_subprocess", return_value=(empty_xml, b"", 1, False)):
            result = runner.execute(action)

        from pwnpilot.data.models import ErrorClass
        assert result.error_class == ErrorClass.NONZERO_EXIT

    def test_parse_error_sets_error_class(self, tmp_path):
        runner = self._make_runner(tmp_path)
        action = ActionRequest(
            engagement_id=uuid4(),
            action_type=ActionType.ACTIVE_SCAN,
            tool_name="nmap",
            params={"target": "10.0.0.1"},
            risk_level=RiskLevel.MEDIUM,
        )
        # Mock parse() on the adapter to raise an unexpected exception
        with mock.patch.object(runner, "_run_subprocess", return_value=(b"output", b"", 0, False)):
            with mock.patch.object(runner._adapters["nmap"], "parse", side_effect=RuntimeError("parser crash")):
                result = runner.execute(action)

        from pwnpilot.data.models import ErrorClass
        assert result.error_class == ErrorClass.PARSE_ERROR
