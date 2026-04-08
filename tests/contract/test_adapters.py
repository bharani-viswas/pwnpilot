"""Contract tests: adapter schema validation (Sprint 3 & 7 gate)."""
from __future__ import annotations

import json

import pytest

from pwnpilot.plugins.adapters.nikto import NiktoAdapter
from pwnpilot.plugins.adapters.nmap import NmapAdapter
from pwnpilot.plugins.adapters.nuclei import NucleiAdapter
from pwnpilot.plugins.adapters.searchsploit import SearchsploitAdapter
from pwnpilot.plugins.adapters.sqlmap import SqlmapAdapter
from pwnpilot.plugins.adapters.whatweb import WhatWebAdapter
from pwnpilot.plugins.adapters.zap import ZapAdapter
from pwnpilot.plugins.sdk import BaseAdapter, PluginManifest


class TestNmapContract:
    def setup_method(self):
        self.adapter = NmapAdapter()

    def test_manifest_fields_present(self):
        m = self.adapter.manifest
        assert m.name == "nmap"
        assert m.risk_class == "active_scan"
        assert m.version

    def test_valid_params_accepted(self):
        params = self.adapter.validate_params(
            {"target": "10.0.0.1", "ports": "80,443", "scan_type": "sV", "timing": 3}
        )
        assert params.target == "10.0.0.1"

    def test_empty_target_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": ""})

    def test_invalid_scan_type_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": "10.0.0.1", "scan_type": "INVALID"})

    def test_build_command_returns_list(self):
        params = self.adapter.validate_params({"target": "10.0.0.1"})
        cmd = self.adapter.build_command(params)
        assert isinstance(cmd, list)
        assert cmd[0] == "nmap"

    def test_parse_empty_output_returns_parsed_output(self):
        result = self.adapter.parse(b"", b"", 1)
        assert result.parser_error is not None

    def test_parse_valid_xml(self):
        xml = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="target.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        result = self.adapter.parse(xml, b"", 0)
        assert len(result.hosts) == 1
        assert result.hosts[0]["ip"] == "10.0.0.1"
        assert len(result.services) == 1
        assert result.services[0]["port"] == 80
        assert result.confidence > 0.5


class TestNucleiContract:
    def setup_method(self):
        self.adapter = NucleiAdapter()

    def test_manifest_fields_present(self):
        m = self.adapter.manifest
        assert m.name == "nuclei"
        assert m.risk_class == "active_scan"

    def test_valid_params_accepted(self):
        params = self.adapter.validate_params(
            {"target": "http://10.0.0.1", "severity": "high"}
        )
        assert params.target == "http://10.0.0.1"

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": "10.0.0.1", "severity": "extreme"})

    def test_unsafe_template_tag_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params(
                {"target": "10.0.0.1", "template_tags": ["../etc/passwd"]}
            )

    def test_build_command_returns_list(self):
        params = self.adapter.validate_params({"target": "http://10.0.0.1"})
        cmd = self.adapter.build_command(params)
        assert isinstance(cmd, list)
        assert cmd[0] == "nuclei"

    def test_parse_jsonl_output(self):
        import json
        line = json.dumps({
            "template-id": "CVE-2024-0001",
            "matched-at": "http://10.0.0.1/vuln",
            "info": {
                "name": "Test Vuln",
                "severity": "high",
                "classification": {"cve-id": ["CVE-2024-0001"], "cwe-id": []},
            },
        })
        result = self.adapter.parse(line.encode(), b"", 0)
        assert len(result.findings) == 1
        assert result.findings[0]["vuln_ref"] == "CVE-2024-0001"


# ---------------------------------------------------------------------------
# ZAP adapter
# ---------------------------------------------------------------------------


class TestZapContract:
    def setup_method(self):
        self.adapter = ZapAdapter()

    def test_manifest_fields_present(self):
        m = self.adapter.manifest
        assert m.name == "zap"
        assert m.risk_class == "active_scan"
        assert m.version

    def test_valid_params_accepted(self):
        params = self.adapter.validate_params({"target": "http://10.0.0.1"})
        assert params.target == "http://10.0.0.1"

    def test_non_http_target_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": "10.0.0.1"})

    def test_shell_special_chars_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": "http://10.0.0.1; rm -rf /"})

    def test_invalid_min_level_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params(
                {"target": "http://10.0.0.1", "min_level": "CRITICAL"}
            )

    def test_max_duration_out_of_range_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params(
                {"target": "http://10.0.0.1", "max_duration": 0}
            )

    def test_build_command_returns_list(self):
        params = self.adapter.validate_params({"target": "http://10.0.0.1"})
        cmd = self.adapter.build_command(params)
        assert isinstance(cmd, list)
        assert cmd[0] == "zap-baseline.py"
        assert "http://10.0.0.1" in cmd

    def test_build_command_ajax_spider_flag(self):
        params = self.adapter.validate_params(
            {"target": "http://10.0.0.1", "ajax_spider": True}
        )
        cmd = self.adapter.build_command(params)
        assert "-j" in cmd

    def test_parse_text_output_with_alerts(self):
        output = (
            b"WARN-NEW: X-Content-Type-Options Header Missing [10021] x 3\n"
            b"FAIL-NEW: Missing Anti-clickjacking Header [10020] x 1\n"
            b"PASS: Application Error Disclosure [10023]\n"
        )
        result = self.adapter.parse(b"", output, 1)
        assert len(result.findings) == 3
        severities = {f["severity"] for f in result.findings}
        assert "high" in severities
        assert "medium" in severities

    def test_parse_empty_output_no_crash(self):
        result = self.adapter.parse(b"", b"", 0)
        assert result.findings == []
        assert result.confidence > 0

    def test_parse_bad_exit_code_returns_error(self):
        result = self.adapter.parse(b"", b"", 99)
        assert result.parser_error is not None


# ---------------------------------------------------------------------------
# Nikto adapter
# ---------------------------------------------------------------------------


class TestNiktoContract:
    def setup_method(self):
        self.adapter = NiktoAdapter()

    def test_manifest_fields_present(self):
        m = self.adapter.manifest
        assert m.name == "nikto"
        assert m.risk_class == "active_scan"

    def test_valid_params_accepted(self):
        params = self.adapter.validate_params({"target": "10.0.0.1"})
        assert params.target == "10.0.0.1"

    def test_shell_special_chars_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": "10.0.0.1; id"})

    def test_invalid_port_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": "10.0.0.1", "port": 99999})

    def test_invalid_tuning_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": "10.0.0.1", "tuning": "!!"})

    def test_build_command_returns_list(self):
        params = self.adapter.validate_params({"target": "10.0.0.1"})
        cmd = self.adapter.build_command(params)
        assert isinstance(cmd, list)
        assert cmd[0] == "nikto"
        assert "10.0.0.1" in cmd

    def test_ssl_flag_added(self):
        params = self.adapter.validate_params({"target": "10.0.0.1", "ssl": True})
        cmd = self.adapter.build_command(params)
        assert "-ssl" in cmd

    def test_parse_json_output(self):
        data = json.dumps({
            "vulnerabilities": [
                {
                    "id": "1",
                    "OSVDB": "3093",
                    "url": "/admin/",
                    "method": "GET",
                    "msg": "Admin directory found",
                }
            ]
        })
        result = self.adapter.parse(data.encode(), b"", 0)
        assert len(result.findings) == 1
        assert result.findings[0]["vuln_ref"] == "OSVDB-3093"

    def test_parse_text_output_fallback(self):
        text = (
            b"+ Server: Apache/2.4\n"
            b"+ OSVDB-3092: /admin/ might be interesting\n"
            b"+ The anti-clickjacking X-Frame-Options header is not present.\n"
        )
        result = self.adapter.parse(text, b"", 0)
        assert len(result.findings) >= 1

    def test_parse_no_output_returns_error(self):
        result = self.adapter.parse(b"", b"", 0)
        assert result.parser_error is not None


# ---------------------------------------------------------------------------
# sqlmap adapter
# ---------------------------------------------------------------------------


class TestSqlmapContract:
    def setup_method(self):
        self.adapter = SqlmapAdapter()

    def test_manifest_fields_present(self):
        m = self.adapter.manifest
        assert m.name == "sqlmap"
        assert m.risk_class == "active_scan"

    def test_valid_params_accepted(self):
        params = self.adapter.validate_params(
            {"target": "http://10.0.0.1/page?id=1"}
        )
        assert params.target == "http://10.0.0.1/page?id=1"

    def test_non_http_target_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": "10.0.0.1"})

    def test_shell_chars_in_target_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": "http://10.0.0.1/; rm -rf /"})

    def test_level_out_of_range_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params(
                {"target": "http://10.0.0.1/", "level": 5}
            )

    def test_risk_out_of_range_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params(
                {"target": "http://10.0.0.1/", "risk": 3}
            )

    def test_unsafe_data_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params(
                {"target": "http://10.0.0.1/", "data": "id=1; DROP TABLE users--"}
            )

    def test_build_command_returns_list(self):
        params = self.adapter.validate_params({"target": "http://10.0.0.1/?id=1"})
        cmd = self.adapter.build_command(params)
        assert isinstance(cmd, list)
        assert cmd[0] == "sqlmap"
        assert "--batch" in cmd

    def test_build_command_no_shell_exploits(self):
        params = self.adapter.validate_params({"target": "http://10.0.0.1/?id=1"})
        cmd = self.adapter.build_command(params)
        # Ensure no exploitation flags leaked into detection-only command
        cmd_str = " ".join(cmd)
        assert "--dump" not in cmd_str
        assert "--os-shell" not in cmd_str
        assert "--file-write" not in cmd_str

    def test_parse_injectable_output(self):
        output = (
            b"Parameter: id (GET) is vulnerable\n"
            b"Type: boolean-based blind\n"
            b"Title: AND Boolean-Based Blind\n"
            b"Payload: id=1 AND 1=1\n"
        )
        result = self.adapter.parse(output, b"", 0)
        assert len(result.findings) >= 1
        assert result.findings[0]["vuln_ref"] == "CWE-89"

    def test_parse_not_injectable_output(self):
        output = b"all tested parameters appear to be not injectable"
        result = self.adapter.parse(output, b"", 0)
        assert any(f["severity"] == "info" for f in result.findings)

    def test_parse_empty_no_crash(self):
        result = self.adapter.parse(b"", b"", 1)
        assert isinstance(result.findings, list)


# ---------------------------------------------------------------------------
# WhatWeb adapter
# ---------------------------------------------------------------------------


class TestWhatWebContract:
    def setup_method(self):
        self.adapter = WhatWebAdapter()

    def test_manifest_fields_present(self):
        m = self.adapter.manifest
        assert m.name == "whatweb"
        assert m.risk_class == "recon_passive"

    def test_valid_params_accepted(self):
        params = self.adapter.validate_params({"target": "http://10.0.0.1"})
        assert params.target == "http://10.0.0.1"

    def test_non_http_target_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"target": "10.0.0.1"})

    def test_invalid_aggression_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params(
                {"target": "http://10.0.0.1", "aggression": 5}
            )

    def test_build_command_returns_list(self):
        params = self.adapter.validate_params({"target": "http://10.0.0.1"})
        cmd = self.adapter.build_command(params)
        assert isinstance(cmd, list)
        assert cmd[0] == "whatweb"
        assert "--log-json=-" in cmd
        assert "http://10.0.0.1" in cmd

    def test_parse_jsonl_output(self):
        entry = json.dumps({
            "target": "http://10.0.0.1",
            "http_status": 200,
            "plugins": {
                "Apache": {"confidence": [75], "version": ["2.4.51"]},
                "PHP": {"confidence": [50], "version": ["8.1"]},
            },
        })
        result = self.adapter.parse(entry.encode(), b"", 0)
        assert len(result.services) == 1
        tech_names = [t["name"] for t in result.services[0]["technologies"]]
        assert "Apache" in tech_names
        assert "PHP" in tech_names

    def test_parse_empty_output_no_crash(self):
        result = self.adapter.parse(b"", b"", 0)
        assert result.parser_error is not None

    def test_new_findings_count_zero(self):
        """Fingerprinting does not produce vulnerability findings."""
        entry = json.dumps({
            "target": "http://10.0.0.1",
            "http_status": 200,
            "plugins": {"WordPress": {"confidence": [100], "version": ["6.2"]}},
        })
        result = self.adapter.parse(entry.encode(), b"", 0)
        assert result.new_findings_count == 0


# ---------------------------------------------------------------------------
# Searchsploit adapter
# ---------------------------------------------------------------------------


class TestSearchsploitContract:
    def setup_method(self):
        self.adapter = SearchsploitAdapter()

    def test_manifest_fields_present(self):
        m = self.adapter.manifest
        assert m.name == "searchsploit"
        assert m.risk_class == "recon_passive"

    def test_valid_query_accepted(self):
        params = self.adapter.validate_params({"query": "Apache 2.4"})
        assert params.target == "Apache 2.4"

    def test_target_alias_accepted(self):
        """'target' key accepted as alias for 'query'."""
        params = self.adapter.validate_params({"target": "nginx 1.18"})
        assert params.extra["query"] == "nginx 1.18"

    def test_empty_query_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"query": ""})

    def test_shell_chars_in_query_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params({"query": "apache; rm -rf /"})

    def test_invalid_cve_format_rejected(self):
        with pytest.raises(ValueError):
            self.adapter.validate_params(
                {"query": "apache", "cve": "CVE-NOTVALID"}
            )

    def test_valid_cve_accepted(self):
        params = self.adapter.validate_params(
            {"query": "apache", "cve": "CVE-2021-41773"}
        )
        assert params.extra["cve"] == "CVE-2021-41773"

    def test_build_command_returns_list(self):
        params = self.adapter.validate_params({"query": "Apache 2.4"})
        cmd = self.adapter.build_command(params)
        assert isinstance(cmd, list)
        assert cmd[0] == "searchsploit"
        assert "--json" in cmd

    def test_build_command_exact_flag(self):
        params = self.adapter.validate_params(
            {"query": "Apache 2.4", "exact_match": True}
        )
        cmd = self.adapter.build_command(params)
        assert "--exact" in cmd

    def test_parse_json_output_with_results(self):
        data = json.dumps({
            "RESULTS_EXPLOIT": [
                {
                    "Title": "Apache 2.4.49 - Path Traversal CVE-2021-41773",
                    "EDB-ID": "50406",
                    "Path": "/usr/share/exploitdb/exploits/linux/webapps/50406.py",
                    "Date": "2021-10-05",
                    "Type": "webapps",
                }
            ],
            "RESULTS_SHELLCODE": [],
        })
        result = self.adapter.parse(data.encode(), b"", 0)
        assert len(result.findings) == 1
        assert result.findings[0]["vuln_ref"] == "CVE-2021-41773"
        assert result.findings[0]["edb_id"] == "50406"

    def test_parse_no_results_returns_empty(self):
        data = json.dumps({"RESULTS_EXPLOIT": [], "RESULTS_SHELLCODE": []})
        result = self.adapter.parse(data.encode(), b"", 0)
        assert result.findings == []
        assert result.confidence > 0

    def test_parse_invalid_json_returns_error(self):
        result = self.adapter.parse(b"NOT JSON", b"", 0)
        assert result.parser_error is not None
