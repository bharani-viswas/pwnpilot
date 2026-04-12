from __future__ import annotations

from pwnpilot.plugins.parsers.contracts import canonicalize_finding, infer_host_from_service, infer_service_port


def test_canonicalize_finding_prefers_explicit_fields() -> None:
    finding = {
        "title": "Prometheus Metrics - Detect",
        "vuln_ref": "cwe-200",
        "severity": "medium",
        "matched_at": "http://localhost:3000/metrics",
    }

    normalized = canonicalize_finding(finding, "nuclei", "http://localhost:3000")

    assert normalized["title"] == "Prometheus Metrics - Detect"
    assert normalized["vuln_ref"] == "cwe-200"
    assert normalized["asset_ref"] == "http://localhost:3000/metrics"


def test_canonicalize_finding_falls_back_without_unknown_loss() -> None:
    finding = {
        "name": "Directory listing enabled",
        "template_id": "dir-listing",
    }

    normalized = canonicalize_finding(finding, "nuclei", "http://localhost:3000")

    assert normalized["title"] == "Directory listing enabled"
    assert normalized["vuln_ref"] == "dir-listing"
    assert normalized["asset_ref"] == "http://localhost:3000"


def test_infer_host_from_service_localhost_url() -> None:
    host = infer_host_from_service({"url": "http://localhost:3000", "service_name": "http"})

    assert host is not None
    assert host["ip_address"] == "127.0.0.1"
    assert host["hostname"] == "localhost"


def test_infer_service_port_from_url() -> None:
    assert infer_service_port({"url": "https://example.com"}) == 443
