from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Callable

from pwnpilot.plugins.parsers.contracts import normalize_execution_hint
from pwnpilot.plugins.sdk import ParsedOutput


_SAFE_FINDING = {
    "severity": "medium",
}

_RISK_MAP = {
    "FAIL": "high",
    "WARN": "medium",
    "INFO": "low",
    "PASS": "info",
}

_ALERT_LINE_RE = re.compile(
    r"^(PASS|WARN|FAIL|INFO)(?:-NEW|-CHANGED|-ABSENT)?\s*:\s+(.+?)\s+\[(\d+)\]"
    r"(?:\s+x\s+(\d+))?",
    re.IGNORECASE,
)

_INJECTABLE_RE = re.compile(
    r"Parameter:\s+(.+?)\s+\((GET|POST|Cookie|User-Agent|Referer|Host|URI)\)\s+is\s+vulnerable",
    re.IGNORECASE,
)

_OSVDB_RE = re.compile(r"OSVDB-(\d+)")
_DIR_LINE_RE = re.compile(
    r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d{3})\)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
)
_DNS_LINE_RE = re.compile(r"^Found:\s*(?P<host>[a-zA-Z0-9.-]+)\s*$")


def parse_zap_text(stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
    if exit_code > 2 and not stdout and not stderr:
        return ParsedOutput(parser_error=f"zap-baseline.py exited with unexpected code {exit_code}", confidence=0.0)

    combined = (stdout + b"\n" + stderr).decode(errors="replace")
    findings: list[dict[str, Any]] = []

    for line in combined.splitlines():
        m = _ALERT_LINE_RE.match(line.strip())
        if not m:
            continue
        risk_word, alert_name, alert_id, count_str = m.groups()
        risk_word = risk_word.upper()
        findings.append(
            {
                "alert_id": alert_id,
                "title": alert_name.strip(),
                "severity": _RISK_MAP.get(risk_word, "info"),
                "risk_level": risk_word,
                "count": int(count_str) if count_str else 1,
                "vuln_ref": f"ZAP-{alert_id}",
            }
        )

    return ParsedOutput(
        findings=findings,
        new_findings_count=len(findings),
        confidence=0.8 if findings else 0.5,
        raw_summary=f"ZAP scan complete. {len(findings)} alert(s) found.",
    )


def parse_nuclei_jsonl(stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
    if exit_code not in (0, 1):
        return ParsedOutput(parser_error=f"nuclei exited with code {exit_code}", confidence=0.0)

    if not stdout:
        return ParsedOutput(
            findings=[],
            execution_hints=[
                normalize_execution_hint(
                    code="no_matches",
                    message="Nuclei completed with no template matches.",
                    severity="info",
                    recommended_action="Pivot to a different tool family or broader recon strategy instead of repeating identical nuclei scans.",
                )
            ],
            raw_summary="nuclei completed with no matches",
            new_findings_count=0,
            confidence=0.6,
        )

    findings: list[dict[str, Any]] = []
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        template_id = entry.get("template-id", "")
        matched_at = entry.get("matched-at", "")
        severity = entry.get("info", {}).get("severity", "info")
        name = entry.get("info", {}).get("name", template_id)
        cve_ids = entry.get("info", {}).get("classification", {}).get("cve-id", [])
        cwe_ids = entry.get("info", {}).get("classification", {}).get("cwe-id", [])
        vuln_ref = cve_ids[0] if cve_ids else (cwe_ids[0] if cwe_ids else template_id)

        findings.append(
            {
                "template_id": template_id,
                "title": name,
                "matched_at": matched_at,
                "severity": severity,
                "vuln_ref": vuln_ref,
                "matcher_name": entry.get("matcher-name", ""),
                "curl_command": entry.get("curl-command", ""),
            }
        )

    return ParsedOutput(
        findings=findings,
        raw_summary=f"nuclei found {len(findings)} issue(s)",
        new_findings_count=len(findings),
        confidence=0.85 if findings else 0.5,
    )


def parse_whatweb_jsonl(stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
    if exit_code not in (0, 1) or not stdout:
        return ParsedOutput(parser_error=f"whatweb exited with code {exit_code} with no output", confidence=0.0)

    services: list[dict[str, Any]] = []
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        plugins = entry.get("plugins", {})
        techs: list[dict[str, Any]] = []
        for plugin_name, plugin_data in plugins.items():
            raw_conf = plugin_data.get("confidence", [50])
            conf = max(raw_conf) if isinstance(raw_conf, list) and raw_conf else int(raw_conf if not isinstance(raw_conf, list) else 50)
            versions = plugin_data.get("version", [])
            techs.append(
                {
                    "name": plugin_name,
                    "version": ", ".join(str(v) for v in versions) if versions else "",
                    "confidence": round(conf / 100.0, 2),
                }
            )

        services.append(
            {
                "url": entry.get("target", ""),
                "http_status": entry.get("http_status", 0),
                "technologies": techs,
                "service_name": "http",
            }
        )

    tech_count = sum(len(s.get("technologies", [])) for s in services)
    return ParsedOutput(
        services=services,
        new_findings_count=0,
        confidence=0.9 if services else 0.4,
        raw_summary=f"WhatWeb: {tech_count} technology signature(s) across {len(services)} target(s)",
    )


def parse_nmap_xml(stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
    if not stdout or exit_code not in (0, 1):
        return ParsedOutput(parser_error=f"nmap exited with code {exit_code}", confidence=0.0)

    try:
        root = ET.fromstring(stdout.decode(errors="replace"))
    except ET.ParseError as exc:
        return ParsedOutput(parser_error=f"XML parse error: {exc}", confidence=0.0)

    hosts: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']") or host_el.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue

        ip = addr_el.attrib.get("addr", "")
        hostnames_el = host_el.find("hostnames/hostname")
        hostname = hostnames_el.attrib.get("name", "") if hostnames_el is not None else ""
        os_match = host_el.find("os/osmatch")
        os_guess = os_match.attrib.get("name", "") if os_match is not None else ""

        hosts.append({"ip": ip, "hostname": hostname, "os_guess": os_guess})

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue

            service_el = port_el.find("service")
            services.append(
                {
                    "ip": ip,
                    "port": int(port_el.attrib.get("portid", 0)),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "service_name": service_el.attrib.get("name", "") if service_el is not None else "",
                    "product": service_el.attrib.get("product", "") if service_el is not None else "",
                    "version": service_el.attrib.get("version", "") if service_el is not None else "",
                }
            )

    return ParsedOutput(
        hosts=hosts,
        services=services,
        raw_summary=f"Discovered {len(hosts)} host(s), {len(services)} service(s)",
        new_findings_count=len(services),
        confidence=0.9 if hosts else 0.3,
    )


def parse_nikto_text(stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
    if not stdout and not stderr:
        return ParsedOutput(parser_error="nikto produced no output", confidence=0.0)

    findings: list[dict[str, Any]] = []
    execution_hints: list[dict[str, Any]] = []
    combined_text = "\n".join(part for part in [stdout.decode(errors="replace"), stderr.decode(errors="replace")] if part)

    for line in combined_text.splitlines():
        line = line.strip()
        if not line.startswith("+"):
            continue

        message = line.lstrip("+ ")
        lower = message.lower()

        if "invalid output format" in lower:
            execution_hints.append(normalize_execution_hint("output_format_invalid", message, "warning", "Nikto does not support the requested output format; use native text parsing."))
            continue
        if "error" in lower:
            execution_hints.append(normalize_execution_hint("execution_error", message, "warning", "Review nikto execution; tool may not have completed successfully."))
            continue
        if lower.startswith(("target ip:", "target hostname:", "target port:", "start time:", "end time:", "server:", "no banner retrieved", "no cgi directories found")):
            continue

        if not any(marker in lower for marker in ("osvdb-", "might be interesting", "contains", "header", "robots.txt", "file/dir", "returned a non-forbidden")):
            continue

        osvdb_match = _OSVDB_RE.search(message)
        ref = f"OSVDB-{osvdb_match.group(1)}" if osvdb_match else "nikto-finding"
        findings.append({"title": message, "severity": "medium", "vuln_ref": ref})

    confidence = 0.75 if findings else 0.55
    return ParsedOutput(
        findings=findings,
        execution_hints=execution_hints,
        raw_summary=f"nikto: {len(findings)} potential issue(s)",
        new_findings_count=len(findings),
        confidence=confidence,
    )


def parse_gobuster_text(stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
    if exit_code not in (0, 1):
        return ParsedOutput(parser_error=f"gobuster exited with code {exit_code}", confidence=0.0)

    lines = (stdout + b"\n" + stderr).decode(errors="replace").splitlines()
    findings: list[dict[str, Any]] = []
    execution_hints: list[dict[str, Any]] = []

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if "wildcard response found" in line.lower():
            execution_hints.append(normalize_execution_hint("wildcard_detected", line, "warning", "Apply -bl (exclude_length) or -fw only when explicitly intended."))
            continue

        m_dir = _DIR_LINE_RE.match(line)
        if m_dir:
            findings.append(
                {
                    "title": f"Discovered path {m_dir.group('path')}",
                    "severity": "low",
                    "vuln_ref": "gobuster-dir-discovery",
                    "path": m_dir.group("path"),
                    "http_status": int(m_dir.group("status")),
                    "size": int(m_dir.group("size")) if m_dir.group("size") else None,
                }
            )
            continue

        m_dns = _DNS_LINE_RE.match(line)
        if m_dns:
            findings.append(
                {
                    "title": f"Discovered subdomain {m_dns.group('host')}",
                    "severity": "low",
                    "vuln_ref": "gobuster-dns-discovery",
                    "host": m_dns.group("host"),
                }
            )

    return ParsedOutput(
        findings=findings,
        execution_hints=execution_hints,
        raw_summary=f"gobuster discovered {len(findings)} item(s)",
        new_findings_count=len(findings),
        confidence=0.8 if findings else 0.6,
    )


def parse_sqlmap_text(stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
    text = (stdout + b"\n" + stderr).decode(errors="replace")

    hints: list[dict[str, Any]] = []
    low = text.lower()
    if "there were no forms found" in low or "no forms found" in low:
        hints.append(normalize_execution_hint("no_forms_detected", "sqlmap did not find forms to test.", "info", "Retry in parameterized mode with explicit query/body parameters."))
    if "no parameter(s) found" in low:
        hints.append(normalize_execution_hint("no_attack_surface", "sqlmap found no injectable parameters.", "info", "Provide explicit query parameter(s) or POST body to test."))

    findings: list[dict[str, Any]] = []
    current_param = None
    for line in text.splitlines():
        m = _INJECTABLE_RE.search(line)
        if m:
            current_param = m.group(1).strip()
            findings.append(
                {
                    "title": f"Potential SQL injection in parameter {current_param}",
                    "severity": "high",
                    "vuln_ref": "sqli",
                    "parameter": current_param,
                }
            )

    return ParsedOutput(
        findings=findings,
        execution_hints=hints,
        raw_summary=f"sqlmap reported {len(findings)} injectable parameter(s)",
        new_findings_count=len(findings),
        confidence=0.9 if findings else 0.55,
    )


def parse_searchsploit_json(stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
    if exit_code not in (0, 1) or not stdout:
        return ParsedOutput(parser_error=f"searchsploit exited with code {exit_code}", confidence=0.0)

    try:
        data = json.loads(stdout.decode(errors="replace"))
    except json.JSONDecodeError as exc:
        return ParsedOutput(parser_error=f"searchsploit: JSON parse error: {exc}", confidence=0.0)

    exploits = data.get("RESULTS_EXPLOIT", [])
    shellcodes = data.get("RESULTS_SHELLCODE", [])
    findings: list[dict[str, Any]] = []
    for entry in exploits + shellcodes:
        edb_id = str(entry.get("EDB-ID", ""))
        title = entry.get("Title", "")
        findings.append(
            {
                "title": title,
                "edb_id": edb_id,
                "path": entry.get("Path", ""),
                "date": entry.get("Date", ""),
                "type": entry.get("Type", ""),
                "vuln_ref": f"EDB-{edb_id}" if edb_id else "EDB",
                "severity": "high",
            }
        )

    return ParsedOutput(
        findings=findings,
        new_findings_count=len(findings),
        confidence=0.9 if findings else 0.7,
        raw_summary=f"searchsploit: {len(exploits)} exploit(s), {len(shellcodes)} shellcode(s) found",
    )


def parse_whois_text(stdout: bytes, stderr: bytes, exit_code: int) -> ParsedOutput:
    raw = stdout.decode("utf-8", errors="replace")
    if not raw.strip() and stderr:
        raw = stderr.decode("utf-8", errors="replace")

    findings = [{"type": "whois_record", "raw": raw[:8000], "severity": "info", "vuln_ref": "whois-info"}] if raw else []
    return ParsedOutput(
        findings=findings,
        raw_summary="whois lookup completed" if raw else "whois produced no output",
        new_findings_count=0,
        confidence=0.7 if raw else 0.4,
    )


_STRATEGIES: dict[str, Callable[[bytes, bytes, int], ParsedOutput]] = {
    "zap_text": parse_zap_text,
    "nuclei_jsonl": parse_nuclei_jsonl,
    "whatweb_jsonl": parse_whatweb_jsonl,
    "nmap_xml": parse_nmap_xml,
    "nikto_text": parse_nikto_text,
    "gobuster_text": parse_gobuster_text,
    "sqlmap_text": parse_sqlmap_text,
    "searchsploit_json": parse_searchsploit_json,
    "whois_text": parse_whois_text,
}


def get_parse_strategy(name: str) -> Callable[[bytes, bytes, int], ParsedOutput]:
    key = str(name or "").strip()
    if key not in _STRATEGIES:
        raise ValueError(f"Unknown parse strategy: {key}")
    return _STRATEGIES[key]
